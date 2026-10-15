// SPDX-License-Identifier: MPL-2.0

//! A holder-owned procfs lease for a diagnostic crossing window.
//!
//! Only the holder supplies its sandbox FD. Failed reads retain the lease so
//! EBUSY and copy faults can be retried; explicit close also cancels a window.

use std::{
    fs::{File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, RawFd},
        unix::fs::FileExt,
    },
};

use anyhow::{Context, Result, ensure};

use crate::{protocol, uapi::Sandbox};

const PROC_PATH: &str = "/proc/kernelet_rq1_crossing";
// _IOW('K', 0xe2, ArmArgs); private to the Host RQ1 diagnostic node.
// Keep in sync with procfs/kernelet_rq1_crossing.rs, outside the normal Kernelet ABI.
const ARM_CAPTURE: libc::c_ulong = 0x4010_4be2;
// Leave room for JSON-string escaping and the enclosing IPC response. The
// kernel emits ASCII JSON. Oversize is an error, never a successful truncation.
const MAX_SNAPSHOT_BYTES: usize = protocol::MAX_MESSAGE_BYTES / 3;

#[derive(Default)]
pub(super) struct CrossingCapture {
    file: Option<File>,
}

impl CrossingCapture {
    pub(super) fn arm(&mut self, sandbox: &Sandbox, nonce: u64) -> Result<()> {
        ensure!(nonce != 0, "crossing capture nonce must be nonzero");
        ensure!(
            self.file.is_none(),
            "a crossing capture is already open; close it first"
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(PROC_PATH)
            .context("open Host RQ1 crossing diagnostic node")?;
        arm_sandbox_fd(&file, sandbox.file().as_raw_fd(), nonce)
            .context("arm crossing capture using the holder's sandbox descriptor")?;
        self.file = Some(file);
        Ok(())
    }

    pub(super) fn finish(&self) -> Result<String> {
        let file = self.file.as_ref().context("no crossing capture is open")?;
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            // Each attempt starts at zero and reads the immutable cached report.
            let count = file
                .read_at(&mut chunk, bytes.len() as u64)
                .context("finish crossing capture (EBUSY can be retried)")?;
            if count == 0 {
                break;
            }
            ensure!(
                bytes.len() + count <= MAX_SNAPSHOT_BYTES,
                "crossing snapshot exceeds the bounded runtime IPC size"
            );
            bytes.extend_from_slice(&chunk[..count]);
        }
        let raw = String::from_utf8(bytes).context("kernel crossing snapshot is not UTF-8")?;
        let snapshot: serde_json::Value =
            serde_json::from_str(&raw).context("decode kernel crossing snapshot")?;
        ensure!(
            snapshot.is_object(),
            "kernel crossing snapshot is not an object"
        );
        // Preserve the kernel's text. The offline strict parser must see the
        // original fields, including any duplicate or malformed schema fields.
        Ok(raw)
    }

    pub(super) fn close(&mut self) -> Result<()> {
        ensure!(self.file.take().is_some(), "no crossing capture is open");
        Ok(())
    }
}

#[repr(C)]
struct ArmArgs {
    sandbox_fd: i32,
    reserved: u32,
    nonce: u64,
}

fn arm_sandbox_fd(file: &File, sandbox_fd: RawFd, nonce: u64) -> io::Result<()> {
    let args = ArmArgs {
        sandbox_fd,
        reserved: 0,
        nonce,
    };
    // SAFETY: ARM_CAPTURE reads exactly the initialized 16-byte ArmArgs.
    // The sandbox descriptor and args remain alive for the synchronous ioctl.
    let result = unsafe { libc::ioctl(file.as_raw_fd(), ARM_CAPTURE as _, &args) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};

    use super::*;

    #[test]
    fn arm_layout_and_nonce_match_the_private_kernel_request() {
        assert_eq!(std::mem::size_of::<ArmArgs>(), 16);
        assert_eq!(std::mem::offset_of!(ArmArgs, nonce), 8);
        let mut capture = CrossingCapture::default();
        assert!(
            capture
                .arm(&Sandbox::from_file(File::open("/dev/null").unwrap()), 0)
                .is_err()
        );
        assert!(capture.file.is_none());
    }

    #[test]
    fn arm_rejects_a_regular_file_without_writing_or_masking_errno() {
        let path =
            std::env::temp_dir().join(format!("kernelet-crossing-arm-{}", std::process::id()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(path).unwrap();
        file.write_all_at(b"unchanged", 0).unwrap();

        // Linux supplies the real ENOTTY. This checks the runtime ioctl path,
        // not the diagnostic Host's capability checks or capture semantics.
        let error = arm_sandbox_fd(&file, file.as_raw_fd(), 7).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOTTY));
        let mut bytes = [0; 9];
        file.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"unchanged");
    }

    #[test]
    fn finish_rewinds_each_read_and_preserves_failed_or_successful_lease() {
        let (mut writer, reader) = {
            let path =
                std::env::temp_dir().join(format!("kernelet-crossing-read-{}", std::process::id()));
            let writer = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            let reader = File::open(&path).unwrap();
            std::fs::remove_file(path).unwrap();
            (writer, reader)
        };
        // A regular file checks userspace offset/retry handling, not procfs or
        // kernel capture semantics. Successful reports do not consume the FD.
        writer.write_all(b"bad").unwrap();
        let mut capture = CrossingCapture { file: Some(reader) };
        assert!(capture.finish().is_err());
        assert!(capture.file.is_some());
        writer.seek(SeekFrom::Start(0)).unwrap();
        writer.set_len(0).unwrap();
        writer.write_all(b"{\"schema\":1}").unwrap();
        capture
            .file
            .as_mut()
            .unwrap()
            .seek(SeekFrom::End(0))
            .unwrap();
        assert_eq!(capture.finish().unwrap(), "{\"schema\":1}");
        assert_eq!(capture.finish().unwrap(), "{\"schema\":1}");
        capture.close().unwrap();
        assert!(capture.finish().is_err());
        assert!(capture.close().is_err());
    }
}
