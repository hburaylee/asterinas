// SPDX-License-Identifier: MPL-2.0

//! A holder-owned procfs lease for a diagnostic TLB window.
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

const PROC_PATH: &str = "/proc/kernelet_rq1_tlb";
// _IOW('K', 0xe1, int); private to the Host RQ1 diagnostic node.
// Keep in sync with procfs/kernelet_rq1_tlb.rs, outside the normal Kernelet ABI.
const ARM_CAPTURE: libc::c_ulong = 0x4004_4be1;
// Leave room for JSON-string escaping and the enclosing IPC response. The
// kernel emits ASCII JSON. Oversize is an error, never a successful truncation.
const MAX_SNAPSHOT_BYTES: usize = protocol::MAX_MESSAGE_BYTES / 3;

#[derive(Default)]
pub(super) struct TlbCapture {
    file: Option<File>,
}

impl TlbCapture {
    pub(super) fn arm(&mut self, sandbox: &Sandbox) -> Result<()> {
        ensure!(
            self.file.is_none(),
            "a TLB capture is already open; close it first"
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(PROC_PATH)
            .context("open Host RQ1 TLB diagnostic node")?;
        arm_sandbox_fd(&file, sandbox.file().as_raw_fd())
            .context("arm TLB capture using the holder's sandbox descriptor")?;
        self.file = Some(file);
        Ok(())
    }

    pub(super) fn finish(&self) -> Result<String> {
        let file = self.file.as_ref().context("no TLB capture is open")?;
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            // Each attempt starts at zero and reads the immutable cached report.
            let count = file
                .read_at(&mut chunk, bytes.len() as u64)
                .context("finish TLB capture (EBUSY can be retried)")?;
            if count == 0 {
                break;
            }
            ensure!(
                bytes.len() + count <= MAX_SNAPSHOT_BYTES,
                "TLB snapshot exceeds the bounded runtime IPC size"
            );
            bytes.extend_from_slice(&chunk[..count]);
        }
        let raw = String::from_utf8(bytes).context("kernel TLB snapshot is not UTF-8")?;
        let snapshot: serde_json::Value =
            serde_json::from_str(&raw).context("decode kernel TLB snapshot")?;
        ensure!(snapshot.is_object(), "kernel TLB snapshot is not an object");
        // Preserve the kernel's text. The offline strict parser must see the
        // original fields, including any duplicate or malformed schema fields.
        Ok(raw)
    }

    pub(super) fn close(&mut self) -> Result<()> {
        ensure!(self.file.take().is_some(), "no TLB capture is open");
        Ok(())
    }
}

fn arm_sandbox_fd(file: &File, sandbox_fd: RawFd) -> io::Result<()> {
    // SAFETY: ARM_CAPTURE reads one i32. The descriptor value remains alive
    // for the synchronous ioctl; the Host validates its sandbox capability.
    let result = unsafe { libc::ioctl(file.as_raw_fd(), ARM_CAPTURE as _, &sandbox_fd) };
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
    fn arm_rejects_a_regular_file_without_writing_or_masking_errno() {
        let path = std::env::temp_dir().join(format!("kernelet-tlb-arm-{}", std::process::id()));
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
        let error = arm_sandbox_fd(&file, file.as_raw_fd()).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOTTY));
        let mut bytes = [0; 9];
        file.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"unchanged");
    }

    #[test]
    fn finish_rewinds_each_read_and_preserves_failed_or_successful_lease() {
        let (mut writer, reader) = {
            let path =
                std::env::temp_dir().join(format!("kernelet-tlb-read-{}", std::process::id()));
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
        let mut capture = TlbCapture { file: Some(reader) };
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
