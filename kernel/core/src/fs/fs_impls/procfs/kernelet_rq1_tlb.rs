// SPDX-License-Identifier: MPL-2.0

//! Host-only, per-open TLB capture at `/proc/kernelet_rq1_tlb`.
//!
//! The private arm ioctl selects a sandbox FD from the caller's file table.
//! Read the complete JSON document with `pread`. The first nonempty read closes new
//! request admission; `EBUSY` permits retry while admitted requests drain.
//! Successful snapshots are cached for short reads and user-copy retries.
//! Closing the file releases only diagnostic memory, not tenant resources.

use core::fmt::{self, Write};

use ostd::kernelet::tlb_profile::{
    BatchFlushKind, CaptureError, CaptureHandle, CaptureSnapshot, REQUEST_CAPACITY,
};

use crate::{
    dispatch_ioctl,
    events::IoEvents,
    fs::{
        file::{AccessMode, PerOpenFileOps, StatusFlags, file_table::FileDesc, mkmod},
        procfs::template::{ProcFile, ProcFileOpsByHandle},
        vfs::{
            inode::{FileOps, Inode},
            path::Path,
        },
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
    util::ioctl::RawIoctl,
};

mod ioctl_defs {
    use crate::{ioc, util::ioctl::InData};

    // Private to the Host RQ1 diagnostic node; mirrored in runtime/tlb_capture.rs.
    pub(super) type ArmCapture = ioc!(KERNELET_RQ1_TLB_ARM, b'K', 0xe1, InData<i32>);
}

/// Root-only inode for a capability-selected diagnostic capture.
pub(super) struct KerneletRq1TlbFileOps;

impl KerneletRq1TlbFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(u+rw))
    }
}

impl ProcFileOpsByHandle for KerneletRq1TlbFileOps {
    fn open(
        &self,
        access_mode: AccessMode,
        _status_flags: StatusFlags,
    ) -> Result<Box<dyn PerOpenFileOps>> {
        Ok(Box::new(CaptureFile {
            session: Mutex::new(Session {
                capture: None,
                report: None,
            }),
            access_mode,
        }))
    }
}

struct CaptureFile {
    session: Mutex<Session>,
    access_mode: AccessMode,
}

struct Session {
    capture: Option<CaptureHandle>,
    report: Option<Arc<String>>,
}

impl FileOps for CaptureFile {
    fn read_at(
        &self,
        offset: usize,
        writer: &mut VmWriter,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        if writer.avail() == 0 {
            return Ok(0);
        }
        let report = {
            let mut session = self.session.lock();
            if session.report.is_none() {
                let capture = session.capture.as_ref().ok_or_else(|| {
                    Error::with_message(Errno::ENODATA, "no TLB capture is armed")
                })?;
                let snapshot = capture.finish().map_err(|error| {
                    let errno = match error {
                        CaptureError::Busy => Errno::EBUSY,
                        CaptureError::NoMemory => Errno::ENOMEM,
                        CaptureError::Unavailable => Errno::ENODEV,
                    };
                    Error::with_message(errno, "cannot finish TLB capture")
                })?;
                session.report = Some(Arc::new(serialize(&snapshot)?));
            }
            session.report.as_ref().unwrap().clone()
        };
        let bytes = report.as_bytes().get(offset..).unwrap_or_default();
        // Cache publication precedes user access. A copy fault cannot consume
        // the capture, and the file layer advances offsets only on success.
        Ok(writer.write_fallible(&mut VmReader::from(bytes))?)
    }

    fn write_at(
        &self,
        _offset: usize,
        _reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        return_errno_with_message!(Errno::EINVAL, "arm TLB capture with the diagnostic ioctl");
    }
}

impl Pollable for CaptureFile {
    fn poll(&self, mask: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        (IoEvents::IN | IoEvents::OUT) & mask
    }
}

impl PerOpenFileOps for CaptureFile {
    fn ioctl(&self, _path: &Path, raw_ioctl: RawIoctl) -> Result<i32> {
        use ioctl_defs::*;

        dispatch_ioctl!(match raw_ioctl {
            cmd @ ArmCapture => {
                if !self.access_mode.is_writable() {
                    return_errno_with_message!(
                        Errno::EBADF,
                        "TLB capture is not opened for writing"
                    );
                }
                let fd: FileDesc = cmd.read()?.try_into()?;
                let mut session = self.session.lock();
                if session.capture.is_some() {
                    return_errno_with_message!(
                        Errno::EBUSY,
                        "this open file already has a TLB capture"
                    );
                }
                // sys_ioctl releases its file-table borrow before this callback.
                // The capability lookup can then borrow the caller's file table.
                session.capture = Some(crate::endovisor::rq1_tlb_capture(fd)?);
                Ok(0)
            }
            _ => return_errno_with_message!(Errno::ENOTTY, "the ioctl command is unknown"),
        })
    }

    fn check_seekable(&self) -> Result<()> {
        Ok(())
    }

    fn is_offset_aware(&self) -> bool {
        true
    }
}

/// A fallible formatter keeps allocation failure from consuming a snapshot.
struct JsonBuffer(String);

impl Write for JsonBuffer {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.0.try_reserve(value.len()).map_err(|_| fmt::Error)?;
        self.0.push_str(value);
        Ok(())
    }
}

fn serialize(snapshot: &CaptureSnapshot) -> Result<String> {
    let mut output = JsonBuffer(String::new());
    write_snapshot(&mut output, snapshot)
        .map_err(|_| Error::with_message(Errno::ENOMEM, "cannot format TLB capture"))?;
    Ok(output.0)
}

fn write_snapshot(output: &mut impl Write, snapshot: &CaptureSnapshot) -> fmt::Result {
    write!(
        output,
        "{{\"schema\":1,\"capacity\":{REQUEST_CAPACITY},\"instance\":{{\"slot\":{},\"generation\":{}}},\"valid\":{},\"overflow\":{},\"identity_exhausted\":{},\"protocol_error\":{},\"incomplete\":{},\"records\":[",
        snapshot.instance.slot,
        snapshot.instance.generation,
        snapshot.is_valid(),
        snapshot.overflow,
        snapshot.identity_exhausted,
        snapshot.protocol_error,
        snapshot.incomplete,
    )?;
    for (index, record) in snapshot.records.iter().enumerate() {
        if index != 0 {
            output.write_str(",")?;
        }
        let request = &record.request;
        write!(
            output,
            "{{\"sequence\":{},\"request\":{{\"root_id\":",
            record.sequence
        )?;
        match request.root_id {
            Some(id) => write!(output, "{id}")?,
            None => output.write_str("null")?,
        }
        write!(
            output,
            ",\"root_paddr\":{},\"root_generation\":{},\"source_vcpu\":{},\"source_cpu\":{},\"start\":{},\"len\":{}}},\"targets\":[",
            request.root_paddr,
            request.root_generation,
            request.source_vcpu,
            request.source_cpu,
            request.start,
            request.len,
        )?;
        for (target_index, target) in record.targets.iter().enumerate() {
            if target_index != 0 {
                output.write_str(",")?;
            }
            let kind = match target.batch_kind {
                Some(BatchFlushKind::Ranges) => "\"ranges\"",
                Some(BatchFlushKind::FullNonGlobal) => "\"full_non_global\"",
                None => "null",
            };
            write!(
                output,
                "{{\"cpu\":{},\"flush_done\":{},\"batch_kind\":{kind}}}",
                target.cpu, target.flush_done,
            )?;
        }
        write!(output, "],\"wait_returned\":{}}}", record.wait_returned)?;
    }
    output.write_str("]}\n")
}
