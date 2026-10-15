// SPDX-License-Identifier: MPL-2.0

//! Host-owned echo-body capture at `/proc/kernelet_rq1_crossing`.
//!
//! The private arm ioctl selects a sandbox capability from this process.
//! The first nonempty pread closes admission. Busy leaves the capture intact
//! while admitted calls drain; an owned report supports short reads and faults.
//! Closing the last open description closes admission without retaining tenants.

use core::fmt::{self, Write};

use ostd::kernelet::crossing_profile::{
    CALL_CAPACITY, CaptureError, CaptureHandle, CaptureSnapshot, DISTURBANCE, INTERRUPT_COVERAGE,
};

use super::CrossingJsonBuffer;
use crate::{
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
    util::ioctl::{RawIoctl, dispatch_ioctl},
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct ArmArgs {
    sandbox_fd: i32,
    reserved: u32,
    nonce: u64,
}

const _: () = {
    assert!(core::mem::size_of::<ArmArgs>() == 16);
    assert!(core::mem::offset_of!(ArmArgs, nonce) == 8);
};

mod ioctl_defs {
    use super::ArmArgs;
    use crate::util::ioctl::{InData, ioc};

    // Private diagnostic command, mirrored in the runtime; _IOW('K', 0xe2, 16B).
    pub(super) type ArmCapture = ioc!(KERNELET_RQ1_CROSSING_ARM, b'K', 0xe2, InData<ArmArgs>);
}

/// Root-only inode; every open description has its own capture and report.
pub(super) struct KerneletRq1CrossingFileOps;

impl KerneletRq1CrossingFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(u+rw))
    }
}

impl ProcFileOpsByHandle for KerneletRq1CrossingFileOps {
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
                    Error::with_message(Errno::ENODATA, "no crossing capture is armed")
                })?;
                let snapshot = capture.finish().map_err(|error| {
                    Error::with_message(capture_errno(error), "cannot finish crossing capture")
                })?;
                // Failed formatting leaves the closed capture available for retry.
                session.report = Some(Arc::new(serialize(&snapshot)?));
            }
            session.report.as_ref().unwrap().clone()
        };
        let bytes = report.as_bytes().get(offset..).unwrap_or_default();
        // Report publication precedes user access; faults cannot consume records.
        Ok(writer.write_fallible(&mut VmReader::from(bytes))?)
    }

    fn write_at(
        &self,
        _offset: usize,
        _reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        return_errno_with_message!(
            Errno::EINVAL,
            "arm crossing capture with its diagnostic ioctl"
        );
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
                        "crossing capture is not opened for writing"
                    );
                }
                let (fd, nonce) = validate_arm(cmd.read()?)?;
                let mut session = self.session.lock();
                if session.capture.is_some() {
                    return_errno_with_message!(
                        Errno::EBUSY,
                        "this open file already has a crossing capture"
                    );
                }
                // sys_ioctl has released its file-table borrow. The capability
                // helper drops file-table and sandbox guards before OSTD arm.
                session.capture = Some(crate::endovisor::rq1_crossing_capture(fd, nonce)?);
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

fn validate_arm(args: ArmArgs) -> Result<(FileDesc, u64)> {
    if args.reserved != 0 || args.nonce == 0 {
        return_errno_with_message!(
            Errno::EINVAL,
            "reserved must be zero and nonce must be nonzero"
        );
    }
    Ok((args.sandbox_fd.try_into()?, args.nonce))
}

fn capture_errno(error: CaptureError) -> Errno {
    match error {
        CaptureError::Invalid => Errno::EINVAL,
        CaptureError::Busy => Errno::EBUSY,
        CaptureError::NoMemory => Errno::ENOMEM,
        CaptureError::Unavailable => Errno::ENODEV,
    }
}

fn serialize(snapshot: &CaptureSnapshot) -> Result<String> {
    let mut output = CrossingJsonBuffer(String::new());
    write_snapshot(&mut output, snapshot)
        .map_err(|_| Error::with_message(Errno::ENOMEM, "cannot format crossing capture"))?;
    Ok(output.0)
}

fn write_snapshot(output: &mut impl Write, snapshot: &CaptureSnapshot) -> fmt::Result {
    write!(
        output,
        "{{\"version\":1,\"kind\":\"rq1_crossing_host\",\"clock\":\"elapsed_tsc\",\"capacity\":{CALL_CAPACITY},\"disturbance\":\"{DISTURBANCE}\",\"interrupt_coverage\":\"{INTERRUPT_COVERAGE}\",\"instance\":{{\"slot\":{},\"generation\":{}}},\"nonce\":{},\"overflow\":{},\"protocol_error\":{},\"incomplete\":{},\"records\":[",
        snapshot.instance.slot,
        snapshot.instance.generation,
        snapshot.nonce,
        snapshot.overflow,
        snapshot.protocol_error,
        snapshot.incomplete,
    )?;
    for (index, record) in snapshot.records.iter().enumerate() {
        if index != 0 {
            output.write_str(",")?;
        }
        write!(
            output,
            "{{\"sequence\":{},\"token\":{},\"vcpu\":{},\"host_cpu_before\":{},\"host_cpu_after\":",
            record.sequence, record.token, record.vcpu, record.host_cpu_before,
        )?;
        write_optional(output, record.host_cpu_after.map(u64::from))?;
        write!(output, ",\"h0_tsc\":{},\"h1_tsc\":", record.h0_tsc)?;
        write_optional(output, record.h1_tsc)?;
        write!(output, ",\"complete\":{}}}", record.complete)?;
    }
    output.write_str("]}\n")
}

fn write_optional(output: &mut impl Write, value: Option<u64>) -> fmt::Result {
    match value {
        Some(value) => write!(output, "{value}"),
        None => output.write_str("null"),
    }
}

#[cfg(ktest)]
mod test {
    use ostd::{
        kernelet::crossing_profile::{CallRecord, InstanceIdentity},
        prelude::ktest,
    };

    use super::*;

    #[ktest]
    fn arm_rejects_reserved_nonce_and_negative_fd() {
        for args in [
            ArmArgs {
                sandbox_fd: 3,
                reserved: 1,
                nonce: 9,
            },
            ArmArgs {
                sandbox_fd: 3,
                reserved: 0,
                nonce: 0,
            },
        ] {
            assert_eq!(validate_arm(args).unwrap_err().error(), Errno::EINVAL);
        }
        assert_eq!(
            validate_arm(ArmArgs {
                sandbox_fd: -1,
                reserved: 0,
                nonce: 9,
            })
            .unwrap_err()
            .error(),
            Errno::EBADF
        );
    }

    #[ktest]
    fn serialization_retains_partial_records_and_error_flags() {
        let snapshot = CaptureSnapshot {
            instance: InstanceIdentity {
                slot: 7,
                generation: 3,
            },
            nonce: 41,
            records: vec![CallRecord {
                sequence: 1,
                token: u64::MAX,
                vcpu: 2,
                host_cpu_before: 5,
                host_cpu_after: None,
                h0_tsc: 10,
                h1_tsc: None,
                complete: false,
            }],
            overflow: true,
            protocol_error: true,
            incomplete: true,
        };
        let report = serialize(&snapshot).unwrap();
        assert!(report.contains("\"version\":1,\"kind\":\"rq1_crossing_host\""));
        assert!(
            report.contains("\"disturbance\":\"unknown\",\"interrupt_coverage\":\"incomplete\"")
        );
        assert!(report.contains("\"overflow\":true,\"protocol_error\":true,\"incomplete\":true"));
        assert!(report.contains("\"token\":18446744073709551615"));
        assert!(
            report.contains(
                "\"host_cpu_after\":null,\"h0_tsc\":10,\"h1_tsc\":null,\"complete\":false"
            )
        );
        assert!(report.ends_with("]}\n"));
    }
}
