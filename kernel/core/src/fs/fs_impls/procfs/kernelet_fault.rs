// SPDX-License-Identifier: MPL-2.0

//! Opt-in image-only injection of the whole-instance `STOP_PANIC` path.
//!
//! A root write of exactly `fatal-stop\n` at offset zero terminates this
//! Kernelet. This exercises fatal-stop containment and teardown; it does not
//! reproduce a hardware exception, memory corruption, or an uncaught Rust panic.

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
};

const COMMAND: &[u8; 11] = b"fatal-stop\n";

/// Represents the root-only inode at `/proc/kernelet_fault`.
pub(super) struct KerneletFaultFileOps;

impl KerneletFaultFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(u+w))
    }
}

impl ProcFileOps for KerneletFaultFileOps {
    fn read_at(&self, _offset: usize, _writer: &mut VmWriter) -> Result<usize> {
        return_errno_with_message!(Errno::EPERM, "fault injection is write-only");
    }

    fn write_at(&self, offset: usize, reader: &mut VmReader) -> Result<usize> {
        if offset != 0 || reader.remain() != COMMAND.len() {
            return_errno_with_message!(Errno::EINVAL, "write exactly fatal-stop\\n at offset zero");
        }
        // Complete the fallible user copy before committing to termination.
        let command = reader.read_val::<[u8; COMMAND.len()]>()?;
        if command != *COMMAND {
            return_errno_with_message!(Errno::EINVAL, "unknown fault injection command");
        }
        ostd::kernelet::entry::stop_panic(format_args!("kernelet-rq3:fatal-stop:v1"))
    }
}
