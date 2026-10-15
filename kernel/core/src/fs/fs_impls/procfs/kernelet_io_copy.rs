// SPDX-License-Identifier: MPL-2.0

//! Root-only snapshots of Host payload-copy diagnostics.
//!
//! Each read samples 32 empty timer pairs before taking a coherent snapshot.
//! Counter differences cover all Host work between reads, including probe
//! setup/verification. Attribution requires no concurrent unrelated workload.

use aster_util::printer::VmPrinter;

use crate::{
    endovisor::io_copy_profile::{self, Category, Counter},
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
};

const REPORT_BYTES: usize = 4096;
const EMPTY_TIMER_SAMPLES: usize = 32;

pub(super) struct KerneletIoCopyFileOps;

impl KerneletIoCopyFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(u+r))
    }
}

impl ProcFileOps for KerneletIoCopyFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        if offset != 0 {
            return Ok(0);
        }
        if writer.avail() < REPORT_BYTES {
            return_errno_with_message!(Errno::EINVAL, "copy snapshot requires a 4096-byte read");
        }
        io_copy_profile::sample_empty_timer(EMPTY_TIMER_SAMPLES);
        let snapshot = io_copy_profile::snapshot();
        let mut printer = VmPrinter::from(writer);
        write!(
            printer,
            "{{\"version\":1,\"scope\":\"global_host_cumulative_since_boot\",\"timer\":\"task_cpu_excludes_deschedule_includes_irq\",\"copy_scope\":\"device_buffer_copy_only\",\"concurrent_workloads\":\"included_no_automatic_attribution\",\"empty_timer_subtracted\":false,\"empty_samples_per_snapshot\":{EMPTY_TIMER_SAMPLES},\"categories\":{{"
        )?;
        for (index, category) in Category::ALL.iter().enumerate() {
            if index != 0 {
                write!(printer, ",")?;
            }
            write!(printer, "\"{}\":", category.name())?;
            print_counter(&mut printer, snapshot.categories[index])?;
        }
        write!(printer, "}},\"empty_timer\":")?;
        print_counter(&mut printer, snapshot.empty_timer)?;
        writeln!(printer, "}}")?;
        Ok(printer.bytes_written())
    }
}

fn print_counter(printer: &mut VmPrinter, counter: Counter) -> Result<()> {
    write!(
        printer,
        "{{\"bytes\":{},\"calls\":{},\"cpu_ns\":{},\"errors\":{},\"saturated\":{}}}",
        counter.bytes, counter.calls, counter.cpu_ns, counter.errors, counter.saturated
    )?;
    Ok(())
}
