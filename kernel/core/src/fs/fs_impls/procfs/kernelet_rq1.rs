// SPDX-License-Identifier: MPL-2.0

//! Experimental kernel-boundary measurement entry at `/proc/kernelet_rq1`.
//!
//! This file exists only when the kernel is built with `KERNELET_RQ1_BENCH=1`
//! in the build environment (`cfg(kernelet_rq1)`); it is absent from normal
//! builds. One sufficiently large read at offset zero executes one batch of
//! in-kernel measurements of the image-to-Host kernelet service boundary and
//! emits the results as JSON lines, without paying one user-space syscall per
//! measured iteration. Reads at any nonzero offset report EOF, and the file
//! supports only this one-shot read pattern, not general procfs text
//! semantics.
//!
//! Reported tests
//!
//! - `native_kick_invalid_ref`: a `#[inline(never)]` native function that
//!   checks the ABI's maximum vCPU count and returns `-INVALID` for the
//!   measured `u32::MAX`, as the Host's instance-sized carrier lookup does.
//!   The function pointer and the argument are `black_box`ed so the compiler
//!   cannot inline, hoist, or elide calls. This is a lower-bound reference
//!   only: it performs no Host crossing and no authentication, admission, or
//!   accounting.
//! - `empty_loop_ref`: an empty loop with the same iteration count and shape
//!   as the other batches.
//! - `vcpu_kick_invalid` (kernelet image builds only): complete
//!   `services().vcpu_kick(u32::MAX)` service calls. The target is out of
//!   range, so each call enters the normal Host crossing (authentication,
//!   admission, and accounting) and is rejected with `-INVALID`; no device
//!   I/O and no inter-processor work is performed. This deliberately measures
//!   the rejected-argument path: it is NOT a success-path kick and NOT a
//!   universal measure of service cost.
//!
//! Caveats
//!
//! - Every timed loop is bracketed by `aster_time::read_monotonic_time()`
//!   reads: the reported `duration_ns` covers the loop only, including the
//!   per-call `-INVALID` return verification and checksum accumulation, and
//!   never the outer read, console, or cat. Preemption is never disabled, so
//!   normal interruptions are included in the measured wall time, and the
//!   task may migrate between batches (`cpu` is observed racily at report
//!   time).
//! - Each measured call is verified to return `-INVALID`; any other return
//!   aborts the read with an error and no JSON lines are produced.
//! - There is no warmup, repetition, or CPU pinning: single-run results are
//!   noisy by construction.

use core::{hint::black_box, time::Duration};

use aster_util::printer::VmPrinter;
use ostd::{cpu::CpuId, kernelet::abi::INVALID};

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
};

/// Iterations of the native-reference and empty-loop batches.
const REFERENCE_OPERATIONS: u64 = 200_000_000;
/// Iterations of the complete `vcpu_kick(u32::MAX)` service batch.
#[cfg(feature = "kernelet")]
const KICK_OPERATIONS: u64 = 1_000_000;
/// Minimum writable buffer, in bytes, that a single read must provide.
const MIN_BUFFER_BYTES: usize = 1024;

/// Represents the inode at `/proc/kernelet_rq1`.
pub(super) struct KerneletRq1FileOps;

impl KerneletRq1FileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Root-only and read-only: this is an experimental measurement entry.
        ProcFile::new(Self, parent, mkmod!(u+r))
    }
}

impl ProcFileOps for KerneletRq1FileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        // One batch is produced per file, in a single read at offset zero;
        // every other offset reports EOF.
        if offset != 0 {
            return Ok(0);
        }
        // Reject small buffers before any measurement runs: the complete
        // report of one batch must fit in a single read.
        if writer.avail() < MIN_BUFFER_BYTES {
            return_errno_with_message!(
                Errno::EINVAL,
                "the read buffer is too small; a single read of at least 1024 bytes is required"
            );
        }

        let mut printer = VmPrinter::from(writer);
        run_batch(&mut printer)?;
        Ok(printer.bytes_written())
    }
}

/// One completed measurement batch.
struct Measurement {
    test: &'static str,
    operations: u64,
    duration_ns: u64,
    checksum: i64,
}

/// Runs every batch of this build before anything is printed, so that a
/// failed measurement produces an error instead of a partial report.
#[cfg(not(feature = "kernelet"))]
fn run_batch(printer: &mut VmPrinter) -> Result<()> {
    let cpu: u32 = CpuId::current_racy().into();
    let native = bench_native_reference()?;
    let empty = bench_empty_reference()?;
    write_measurement(printer, &native, cpu)?;
    write_measurement(printer, &empty, cpu)
}

/// Runs every batch of this build before anything is printed, so that a
/// failed measurement produces an error instead of a partial report.
#[cfg(feature = "kernelet")]
fn run_batch(printer: &mut VmPrinter) -> Result<()> {
    use ostd::kernelet::entry::services;

    let cpu: u32 = CpuId::current_racy().into();
    let kick: extern "C" fn(u32) -> i64 = black_box(services().vcpu_kick);
    let target: u32 = black_box(u32::MAX);
    let native = bench_native_reference()?;
    let empty = bench_empty_reference()?;
    let kick = measure_invalid_returns("vcpu_kick_invalid", KICK_OPERATIONS, || kick(target))?;
    write_measurement(printer, &native, cpu)?;
    write_measurement(printer, &empty, cpu)?;
    write_measurement(printer, &kick, cpu)
}

/// Measures the native out-of-range validation reference.
fn bench_native_reference() -> Result<Measurement> {
    // The function pointer and the argument are `black_box`ed so that the
    // per-call validation can be neither inlined nor optimized away.
    let validate: fn(u32) -> i64 = black_box(native_kick_invalid_reference as fn(u32) -> i64);
    let target: u32 = black_box(u32::MAX);
    measure_invalid_returns("native_kick_invalid_ref", REFERENCE_OPERATIONS, || {
        validate(target)
    })
}

/// Measures an empty loop with the same iteration count and shape as the
/// measured batches, as a loop-overhead reference.
fn bench_empty_reference() -> Result<Measurement> {
    let start = aster_time::read_monotonic_time();
    for i in 0..REFERENCE_OPERATIONS {
        black_box(i);
    }
    let duration_ns = duration_since(start)?;
    Ok(Measurement {
        test: "empty_loop_ref",
        operations: REFERENCE_OPERATIONS,
        duration_ns,
        checksum: 0,
    })
}

/// Times one batch of calls, each of which must return `-INVALID`; any other
/// return aborts the measurement with an error.
fn measure_invalid_returns<F>(
    test: &'static str,
    operations: u64,
    mut call: F,
) -> Result<Measurement>
where
    F: FnMut() -> i64,
{
    let mut checksum: i64 = 0;
    let start = aster_time::read_monotonic_time();
    for _ in 0..operations {
        let returned = call();
        if returned != -INVALID {
            return_errno_with_message!(Errno::EIO, "a measured call did not return -INVALID");
        }
        checksum = checksum.wrapping_add(returned);
    }
    let duration_ns = duration_since(start)?;
    Ok(Measurement {
        test,
        operations,
        duration_ns,
        checksum,
    })
}

/// Native lower-bound reference for the Host `vcpu_kick` rejection path.
///
/// Rejects the measured `u32::MAX` with the same result as the final
/// instance-sized carrier lookup in `kernelet_host_vcpu_kick_impl`.
/// It performs no Host crossing and no
/// authentication, admission, or accounting, so its cost is a lower bound on
/// the complete service, not an emulation of it.
#[inline(never)]
fn native_kick_invalid_reference(vcpu: u32) -> i64 {
    const CARRIER_CAPACITY: usize = ostd::kernelet::abi::MAX_VCPUS;

    if (vcpu as usize) < CARRIER_CAPACITY {
        0
    } else {
        -INVALID
    }
}

/// Computes the checked, nonzero nanoseconds from a monotonic reading to
/// now.
fn duration_since(start: Duration) -> Result<u64> {
    let duration = aster_time::read_monotonic_time()
        .checked_sub(start)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "the monotonic clock went backwards"))?;
    let nanos = u64::try_from(duration.as_nanos())
        .map_err(|_| Error::with_message(Errno::EINVAL, "the measured duration overflows"))?;
    if nanos == 0 {
        return_errno_with_message!(
            Errno::EINVAL,
            "the monotonic clock did not advance during the measurement"
        );
    }
    Ok(nanos)
}

/// Writes one measurement as a JSON line.
///
/// `correct` is always `true` on output: a batch with any unexpected return
/// aborts the read with an error instead of being reported.
fn write_measurement(printer: &mut VmPrinter, measurement: &Measurement, cpu: u32) -> Result<()> {
    let test = measurement.test;
    let operations = measurement.operations;
    let duration_ns = measurement.duration_ns;
    let checksum = measurement.checksum;
    writeln!(
        printer,
        "{{\"test\":\"{test}\",\"operations\":{operations},\"duration_ns\":{duration_ns},\"checksum\":{checksum},\"correct\":true,\"cpu\":{cpu},\"kernel_mode\":true}}"
    )?;
    Ok(())
}
