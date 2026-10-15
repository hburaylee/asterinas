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
//! Fixture-only builds retain the batch read interface. Diagnostic writes
//! require `KERNELET_RQ1_DIAGNOSTICS=1`; otherwise they return EOPNOTSUPP.
//!
//! With diagnostics enabled, writing a count from 1 to 64 arms a same-task
//! getpid timeline. The next sufficiently large read consumes its complete
//! records instead of running
//! the boundary batches. Timestamps cover the task loop's returned-syscall
//! handling through completion of its next pre-user hook; they exclude the
//! Host gate and the eventual hardware return to user mode.
//! Writing zero starts a count-only FPU window on this Task; the next read
//! consumes it. Native builds also report separate Host-wide counter deltas.
//! Counter snapshots surround each kernel round and include their own probe
//! window. They are paired to the Task sequence, not exact TSC boundaries.
//!
//! Reported tests
//!
//! - `native_echo_ref`: a non-inlined indirect call returning its token.
//!   Both the token and function pointer are opaque to the optimizer.
//! - `vcpu_echo` (image builds only): a successful token return through the
//!   normal authenticated entry, stack check, admission/accounting, and
//!   common return path. The body performs no device operation, allocation,
//!   wakeup, or scheduler request.
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
//! - Every timed loop is bracketed by `crate::time::read_monotonic_time()`
//!   reads: the reported `duration_ns` covers the loop only, including the
//!   per-call return verification, and
//!   never the outer read, console, or cat. Preemption is never disabled, so
//!   normal interruptions are included in the measured wall time, and the
//!   CPU is checked before and after each batch. The caller must pin its
//!   thread; a detected migration aborts the complete read.
//! - Each measured return value is checked. A failed check aborts the read
//!   with an error before any JSON lines are produced.
//! - There is no warmup, repetition, or CPU pinning: single-run results are
//!   noisy by construction.

use core::{hint::black_box, time::Duration};

use aster_util::printer::VmPrinter;
use ostd::{cpu::CpuId, kernelet::abi::INVALID};

#[cfg(kernelet_rq1_diagnostics)]
use crate::fs::procfs::template::read_u64_from;
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
/// Successful service calls per batch in an image build.
#[cfg(feature = "kernelet")]
const ECHO_OPERATIONS: u64 = 1_000_000;
/// Small positive token shared by the native reference and service call.
const ECHO_TOKEN: u64 = 7;
/// Minimum writable buffer, in bytes, that a single read must provide.
const MIN_BUFFER_BYTES: usize = 4096;

/// Represents the inode at `/proc/kernelet_rq1`.
pub(super) struct KerneletRq1FileOps;

impl KerneletRq1FileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Root-only: writes arm a diagnostic capture for the calling task.
        ProcFile::new(Self, parent, mkmod!(u+rw))
    }
}

impl ProcFileOps for KerneletRq1FileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        // One batch is produced per file, in a single read at offset zero;
        // every other offset reports EOF.
        if offset != 0 {
            return Ok(0);
        }
        #[cfg(kernelet_rq1_diagnostics)]
        {
            let task = ostd::task::Task::current().unwrap();
            let thread_local = task.as_thread_local().unwrap();
            let mut timeline = thread_local.getpid_timeline().borrow_mut();
            if timeline.has_event_window() {
                if writer.avail() < MIN_BUFFER_BYTES {
                    return_errno_with_message!(
                        Errno::EINVAL,
                        "FPU window requires a 4096-byte read"
                    );
                }
                let report = timeline.take_event_window().ok_or_else(|| {
                    Error::with_message(Errno::EIO, "FPU counter overflow or unstable snapshot")
                })?;
                drop(timeline);
                let mut printer = VmPrinter::from(writer);
                write_fpu_window(&mut printer, &report)?;
                return Ok(printer.bytes_written());
            }
            if timeline.is_armed() {
                if writer.avail() < 65_536 {
                    return_errno_with_message!(
                        Errno::EINVAL,
                        "timeline requires a 65536-byte read"
                    );
                }
                let batch = timeline.take_batch().ok_or_else(|| {
                    Error::with_message(Errno::EIO, "incomplete or invalid getpid timeline")
                })?;
                drop(timeline);
                let mut printer = VmPrinter::from(writer);
                write_timeline(&mut printer, &batch)?;
                return Ok(printer.bytes_written());
            }
            drop(timeline);
        }
        // Reject small buffers before any measurement runs: the complete
        // report of one batch must fit in a single read.
        if writer.avail() < MIN_BUFFER_BYTES {
            return_errno_with_message!(
                Errno::EINVAL,
                "the read buffer is too small; a single read of at least 4096 bytes is required"
            );
        }

        let mut printer = VmPrinter::from(writer);
        run_batch(&mut printer)?;
        Ok(printer.bytes_written())
    }

    #[cfg(kernelet_rq1_diagnostics)]
    fn write_at(&self, offset: usize, reader: &mut VmReader) -> Result<usize> {
        if offset != 0 {
            return_errno_with_message!(Errno::EINVAL, "timeline must be armed at offset zero");
        }
        let (count, bytes) = read_u64_from(reader)?;
        if count > ostd::kernelet::getpid_profile::timeline::MAX_RECORDS as u64 {
            return_errno_with_message!(Errno::EINVAL, "diagnostic count must be from 0 to 64");
        }
        let task = ostd::task::Task::current().unwrap();
        let thread_local = task.as_thread_local().unwrap();
        if count == 0 {
            let mut timeline = thread_local.getpid_timeline().borrow_mut();
            if timeline.is_armed() {
                return_errno_with_message!(Errno::EBUSY, "a diagnostic capture is already armed");
            }
            if !timeline.arm_event_window() {
                return_errno_with_message!(Errno::EIO, "FPU counter overflow or unstable snapshot");
            }
            return Ok(bytes);
        }
        if !thread_local
            .getpid_timeline()
            .borrow_mut()
            .arm(count as usize, u64::from(current!().pid()))
        {
            return_errno_with_message!(Errno::EBUSY, "a getpid timeline is already armed");
        }
        Ok(bytes)
    }

    #[cfg(not(kernelet_rq1_diagnostics))]
    fn write_at(&self, _offset: usize, _reader: &mut VmReader) -> Result<usize> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "RQ1 per-call diagnostics are disabled");
    }
}

#[cfg(kernelet_rq1_diagnostics)]
fn write_timeline(
    printer: &mut VmPrinter,
    batch: &ostd::kernelet::getpid_profile::timeline::Batch,
) -> Result<()> {
    let operations = batch.records.len() as u64;
    let names = [
        "before_dispatch",
        "dispatch_before_body",
        "body",
        "dispatch_after_body",
        "return_prepare",
    ];
    for (index, (name, ticks)) in core::iter::once(("kernel_round", batch.total_ticks))
        .chain(names.into_iter().zip(batch.sums))
        .chain(core::iter::once(("empty_probe", batch.empty_probe_ticks)))
        .enumerate()
    {
        let whole = ticks / operations;
        let fraction = u128::from(ticks % operations) * 1_000_000_000 / u128::from(operations);
        let unit = if name == "empty_probe" {
            "tsc_ticks/probe"
        } else {
            "tsc_ticks/call"
        };
        write!(
            printer,
            "{{\"metric\":\"getpid.timeline.{name}\",\"value\":{whole}.{fraction:09},\"unit\":\"{unit}\",\"verified\":true,\"errors\":0,\"operations\":{operations},\"elapsed_tsc_ticks\":{ticks},\"clock\":\"ORDERED_TSC\",\"paired\":true,\"kernel_mode\":true,\"probe_reads_per_record\":8"
        )?;
        if index == 0 {
            write!(printer, ",\"fpu_event_names\":[")?;
            write_names(
                printer,
                ostd::kernelet::fpu_profile::EVENT_NAMES.into_iter(),
            )?;
            write!(printer, "],\"fpu_counts\":[")?;
            write_counts(printer, &batch.fpu_counts)?;
            write!(
                printer,
                "],\"fpu_counts_scope\":\"task_counter_snapshots_enclosing_kernel_round\",\"fpu_overflow\":false,\"fpu_complete\":true"
            )?;
            write!(printer, ",\"boundaries\":[")?;
            write_names(
                printer,
                ostd::kernelet::getpid_profile::timeline::Boundary::ALL
                    .into_iter()
                    .map(|boundary| boundary.name()),
            )?;
            write!(printer, "],\"records\":[")?;
            for (index, record) in batch.records.iter().enumerate() {
                if index != 0 {
                    write!(printer, ",")?;
                }
                write!(
                    printer,
                    "{{\"sequence\":{},\"cpu\":{},\"returned_pid\":{},\"empty_probe_ticks\":{},\"timestamps\":[",
                    record.sequence, record.cpu, record.returned_pid, record.empty_probe_ticks,
                )?;
                for (index, ticks) in record.timestamps.iter().enumerate() {
                    if index != 0 {
                        write!(printer, ",")?;
                    }
                    write!(printer, "{ticks}")?;
                }
                write!(printer, "],\"fpu_counts\":[")?;
                write_counts(printer, &record.fpu_counts)?;
                write!(printer, "]}}")?;
            }
            write!(printer, "]")?;
        }
        writeln!(printer, "}}")?;
    }
    Ok(())
}

#[cfg(kernelet_rq1_diagnostics)]
fn write_names<'a>(printer: &mut VmPrinter, names: impl Iterator<Item = &'a str>) -> Result<()> {
    for (index, name) in names.enumerate() {
        if index != 0 {
            write!(printer, ",")?;
        }
        write!(printer, "\"{name}\"")?;
    }
    Ok(())
}

#[cfg(kernelet_rq1_diagnostics)]
fn write_counts(printer: &mut VmPrinter, counts: &[u64]) -> Result<()> {
    for (index, count) in counts.iter().enumerate() {
        if index != 0 {
            write!(printer, ",")?;
        }
        write!(printer, "{count}")?;
    }
    Ok(())
}

#[cfg(kernelet_rq1_diagnostics)]
fn write_fpu_window(
    printer: &mut VmPrinter,
    report: &ostd::kernelet::fpu_profile::WindowReport,
) -> Result<()> {
    use ostd::kernelet::fpu_profile::{CARRIER_EVENT_NAMES, EVENT_NAMES};

    write_fpu_counts(
        printer,
        "task",
        "current_task",
        &report.task_counts,
        EVENT_NAMES.into_iter(),
    )?;
    if let Some(counts) = &report.host_counts {
        write_fpu_counts(
            printer,
            "host",
            "host_kernel_global",
            counts,
            EVENT_NAMES.into_iter().chain(CARRIER_EVENT_NAMES),
        )?;
    }
    Ok(())
}

#[cfg(kernelet_rq1_diagnostics)]
fn write_fpu_counts<'a>(
    printer: &mut VmPrinter,
    name: &str,
    attribution: &str,
    counts: &[u64],
    names: impl Iterator<Item = &'a str>,
) -> Result<()> {
    let total = counts
        .iter()
        .try_fold(0u64, |sum, count| sum.checked_add(*count))
        .ok_or_else(|| Error::with_message(Errno::EOVERFLOW, "FPU event sum overflow"))?;
    write!(
        printer,
        "{{\"metric\":\"fpu.events.{name}\",\"value\":{total},\"unit\":\"events\",\"verified\":true,\"errors\":0,\"operations\":1,\"attribution\":\"{attribution}\",\"paired\":false,\"overflow\":false,\"complete\":true,\"event_names\":["
    )?;
    write_names(printer, names)?;
    write!(printer, "],\"counts\":[")?;
    write_counts(printer, counts)?;
    writeln!(printer, "]}}")?;
    Ok(())
}

/// One completed measurement batch.
struct Measurement {
    test: &'static str,
    operations: u64,
    duration_ns: u64,
    checksum: i64,
    cpu: u32,
}

/// Runs every batch of this build before anything is printed, so that a
/// failed measurement produces an error instead of a partial report.
#[cfg(not(feature = "kernelet"))]
fn run_batch(printer: &mut VmPrinter) -> Result<()> {
    let echo = bench_echo_reference()?;
    let native = bench_native_reference()?;
    let empty = bench_empty_reference()?;
    write_measurement(printer, &echo)?;
    write_measurement(printer, &native)?;
    write_measurement(printer, &empty)
}

/// Runs every batch of this build before anything is printed, so that a
/// failed measurement produces an error instead of a partial report.
#[cfg(feature = "kernelet")]
fn run_batch(printer: &mut VmPrinter) -> Result<()> {
    use ostd::kernelet::entry::{rq1_echo_service, vcpu_kick_service};

    let echo: extern "C" fn(u64) -> i64 = black_box(rq1_echo_service());
    let token = black_box(ECHO_TOKEN);
    let kick: extern "C" fn(u32) -> i64 = black_box(vcpu_kick_service());
    let target: u32 = black_box(u32::MAX);
    let echo_reference = bench_echo_reference()?;
    let native = bench_native_reference()?;
    let empty = bench_empty_reference()?;
    let echo = measure_returns("vcpu_echo", ECHO_OPERATIONS, ECHO_TOKEN as i64, || {
        echo(token)
    })?;
    let kick = measure_invalid_returns("vcpu_kick_invalid", KICK_OPERATIONS, || kick(target))?;
    write_measurement(printer, &echo_reference)?;
    write_measurement(printer, &native)?;
    write_measurement(printer, &empty)?;
    write_measurement(printer, &echo)?;
    write_measurement(printer, &kick)
}

/// Measures a non-inlined indirect token return without a Host crossing.
fn bench_echo_reference() -> Result<Measurement> {
    let echo: extern "C" fn(u64) -> i64 =
        black_box(native_echo_reference as extern "C" fn(u64) -> i64);
    let token = black_box(ECHO_TOKEN);
    measure_returns(
        "native_echo_ref",
        REFERENCE_OPERATIONS,
        ECHO_TOKEN as i64,
        || echo(token),
    )
}

#[inline(never)]
pub(super) extern "C" fn native_echo_reference(token: u64) -> i64 {
    token as i64
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
    let cpu: u32 = CpuId::current_racy().into();
    let start = crate::time::read_monotonic_time();
    for i in 0..REFERENCE_OPERATIONS {
        black_box(i);
    }
    let duration_ns = duration_since(start)?;
    check_cpu(cpu)?;
    Ok(Measurement {
        test: "empty_loop_ref",
        operations: REFERENCE_OPERATIONS,
        duration_ns,
        checksum: 0,
        cpu,
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
    measure_returns(test, operations, -INVALID, &mut call)
}

fn measure_returns<F>(
    test: &'static str,
    operations: u64,
    expected: i64,
    mut call: F,
) -> Result<Measurement>
where
    F: FnMut() -> i64,
{
    let cpu: u32 = CpuId::current_racy().into();
    let mut checksum: i64 = 0;
    let start = crate::time::read_monotonic_time();
    for _ in 0..operations {
        let returned = call();
        if returned != expected {
            return_errno_with_message!(Errno::EIO, "a measured call returned an unexpected value");
        }
        checksum = checksum.wrapping_add(returned);
    }
    let duration_ns = duration_since(start)?;
    check_cpu(cpu)?;
    Ok(Measurement {
        test,
        operations,
        duration_ns,
        checksum,
        cpu,
    })
}

fn check_cpu(before: u32) -> Result<()> {
    let after: u32 = CpuId::current_racy().into();
    if before != after {
        return_errno_with_message!(Errno::EIO, "the measurement task migrated to another CPU");
    }
    Ok(())
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
    let duration = crate::time::read_monotonic_time()
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
fn write_measurement(printer: &mut VmPrinter, measurement: &Measurement) -> Result<()> {
    let test = measurement.test;
    let operations = measurement.operations;
    let duration_ns = measurement.duration_ns;
    let checksum = measurement.checksum;
    let cpu = measurement.cpu;
    // Keep the kernel's formatting path free of floating-point instructions.
    let whole = duration_ns / operations;
    let fraction = u128::from(duration_ns % operations) * 1_000_000_000 / u128::from(operations);
    writeln!(
        printer,
        "{{\"metric\":\"boundary.{test}\",\"value\":{whole}.{fraction:09},\"unit\":\"ns/op\",\"verified\":true,\"test\":\"{test}\",\"operations\":{operations},\"duration_ns\":{duration_ns},\"checksum\":{checksum},\"correct\":true,\"cpu\":{cpu},\"kernel_mode\":true,\"clock\":\"CLOCK_MONOTONIC\"}}"
    )?;
    Ok(())
}
