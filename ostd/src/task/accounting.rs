// SPDX-License-Identifier: MPL-2.0

//! Execution and deadline clocks, with optional explicit CPU measurements.

#[cfg(feature = "kernelet")]
use core::sync::atomic::Ordering;

#[cfg(any(feature = "kernelet", kernelet_rq1, kernelet_rq1_diagnostics, ktest))]
mod measurement;
#[cfg(ktest)]
pub(crate) use measurement::CpuTimeAccount;
#[cfg(any(feature = "kernelet", kernelet_rq1, kernelet_rq1_diagnostics, ktest))]
pub use measurement::CpuTimeMeasurement;
#[cfg(any(feature = "kernelet", kernelet_rq1, kernelet_rq1_diagnostics, ktest))]
pub(in crate::task) use measurement::TaskAccounting;

/// The execution clock shared by scheduler deltas and Task accounting.
#[cfg(any(feature = "kernelet", kernelet_rq1, kernelet_rq1_diagnostics, ktest))]
pub(super) fn runtime_ticks() -> u64 {
    #[cfg(feature = "kernelet")]
    {
        let offset = &crate::kernelet::entry::vcpu_record().nonrunning_tsc;
        loop {
            let before = offset.load(Ordering::Acquire);
            let now = crate::arch::read_tsc_ordered();
            let after = offset.load(Ordering::Acquire);
            if before == after {
                return now.saturating_sub(after);
            }
        }
    }

    #[cfg(not(feature = "kernelet"))]
    {
        crate::arch::read_tsc()
    }
}

fn ticks_to_ns(ticks: u64) -> u64 {
    ((u128::from(ticks) * 1_000_000_000) / u128::from(crate::arch::tsc_freq())) as u64
}

#[cfg(any(feature = "kernelet", kernelet_rq1, kernelet_rq1_diagnostics, ktest))]
fn runtime_ns() -> u64 {
    ticks_to_ns(runtime_ticks())
}

/// Host monotonic wall time for logging limits and cancellable deadlines.
#[cfg(feature = "kernelet-host")]
pub(crate) fn now_ns() -> u64 {
    ticks_to_ns(crate::arch::read_tsc())
}
