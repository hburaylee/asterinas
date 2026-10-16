// SPDX-License-Identifier: MPL-2.0

//! Local TSC conversion using an immutable Host-boot clock calibration.
//!
//! Host service deadlines and image time readers use the same origin. Each
//! side owns its monotonic watermark; neither needs a periodically written page.

use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "kernelet-host")]
use spin::Once;

/// Converts a TSC sample and retains the largest value observed by this clock.
///
/// The caller supplies a validated nonzero frequency. The watermark prevents
/// regressions across CPU migration; elapsed-time accuracy still requires a
/// stable frequency and synchronized TSCs on the configured Host CPUs.
pub(super) fn monotonic_ns_at(
    tsc: u64,
    origin_tsc: u64,
    tsc_freq_hz: u64,
    latest: &AtomicU64,
) -> u64 {
    debug_assert_ne!(tsc_freq_hz, 0);
    let cycles = tsc.saturating_sub(origin_tsc);
    let nanos = (u128::from(cycles) * 1_000_000_000 / u128::from(tsc_freq_hz))
        .min(u128::from(u64::MAX)) as u64;
    latest.fetch_max(nanos, Ordering::Relaxed).max(nanos)
}

#[cfg(feature = "kernelet-host")]
static CALIBRATION: Once<Calibration> = Once::new();

#[cfg(feature = "kernelet-host")]
pub(super) struct Calibration {
    pub(super) origin_tsc: u64,
    pub(super) tsc_freq_hz: u64,
    latest_ns: AtomicU64,
}

#[cfg(feature = "kernelet-host")]
pub(super) fn calibration() -> crate::Result<&'static Calibration> {
    CALIBRATION.try_call_once(|| {
        let tsc_freq_hz = crate::arch::tsc_freq();
        if tsc_freq_hz == 0 {
            return Err(crate::Error::InvalidArgs);
        }
        // Preserve the Host-boot epoch used by Jiffies and existing deadlines.
        // This calibration is created once, rather than at every instance boot.
        let elapsed_ticks = crate::timer::Jiffies::elapsed().as_u64();
        let elapsed_cycles = (u128::from(elapsed_ticks) * u128::from(tsc_freq_hz)
            / u128::from(crate::timer::TIMER_FREQ))
        .min(u128::from(u64::MAX)) as u64;
        let origin_tsc = crate::arch::read_tsc_ordered().saturating_sub(elapsed_cycles);
        Ok(Calibration {
            origin_tsc,
            tsc_freq_hz,
            latest_ns: AtomicU64::new(0),
        })
    })
}

/// Returns local monotonic time in the same epoch as image deadlines.
#[cfg(feature = "kernelet-host")]
pub(super) fn now_ns() -> u64 {
    let clock = CALIBRATION
        .get()
        .expect("clock calibration absent for a running kernelet");
    monotonic_ns_at(
        crate::arch::read_tsc_ordered(),
        clock.origin_tsc,
        clock.tsc_freq_hz,
        &clock.latest_ns,
    )
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::prelude::*;
    #[cfg(feature = "kernelet-host")]
    use crate::util::id_set::Id;

    #[ktest]
    fn local_clock_advances_without_publication_and_never_regresses() {
        let latest = AtomicU64::new(0);
        assert_eq!(monotonic_ns_at(90, 100, 1_000_000_000, &latest), 0);
        assert_eq!(monotonic_ns_at(110, 100, 1_000_000_000, &latest), 10);
        assert_eq!(monotonic_ns_at(105, 100, 1_000_000_000, &latest), 10);
        assert_eq!(monotonic_ns_at(130, 100, 1_000_000_000, &latest), 30);
    }

    #[ktest]
    fn local_clock_rounds_fractional_cycles_and_saturates() {
        let latest = AtomicU64::new(0);
        assert_eq!(monotonic_ns_at(101, 100, 3_000_000_000, &latest), 0);
        assert_eq!(monotonic_ns_at(103, 100, 3_000_000_000, &latest), 1);
        assert_eq!(monotonic_ns_at(u64::MAX, 0, 1, &latest), u64::MAX);
        assert_eq!(monotonic_ns_at(0, 0, 1, &latest), u64::MAX);
    }

    #[cfg(feature = "kernelet-host")]
    static IPI_CLOCK_NS: AtomicU64 = AtomicU64::new(0);
    #[cfg(feature = "kernelet-host")]
    static IPI_SAMPLE_NS: AtomicU64 = AtomicU64::new(0);
    #[cfg(feature = "kernelet-host")]
    static IPI_SAMPLE_CPU: AtomicU64 = AtomicU64::new(u64::MAX);

    #[cfg(feature = "kernelet-host")]
    fn sample_clock_on_cpu() {
        let clock = CALIBRATION.get().unwrap();
        let sample = monotonic_ns_at(
            crate::arch::read_tsc_ordered(),
            clock.origin_tsc,
            clock.tsc_freq_hz,
            &IPI_CLOCK_NS,
        );
        IPI_SAMPLE_CPU.store(
            crate::cpu::CpuId::current_racy().as_usize() as u64,
            Ordering::Relaxed,
        );
        IPI_SAMPLE_NS.store(sample, Ordering::Release);
    }

    #[cfg(feature = "kernelet-host")]
    #[ktest]
    fn local_clock_reads_on_distinct_cpus_without_publication() {
        let cpus = crate::cpu::CpuSet::new_full();
        let mut iter = cpus.iter();
        let first = iter.next().unwrap();
        let Some(second) = iter.next() else {
            crate::early_println!("[skipped: cross-CPU clock requires two CPUs]");
            return;
        };
        calibration().unwrap();
        let mut previous = 0;
        for _ in 0..32 {
            for cpu in [first, second] {
                crate::smp::inter_processor_call(&cpu.into(), sample_clock_on_cpu).wait();
                let sample = IPI_SAMPLE_NS.load(Ordering::Acquire);
                assert_eq!(
                    IPI_SAMPLE_CPU.load(Ordering::Relaxed),
                    cpu.as_usize() as u64
                );
                assert!(sample >= previous);
                previous = sample;
            }
        }
        assert!(previous > 0);
    }
}
