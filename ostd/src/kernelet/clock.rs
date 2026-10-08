// SPDX-License-Identifier: MPL-2.0

//! Host-owned monotonic clock page shared by kernelet instances.
//!
//! The loader maps this page read-only into each instance. Host service
//! deadlines use the same clock epoch as the values published to the image.

use core::{sync::atomic::Ordering, time::Duration};

use spin::Once;

use super::abi::ClockPage;
use crate::{
    Error, Result,
    mm::{Frame, FrameAllocOptions, HasPaddr},
};

/// One Host-owned frame shared read-only with every kernelet instance.
static CLOCK: Once<SharedClock> = Once::new();

struct SharedClock {
    frame: Frame<()>,
    origin_tsc: u64,
    tsc_freq_hz: u64,
}

impl SharedClock {
    fn page(&self) -> &ClockPage {
        // SAFETY: The zeroed frame is aligned for ClockPage, remains pinned by
        // CLOCK for the Host lifetime, and only its atomic field is mutated.
        unsafe { &*(crate::mm::paddr_to_vaddr(self.frame.paddr()) as *const ClockPage) }
    }

    fn publish(&self) {
        let cycles = crate::arch::read_tsc().saturating_sub(self.origin_tsc);
        let nanos = ((cycles as u128 * Duration::from_secs(1).as_nanos())
            / self.tsc_freq_hz as u128)
            .min(u64::MAX as u128) as u64;
        self.page().monotonic_ns.fetch_max(nanos, Ordering::Relaxed);
    }
}

fn shared_clock() -> Result<&'static SharedClock> {
    CLOCK.try_call_once(|| {
        let tsc_freq_hz = crate::arch::tsc_freq();
        if tsc_freq_hz == 0 {
            return Err(Error::InvalidArgs);
        }
        // Anchor the TSC to Host jiffies when the first instance is created.
        // Jiffies starts with the Host timer; the TSC supplies sub-tick time.
        let elapsed_ticks = crate::timer::Jiffies::elapsed().as_u64();
        let elapsed_cycles = ((elapsed_ticks as u128 * tsc_freq_hz as u128)
            / crate::timer::TIMER_FREQ as u128)
            .min(u64::MAX as u128) as u64;
        let origin_tsc = crate::arch::read_tsc().saturating_sub(elapsed_cycles);
        let frame = FrameAllocOptions::new().alloc_frame()?;
        let clock = SharedClock {
            frame,
            origin_tsc,
            tsc_freq_hz,
        };
        clock.publish();
        Ok(clock)
    })
}

/// Publishes Host monotonic time for kernelet clock readers.
pub(crate) fn publish() {
    if let Some(clock) = CLOCK.get() {
        clock.publish();
    }
}

/// Returns the Host-published clock in the same epoch as guest deadlines.
pub(super) fn now_ns() -> u64 {
    let clock = CLOCK
        .get()
        .expect("clock page absent for a running kernelet");
    clock.publish();
    clock.page().monotonic_ns.load(Ordering::Relaxed)
}

/// Returns the pinned frame mapped read-only into each instance.
pub(super) fn frame() -> Result<&'static Frame<()>> {
    Ok(&shared_clock()?.frame)
}
