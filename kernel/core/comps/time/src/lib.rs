// SPDX-License-Identifier: MPL-2.0

//! The system time of Asterinas.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

#[cfg(not(feature = "kernelet"))]
use alloc::sync::Arc;
#[cfg(not(feature = "kernelet"))]
use core::time::Duration;

pub use clocksource::{ClockSource, Instant};
#[cfg(not(feature = "kernelet"))]
use component::{ComponentInitError, init_component};
#[cfg(not(feature = "kernelet"))]
use rtc::Driver;
#[cfg(not(feature = "kernelet"))]
use spin::Once;

// Set this crate's log prefix for `ostd::log`.
macro_rules! __log_prefix {
    () => {
        "time: "
    };
}

mod clocksource;
#[cfg(not(feature = "kernelet"))]
mod rtc;
#[cfg(not(feature = "kernelet"))]
mod tsc;

#[cfg(not(feature = "kernelet"))]
pub static VDSO_DATA_HIGH_RES_UPDATE_FN: Once<fn(Instant, u64)> = Once::new();

#[cfg(not(feature = "kernelet"))]
static RTC_DRIVER: Once<Arc<dyn Driver + Send + Sync>> = Once::new();

#[cfg(not(feature = "kernelet"))]
#[init_component]
fn time_init() -> Result<(), ComponentInitError> {
    let rtc = rtc::init_rtc_driver();
    RTC_DRIVER.call_once(|| rtc);
    tsc::init();
    Ok(())
}

/// Initializes the real RTC and TSC clocksource once for Host kernel tests.
///
/// The OSDK test runner initializes OSTD but does not run component bootstrap.
#[cfg(all(ktest, not(feature = "kernelet")))]
pub fn init_for_ktest() {
    static INIT: Once<()> = Once::new();
    INIT.call_once(|| time_init().expect("cannot initialize the time component for ktests"));
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SystemTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub nanos: u64,
}

#[cfg(any(target_arch = "riscv64", target_arch = "aarch64"))]
impl From<chrono::NaiveDateTime> for SystemTime {
    fn from(time: chrono::NaiveDateTime) -> Self {
        use chrono::{Datelike, Timelike};

        Self {
            year: time.year() as u16,
            month: time.month() as u8,
            day: time.day() as u8,
            hour: time.hour() as u8,
            minute: time.minute() as u8,
            second: time.second() as u8,
            nanos: time.nanosecond() as u64,
        }
    }
}

#[cfg(not(feature = "kernelet"))]
static START_TIME: Once<SystemTime> = Once::new();

/// Returns the `START_TIME`, which is the system time when calibrating.
#[cfg(not(feature = "kernelet"))]
pub fn read_start_time() -> SystemTime {
    *START_TIME.get().unwrap()
}

/// Returns the monotonic time from the TSC clocksource.
#[cfg(not(feature = "kernelet"))]
pub fn read_monotonic_time() -> Duration {
    let instant = tsc::read_instant();
    Duration::new(instant.secs(), instant.nanos())
}

/// Returns the default (TSC) clocksource.
#[cfg(not(feature = "kernelet"))]
pub fn default_clocksource() -> Arc<ClockSource> {
    tsc::CLOCK.get().unwrap().clone()
}
