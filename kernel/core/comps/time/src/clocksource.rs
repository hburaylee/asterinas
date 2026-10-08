// SPDX-License-Identifier: MPL-2.0

//! This module provides abstractions for hardware-assisted timing mechanisms, encapsulated
//! by the `ClockSource` struct.
//!
//! A `ClockSource` can be constructed from any counter with a stable frequency, enabling precise
//! time measurements to be taken by retrieving instances of `Instant`.
//!
//! The `ClockSource` module is a fundamental building block for timing in systems that require
//! high precision and accuracy. It can be integrated into larger systems to provide timing capabilities,
//! or used standalone for time tracking and elapsed time measurements.

use alloc::sync::Arc;
use core::{cmp::max, ops::Add, time::Duration};

use aster_util::coeff::Coeff;
use ostd::sync::{LocalIrqDisabled, RwLock};

const NANOS_PER_SECOND: u32 = 1_000_000_000;

/// `ClockSource` is an abstraction for hardware-assisted timing mechanisms.
///
/// A `ClockSource` can be created based on any counter that operates at a stable frequency.
/// Users are able to measure time by retrieving `Instant` from this source.
///
/// # Implementation
/// The `ClockSource` relies on obtaining the frequency of the counter and the method for
/// reading the cycles in order to measure time.
///
/// The **cycles** here refer the counts of the base time counter.
///
/// Additionally, the `ClockSource` also holds a last record for an `Instant` and the
/// corresponding cycles, which acts as a reference point for subsequent time retrieval.
/// The expected interval between updates determines the coefficient used for cycle conversion.
/// Longer intervals use a full-width product to avoid overflowing the coefficient calculation.
///
/// # Examples
/// Suppose we have a counter called `counter` which have the frequency `counter.freq`, and the method
/// to read its cycles called `read_counter()`. We can create a corresponding `ClockSource` and
/// use it as follows:
///
/// ```rust
/// // here we set the max_delay_secs = 10
/// let max_delay_secs = 10;
/// // create a clocksource named counter_clock
/// let counter_clock = ClockSource::new(counter.freq, max_delay_secs, Arc::new(read_counter));
/// // read an instant.
/// let instant = counter_clock.read_instant();
/// ```
///
/// Updating this `ClockSource` within `max_delay_secs` keeps cycle conversion on the fast path.
pub struct ClockSource {
    read_cycles: Arc<dyn Fn() -> u64 + Sync + Send>,
    base: ClockSourceBase,
    coeff: Coeff,
    /// A record to an `Instant` and the corresponding cycles of this `ClockSource`.
    last_record: RwLock<(Instant, u64), LocalIrqDisabled>,
}

impl ClockSource {
    /// Creates a new `ClockSource` instance.
    ///
    /// This method requires basic information of the time counter, including the function for
    /// reading cycles, the frequency, and the expected interval between updates in seconds.
    /// The `ClockSource` also calculates a reliable `Coeff` based on the counter's frequency and
    /// the maximum delay seconds. This `Coeff` is used to convert the number of cycles into
    /// the duration of time that has passed for those cycles.
    pub fn new(
        freq: u64,
        max_delay_secs: u64,
        read_cycles: Arc<dyn Fn() -> u64 + Sync + Send>,
    ) -> Self {
        let base = ClockSourceBase::new(freq, max_delay_secs);
        // Too big `max_delay_secs` will lead to a low resolution `Coeff`.
        debug_assert!(max_delay_secs < 600);
        let coeff = Coeff::new(NANOS_PER_SECOND as u64, freq, max_delay_secs * freq);
        Self {
            read_cycles,
            base,
            coeff,
            last_record: RwLock::new((Instant::zero(), 0)),
        }
    }

    /// Uses the instant cycles to calculate the instant.
    ///
    /// It first calculates the difference between the instant cycles and the last
    /// recorded cycles stored in the clocksource. Then `ClockSource` will convert
    /// the passed cycles into passed time and calculate the current instant.
    ///
    /// Returns the calculated instant and instant cycles.
    fn calculate_instant(&self) -> (Instant, u64) {
        let (instant_cycles, last_instant, last_cycles) = {
            let last_record = self.last_record.read();
            let (last_instant, last_cycles) = *last_record;
            (self.read_cycles(), last_instant, last_cycles)
        };

        let delta_nanos = match instant_cycles.checked_sub(last_cycles) {
            Some(delta) => self.cycles_to_nanos_lossy(delta),
            None => {
                ostd::warn!(
                    "The clock source becomes not reliable since TSC \
                    has moved backwards from {} to {}",
                    last_cycles,
                    instant_cycles
                );
                0
            }
        };
        let duration = Duration::from_nanos(delta_nanos);
        (last_instant + duration, instant_cycles)
    }

    fn cycles_to_nanos_lossy(&self, cycles: u64) -> u64 {
        let max_cycles = self.base.max_delay_secs * self.base.freq;
        if cycles <= max_cycles {
            self.coeff * cycles
        } else {
            // A paused CPU can exceed the coefficient's u64 multiplication
            // bound. Use the same coefficient in a wider product so the
            // conversion stays continuous when crossing that bound.
            let nanos = (u128::from(cycles) * u128::from(self.coeff.mult())) >> self.coeff.shift();
            nanos.min(u128::from(u64::MAX)) as u64
        }
    }

    /// Uses an input instant and cycles to update the `last_record` in the `ClockSource`.
    fn update_last_record(&self, record: (Instant, u64)) {
        *self.last_record.write() = record;
    }

    /// Reads current cycles of the `ClockSource`.
    pub fn read_cycles(&self) -> u64 {
        (self.read_cycles)()
    }

    /// Returns the last instant and last cycles recorded in the `ClockSource`.
    pub fn last_record(&self) -> (Instant, u64) {
        return *self.last_record.read();
    }

    /// Returns the maximum delay seconds for updating of the `ClockSource`.
    pub fn max_delay_secs(&self) -> u64 {
        self.base.max_delay_secs
    }

    /// Returns the reference to the generated cycles coeff of the `ClockSource`.
    pub fn coeff(&self) -> &Coeff {
        &self.coeff
    }

    /// Returns the frequency of the counter used in the `ClockSource`.
    pub fn freq(&self) -> u64 {
        self.base.freq
    }

    /// Calibrates the recorded `Instant` to zero, and record the instant cycles.
    pub(crate) fn calibrate(&self, instant_cycles: u64) {
        self.update_last_record((Instant::zero(), instant_cycles));
    }

    /// Gets the instant to update the internal instant in the `ClockSource`.
    pub(crate) fn update(&self) {
        let (instant, instant_cycles) = self.calculate_instant();
        self.update_last_record((instant, instant_cycles));
    }

    /// Reads the instant corresponding to the current time.
    pub(crate) fn read_instant(&self) -> Instant {
        self.calculate_instant().0
    }
}

/// A specific moment.
///
/// [`Instant`] captures a specific moment, storing the duration of time
/// elapsed since a reference point (typically the system boot time).
/// The [`Instant`] is expressed in seconds and the fractional part is
/// expressed in nanoseconds.
#[derive(Clone, Copy, Debug, Default)]
pub struct Instant {
    secs: u64,
    nanos: u32,
}

impl Instant {
    /// Creates a zeroed `Instant`.
    pub const fn zero() -> Self {
        Self { secs: 0, nanos: 0 }
    }

    /// Creates an new `Instant` based on the inputting `secs` and `nanos`.
    pub fn new(secs: u64, nanos: u32) -> Self {
        Self { secs, nanos }
    }

    /// Returns the seconds recorded in the Instant.
    pub fn secs(&self) -> u64 {
        self.secs
    }

    /// Returns the nanoseconds recorded in the Instant.
    pub fn nanos(&self) -> u32 {
        self.nanos
    }
}

impl From<Duration> for Instant {
    fn from(value: Duration) -> Self {
        Self {
            secs: value.as_secs(),
            nanos: value.subsec_nanos(),
        }
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, other: Duration) -> Self::Output {
        let mut secs = self.secs + other.as_secs();
        let mut nanos = self.nanos + other.subsec_nanos();
        if nanos >= NANOS_PER_SECOND {
            secs += 1;
            nanos -= NANOS_PER_SECOND;
        }
        Instant::new(secs, nanos)
    }
}

/// The basic properties of `ClockSource`.
#[derive(Clone, Copy, Debug)]
struct ClockSourceBase {
    freq: u64,
    max_delay_secs: u64,
}

impl ClockSourceBase {
    fn new(freq: u64, max_delay_secs: u64) -> Self {
        let max_delay_secs = max(2, max_delay_secs);
        ClockSourceBase {
            freq,
            max_delay_secs,
        }
    }
}

#[cfg(ktest)]
mod test {
    use core::sync::atomic::{AtomicU64, Ordering};

    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn elapsed_time_survives_delayed_clocksource_updates() {
        let counter = Arc::new(AtomicU64::new(123_000_000_000));
        let read_counter = counter.clone();
        let clock = ClockSource::new(
            1_000_000_000,
            100,
            Arc::new(move || read_counter.load(Ordering::Relaxed)),
        );
        clock.calibrate(clock.read_cycles());

        counter.fetch_add(105_123_000_000, Ordering::Relaxed);
        let instant = clock.read_instant();
        assert_eq!(
            Duration::new(instant.secs(), instant.nanos()),
            Duration::from_millis(105_123)
        );

        clock.update();
        counter.fetch_add(2_000_000_000, Ordering::Relaxed);
        let instant = clock.read_instant();
        assert_eq!(
            Duration::new(instant.secs(), instant.nanos()),
            Duration::from_millis(107_123)
        );
    }

    #[ktest]
    fn clocksource_conversion_is_monotonic_across_its_fast_path_bound() {
        for frequency in [1_000_000_000, 1_500_000_000, 2_400_000_000, 4_000_000_000] {
            let counter = Arc::new(AtomicU64::new(0));
            let reader = counter.clone();
            let clock = ClockSource::new(
                frequency,
                100,
                Arc::new(move || reader.load(Ordering::Relaxed)),
            );
            clock.calibrate(0);
            let boundary = frequency * clock.max_delay_secs();
            let mut previous = Duration::ZERO;
            for cycles in [boundary - 1, boundary, boundary + 1, boundary + frequency] {
                counter.store(cycles, Ordering::Relaxed);
                let instant = clock.read_instant();
                let now = Duration::new(instant.secs(), instant.nanos());
                assert!(now >= previous, "clock moved backwards at {frequency} Hz");
                previous = now;
            }
            clock.update();
            counter.fetch_add(frequency, Ordering::Relaxed);
            let instant = clock.read_instant();
            assert!(Duration::new(instant.secs(), instant.nanos()) >= previous);
        }
    }
}
