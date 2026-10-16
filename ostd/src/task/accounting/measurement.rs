// SPDX-License-Identifier: MPL-2.0

//! Explicit CPU measurements used by Images, experiments, and kernel tests.

use alloc::sync::Arc;
#[cfg(ktest)]
use core::fmt::Debug;
use core::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use super::{runtime_ns, runtime_ticks, ticks_to_ns};
use crate::sync::{LocalIrqDisabled, SpinLock};

/// An account receives only time that its Task actually executes on a CPU.
/// The callback runs with IRQs disabled and must not sleep or schedule.
#[cfg(ktest)]
pub(crate) trait CpuTimeAccount: Send + Sync + Debug {
    fn charge(&self, nanoseconds: u64);
    fn owner(&self) -> usize;
}

#[derive(Debug)]
struct State {
    #[cfg(ktest)]
    account: Option<Arc<dyn CpuTimeAccount>>,
    started: Option<u64>,
    elapsed_ns: u64,
    measurements: u32,
}

impl State {
    fn sample(&mut self, now: u64) {
        if let Some(previous) = self.started.take() {
            let elapsed = now.saturating_sub(previous);
            self.elapsed_ns = self.elapsed_ns.saturating_add(elapsed);
            #[cfg(ktest)]
            if let Some(account) = &self.account {
                account.charge(elapsed);
            }
        }
    }

    fn enabled(&self) -> bool {
        #[cfg(ktest)]
        if self.account.is_some() {
            return true;
        }
        self.measurements != 0
    }
}

/// A measurement of the current Task's CPU execution across preemption.
///
/// Sleeping and time spent running other Tasks are excluded. IRQ handling is
/// included in the measurement.
#[must_use]
pub struct CpuTimeMeasurement {
    task: Arc<crate::task::Task>,
    started: u64,
}

impl !Send for CpuTimeMeasurement {}
impl !Sync for CpuTimeMeasurement {}

impl CpuTimeMeasurement {
    pub(in crate::task) fn start(task: Arc<crate::task::Task>) -> Self {
        let started = task.accounting.begin_measurement();
        Self { task, started }
    }

    /// Returns the CPU time elapsed so far, without ending the measurement.
    pub fn elapsed(&self) -> Duration {
        let mut state = self.task.accounting.state.lock();
        let now = runtime_ns();
        state.sample(now);
        state.started = Some(now);
        Duration::from_nanos(state.elapsed_ns.saturating_sub(self.started))
    }
}

impl Drop for CpuTimeMeasurement {
    fn drop(&mut self) {
        self.task.accounting.end_measurement();
    }
}

#[derive(Debug)]
pub(in crate::task) struct TaskAccounting {
    enabled: AtomicBool,
    state: SpinLock<State, LocalIrqDisabled>,
}

impl TaskAccounting {
    pub(in crate::task) fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            state: SpinLock::new(State {
                #[cfg(ktest)]
                account: None,
                started: None,
                elapsed_ns: 0,
                measurements: 0,
            }),
        }
    }

    #[cfg(ktest)]
    pub(in crate::task) fn attach(&self, account: Arc<dyn CpuTimeAccount>) -> crate::Result<()> {
        let mut state = self.state.lock();
        if state.account.is_some() {
            return Err(crate::Error::InvalidArgs);
        }
        let now = runtime_ns();
        state.sample(now);
        state.account = Some(account);
        let enabled = state.enabled();
        state.started = enabled.then_some(now);
        self.enabled.store(enabled, Ordering::Release);
        Ok(())
    }

    #[cfg(ktest)]
    pub(in crate::task) fn detach(&self, owner: Option<usize>) -> crate::Result<()> {
        let _ = self.sample(false);
        let account = {
            let mut state = self.state.lock();
            if let Some(owner) = owner
                && state
                    .account
                    .as_ref()
                    .is_none_or(|account| account.owner() != owner)
            {
                if state.enabled() {
                    state.started = Some(runtime_ns());
                }
                return Err(crate::Error::AccessDenied);
            }
            let account = state.account.take();
            self.enabled.store(state.enabled(), Ordering::Release);
            if state.enabled() {
                state.started = Some(runtime_ns());
            }
            account
        };
        // Account destruction can wake the instance reaper; never do it under
        // the per-Task accounting lock.
        drop(account);
        Ok(())
    }

    pub(in crate::task) fn sample(&self, running: bool) -> Option<u64> {
        if !self.enabled.load(Ordering::Acquire) {
            return None;
        }
        let mut state = self.state.lock();
        let ticks = runtime_ticks();
        let now = ticks_to_ns(ticks);
        state.sample(now);
        if running {
            state.started = Some(now);
        }
        Some(ticks)
    }

    fn begin_measurement(&self) -> u64 {
        let mut state = self.state.lock();
        let now = runtime_ns();
        state.sample(now);
        state.measurements = state.measurements.checked_add(1).unwrap();
        state.started = Some(now);
        self.enabled.store(true, Ordering::Release);
        state.elapsed_ns
    }

    fn end_measurement(&self) {
        let mut state = self.state.lock();
        let now = runtime_ns();
        state.sample(now);
        state.measurements -= 1;
        if state.enabled() {
            state.started = Some(now);
        }
        self.enabled.store(state.enabled(), Ordering::Release);
    }

    pub(in crate::task) fn resume(&self) {
        if self.enabled.load(Ordering::Acquire) {
            self.state.lock().started = Some(runtime_ns());
        }
    }
}

#[cfg(ktest)]
mod tests {
    use core::sync::atomic::AtomicU64;

    use super::*;
    use crate::prelude::*;

    #[derive(Debug, Default)]
    struct Account(AtomicU64);

    impl CpuTimeAccount for Account {
        fn charge(&self, nanoseconds: u64) {
            self.0.fetch_add(nanoseconds, Ordering::Relaxed);
        }

        fn owner(&self) -> usize {
            0
        }
    }

    #[ktest]
    fn scheduler_clock_and_measurements_share_cpu_accounting() {
        let _irq_guard = crate::irq::disable_local();
        let task = crate::task::Task::current().unwrap();
        let account = Arc::new(Account::default());
        task.attach_cpu_account(account.clone()).unwrap();
        let measurement = task.measure_cpu_time();

        let first = crate::task::scheduler::runtime_ticks();
        let charged_before = account.0.load(Ordering::Relaxed);
        for _ in 0..1_000 {
            core::hint::spin_loop();
        }
        let _elapsed = measurement.elapsed();
        let second = crate::task::scheduler::runtime_ticks();
        let charged_after = account.0.load(Ordering::Relaxed);

        drop(measurement);
        task.detach_cpu_account(0).unwrap();
        assert!(second > first);
        assert_eq!(
            charged_after - charged_before,
            ticks_to_ns(second) - ticks_to_ns(first)
        );
    }

    #[ktest]
    fn cpu_measurement_excludes_descheduling_and_does_not_charge_twice() {
        let account = Arc::new(Account::default());
        let mut state = State {
            account: Some(account.clone()),
            started: Some(100),
            elapsed_ns: 0,
            measurements: 1,
        };
        state.sample(110); // Switch out after ten nanoseconds of execution.
        state.sample(1_000); // Another Task runs; there is no active interval.
        state.started = Some(1_000); // Resume this Task.
        state.sample(1_005); // Read an outer measurement.
        state.started = Some(1_005);
        state.sample(1_005); // A nested read must not charge it again.
        state.started = Some(1_005);
        state.sample(1_010);
        assert_eq!(state.elapsed_ns, 20);
        assert_eq!(account.0.load(Ordering::Relaxed), 20);
    }
}
