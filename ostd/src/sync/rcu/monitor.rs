// SPDX-License-Identifier: MPL-2.0

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, Ordering::Relaxed};

use crate::{
    cpu::{AtomicCpuSet, CpuId, CpuSet, PinCurrentCpu},
    prelude::*,
    sync::SpinLock,
    task::atomic_mode::AsAtomicModeGuard,
};

/// A RCU monitor ensures the completion of _grace periods_ by keeping track
/// of each CPU's passing _quiescent states_.
pub(super) struct RcuMonitor {
    is_monitoring: AtomicBool,
    state: SpinLock<State>,
}

impl RcuMonitor {
    /// Creates a new RCU monitor.
    ///
    /// This function is used to initialize a singleton instance of `RcuMonitor`.
    /// The singleton instance is globally accessible via the `RCU_MONITOR`.
    pub(super) fn new() -> Self {
        Self {
            is_monitoring: AtomicBool::new(false),
            state: SpinLock::new(State::new()),
        }
    }

    pub(super) unsafe fn finish_grace_period(&self) {
        // There may be completed callbacks even when no grace period is active.
        if !self.is_monitoring.load(Relaxed) {
            return;
        }

        let callbacks = {
            let mut state = self.state.disable_irq().lock();
            let cpu = state.as_atomic_mode_guard().current_cpu();
            state.report_quiescent_state(cpu);
            let callbacks = core::mem::take(&mut state.ready_callbacks);
            self.is_monitoring.store(state.has_work(), Relaxed);
            callbacks
        };

        // A callback may sleep or register another callback. Keep it outside
        // the monitor lock and run it only in ordinary task context.
        for f in callbacks {
            (f)();
        }
    }

    pub(super) fn after_grace_period<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let mut state = self.state.disable_irq().lock();

        state.next_callbacks.push_back(Box::new(f));
        state.advance_completed_periods();
        self.is_monitoring.store(state.has_work(), Relaxed);
    }

    /// Enters an extended quiescent state before the idle Host service.
    ///
    /// Returns false when completed callbacks need an active virtual CPU.
    /// In that case this call retracts the idle state; the caller enables
    /// virtual IRQs and drains callbacks instead of parking.
    #[cfg(feature = "kernelet")]
    pub(super) fn enter_idle(&self) -> bool {
        let mut state = self.state.disable_irq().lock();
        let cpu = state.as_atomic_mode_guard().current_cpu();
        debug_assert!(!state.idle_cpus.contains(cpu));
        state.idle_cpus.add(cpu);
        state.report_quiescent_state(cpu);
        let should_park = state.can_park_idle(cpu);
        self.is_monitoring.store(state.has_work(), Relaxed);
        should_park
    }

    /// Rechecks for callbacks after the idle Task queries its next deadline.
    /// Deadline discovery can retire timer objects that contain `RcuDrop`s.
    #[cfg(feature = "kernelet")]
    pub(super) fn can_park_idle(&self) -> bool {
        let mut state = self.state.disable_irq().lock();
        let cpu = state.as_atomic_mode_guard().current_cpu();
        debug_assert!(state.idle_cpus.contains(cpu));
        state.can_park_idle(cpu)
    }

    /// Leaves the extended quiescent state before virtual IRQs are enabled.
    #[cfg(feature = "kernelet")]
    pub(super) fn leave_idle(&self) {
        let mut state = self.state.disable_irq().lock();
        let cpu = state.as_atomic_mode_guard().current_cpu();
        debug_assert!(state.idle_cpus.contains(cpu));
        state.idle_cpus.remove(cpu);
    }
}

struct State {
    current_gp: GracePeriod,
    next_callbacks: Callbacks,
    ready_callbacks: Callbacks,
    /// A Host pause never changes this set. Only the inner idle path does.
    idle_cpus: CpuSet,
}

impl State {
    fn new() -> Self {
        Self {
            current_gp: GracePeriod::new(),
            next_callbacks: VecDeque::new(),
            ready_callbacks: VecDeque::new(),
            idle_cpus: CpuSet::new_empty(),
        }
    }

    fn has_work(&self) -> bool {
        !self.current_gp.is_complete()
            || !self.next_callbacks.is_empty()
            || !self.ready_callbacks.is_empty()
    }

    #[cfg(any(feature = "kernelet", ktest))]
    fn can_park_idle(&mut self, cpu: CpuId) -> bool {
        if self.ready_callbacks.is_empty() {
            return true;
        }
        self.idle_cpus.remove(cpu);
        false
    }

    fn report_quiescent_state(&mut self, cpu: CpuId) {
        if !self.current_gp.is_complete() {
            self.current_gp.finish_grace_period(cpu);
        }
        self.advance_completed_periods();
    }

    fn advance_completed_periods(&mut self) {
        while self.current_gp.is_complete() {
            self.ready_callbacks
                .extend(self.current_gp.take_callbacks());
            if self.next_callbacks.is_empty() {
                break;
            }
            let callbacks = core::mem::take(&mut self.next_callbacks);
            // An idle vCPU has had no reader since it entered idle. It also
            // satisfies a grace period that starts while it remains idle.
            self.current_gp.restart(callbacks, &self.idle_cpus);
        }
    }
}

type Callbacks = VecDeque<Box<dyn FnOnce() + Send + 'static>>;

struct GracePeriod {
    callbacks: Callbacks,
    cpu_mask: AtomicCpuSet,
    is_complete: bool,
}

impl GracePeriod {
    fn new() -> Self {
        Self {
            callbacks: Callbacks::new(),
            cpu_mask: AtomicCpuSet::new(CpuSet::new_empty()),
            is_complete: true,
        }
    }

    fn is_complete(&self) -> bool {
        self.is_complete
    }

    fn finish_grace_period(&mut self, this_cpu: CpuId) {
        self.cpu_mask.add(this_cpu, Relaxed);

        if self.cpu_mask.load(Relaxed).is_full() {
            self.is_complete = true;
        }
    }

    fn take_callbacks(&mut self) -> Callbacks {
        core::mem::take(&mut self.callbacks)
    }

    fn restart(&mut self, callbacks: Callbacks, idle_cpus: &CpuSet) {
        self.cpu_mask.store(idle_cpus, Relaxed);
        self.is_complete = self.cpu_mask.load(Relaxed).is_full();
        self.callbacks = callbacks;
    }
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::{cpu::all_cpus, prelude::ktest};

    #[ktest]
    fn idle_cpu_satisfies_grace_periods_until_it_wakes() {
        let mut state = State::new();
        let cpus: Vec<_> = all_cpus().collect();
        let idle_cpu = *cpus.last().unwrap();

        state.next_callbacks.push_back(Box::new(|| {}));
        state.advance_completed_periods();
        for &cpu in &cpus[..cpus.len() - 1] {
            state.report_quiescent_state(cpu);
        }
        assert!(state.ready_callbacks.is_empty());

        state.idle_cpus.add(idle_cpu);
        state.report_quiescent_state(idle_cpu);
        assert_eq!(state.ready_callbacks.len(), 1);

        // A later period may count a CPU that remained idle throughout it.
        state.next_callbacks.push_back(Box::new(|| {}));
        state.advance_completed_periods();
        for &cpu in &cpus[..cpus.len() - 1] {
            state.report_quiescent_state(cpu);
        }
        assert_eq!(state.ready_callbacks.len(), 2);

        // Once it wakes, a new period must wait for a real switch/checkpoint.
        state.idle_cpus.remove(idle_cpu);
        state.next_callbacks.push_back(Box::new(|| {}));
        state.advance_completed_periods();
        for &cpu in &cpus[..cpus.len() - 1] {
            state.report_quiescent_state(cpu);
        }
        assert_eq!(state.ready_callbacks.len(), 2);
        state.report_quiescent_state(idle_cpu);
        assert_eq!(state.ready_callbacks.len(), 3);
    }

    #[ktest]
    fn callback_queued_during_deadline_query_prevents_park() {
        let mut state = State::new();
        let cpus: Vec<_> = all_cpus().collect();
        let idle_cpu = *cpus.last().unwrap();

        state.idle_cpus.add(idle_cpu);
        assert!(state.can_park_idle(idle_cpu));

        // The deadline callback can queue a drop after the first idle check.
        state.next_callbacks.push_back(Box::new(|| {}));
        state.advance_completed_periods();
        for &cpu in &cpus[..cpus.len() - 1] {
            state.report_quiescent_state(cpu);
        }
        assert_eq!(state.ready_callbacks.len(), 1);
        assert!(!state.can_park_idle(idle_cpu));
        assert!(!state.idle_cpus.contains(idle_cpu));
    }
}
