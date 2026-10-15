// SPDX-License-Identifier: MPL-2.0

//! Host-observed CPU time and explicitly charged device memory.

use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};
use core::{
    fmt,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    time::Duration,
};

use crate::{
    sync::{LocalIrqDisabled, SpinLock, WaitQueue},
    task::accounting::{CpuTimeAccount, now_ns},
};

const NS_PER_US: u64 = 1_000;
const LOG_WINDOW_NS: u64 = Duration::from_secs(1).as_nanos() as u64;

/// Per-carrier fair weight and aggregate instance CPU bandwidth.
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuBudget {
    /// Host fair-scheduler nice value, from -20 through 19.
    pub nice: i8,
    /// Aggregate `(quota_us, period_us)` CPU bandwidth in microseconds.
    pub quota: Option<(u32, u32)>,
}

impl CpuBudget {
    /// Lowest Linux nice value accepted for a Host carrier.
    pub const MIN_NICE: i8 = -20;
    /// Highest Linux nice value accepted for a Host carrier.
    pub const MAX_NICE: i8 = 19;

    /// Checks the Host nice range and that a quota period exceeds one timer tick.
    pub fn validate(self) -> Result<(), super::control::BudgetError> {
        if !(Self::MIN_NICE..=Self::MAX_NICE).contains(&self.nice) {
            return Err(super::control::BudgetError::InvalidNice);
        }
        if let Some((quota, period)) = self.quota {
            if quota == 0 || period as u64 <= 1_000_000 / crate::timer::TIMER_FREQ {
                return Err(super::control::BudgetError::InvalidQuota);
            }
        }
        Ok(())
    }
}

struct LogWindow {
    started: u64,
    bytes: u32,
}

struct Window {
    budget: CpuBudget,
    started: u64,
    charged: u64,
}

impl Window {
    fn deadline(&mut self, now: u64, charged: u64) -> Option<u64> {
        let (quota, period) = self.budget.quota?;
        let quota_ns = quota as u64 * NS_PER_US;
        let period_ns = period as u64 * NS_PER_US;
        let elapsed = now.saturating_sub(self.started);
        if elapsed >= period_ns {
            // Retain execution debt when a delayed tick crosses a period.
            // Resetting charged to the current total would erase all usage
            // when the period is close to a tick and defeat the hard cap.
            let refill = (elapsed / period_ns).saturating_mul(quota_ns);
            self.charged = self.charged.saturating_add(refill).min(charged);
            self.started = now.saturating_sub(elapsed % period_ns);
        }
        (charged.saturating_sub(self.charged) >= quota_ns)
            .then_some(self.started.saturating_add(period_ns))
    }
}

pub(crate) struct Account {
    pub(crate) policy: super::control::KerneletPolicy,
    log_window: SpinLock<LogWindow, LocalIrqDisabled>,
    pub(crate) vcpu_ns: AtomicU64,
    pub(crate) adopted_ns: AtomicU64,
    pub(crate) adopted: AtomicU32,
    pub(crate) host_bytes: Arc<AtomicUsize>,
    pub(crate) grains: AtomicU32,
    pub(crate) ceiling: AtomicU32,
    pub(crate) overhead: AtomicUsize,
    pub(crate) grant_overhead: AtomicUsize,
    pub(crate) service_calls: AtomicU64,
    #[cfg(kernelet_rq1_diagnostics)]
    pub(crate) forced_yields: AtomicU64,
    pub(crate) mmio_accesses: AtomicU64,
    pub(crate) irqs_raised: AtomicU64,
    pub(crate) log_bytes: AtomicU64,
    pub(crate) logs_dropped: AtomicU64,
    pub(crate) oopses: AtomicU32,
    pub(crate) stacks: AtomicU32,
    pub(crate) throttled_ns: AtomicU64,
    #[cfg(kernelet_rq1_diagnostics)]
    pub(crate) completion_ns: AtomicU64,
    #[cfg(kernelet_rq1_diagnostics)]
    pub(crate) ingress_ns: AtomicU64,
    window: SpinLock<Window, LocalIrqDisabled>,
    throttled: AtomicBool,
    limited: AtomicBool,
    throttle_wait: Arc<WaitQueue>,
    pub(crate) drained: Arc<WaitQueue>,
}

impl Account {
    pub(crate) fn new(
        drained: Arc<WaitQueue>,
        budget: CpuBudget,
        policy: super::control::KerneletPolicy,
    ) -> Arc<Self> {
        Arc::new(Self {
            policy,
            log_window: SpinLock::new(LogWindow {
                started: now_ns(),
                bytes: 0,
            }),
            vcpu_ns: AtomicU64::new(0),
            adopted_ns: AtomicU64::new(0),
            adopted: AtomicU32::new(0),
            host_bytes: Arc::new(AtomicUsize::new(0)),
            grains: AtomicU32::new(0),
            ceiling: AtomicU32::new(0),
            overhead: AtomicUsize::new(0),
            grant_overhead: AtomicUsize::new(0),
            service_calls: AtomicU64::new(0),
            #[cfg(kernelet_rq1_diagnostics)]
            forced_yields: AtomicU64::new(0),
            mmio_accesses: AtomicU64::new(0),
            irqs_raised: AtomicU64::new(0),
            log_bytes: AtomicU64::new(0),
            logs_dropped: AtomicU64::new(0),
            oopses: AtomicU32::new(0),
            stacks: AtomicU32::new(0),
            throttled_ns: AtomicU64::new(0),
            throttled: AtomicBool::new(false),
            limited: AtomicBool::new(budget.quota.is_some()),
            #[cfg(kernelet_rq1_diagnostics)]
            completion_ns: AtomicU64::new(0),
            #[cfg(kernelet_rq1_diagnostics)]
            ingress_ns: AtomicU64::new(0),
            window: SpinLock::new(Window {
                budget,
                started: now_ns(),
                charged: 0,
            }),
            throttle_wait: Arc::new(WaitQueue::new()),
            drained,
        })
    }

    pub(crate) fn admit_log(&self, bytes: u32) -> bool {
        let mut window = self.log_window.lock();
        let now = now_ns();
        if now.saturating_sub(window.started) >= LOG_WINDOW_NS {
            window.started = now;
            window.bytes = 0;
        }
        let remaining = self.policy.log_bytes_per_sec - window.bytes;
        if bytes > remaining {
            self.logs_dropped.fetch_add(1, Ordering::Relaxed);
            false
        } else {
            window.bytes += bytes;
            true
        }
    }

    pub(crate) fn attach_carrier(self: &Arc<Self>) -> crate::Result<()> {
        self.attach(false)
    }

    pub(crate) fn attach_adopted(self: &Arc<Self>) -> crate::Result<()> {
        self.attach(true)
    }

    fn attach(self: &Arc<Self>, adopted: bool) -> crate::Result<()> {
        let charge = Arc::new(TaskCharge {
            account: self.clone(),
            adopted,
        });
        let task = crate::task::Task::current().ok_or(crate::Error::InvalidArgs)?;
        task.attach_cpu_account(charge)
    }

    pub(crate) fn detach(&self) {
        if let Some(task) = crate::task::Task::current() {
            let _ = task.detach_cpu_account(self as *const Self as usize);
        }
    }

    pub(crate) fn cpu_time(&self) -> Duration {
        Duration::from_nanos(
            self.vcpu_ns
                .load(Ordering::Acquire)
                .saturating_add(self.adopted_ns.load(Ordering::Acquire)),
        )
    }

    pub(crate) fn set_budget(&self, budget: CpuBudget) {
        *self.window.lock() = Window {
            budget,
            started: now_ns(),
            charged: self.charged_ns(),
        };
        self.limited
            .store(budget.quota.is_some(), Ordering::Release);
        self.throttled.store(false, Ordering::Release);
        self.cancel_wait();
    }

    fn charged_ns(&self) -> u64 {
        self.vcpu_ns
            .load(Ordering::Acquire)
            .saturating_add(self.adopted_ns.load(Ordering::Acquire))
    }

    pub(crate) fn is_limited(&self) -> bool {
        self.limited.load(Ordering::Acquire)
    }

    fn deadline(&self) -> Option<u64> {
        let mut window = self.window.lock();
        let deadline = window.deadline(now_ns(), self.charged_ns());
        self.throttled.store(deadline.is_some(), Ordering::Release);
        deadline
    }

    pub(crate) fn exhausted(&self) -> bool {
        self.deadline().is_some()
    }

    pub(crate) fn is_throttled(&self) -> bool {
        self.throttled.load(Ordering::Acquire)
    }

    pub(crate) fn wait_for_budget(self: &Arc<Self>, stopped: impl Fn() -> bool) {
        let started = now_ns();
        while !stopped() {
            let Some(deadline) = self.deadline() else {
                break;
            };
            // Each carrier owns its registration. Leaving this wait cannot
            // cancel a different carrier's deadline, including a later period.
            let _deadline = Deadline::new(deadline, &self.throttle_wait);
            self.throttle_wait.wait_until(|| {
                // Another carrier may consume the next period before this
                // carrier resumes. Return to the outer loop to arm that period.
                (stopped() || self.deadline() != Some(deadline)).then_some(())
            });
        }
        self.throttled_ns
            .fetch_add(now_ns().saturating_sub(started), Ordering::Relaxed);
    }

    pub(crate) fn cancel_wait(&self) {
        // Stop and policy changes ask each carrier to recheck its condition.
        // Only that carrier may remove its owned Deadline registration.
        self.throttle_wait.wake_all();
    }
}

struct TaskCharge {
    account: Arc<Account>,
    adopted: bool,
}
impl fmt::Debug for TaskCharge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskCharge")
            .field("adopted", &self.adopted)
            .finish_non_exhaustive()
    }
}
impl CpuTimeAccount for TaskCharge {
    fn charge(&self, nanoseconds: u64) {
        let counter = if self.adopted {
            &self.account.adopted_ns
        } else {
            &self.account.vcpu_ns
        };
        counter.fetch_add(nanoseconds, Ordering::Relaxed);
    }
    fn owner(&self) -> usize {
        Arc::as_ptr(&self.account) as usize
    }
}
impl Drop for TaskCharge {
    fn drop(&mut self) {
        if self.adopted {
            self.account.adopted.fetch_sub(1, Ordering::AcqRel);
        }
        self.account.drained.wake_all();
    }
}

/// The BSP timer services a bounded batch, with no scheduler wake under the
/// registry lock. Remaining due deadlines are serviced by the following tick.
pub(crate) fn on_timer_tick() {
    expire_deadlines(now_ns());
}

/// A cancellable Host deadline retains only its wake queue, never image state.
pub(crate) struct Deadline {
    key: (u64, u64),
}
static NEXT_DEADLINE: AtomicU64 = AtomicU64::new(1);
static DEADLINES: SpinLock<BTreeMap<(u64, u64), Weak<WaitQueue>>, LocalIrqDisabled> =
    SpinLock::new(BTreeMap::new());
impl Deadline {
    pub(crate) fn new(at: u64, queue: &Arc<WaitQueue>) -> Self {
        let key = (at, NEXT_DEADLINE.fetch_add(1, Ordering::Relaxed));
        DEADLINES.lock().insert(key, Arc::downgrade(queue));
        Self { key }
    }
}
impl Drop for Deadline {
    fn drop(&mut self) {
        DEADLINES.lock().remove(&self.key);
    }
}

fn expire_deadlines(now: u64) {
    for _ in 0..64 {
        let entry = {
            let mut queue = DEADLINES.lock();
            if queue.first_key_value().is_none_or(|(key, _)| key.0 > now) {
                break;
            }
            queue.pop_first().unwrap().1
        };
        if let Some(queue) = entry.upgrade() {
            queue.wake_all();
        }
    }
}

#[cfg(ktest)]
mod test {
    use core::sync::atomic::AtomicBool;

    use super::*;
    use crate::{
        prelude::*,
        task::{Task, TaskOptions},
    };

    const TEST_PERIOD_US: u32 = 100_000;
    const WAIT_TIMEOUT_NS: u64 = 2_000_000_000;

    #[ktest]
    fn late_tick_preserves_quota_debt_across_periods() {
        let mut window = Window {
            budget: CpuBudget {
                nice: 0,
                quota: Some((1, 1_001)),
            },
            started: 0,
            charged: 0,
        };
        // A delayed first tick must not erase the entire executed interval.
        assert_eq!(window.deadline(1_001_000, 1_001_000), Some(2_002_000));
        assert_eq!(window.charged, 1_000);
        assert_eq!(window.deadline(2_002_000, 1_001_000), Some(3_003_000));
        // With no further execution, later refills repay the debt. Idle
        // periods do not accumulate more than one period of fresh credit.
        assert_eq!(window.deadline(1_002_001_000, 1_001_000), None);
        assert_eq!(window.charged, 1_001_000);
        assert_eq!(
            window.deadline(1_002_001_000, 1_002_000),
            Some(1_003_002_000)
        );
    }

    struct BudgetWaitState {
        probes: AtomicUsize,
        held: AtomicBool,
        released: AtomicBool,
        stopped: AtomicBool,
        done: AtomicBool,
        gate: WaitQueue,
        events: Arc<WaitQueue>,
    }

    struct BudgetWaiter {
        account: Arc<Account>,
        state: Arc<BudgetWaitState>,
        task: Weak<Task>,
    }

    impl BudgetWaiter {
        fn spawn(account: &Arc<Account>, hold_after: Option<u64>) -> Self {
            let state = Arc::new(BudgetWaitState {
                probes: AtomicUsize::new(0),
                held: AtomicBool::new(false),
                released: AtomicBool::new(false),
                stopped: AtomicBool::new(false),
                done: AtomicBool::new(false),
                gate: WaitQueue::new(),
                events: Arc::new(WaitQueue::new()),
            });
            let worker_state = state.clone();
            let worker_account = account.clone();
            let task = TaskOptions::new(move || {
                worker_account.wait_for_budget(|| {
                    let probe = worker_state.probes.fetch_add(1, Ordering::AcqRel) + 1;
                    // The third probe follows WaitQueue registration. Hold
                    // the next due-period check before Account rolls its window.
                    if hold_after.is_some_and(|at| probe >= 3 && now_ns() >= at)
                        && !worker_state.released.load(Ordering::Acquire)
                    {
                        worker_state.held.store(true, Ordering::Release);
                        worker_state.events.wake_all();
                        worker_state.gate.wait_until(|| {
                            worker_state.released.load(Ordering::Acquire).then_some(())
                        });
                    }
                    worker_state.events.wake_all();
                    worker_state.stopped.load(Ordering::Acquire)
                });
                worker_state.done.store(true, Ordering::Release);
                worker_state.events.wake_all();
            })
            .data(())
            .spawn()
            .unwrap();
            Self {
                account: account.clone(),
                state,
                task: Arc::downgrade(&task),
            }
        }

        fn wait_until(&self, condition: impl Fn(&BudgetWaitState) -> bool) -> bool {
            let timeout = now_ns().saturating_add(WAIT_TIMEOUT_NS);
            let _deadline = Deadline::new(timeout, &self.state.events);
            self.state.events.wait_until(|| {
                let ready = condition(&self.state);
                (ready || now_ns() >= timeout).then_some(ready)
            })
        }

        fn release(&self) {
            self.state.released.store(true, Ordering::Release);
            self.state.gate.wake_all();
        }

        fn stop(&self) {
            self.state.stopped.store(true, Ordering::Release);
            self.release();
            self.account.cancel_wait();
        }

        fn wait_for_exit(&self) -> bool {
            let timeout = now_ns().saturating_add(WAIT_TIMEOUT_NS);
            while self.task.strong_count() != 0 && now_ns() < timeout {
                Task::yield_now();
            }
            self.task.strong_count() == 0
        }
    }

    impl Drop for BudgetWaiter {
        fn drop(&mut self) {
            // Also release the real waiting Task if an assertion unwinds.
            self.stop();
            let _ = self.wait_until(|state| state.done.load(Ordering::Acquire));
            let _ = self.wait_for_exit();
        }
    }

    fn assert_no_budget_timers(account: &Arc<Account>) {
        let wait_queue = Arc::downgrade(&account.throttle_wait);
        assert!(
            !DEADLINES
                .lock()
                .values()
                .any(|queue| Weak::ptr_eq(queue, &wait_queue))
        );
    }

    fn exhausted_account() -> Arc<Account> {
        let account = Account::new(
            Arc::new(WaitQueue::new()),
            CpuBudget {
                nice: 0,
                quota: Some((1, TEST_PERIOD_US)),
            },
            super::super::control::KerneletPolicy::default(),
        );
        account.vcpu_ns.store(NS_PER_US, Ordering::Release);
        account
    }

    // Regression for the account.rs:206 finding in the Kernelet review:
    // a late carrier must rearm when another carrier spent the next period.
    #[ktest]
    fn budget_wait_rearms_after_quota_is_spent_in_next_period() {
        let account = exhausted_account();
        let first_deadline = account.deadline().unwrap();
        let late = BudgetWaiter::spawn(&account, Some(first_deadline));
        assert!(late.wait_until(|state| state.held.load(Ordering::Acquire)));
        on_timer_tick();
        assert!(!account.exhausted());
        account.vcpu_ns.fetch_add(NS_PER_US, Ordering::AcqRel);
        let next_deadline = account.deadline().unwrap();
        assert!(now_ns() < next_deadline);
        late.release();
        assert!(late.wait_until(|state| state.done.load(Ordering::Acquire)));
        assert!(late.wait_for_exit());
        assert_no_budget_timers(&account);
    }

    // Regression for the same finding: an old-period carrier exiting must
    // leave another carrier's new-period timer able to wake it.
    #[ktest]
    fn carrier_exit_preserves_other_carriers_budget_timer() {
        let account = exhausted_account();
        let first_deadline = account.deadline().unwrap();
        let exiting = BudgetWaiter::spawn(&account, Some(first_deadline));
        assert!(exiting.wait_until(|state| state.held.load(Ordering::Acquire)));
        on_timer_tick();
        assert!(!account.exhausted());
        account.vcpu_ns.fetch_add(NS_PER_US, Ordering::AcqRel);
        let next_deadline = account.deadline().unwrap();

        let waiting = BudgetWaiter::spawn(&account, None);
        assert!(waiting.wait_until(|state| state.probes.load(Ordering::Acquire) >= 3));
        exiting.state.stopped.store(true, Ordering::Release);
        exiting.release();
        assert!(exiting.wait_until(|state| state.done.load(Ordering::Acquire)));
        assert!(exiting.wait_for_exit());
        assert!(now_ns() < next_deadline);
        assert!(!waiting.state.done.load(Ordering::Acquire));
        assert!(waiting.wait_until(|state| state.done.load(Ordering::Acquire)));
        assert!(waiting.wait_for_exit());
        assert_no_budget_timers(&account);
    }

    #[ktest]
    fn budget_update_and_stop_wake_all_carriers() {
        for update_budget in [true, false] {
            let account = exhausted_account();
            let first = BudgetWaiter::spawn(&account, None);
            let second = BudgetWaiter::spawn(&account, None);
            assert!(first.wait_until(|state| state.probes.load(Ordering::Acquire) >= 3));
            assert!(second.wait_until(|state| state.probes.load(Ordering::Acquire) >= 3));
            assert!(account.exhausted());
            if update_budget {
                account.set_budget(CpuBudget::default());
            } else {
                first.state.stopped.store(true, Ordering::Release);
                second.state.stopped.store(true, Ordering::Release);
                account.cancel_wait();
            }
            assert!(first.wait_until(|state| state.done.load(Ordering::Acquire)));
            assert!(second.wait_until(|state| state.done.load(Ordering::Acquire)));
            assert!(first.wait_for_exit());
            assert!(second.wait_for_exit());
            assert_no_budget_timers(&account);
        }
    }

    #[ktest]
    fn cpu_budget_validation_preserves_nice_and_tick_boundaries() {
        use super::super::control::BudgetError;

        assert!(CpuBudget::default().validate().is_ok());
        for nice in [-20, 19] {
            assert!(CpuBudget { nice, quota: None }.validate().is_ok());
        }
        for nice in [-21, 20] {
            assert!(matches!(
                CpuBudget { nice, quota: None }.validate(),
                Err(BudgetError::InvalidNice)
            ));
        }
        let tick_us = (1_000_000 / crate::timer::TIMER_FREQ) as u32;
        for quota in [(0, tick_us + 1), (1, 0), (1, tick_us)] {
            assert!(matches!(
                CpuBudget {
                    nice: 0,
                    quota: Some(quota),
                }
                .validate(),
                Err(BudgetError::InvalidQuota)
            ));
        }
        assert!(
            CpuBudget {
                nice: 0,
                quota: Some((1, tick_us + 1)),
            }
            .validate()
            .is_ok()
        );
    }

    #[ktest]
    fn adopted_cpu_time_consumes_instance_quota() {
        let account = Account::new(
            Arc::new(WaitQueue::new()),
            CpuBudget {
                nice: 0,
                quota: Some((100, 1_000_000)),
            },
            super::super::control::KerneletPolicy::default(),
        );
        account.adopted_ns.store(200_000, Ordering::Release);
        assert!(account.exhausted());
        account.vcpu_ns.store(100_000, Ordering::Release);
        assert!(account.exhausted());
        assert_eq!(account.cpu_time(), Duration::from_nanos(300_000));
        account.set_budget(CpuBudget::default());
        assert!(!account.exhausted());
    }

    #[ktest]
    fn adopted_charge_can_throttle_an_otherwise_idle_instance() {
        let account = exhausted_account();
        account.vcpu_ns.store(0, Ordering::Release);
        let worker_charge = TaskCharge {
            account: account.clone(),
            adopted: true,
        };
        account.adopted.store(1, Ordering::Release);
        worker_charge.charge(NS_PER_US);
        assert_eq!(account.vcpu_ns.load(Ordering::Acquire), 0);
        let waiting = BudgetWaiter::spawn(&account, None);
        assert!(waiting.wait_until(|state| state.probes.load(Ordering::Acquire) >= 3));
        assert!(!waiting.state.done.load(Ordering::Acquire));
        account.set_budget(CpuBudget::default());
        assert!(waiting.wait_until(|state| state.done.load(Ordering::Acquire)));
        assert!(waiting.wait_for_exit());
        assert_no_budget_timers(&account);
    }

    #[ktest]
    fn logging_policy_drops_whole_records() {
        let account = Account::new(
            Arc::new(WaitQueue::new()),
            CpuBudget::default(),
            super::super::control::KerneletPolicy {
                log_bytes_per_sec: 10,
                ..Default::default()
            },
        );
        assert!(account.admit_log(6));
        assert!(!account.admit_log(5));
        assert!(account.admit_log(4));
        assert_eq!(account.logs_dropped.load(Ordering::Acquire), 1);
    }
}
