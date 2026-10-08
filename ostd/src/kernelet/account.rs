// SPDX-License-Identifier: MPL-2.0

//! Host-observed CPU time and explicitly charged device memory.

use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};
use core::{
    fmt,
    sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
    time::Duration,
};

use crate::{
    sync::{LocalIrqDisabled, SpinLock, WaitQueue},
    task::accounting::{CpuTimeAccount, now_ns},
};

const NS_PER_US: u64 = 1_000;
const LOG_WINDOW_NS: u64 = Duration::from_secs(1).as_nanos() as u64;

/// Per-carrier fair weight and aggregate carrier bandwidth.
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuBudget {
    /// Host fair-scheduler nice value, from -20 through 19.
    pub nice: i8,
    /// Aggregate `(quota_us, period_us)` CPU bandwidth in microseconds.
    pub quota: Option<(u32, u32)>,
}

impl CpuBudget {
    pub(crate) fn validate(self) -> crate::Result<()> {
        if !(-20..=19).contains(&self.nice) {
            return Err(crate::Error::InvalidArgs);
        }
        if let Some((quota, period)) = self.quota {
            if quota == 0 || period as u64 <= 1_000_000 / crate::timer::TIMER_FREQ {
                return Err(crate::Error::InvalidArgs);
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

pub(crate) struct Account {
    pub(crate) policy: super::control::KerneletPolicy,
    log_window: SpinLock<LogWindow, LocalIrqDisabled>,
    pub(crate) vcpu_ns: AtomicU64,
    pub(crate) adopted_ns: AtomicU64,
    pub(crate) adopted: AtomicU32,
    pub(crate) host_bytes: AtomicUsize,
    pub(crate) grains: AtomicU32,
    pub(crate) ceiling: AtomicU32,
    pub(crate) overhead: AtomicUsize,
    pub(crate) grant_overhead: AtomicUsize,
    pub(crate) service_calls: AtomicU64,
    pub(crate) mmio_accesses: AtomicU64,
    pub(crate) irqs_raised: AtomicU64,
    pub(crate) log_bytes: AtomicU64,
    pub(crate) logs_dropped: AtomicU64,
    pub(crate) oopses: AtomicU32,
    pub(crate) stacks: AtomicU32,
    pub(crate) throttled_ns: AtomicU64,
    pub(crate) completion_ns: AtomicU64,
    pub(crate) ingress_ns: AtomicU64,
    window: SpinLock<Window, LocalIrqDisabled>,
    queued_deadline: AtomicU64,
    throttle_wait: WaitQueue,
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
            host_bytes: AtomicUsize::new(0),
            grains: AtomicU32::new(0),
            ceiling: AtomicU32::new(0),
            overhead: AtomicUsize::new(0),
            grant_overhead: AtomicUsize::new(0),
            service_calls: AtomicU64::new(0),
            mmio_accesses: AtomicU64::new(0),
            irqs_raised: AtomicU64::new(0),
            log_bytes: AtomicU64::new(0),
            logs_dropped: AtomicU64::new(0),
            oopses: AtomicU32::new(0),
            stacks: AtomicU32::new(0),
            throttled_ns: AtomicU64::new(0),
            completion_ns: AtomicU64::new(0),
            ingress_ns: AtomicU64::new(0),
            window: SpinLock::new(Window {
                budget,
                started: now_ns(),
                charged: 0,
            }),
            queued_deadline: AtomicU64::new(0),
            throttle_wait: WaitQueue::new(),
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

    pub(crate) fn attach(self: &Arc<Self>, adopted: bool) -> crate::Result<()> {
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
            charged: self.vcpu_ns.load(Ordering::Acquire),
        };
        self.cancel_wait();
    }

    fn deadline(&self) -> Option<u64> {
        let mut window = self.window.lock();
        let (quota, period) = window.budget.quota?;
        let now = now_ns();
        let period_ns = period as u64 * NS_PER_US;
        let charged = self.vcpu_ns.load(Ordering::Acquire);
        if now.saturating_sub(window.started) >= period_ns {
            window.started = now;
            window.charged = charged;
        }
        (charged.saturating_sub(window.charged) >= quota as u64 * NS_PER_US)
            .then_some(window.started.saturating_add(period_ns))
    }

    pub(crate) fn exhausted(&self) -> bool {
        self.deadline().is_some()
    }

    pub(crate) fn wait_for_budget(self: &Arc<Self>, stopped: impl Fn() -> bool) {
        let started = now_ns();
        while !stopped() {
            let Some(deadline) = self.deadline() else {
                break;
            };
            {
                let mut queue = THROTTLED.lock();
                if self.queued_deadline.load(Ordering::Relaxed) == 0 {
                    self.queued_deadline.store(deadline, Ordering::Relaxed);
                    queue.insert((deadline, Arc::as_ptr(self) as usize), Arc::downgrade(self));
                }
            }
            self.throttle_wait
                .wait_until(|| (stopped() || self.deadline().is_none()).then_some(()));
        }
        self.throttled_ns
            .fetch_add(now_ns().saturating_sub(started), Ordering::Relaxed);
        self.cancel_wait();
    }

    pub(crate) fn cancel_wait(&self) {
        {
            let mut queue = THROTTLED.lock();
            let deadline = self.queued_deadline.swap(0, Ordering::Relaxed);
            if deadline != 0 {
                queue.remove(&(deadline, self as *const Self as usize));
            }
        }
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

type Throttled = BTreeMap<(u64, usize), Weak<Account>>;
static THROTTLED: SpinLock<Throttled, LocalIrqDisabled> = SpinLock::new(BTreeMap::new());

/// The BSP timer services a bounded batch, with no scheduler wake under the
/// registry lock. Remaining due accounts are serviced by the following tick.
pub(crate) fn on_timer_tick() {
    let now = now_ns();
    expire_deadlines(now);
    for _ in 0..64 {
        let due = {
            let mut queue = THROTTLED.lock();
            if queue.first_key_value().is_none_or(|(key, _)| key.0 > now) {
                break;
            }
            let (_, account) = queue.pop_first().unwrap();
            let account = account.upgrade();
            if let Some(account) = &account {
                account.queued_deadline.store(0, Ordering::Relaxed);
            }
            account
        };
        if let Some(account) = due {
            account.throttle_wait.wake_all();
        }
    }
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
    use super::*;
    use crate::prelude::*;

    #[ktest]
    fn adopted_cpu_time_does_not_consume_carrier_quota() {
        let account = Account::new(
            Arc::new(WaitQueue::new()),
            CpuBudget {
                nice: 0,
                quota: Some((100, 1_000_000)),
            },
            super::super::control::KerneletPolicy::default(),
        );
        account.adopted_ns.store(200_000, Ordering::Release);
        assert!(!account.exhausted());
        account.vcpu_ns.store(100_000, Ordering::Release);
        assert!(account.exhausted());
        assert_eq!(account.cpu_time(), Duration::from_nanos(300_000));
        account.set_budget(CpuBudget::default());
        assert!(!account.exhausted());
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
