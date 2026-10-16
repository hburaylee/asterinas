// SPDX-License-Identifier: MPL-2.0

//! Instance resource ownership and logging limits.

use alloc::sync::Arc;
use core::{
    sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
    time::Duration,
};

use crate::{
    sync::{LocalIrqDisabled, SpinLock, WaitQueue},
    task::accounting::now_ns,
};

const LOG_WINDOW_NS: u64 = Duration::from_secs(1).as_nanos() as u64;

/// Host fair scheduling policy; hard CPU bandwidth limits are unsupported.
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuBudget {
    /// Host fair-scheduler nice value, from -20 through 19.
    pub nice: i8,
    /// Reserved `(quota_us, period_us)` request; every nonempty request is rejected.
    pub quota: Option<(u32, u32)>,
}

impl CpuBudget {
    /// Lowest Linux nice value accepted for a Host carrier.
    pub const MIN_NICE: i8 = -20;
    /// Highest Linux nice value accepted for a Host carrier.
    pub const MAX_NICE: i8 = 19;

    /// Checks the Host nice range and rejects unsupported hard quotas.
    pub fn validate(self) -> Result<(), super::control::BudgetError> {
        if !(Self::MIN_NICE..=Self::MAX_NICE).contains(&self.nice) {
            return Err(super::control::BudgetError::InvalidNice);
        }
        if self.quota.is_some() {
            return Err(super::control::BudgetError::UnsupportedQuota);
        }
        Ok(())
    }
}

struct LogWindow {
    started: u64,
    bytes: u32,
}

pub(crate) struct Account {
    pub(crate) policy: super::control::KerneletPolicy,
    log_window: SpinLock<LogWindow, LocalIrqDisabled>,
    pub(crate) adopted: AtomicU32,
    pub(crate) host_bytes: Arc<AtomicUsize>,
    pub(crate) grains: AtomicU32,
    pub(crate) ceiling: AtomicU32,
    pub(crate) overhead: AtomicUsize,
    pub(crate) grant_overhead: AtomicUsize,
    #[cfg(kernelet_rq1_diagnostics)]
    pub(crate) forced_yields: AtomicU64,
    pub(crate) log_bytes: AtomicU64,
    pub(crate) logs_dropped: AtomicU64,
    pub(crate) oopses: AtomicU32,
    pub(crate) stacks: AtomicU32,
    #[cfg(kernelet_rq1_diagnostics)]
    pub(crate) completion_ns: AtomicU64,
    #[cfg(kernelet_rq1_diagnostics)]
    pub(crate) ingress_ns: AtomicU64,
    pub(crate) drained: Arc<WaitQueue>,
}

impl Account {
    pub(crate) fn new(
        drained: Arc<WaitQueue>,
        policy: super::control::KerneletPolicy,
    ) -> Arc<Self> {
        Arc::new(Self {
            policy,
            log_window: SpinLock::new(LogWindow {
                started: now_ns(),
                bytes: 0,
            }),
            adopted: AtomicU32::new(0),
            host_bytes: Arc::new(AtomicUsize::new(0)),
            grains: AtomicU32::new(0),
            ceiling: AtomicU32::new(0),
            overhead: AtomicUsize::new(0),
            grant_overhead: AtomicUsize::new(0),
            #[cfg(kernelet_rq1_diagnostics)]
            forced_yields: AtomicU64::new(0),
            log_bytes: AtomicU64::new(0),
            logs_dropped: AtomicU64::new(0),
            oopses: AtomicU32::new(0),
            stacks: AtomicU32::new(0),
            #[cfg(kernelet_rq1_diagnostics)]
            completion_ns: AtomicU64::new(0),
            #[cfg(kernelet_rq1_diagnostics)]
            ingress_ns: AtomicU64::new(0),
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

    pub(crate) fn attach_adopted(self: &Arc<Self>) -> crate::Result<()> {
        // The caller reserved adopted before attaching. A rejected attachment
        // drops this owner and refunds the reservation outside control locks.
        let owner = AdoptedTask {
            account: self.clone(),
        };
        let task = crate::task::Task::current().ok_or(crate::Error::InvalidArgs)?;
        task.adopt_kernelet(owner)
    }

    pub(crate) fn detach(&self) {
        if let Some(task) = crate::task::Task::current() {
            let _ = task.disown_kernelet(self as *const Self as usize);
        }
    }
}

/// Keeps an instance alive until its adopted Host worker disowns or exits.
pub(crate) struct AdoptedTask {
    account: Arc<Account>,
}

impl core::fmt::Debug for AdoptedTask {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AdoptedTask").finish_non_exhaustive()
    }
}

impl AdoptedTask {
    pub(crate) fn owner(&self) -> usize {
        Arc::as_ptr(&self.account) as usize
    }
}

impl Drop for AdoptedTask {
    fn drop(&mut self) {
        self.account.adopted.fetch_sub(1, Ordering::AcqRel);
        self.account.drained.wake_all();
    }
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::prelude::*;

    #[ktest]
    fn host_weights_reject_hard_quotas() {
        use super::super::control::BudgetError;

        assert!(CpuBudget::default().validate().is_ok());
        for nice in [CpuBudget::MIN_NICE, CpuBudget::MAX_NICE] {
            assert!(CpuBudget { nice, quota: None }.validate().is_ok());
        }
        for nice in [-21, 20] {
            assert!(matches!(
                CpuBudget { nice, quota: None }.validate(),
                Err(BudgetError::InvalidNice)
            ));
        }
        for quota in [(0, 0), (1, 1), (100, 100_000)] {
            assert!(matches!(
                CpuBudget {
                    nice: 0,
                    quota: Some(quota)
                }
                .validate(),
                Err(BudgetError::UnsupportedQuota)
            ));
        }
    }

    #[ktest]
    fn adopted_worker_ownership_rejects_duplicates_and_wrong_disown() {
        let account = Account::new(
            Arc::new(WaitQueue::new()),
            super::super::control::KerneletPolicy::default(),
        );
        account.adopted.store(1, Ordering::Release);
        account.attach_adopted().unwrap();
        let task = crate::task::Task::current().unwrap();
        assert!(task.disown_kernelet(0).is_err());
        assert_eq!(account.adopted.load(Ordering::Acquire), 1);
        account.adopted.fetch_add(1, Ordering::AcqRel);
        assert!(account.attach_adopted().is_err());
        assert_eq!(account.adopted.load(Ordering::Acquire), 1);
        account.detach();
        assert_eq!(account.adopted.load(Ordering::Acquire), 0);
    }

    #[ktest]
    fn logging_policy_drops_whole_records() {
        let account = Account::new(
            Arc::new(WaitQueue::new()),
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
