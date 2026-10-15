// SPDX-License-Identifier: MPL-2.0

//! Diagnostic FPU event counts. This module exists only in RQ1 diagnostic builds.
//!
//! Task snapshots belong to one OSTD Task. Host totals include every native
//! Task and carrier; they are not associated with an image getpid sequence.
//! Counts identify observed paths, not instruction latency or CPU time.
//! No reset, allocation, guard, or FPU operation is added by an event.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::task::Task;

/// Stable task-event identifiers, shared by native and image diagnostics.
#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Event {
    GetInMemory,
    GetOnCpu,
    GetBoth,
    ScheduleInMemory,
    ScheduleOnCpu,
    ScheduleBoth,
    UserEntryInMemory,
    UserEntryOnCpu,
    UserEntryBoth,
    SaveGet,
    SaveSchedule,
    LoadUserEntry,
    Set,
    Xsave,
    Fxsave,
    Xrstor,
    Fxrstor,
    Clone,
    TaskSwitchOut,
}

/// Names at their stable integer positions in every task count array.
pub const EVENT_NAMES: [&str; 19] = [
    "cpusync.get.in_memory",
    "cpusync.get.on_cpu",
    "cpusync.get.both",
    "cpusync.schedule.in_memory",
    "cpusync.schedule.on_cpu",
    "cpusync.schedule.both",
    "cpusync.user_entry.in_memory",
    "cpusync.user_entry.on_cpu",
    "cpusync.user_entry.both",
    "cpusync.save.get",
    "cpusync.save.schedule",
    "cpusync.load.user_entry",
    "cpusync.set",
    "instruction.xsave",
    "instruction.fxsave",
    "instruction.xrstor",
    "instruction.fxrstor",
    "context.clone",
    "task.switch_out",
];
pub const EVENT_COUNT: usize = EVENT_NAMES.len();

/// Host-only events, after the common task events in Host total arrays.
#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum CarrierEvent {
    Pause,
    SaveCompleted,
    Resume,
    LoadCompleted,
}

pub const CARRIER_EVENT_NAMES: [&str; 4] = [
    "carrier.pause",
    "carrier.save_completed",
    "carrier.resume",
    "carrier.load_completed",
];
pub const HOST_EVENT_COUNT: usize = EVENT_COUNT + CARRIER_EVENT_NAMES.len();
const SNAPSHOT_ATTEMPTS: usize = 8;
static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);

/// Fixed storage; overflow invalidates all subsequent snapshots.
#[derive(Debug)]
pub struct Counters<const N: usize> {
    counts: [AtomicU64; N],
    writers: AtomicU64,
    generation: AtomicU64,
    overflow: AtomicBool,
    identity: AtomicU64,
}

impl<const N: usize> Counters<N> {
    pub const fn new() -> Self {
        Self {
            counts: [const { AtomicU64::new(0) }; N],
            writers: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            overflow: AtomicBool::new(false),
            identity: AtomicU64::new(0),
        }
    }

    fn increment(&self, index: usize) {
        self.writers.fetch_add(1, Ordering::SeqCst);
        for counter in [&self.counts[index], &self.generation] {
            if counter
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                    value.checked_add(1)
                })
                .is_err()
            {
                self.overflow.store(true, Ordering::SeqCst);
            }
        }
        self.writers.fetch_sub(1, Ordering::SeqCst);
    }

    fn task_identity(&self) -> Option<u64> {
        let identity = self.identity.load(Ordering::SeqCst);
        if identity != 0 {
            return Some(identity);
        }
        // Never reuse an identity, including after a Task allocation is freed.
        let next = NEXT_TASK_ID
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            })
            .ok()?;
        Some(
            match self
                .identity
                .compare_exchange(0, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => next,
                Err(existing) => existing,
            },
        )
    }

    /// Rejects overflow or a window that cannot obtain a stable snapshot.
    /// Writers never wait for a reader; no interrupt or preemption is masked.
    pub fn snapshot(&self) -> Option<Snapshot<N>> {
        for _ in 0..SNAPSHOT_ATTEMPTS {
            let generation = self.generation.load(Ordering::SeqCst);
            if self.writers.load(Ordering::SeqCst) != 0 {
                continue;
            }
            let counts = core::array::from_fn(|index| self.counts[index].load(Ordering::SeqCst));
            if self.writers.load(Ordering::SeqCst) == 0
                && self.generation.load(Ordering::SeqCst) == generation
                && !self.overflow.load(Ordering::SeqCst)
            {
                return Some(Snapshot { counts });
            }
        }
        None
    }
}

impl<const N: usize> Default for Counters<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// A stable, non-overflowing counter snapshot.
pub struct Snapshot<const N: usize> {
    pub counts: [u64; N],
}

impl<const N: usize> Snapshot<N> {
    pub fn delta_since(&self, start: &Self) -> Option<[u64; N]> {
        let mut delta = [0; N];
        for (index, count) in delta.iter_mut().enumerate() {
            *count = self.counts[index].checked_sub(start.counts[index])?;
        }
        Some(delta)
    }
}

/// Private, never-reused owner identity; no Task address is retained.
pub struct TaskSnapshot {
    owner: u64,
    snapshot: Snapshot<EVENT_COUNT>,
}

impl TaskSnapshot {
    pub fn delta_since(&self, start: &Self) -> Option<[u64; EVENT_COUNT]> {
        (self.owner == start.owner).then(|| self.snapshot.delta_since(&start.snapshot))?
    }
}

#[cfg(not(feature = "kernelet"))]
static HOST: Counters<HOST_EVENT_COUNT> = Counters::new();

/// Counts one observed event in the current Task, and in Host totals if native.
#[inline]
pub fn event(event: Event) {
    if let Some(task) = Task::current() {
        task.rq1_fpu_counters().increment(event as usize);
    }
    #[cfg(not(feature = "kernelet"))]
    HOST.increment(event as usize);
}

#[cfg(feature = "kernelet-host")]
pub(crate) fn carrier_event(event: CarrierEvent) {
    HOST.increment(EVENT_COUNT + event as usize);
}

pub fn task_snapshot() -> Option<TaskSnapshot> {
    let task = Task::current()?;
    Some(TaskSnapshot {
        owner: task.rq1_fpu_counters().task_identity()?,
        snapshot: task.rq1_fpu_counters().snapshot()?,
    })
}

/// A standalone Task window, with separate Host-wide totals in native builds.
pub struct Window {
    task: TaskSnapshot,
    #[cfg(not(feature = "kernelet"))]
    host: Snapshot<HOST_EVENT_COUNT>,
}

pub struct WindowReport {
    pub task_counts: [u64; EVENT_COUNT],
    pub host_counts: Option<[u64; HOST_EVENT_COUNT]>,
}

impl Window {
    pub fn begin() -> Option<Self> {
        Some(Self {
            task: task_snapshot()?,
            #[cfg(not(feature = "kernelet"))]
            host: HOST.snapshot()?,
        })
    }

    pub fn finish(self) -> Option<WindowReport> {
        Some(WindowReport {
            task_counts: task_snapshot()?.delta_since(&self.task)?,
            #[cfg(not(feature = "kernelet"))]
            host_counts: Some(HOST.snapshot()?.delta_since(&self.host)?),
            #[cfg(feature = "kernelet")]
            host_counts: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_are_exact_and_deltas_do_not_reset_other_windows() {
        let counters = Counters::<2>::new();
        let first = counters.snapshot().unwrap();
        counters.increment(0);
        counters.increment(1);
        let second = counters.snapshot().unwrap();
        counters.increment(0);
        let third = counters.snapshot().unwrap();
        assert_eq!(second.delta_since(&first), Some([1, 1]));
        assert_eq!(third.delta_since(&first), Some([2, 1]));
        assert_eq!(third.delta_since(&second), Some([1, 0]));
        assert_eq!(first.delta_since(&second), None);
    }

    #[test]
    fn overflow_or_active_writer_is_rejected() {
        let counters = Counters::<1>::new();
        counters.counts[0].store(u64::MAX, Ordering::SeqCst);
        counters.increment(0);
        assert_eq!(counters.counts[0].load(Ordering::SeqCst), u64::MAX);
        assert!(counters.snapshot().is_none());
        let counters = Counters::<1>::new();
        counters.writers.store(1, Ordering::SeqCst);
        assert!(counters.snapshot().is_none());
    }

    #[test]
    fn task_identity_mismatch_is_rejected() {
        let start = TaskSnapshot {
            owner: 1,
            snapshot: Snapshot {
                counts: [0; EVENT_COUNT],
            },
        };
        let end = TaskSnapshot {
            owner: 2,
            snapshot: Snapshot {
                counts: [0; EVENT_COUNT],
            },
        };
        assert!(end.delta_since(&start).is_none());
        let first = Counters::<1>::new();
        let second = Counters::<1>::new();
        assert_eq!(first.task_identity(), first.task_identity());
        assert_ne!(first.task_identity(), second.task_identity());
    }
}
