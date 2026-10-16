// SPDX-License-Identifier: MPL-2.0

//! Static fair shares for an instance's carriers and dedicated device workers.

use core::num::NonZeroU16;

use ostd::task::Task;

use crate::{
    prelude::*,
    sched::{Nice, SchedPolicy},
    thread::{AsThread, Thread, kernel_thread::ThreadOptions},
};

/// All configured participants split one instance weight, even while asleep.
/// This is a fixed share, without group scheduling or runtime CPU accounting.
/// Shared Host services do not belong to this set.
pub(super) struct ExecutionThreads {
    divisor: NonZeroU16,
    state: SpinLock<State>,
}

struct State {
    nice: Nice,
    threads: Vec<Weak<Thread>>,
}

impl ExecutionThreads {
    pub(super) fn new(nice: i8, carriers: u16, workers: usize) -> ostd::Result<Self> {
        if carriers == 0 {
            return Err(ostd::Error::InvalidArgs);
        }
        let participants = usize::from(carriers)
            .checked_add(workers)
            .and_then(|count| u16::try_from(count).ok())
            .and_then(NonZeroU16::new)
            .ok_or(ostd::Error::InvalidArgs)?;
        Ok(Self {
            divisor: participants,
            state: SpinLock::new(State {
                nice: Nice::try_from(nice).map_err(|_| ostd::Error::InvalidArgs)?,
                threads: Vec::with_capacity(usize::from(participants.get())),
            }),
        })
    }

    pub(super) fn build(&self, options: ThreadOptions) -> Arc<Task> {
        // Registration and policy changes use one lock so a new thread cannot
        // retain an obsolete nice value after an instance-wide update.
        let mut state = self.state.lock();
        let task = options
            .sched_policy(SchedPolicy::Fair(state.nice))
            .fair_weight_divisor(self.divisor)
            .build();
        state
            .threads
            .push(Arc::downgrade(task.as_thread().unwrap()));
        task
    }

    pub(super) fn spawn_worker(&self, body: impl FnOnce() + Send + 'static) {
        let task = self.build(ThreadOptions::new(body));
        task.as_thread().unwrap().run();
    }

    pub(super) fn set_nice(&self, nice: i8) -> ostd::Result<()> {
        let nice = Nice::try_from(nice).map_err(|_| ostd::Error::InvalidArgs)?;
        let mut state = self.state.lock();
        state.nice = nice;
        for thread in state.threads.iter().filter_map(Weak::upgrade) {
            thread.sched_attr().set_policy(SchedPolicy::Fair(nice));
        }
        Ok(())
    }
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn instance_policy_reaches_existing_and_later_execution_threads() {
        let execution = ExecutionThreads::new(3, 2, 3).unwrap();
        assert_eq!(execution.divisor.get(), 5);
        let carrier = execution.build(ThreadOptions::new(|| {}));
        let worker = execution.build(ThreadOptions::new(|| {}));
        let policy = SchedPolicy::Fair(Nice::try_from(3).unwrap());
        assert_eq!(carrier.as_thread().unwrap().sched_attr().policy(), policy);
        assert_eq!(worker.as_thread().unwrap().sched_attr().policy(), policy);
        execution.set_nice(7).unwrap();
        let later_worker = execution.build(ThreadOptions::new(|| {}));
        let policy = SchedPolicy::Fair(Nice::try_from(7).unwrap());
        for task in [&carrier, &worker, &later_worker] {
            assert_eq!(task.as_thread().unwrap().sched_attr().policy(), policy);
        }
        assert!(execution.set_nice(20).is_err());
        assert_eq!(worker.as_thread().unwrap().sched_attr().policy(), policy);
        assert!(ExecutionThreads::new(0, 0, 1).is_err());
        assert!(ExecutionThreads::new(0, u16::MAX, 1).is_err());
    }
}
