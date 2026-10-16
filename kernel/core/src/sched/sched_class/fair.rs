// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::BinaryHeap, sync::Arc};
#[cfg(feature = "kernelet-host")]
use core::num::NonZeroU16;
use core::{
    cmp::{self, Reverse},
    sync::atomic::{AtomicU64, Ordering},
};

use ostd::{
    cpu::{CpuId, num_cpus},
    sync::SpinLock,
    task::{
        Task,
        scheduler::{EnqueueFlags, UpdateFlags},
    },
};

use super::{
    CurrentRuntime, SchedAttr, SchedClassRq,
    time::{base_slice_clocks, min_period_clocks},
};
use crate::{
    sched::nice::{Nice, NiceValue},
    thread::AsThread,
};

const WEIGHT_0: u64 = 1024;

// Keep small shares representable without changing the user-visible nice ladder.
#[cfg(feature = "kernelet-host")]
const WEIGHT_SCALE: u64 = 1 << 16;

const HAS_PENDING: u64 = 1 << (u64::BITS - 1);

pub(crate) const fn nice_to_weight(nice: Nice) -> u64 {
    // Calculated by the formula below:
    //
    //     weight = 1024 * 1.25^(-nice)
    //
    // We propose that every increment of the nice value results
    // in 12.5% change of the CPU load weight.
    const FACTOR_NUMERATOR: u64 = 5;
    const FACTOR_DENOMINATOR: u64 = 4;

    const NICE_TO_WEIGHT: [u64; 40] = const {
        let mut ret = [0; 40];

        let mut index = 0;
        let mut nice = NiceValue::MIN.get();
        while nice <= NiceValue::MAX.get() {
            ret[index] = match nice {
                0 => WEIGHT_0,
                nice @ 1.. => {
                    let numerator = FACTOR_DENOMINATOR.pow(nice as u32);
                    let denominator = FACTOR_NUMERATOR.pow(nice as u32);
                    WEIGHT_0 * numerator / denominator
                }
                nice => {
                    let numerator = FACTOR_NUMERATOR.pow((-nice) as u32);
                    let denominator = FACTOR_DENOMINATOR.pow((-nice) as u32);
                    WEIGHT_0 * numerator / denominator
                }
            };
            assert!(ret[index] & HAS_PENDING == 0);

            index += 1;
            nice += 1;
        }
        ret
    };

    NICE_TO_WEIGHT[(nice.value().get() + 20) as usize]
}

#[cfg(feature = "kernelet-host")]
fn effective_weight(nice: Nice, divisor: NonZeroU16) -> u64 {
    nice_to_weight(nice) * WEIGHT_SCALE / u64::from(divisor.get())
}

/// The scheduling entity for the FAIR scheduling class.
///
/// The structure contains a significant indicator: `vruntime`.
///
/// # `vruntime`
///
/// The vruntime (virtual runtime) is calculated by the formula:
///
///     vruntime += runtime_delta * WEIGHT_0 / weight
///
/// and a thread with a lower vruntime gains a greater privilege to be
/// scheduled, making the whole run queue balanced on vruntime (thus FAIR).
/// With Kernelet Host support, weights and the numerator use the same
/// fixed-point scale so dividing carrier shares does not round them to zero.
///
/// # Scheduling periods
///
/// Scheduling periods are designed to calculate the time slice for each threads.
///
/// The time slice for each threads is calculated by the formula:
///
///     time_slice = period * weight / total_weight
///
/// where `total_weight` is the sum of all weights in the run queue including
/// the current thread and [`period`](FairClassRq::period) is calculated
/// regarding the number of running threads.
///
/// When a thread meets the condition below, it will be preempted to the
/// run queue. See [`FairClassRq::update_current`] for more details.
///
///     period_delta > time_slice
///         || vruntime > rq_min_vruntime + normalized_time_slice
///
/// # The weight update process
///
/// The weight of a thread can be updated by the `sched_setattr` syscall series in
/// any thread. This makes it difficult to re-evaluate the data of its run queue
/// instantly after the update without a direct backward reference (which is
/// impossible to be represented in safe Rust).
///
/// To handle this problem, we use a `pending_weight` field to store the new weight.
/// When the thread is scheduled within the run queue, we will check if the weight
/// needs to be updated since both the old and new weights are needed for re-evaluation.
///
/// To indicate whether the weight needs to be updated, we pack the `weight` field
/// with a bit flag `HAS_PENDING`. When accessing the `weight` field:
///
/// - If the weight does not need to be updated (i.e., `weight & HAS_PENDING == 0`),
///   we simply return the weight.
/// - If the weight needs to be updated (i.e., `weight & HAS_PENDING != 0`), we try to
///   store the new weight into the `weight` field, which shouldn't take too much time
///   since the update frequency is usually relatively low.
/// - After a successful update, we re-evaluate the data of the run queue.
///
/// Most of the time, this mechanism allows the access to the weight lock-free and
/// ensures that only one load is needed.
#[derive(Debug)]
pub(crate) struct FairAttr {
    // Updates to the `weight` field must be serialized with the `pending_weight` lock.
    weight: AtomicU64,
    pending_weight: SpinLock<u64>,
    vruntime: AtomicU64,
    #[cfg(feature = "kernelet-host")]
    weight_divisor: NonZeroU16,
}

impl FairAttr {
    pub(crate) fn new(nice: Nice) -> Self {
        #[cfg(feature = "kernelet-host")]
        {
            Self::new_with_weight_divisor(nice, NonZeroU16::MIN)
        }
        #[cfg(not(feature = "kernelet-host"))]
        {
            let weight = nice_to_weight(nice);
            Self {
                weight: weight.into(),
                pending_weight: SpinLock::new(weight),
                vruntime: Default::default(),
            }
        }
    }

    #[cfg(feature = "kernelet-host")]
    pub(super) fn new_with_weight_divisor(nice: Nice, weight_divisor: NonZeroU16) -> Self {
        let weight = effective_weight(nice, weight_divisor);
        FairAttr {
            weight: weight.into(),
            pending_weight: SpinLock::new(weight),
            vruntime: Default::default(),
            weight_divisor,
        }
    }

    pub(crate) fn update(&self, nice: Nice) {
        let mut pending_weight = self.pending_weight.lock();
        #[cfg(feature = "kernelet-host")]
        let weight = effective_weight(nice, self.weight_divisor);
        #[cfg(not(feature = "kernelet-host"))]
        let weight = nice_to_weight(nice);
        *pending_weight = weight;
        self.weight.store(
            self.weight.load(Ordering::Relaxed) | HAS_PENDING,
            Ordering::Relaxed,
        );
    }

    fn update_vruntime(&self, delta: u64, weight: u64) -> u64 {
        #[cfg(feature = "kernelet-host")]
        let delta = {
            // Ordinary threads have integral nice weights. Cancel the shared
            // queue's scale so they use the upstream vruntime formula.
            let (numerator_weight, weight) = if self.weight_divisor == NonZeroU16::MIN {
                (WEIGHT_0, weight / WEIGHT_SCALE)
            } else {
                (WEIGHT_0 * WEIGHT_SCALE, weight)
            };
            if let Some(numerator) = delta.checked_mul(numerator_weight) {
                numerator / weight
            } else {
                u64::try_from(u128::from(delta) * u128::from(numerator_weight) / u128::from(weight))
                    .expect("fair vruntime delta overflow")
            }
        };
        #[cfg(not(feature = "kernelet-host"))]
        let delta = delta * WEIGHT_0 / weight;
        self.vruntime.fetch_add(delta, Ordering::Relaxed) + delta
    }

    fn fetch_weight(&self) -> (u64, u64) {
        // Synchronization is done via the `pending_weight` lock. Therefore, no additional ordering
        // is required to access the atomic variable.
        let weight = self.weight.load(Ordering::Relaxed);
        if weight & HAS_PENDING == 0 {
            return (weight, weight);
        }

        let new_weight = {
            // `pending_weight` always stores the latest weight.
            let pending_weight = self.pending_weight.lock();
            self.weight.store(*pending_weight, Ordering::Relaxed);
            *pending_weight
        };
        let old_weight = weight & !HAS_PENDING;

        // The `vruntime` field is an accumulated value, and we don't update
        // it here.

        (old_weight, new_weight)
    }
}

/// The wrapper for threads in the FAIR run queue.
///
/// This structure is used to provide the capability for keying in the
/// run queue implemented by `BTreeSet` in the `FairClassRq`.
struct FairQueueItem(Arc<Task>, u64);

impl core::fmt::Debug for FairQueueItem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.key())
    }
}

impl FairQueueItem {
    fn key(&self) -> u64 {
        self.1
    }
}

impl PartialEq for FairQueueItem {
    fn eq(&self, other: &Self) -> bool {
        self.key().eq(&other.key())
    }
}

impl Eq for FairQueueItem {}

impl PartialOrd for FairQueueItem {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FairQueueItem {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.key().cmp(&other.key())
    }
}

/// The per-cpu run queue for the FAIR scheduling class.
///
/// See [`FairAttr`] for the explanation of vruntimes and scheduling periods.
///
/// The structure contains a `BTreeSet` to store the threads in the run queue to
/// ensure the efficiency for finding next-to-run threads.
#[derive(Debug)]
pub(super) struct FairClassRq {
    #[expect(unused)]
    cpu: CpuId,
    /// The ready-to-run threads.
    entities: BinaryHeap<Reverse<FairQueueItem>>,
    /// The minimum of vruntime in the run queue. Serves as the initial
    /// value of newly-enqueued threads.
    min_vruntime: u64,
    total_weight: u64,
}

impl FairClassRq {
    pub(crate) fn new(cpu: CpuId) -> Self {
        Self {
            cpu,
            entities: BinaryHeap::new(),
            min_vruntime: 0,
            total_weight: 0,
        }
    }

    /// The scheduling period is calculated as the maximum of the following two values:
    ///
    /// 1. The minimum period value, defined by [`min_period_clocks`].
    /// 2. `period = min_granularity * n` where
    ///    `min_granularity = log2(1 + num_cpus) * base_slice_clocks`, and `n` is the number of
    ///    runnable threads (including the current running thread).
    ///
    /// The formula is chosen by 3 principles:
    ///
    /// 1. The scheduling period should reflect the running threads and CPUs;
    /// 2. The scheduling period should not be too low to limit the overhead of context switching;
    /// 3. The scheduling period should not be too high to ensure the scheduling latency
    ///    & responsiveness.
    fn period(&self) -> u64 {
        let base_slice_clks = base_slice_clocks();
        let min_period_clks = min_period_clocks();

        // `+ 1` means including the current running thread.
        let period_single_cpu =
            (base_slice_clks * (self.entities.len() + 1) as u64).max(min_period_clks);
        period_single_cpu * u64::from((1 + num_cpus()).ilog2())
    }

    /// The virtual time slice for each thread in the run queue, measured in vruntime clocks.
    fn vtime_slice(&self) -> u64 {
        self.period() / (self.entities.len() + 1) as u64
    }

    /// The time slice for each thread in the run queue, measured in sched clocks.
    fn time_slice(&self, cur_weight: u64) -> u64 {
        #[cfg(feature = "kernelet-host")]
        {
            let period = self.period();
            // Cancel the fixed-point scale whenever both operands are integral.
            // This includes ordinary-only queues, without adding queue accounting
            // or inspecting any other task. Mixed fractional sums stay exact.
            let (cur_weight, total_weight) =
                if (cur_weight | self.total_weight).is_multiple_of(WEIGHT_SCALE) {
                    (cur_weight / WEIGHT_SCALE, self.total_weight / WEIGHT_SCALE)
                } else {
                    (cur_weight, self.total_weight)
                };
            if let (Some(numerator), Some(total_weight)) = (
                period.checked_mul(cur_weight),
                total_weight.checked_add(cur_weight),
            ) {
                return numerator / total_weight;
            }
            // The quotient is at most the period, so it fits in `u64`.
            (u128::from(period) * u128::from(cur_weight)
                / (u128::from(total_weight) + u128::from(cur_weight))) as u64
        }
        #[cfg(not(feature = "kernelet-host"))]
        {
            self.period() * cur_weight / (self.total_weight + cur_weight)
        }
    }
}

impl SchedClassRq for FairClassRq {
    fn enqueue(&mut self, entity: Arc<Task>, flags: Option<EnqueueFlags>) {
        let fair_attr = &entity.as_thread().unwrap().sched_attr().fair;
        let vruntime = match flags {
            Some(EnqueueFlags::Spawn) => self.min_vruntime + self.vtime_slice(),
            _ => self.min_vruntime,
        };
        let (_old_weight, weight) = fair_attr.fetch_weight();

        let vruntime = fair_attr
            .vruntime
            .fetch_max(vruntime, Ordering::Relaxed)
            .max(vruntime);

        self.total_weight += weight;
        self.entities.push(Reverse(FairQueueItem(entity, vruntime)));
    }

    fn len(&self) -> usize {
        self.entities.len()
    }

    fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }

    fn pick_next(&mut self) -> Option<Arc<Task>> {
        let Reverse(FairQueueItem(entity, _)) = self.entities.pop()?;

        let sched_attr = entity.as_thread().unwrap().sched_attr();
        let (old_weight, _weight) = sched_attr.fair.fetch_weight();
        // Equals to:
        //
        // self.total_weight = self.total_weight + weight - old_weight;
        // self.total_weight -= weight;
        self.total_weight -= old_weight;

        Some(entity)
    }

    fn update_current(
        &mut self,
        rt: &CurrentRuntime,
        attr: &SchedAttr,
        flags: UpdateFlags,
    ) -> bool {
        match flags {
            UpdateFlags::Tick | UpdateFlags::Yield | UpdateFlags::Wait => {
                let (_old_weight, weight) = attr.fair.fetch_weight();
                let vruntime = attr.fair.update_vruntime(rt.delta, weight);
                let leftmost = self.entities.peek();
                self.min_vruntime = match leftmost {
                    Some(Reverse(leftmost)) => vruntime.min(leftmost.key()),
                    None => vruntime,
                };
                if leftmost.is_none() {
                    return false;
                }

                matches!(flags, UpdateFlags::Wait)
                    || rt.period_delta > self.time_slice(weight)
                    || vruntime > self.min_vruntime + self.vtime_slice()
            }
            UpdateFlags::Exit => !self.is_empty(),
        }
    }
}

#[cfg(ktest)]
mod test {
    use ostd::prelude::ktest;

    use super::*;
    #[cfg(feature = "kernelet-host")]
    use crate::sched::SchedPolicy;
    use crate::thread::kernel_thread::ThreadOptions;

    #[cfg(not(feature = "kernelet-host"))]
    #[ktest]
    fn native_fair_weights_preserve_nice_runtime_and_time_slice() {
        for value in -20..=19 {
            let nice = Nice::try_from(value).unwrap();
            let weight = nice_to_weight(nice);
            let attr = FairAttr::new(nice);
            assert_eq!(attr.fetch_weight(), (weight, weight));
            assert_eq!(attr.update_vruntime(137 * weight, weight), 137 * WEIGHT_0);
            attr.update(Nice::MAX);
            assert_eq!(attr.fetch_weight(), (weight, nice_to_weight(Nice::MAX)));
        }
        let peer = ThreadOptions::new(|| {}).build();
        let mut rq = FairClassRq::new(CpuId::current_racy());
        rq.enqueue(peer, Some(EnqueueFlags::Spawn));
        assert_eq!(rq.time_slice(WEIGHT_0), rq.period() / 2);
        assert!(rq.pick_next().is_some());
        assert_eq!(rq.total_weight, 0);
    }

    #[cfg(feature = "kernelet-host")]
    #[ktest]
    fn fair_shares_preserve_nice_weights_and_positive_extreme_shares() {
        assert_eq!(nice_to_weight(Nice::default()), 1024);
        assert_eq!(nice_to_weight(Nice::MAX), 14);
        for value in -20..=19 {
            let nice = Nice::try_from(value).unwrap();
            let base_weight = nice_to_weight(nice);
            let whole_weight = base_weight * WEIGHT_SCALE;
            let ordinary = FairAttr::new(nice);
            assert_eq!(ordinary.fetch_weight(), (whole_weight, whole_weight));
            let delta = 137 * base_weight;
            assert_eq!(
                ordinary.update_vruntime(delta, whole_weight),
                137 * WEIGHT_0
            );

            for divisor in [1, 2, 3, 64, u16::MAX] {
                let attr =
                    FairAttr::new_with_weight_divisor(nice, NonZeroU16::new(divisor).unwrap());
                let (old_weight, weight) = attr.fetch_weight();
                assert_eq!(old_weight, weight);
                assert_ne!(weight, 0);
                assert_eq!(weight & HAS_PENDING, 0);
                // Flooring loses less than one fixed-point unit per carrier.
                let total_weight = weight * u64::from(divisor);
                assert!(total_weight <= whole_weight);
                assert!(whole_weight - total_weight < u64::from(divisor));
            }
        }
    }

    #[cfg(feature = "kernelet-host")]
    #[ktest]
    fn policy_updates_preserve_fair_share_and_latest_queued_weight() {
        let divisor = NonZeroU16::new(64).unwrap();
        let task = ThreadOptions::new(|| {})
            .fair_weight_divisor(divisor)
            .build();
        let attr = task.as_thread().unwrap().sched_attr();
        let initial_weight = effective_weight(Nice::default(), divisor);
        let mut rq = FairClassRq::new(CpuId::current_racy());
        rq.enqueue(task.clone(), Some(EnqueueFlags::Spawn));
        assert_eq!(rq.total_weight, initial_weight);

        attr.set_policy(SchedPolicy::Fair(Nice::MIN));
        attr.update_policy(|policy| *policy = SchedPolicy::Fair(Nice::MAX));
        assert_eq!(attr.policy(), SchedPolicy::Fair(Nice::MAX));
        assert_eq!(attr.fair.weight_divisor, divisor);
        assert_eq!(rq.total_weight, initial_weight);

        let picked = rq.pick_next().unwrap();
        assert!(Arc::ptr_eq(&picked, &task));
        assert_eq!(rq.total_weight, 0);
        let updated_weight = effective_weight(Nice::MAX, divisor);
        assert_eq!(attr.fair.fetch_weight(), (updated_weight, updated_weight));
        rq.enqueue(picked, Some(EnqueueFlags::Wake));
        assert_eq!(rq.total_weight, updated_weight);
        assert!(rq.pick_next().is_some());
        assert_eq!(rq.total_weight, 0);

        attr.set_policy(SchedPolicy::Idle);
        attr.set_policy(SchedPolicy::Fair(Nice::default()));
        assert_eq!(attr.fair.fetch_weight(), (updated_weight, initial_weight));
    }

    #[cfg(feature = "kernelet-host")]
    #[ktest]
    fn fair_runqueue_uses_divided_share_for_runtime_and_time_slice() {
        let peer = ThreadOptions::new(|| {}).build();
        let mut rq = FairClassRq::new(CpuId::current_racy());
        rq.enqueue(peer, Some(EnqueueFlags::Spawn));
        let ordinary = SchedAttr::new(SchedPolicy::Fair(Nice::default()));
        let divided = SchedAttr::new(SchedPolicy::Fair(Nice::default()))
            .with_fair_weight_divisor(NonZeroU16::new(64).unwrap());
        let (_, ordinary_weight) = ordinary.fair.fetch_weight();
        let (_, divided_weight) = divided.fair.fetch_weight();
        let period = rq.period();
        assert_eq!(rq.time_slice(ordinary_weight), period / 2);
        assert_eq!(rq.time_slice(divided_weight), period / 65);

        // The fixed-point multiplication exceeds u64, while both results fit.
        let runtime = CurrentRuntime {
            start: 0,
            delta: 1 << 40,
            period_delta: period,
        };
        assert!(rq.update_current(&runtime, &ordinary, UpdateFlags::Tick));
        assert!(rq.update_current(&runtime, &divided, UpdateFlags::Tick));
        assert_eq!(ordinary.fair.vruntime.load(Ordering::Relaxed), 1 << 40);
        assert_eq!(divided.fair.vruntime.load(Ordering::Relaxed), 1 << 46);
        assert!(rq.pick_next().is_some());
        assert_eq!(rq.total_weight, 0);
    }

    #[cfg(feature = "kernelet-host")]
    #[ktest]
    fn fair_runtime_preserves_rounding_and_large_deltas() {
        for value in -20..=19 {
            let nice = Nice::try_from(value).unwrap();
            for divisor in [1, 2, 3, 64] {
                for delta in [0, 1, 13, 137, 1 << 40, 1 << 44] {
                    let attr =
                        FairAttr::new_with_weight_divisor(nice, NonZeroU16::new(divisor).unwrap());
                    let (_, weight) = attr.fetch_weight();
                    let expected = u64::try_from(
                        u128::from(delta) * u128::from(WEIGHT_0 * WEIGHT_SCALE)
                            / u128::from(weight),
                    )
                    .unwrap();
                    assert_eq!(attr.update_vruntime(delta, weight), expected);
                }
            }

            // The upstream numerator can overflow even when the quotient fits.
            for delta in [u64::MAX / WEIGHT_0, u64::MAX / WEIGHT_0 + 1] {
                let attr = FairAttr::new(nice);
                let (_, weight) = attr.fetch_weight();
                let expected = u64::try_from(
                    u128::from(delta) * u128::from(WEIGHT_0) / u128::from(nice_to_weight(nice)),
                )
                .unwrap();
                assert_eq!(attr.update_vruntime(delta, weight), expected);
            }
        }
    }

    #[cfg(feature = "kernelet-host")]
    #[ktest]
    fn fair_time_slice_preserves_large_weight_ratios() {
        let mut rq = FairClassRq::new(CpuId::current_racy());
        let period = rq.period();
        // Exercise intermediate multiplication and addition overflow separately.
        assert_eq!(rq.time_slice(u64::MAX), period);
        rq.total_weight = u64::MAX;
        assert_eq!(rq.time_slice(u64::MAX), period / 2);
        assert_eq!(rq.time_slice(1), 0);
    }
}
