// SPDX-License-Identifier: MPL-2.0

//! Diagnostic counters and sampled elapsed-TSC measurements for getpid paths.
//!
//! Legacy probes use `kernelet_getpid_profile`. RQ1 diagnostic builds also
//! expose the task-owned `timeline` records below. Host and image have
//! separate counters. GDB can set `ENABLED`, `MODE`, masks and `SAMPLE_STRIDE`
//! through their exported `KERNELET_GETPID_PROFILE_*` symbols. Mode 1 counts
//! events and stage visits; mode 2 also samples spans. Configuration changes,
//! resets and consistent snapshots require all CPUs stopped and no active
//! counter writers after disabling probes and letting short writers finish.
//! Every exported element is one `AtomicU64` (eight bytes on x86-64). Histogram
//! element `[stage][bucket]` is at `(stage * 16 + bucket) * 8` bytes. Empty
//! `MIN_TICKS` slots contain `u64::MAX`. Advance `EPOCH` before resetting arrays.
//! Suspended spans from older epochs are discarded when their Tasks resume.
//! Never reset `ACTIVE_WRITERS`; it covers updates, not suspended spans.
//!
//! Spans measure elapsed time, including IRQs, scheduling and user residence
//! when a caller brackets `raw.run`. Nested spans overlap. Sampling is per
//! stage, so these aggregates do not constitute a paired syscall timeline.

use core::sync::atomic::{AtomicU64, Ordering};

/// The number of stage and event slots.
pub const SLOT_COUNT: usize = 64;
/// The number of elapsed-TSC histogram buckets per stage.
pub const HISTOGRAM_BUCKETS: usize = 16;

/// Stage identifiers shared by Host and image probes.
pub mod stage {
    /// An empty span used to measure the clock and span boundary overhead.
    pub const EMPTY: u8 = 0;
    /// The Host user gate, including residence in user mode.
    pub const HOST_USER_RUN: u8 = 1;
    /// The Host user-context and stack validation.
    pub const HOST_VALIDATE: u8 = 2;
    /// The Host carrier authentication and service admission.
    pub const HOST_ADMIT: u8 = 3;
    /// The user gate's budget check and any wait.
    pub const HOST_BUDGET_USER: u8 = 4;
    /// The service epilogue's budget check and any wait.
    pub const HOST_BUDGET_RETURN: u8 = 5;
    /// The user gate's registered-root preparation.
    pub const HOST_ROOT_USER: u8 = 6;
    /// The service epilogue's registered-root preparation.
    pub const HOST_ROOT_RETURN: u8 = 7;
    /// The Host save/install of FS and GS before user entry.
    pub const HOST_FS_GS_ENTER: u8 = 8;
    /// The Host save/restore of FS and GS after user exit.
    pub const HOST_FS_GS_LEAVE: u8 = 9;
    /// The complete service-return preparation.
    pub const HOST_RETURN_PREPARE: u8 = 10;
    /// Physical IRQ processing on the Host.
    pub const HOST_IRQ: u8 = 11;
    /// A Host runtime-accounting sample.
    pub const HOST_ACCOUNT: u8 = 12;
    /// The image adapter's work before the user service call.
    pub const GUEST_USER_PRE: u8 = 13;
    /// The image adapter's work after the user service call.
    pub const GUEST_USER_POST: u8 = 14;
    /// The image syscall dispatcher and return-value handling.
    pub const GUEST_SYSCALL_HANDLE: u8 = 15;
    /// The image getpid body.
    pub const GUEST_GETPID_BODY: u8 = 16;
    /// The image's pre-user hook.
    pub const GUEST_PRE_USER_HOOK: u8 = 17;
    /// The image's CPU-local record lookup.
    pub const GUEST_CPU_LOCAL: u8 = 18;
    /// Native raw user execution, including residence in user mode.
    pub const NATIVE_RAW_RUN: u8 = 19;
    /// Host raw user execution, including residence in user mode.
    pub const HOST_RAW_RUN: u8 = 20;
    /// The native syscall dispatcher and return-value handling.
    pub const NATIVE_SYSCALL_HANDLE: u8 = 21;
    /// The native getpid body.
    pub const NATIVE_GETPID_BODY: u8 = 22;
    /// The native pre-user hook.
    pub const NATIVE_PRE_USER_HOOK: u8 = 23;
    /// The outgoing carrier's state save.
    pub const HOST_CARRIER_PAUSE: u8 = 24;
    /// The incoming carrier's state restore.
    pub const HOST_CARRIER_RESUME: u8 = 25;
    /// A syscall kernel round that excludes user residence.
    pub const KERNEL_ROUND: u8 = 26;
    /// The fixed service-entry stub.
    pub const SERVICE_ENTRY: u8 = 27;
    /// The fixed service-return stub.
    pub const SERVICE_RETURN: u8 = 28;
    /// Host GS identity and generation-checked instance lookup.
    pub const HOST_IDENTITY: u8 = 29;
    /// An eligible Guest IRQ-on window waiting for physical trap-return delivery.
    pub const GUEST_VIRQ_WINDOW: u8 = 30;
}

/// Event identifiers shared by Host and image probes.
pub mod event_id {
    /// A raw user execution entry.
    pub const RAW_RUN: u8 = 0;
    /// A context satisfying every actual SYSRET eligibility condition.
    pub const SYSRET_ELIGIBLE: u8 = 1;
    /// A context whose RCX differs from RIP.
    pub const SYSRET_RCX_MISMATCH: u8 = 2;
    /// A context whose R11 differs from RFLAGS.
    pub const SYSRET_R11_MISMATCH: u8 = 3;
    /// A context with RF or TF set.
    pub const SYSRET_RF_TF: u8 = 4;
    /// A context with a noncanonical RIP.
    pub const SYSRET_NONCANONICAL: u8 = 5;
    /// A raw return carrying a syscall trap.
    pub const RETURN_SYSCALL: u8 = 6;
    /// A raw return carrying an exception trap.
    pub const RETURN_EXCEPTION: u8 = 7;
    /// A raw return carrying a physical interrupt trap.
    pub const RETURN_IRQ: u8 = 8;
    /// A user-run service admission.
    pub const SERVICE_USER_RUN: u8 = 9;
    /// A registered-root preparation using the same-root fast path.
    pub const ROOT_FAST: u8 = 10;
    /// A registered-root preparation using the reserve path.
    pub const ROOT_SLOW: u8 = 11;
    /// A root generation mismatch requiring a flush.
    pub const ROOT_GENERATION_FLUSH: u8 = 12;
    /// An actual CR3 write, rather than a root preparation call.
    pub const CR3_WRITE: u8 = 13;
    /// A budget check.
    pub const BUDGET_CHECK: u8 = 14;
    /// A budget check that requires throttling.
    pub const THROTTLE: u8 = 15;
    /// An actual FPU save.
    pub const FPU_SAVE: u8 = 16;
    /// An actual FPU restore.
    pub const FPU_LOAD: u8 = 17;
    /// An image CPU-local record lookup.
    pub const CPU_LOCAL_LOOKUP: u8 = 18;
    /// An actual native task switch.
    pub const NATIVE_SWITCH: u8 = 19;
    /// An actual image task switch.
    pub const GUEST_SWITCH: u8 = 20;
    /// A physical IRQ handler entry.
    pub const PHYSICAL_IRQ: u8 = 21;
    /// An image virtual interrupt delivery.
    pub const VIRTUAL_IRQ: u8 = 22;
    /// A service rejected before admission.
    pub const SERVICE_REJECTED: u8 = 23;
    /// A getpid body invocation.
    pub const GETPID: u8 = 24;
    /// A Host instance identity lookup after current-Task validation.
    pub const IDENTITY_LOOKUP: u8 = 25;
    /// A Guest IRQ-on window entered with pending virtual interrupts.
    pub const VIRQ_WINDOW: u8 = 26;
}

/// Runtime master switch; zero disables every probe.
#[unsafe(no_mangle)]
pub static KERNELET_GETPID_PROFILE_ENABLED: AtomicU64 = AtomicU64::new(0);
/// Identifies one counter window; the controller advances it before resetting.
#[unsafe(no_mangle)]
pub static KERNELET_GETPID_PROFILE_EPOCH: AtomicU64 = AtomicU64::new(0);
/// Short counter writers, excluding elapsed spans retained on suspended stacks.
///
/// After disabling probes, the controller must observe zero before resetting
/// or reading several counter fields. It must never reset this counter itself.
#[unsafe(no_mangle)]
pub static KERNELET_GETPID_PROFILE_ACTIVE_WRITERS: AtomicU64 = AtomicU64::new(0);
/// Runtime mode: zero is off, one counts, and two counts and samples spans.
#[unsafe(no_mangle)]
pub static KERNELET_GETPID_PROFILE_MODE: AtomicU64 = AtomicU64::new(2);
/// Bit mask selecting the enabled stage slots.
#[unsafe(no_mangle)]
pub static KERNELET_GETPID_PROFILE_STAGE_MASK: AtomicU64 = AtomicU64::new(u64::MAX);
/// Bit mask selecting the enabled event slots.
#[unsafe(no_mangle)]
pub static KERNELET_GETPID_PROFILE_EVENT_MASK: AtomicU64 = AtomicU64::new(u64::MAX);
/// Samples every Nth stage visit, starting at visit zero; zero disables timing.
#[unsafe(no_mangle)]
pub static KERNELET_GETPID_PROFILE_SAMPLE_STRIDE: AtomicU64 = AtomicU64::new(1024);
/// Enabled stage visits, including visits not selected for timing.
#[unsafe(no_mangle)]
pub static KERNELET_GETPID_PROFILE_SEEN: [AtomicU64; SLOT_COUNT] =
    [const { AtomicU64::new(0) }; SLOT_COUNT];
/// Completed timing samples for each stage.
#[unsafe(no_mangle)]
pub static KERNELET_GETPID_PROFILE_COUNT: [AtomicU64; SLOT_COUNT] =
    [const { AtomicU64::new(0) }; SLOT_COUNT];
/// The sum of sampled elapsed TSC ticks for each stage.
#[unsafe(no_mangle)]
pub static KERNELET_GETPID_PROFILE_SUM_TICKS: [AtomicU64; SLOT_COUNT] =
    [const { AtomicU64::new(0) }; SLOT_COUNT];
/// The minimum sampled ticks, initially `u64::MAX` for an empty stage.
#[unsafe(no_mangle)]
pub static KERNELET_GETPID_PROFILE_MIN_TICKS: [AtomicU64; SLOT_COUNT] =
    [const { AtomicU64::new(u64::MAX) }; SLOT_COUNT];
/// The maximum sampled ticks for each stage.
#[unsafe(no_mangle)]
pub static KERNELET_GETPID_PROFILE_MAX_TICKS: [AtomicU64; SLOT_COUNT] =
    [const { AtomicU64::new(0) }; SLOT_COUNT];
/// Histograms indexed by stage then floor(log2(ticks)), capped at bucket 15.
///
/// Bucket zero includes zero and one tick; bucket 15 includes every value at
/// least 32768 ticks. Read only a quiescent snapshot for cross-field consistency.
#[unsafe(no_mangle)]
pub static KERNELET_GETPID_PROFILE_HISTOGRAM: [[AtomicU64; HISTOGRAM_BUCKETS]; SLOT_COUNT] =
    [const { [const { AtomicU64::new(0) }; HISTOGRAM_BUCKETS] }; SLOT_COUNT];
/// Enabled event occurrences, without sampling.
#[unsafe(no_mangle)]
pub static KERNELET_GETPID_PROFILE_EVENTS: [AtomicU64; SLOT_COUNT] =
    [const { AtomicU64::new(0) }; SLOT_COUNT];
/// Backward TSC observations; these spans are excluded from timing aggregates.
#[unsafe(no_mangle)]
pub static KERNELET_GETPID_PROFILE_CLOCK_ERRORS: AtomicU64 = AtomicU64::new(0);
/// Aggregate additions that exceeded `u64`; affected aggregates are invalid.
#[unsafe(no_mangle)]
pub static KERNELET_GETPID_PROFILE_OVERFLOWS: AtomicU64 = AtomicU64::new(0);

/// Returns whether diagnostic probes are enabled in a counting or timing mode.
#[inline]
pub fn enabled() -> bool {
    KERNELET_GETPID_PROFILE_ENABLED.load(Ordering::Relaxed) != 0
        && KERNELET_GETPID_PROFILE_MODE.load(Ordering::Relaxed) != 0
}

/// Starts an independently sampled elapsed-TSC span for the selected stage.
#[inline]
pub fn span(stage: u8) -> Option<Span> {
    let writer = Writer::enter()?;
    let mode = KERNELET_GETPID_PROFILE_MODE.load(Ordering::Relaxed);
    if mode == 0 || usize::from(stage) >= SLOT_COUNT {
        return None;
    }
    if KERNELET_GETPID_PROFILE_STAGE_MASK.load(Ordering::Relaxed) & (1u64 << stage) == 0 {
        return None;
    }
    let ordinal = add(&KERNELET_GETPID_PROFILE_SEEN[usize::from(stage)], 1);
    let stride = KERNELET_GETPID_PROFILE_SAMPLE_STRIDE.load(Ordering::Relaxed);
    if mode != 2 || stride == 0 || ordinal % stride != 0 {
        return None;
    }
    let epoch = writer.epoch;
    drop(writer);
    Some(Span {
        stage: usize::from(stage),
        epoch,
        started: Some(read_tsc_ordered()),
    })
}

/// Ends a sampled span explicitly, returning elapsed ticks when the clock is valid.
#[inline]
pub fn end(span: Option<Span>) -> Option<u64> {
    span.and_then(Span::finish)
}

/// Counts an enabled event without sampling it.
#[inline]
pub fn event(id: u8) {
    let Some(_writer) = Writer::enter() else {
        return;
    };
    if KERNELET_GETPID_PROFILE_MODE.load(Ordering::Relaxed) == 0 || usize::from(id) >= SLOT_COUNT {
        return;
    }
    if KERNELET_GETPID_PROFILE_EVENT_MASK.load(Ordering::Relaxed) & (1u64 << id) != 0 {
        add(&KERNELET_GETPID_PROFILE_EVENTS[usize::from(id)], 1);
    }
}

/// Counts an instantaneous marker in the event array.
#[inline]
pub fn mark(id: u8) {
    event(id);
}

/// Samples an empty span with the same stage selection and clock boundaries.
#[inline]
pub fn calibrate_empty() {
    drop(span(stage::EMPTY));
}

/// An elapsed-TSC measurement that records once on drop or explicit completion.
#[must_use]
pub struct Span {
    stage: usize,
    epoch: u64,
    started: Option<u64>,
}

impl !Send for Span {}
impl !Sync for Span {}

impl Span {
    /// Completes the span once and returns its sampled elapsed TSC ticks.
    #[inline]
    pub fn finish(mut self) -> Option<u64> {
        self.record()
    }

    fn record(&mut self) -> Option<u64> {
        let started = self.started.take()?;
        let ended = read_tsc_ordered();
        let writer = Writer::enter()?;
        if writer.epoch != self.epoch {
            // A suspended Task can outlive several configurations. Its span
            // must not write into a later window's freshly reset aggregates.
            return None;
        }
        let Some(ticks) = ended.checked_sub(started) else {
            add(&KERNELET_GETPID_PROFILE_CLOCK_ERRORS, 1);
            return None;
        };
        let stage = self.stage;
        add(&KERNELET_GETPID_PROFILE_SUM_TICKS[stage], ticks);
        KERNELET_GETPID_PROFILE_MIN_TICKS[stage].fetch_min(ticks, Ordering::Relaxed);
        KERNELET_GETPID_PROFILE_MAX_TICKS[stage].fetch_max(ticks, Ordering::Relaxed);
        let bucket = (u64::BITS - 1 - ticks.max(1).leading_zeros()) as usize;
        add(
            &KERNELET_GETPID_PROFILE_HISTOGRAM[stage][bucket.min(HISTOGRAM_BUCKETS - 1)],
            1,
        );
        // Each field is independently race-free. This is not a snapshot commit:
        // readers must quiesce all writers before interpreting several fields.
        add(&KERNELET_GETPID_PROFILE_COUNT[stage], 1);
        Some(ticks)
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        let _ = self.record();
    }
}

/// Pins only a bounded counter update, never a measured or suspended span.
struct Writer {
    epoch: u64,
}

impl Writer {
    #[inline]
    fn enter() -> Option<Self> {
        if KERNELET_GETPID_PROFILE_ENABLED.load(Ordering::SeqCst) == 0 {
            return None;
        }
        KERNELET_GETPID_PROFILE_ACTIVE_WRITERS.fetch_add(1, Ordering::SeqCst);
        let writer = Self {
            epoch: KERNELET_GETPID_PROFILE_EPOCH.load(Ordering::SeqCst),
        };
        // Pair the registration with the disabled/zero-writer observation.
        // A writer which registers after that observation touches no arrays.
        if KERNELET_GETPID_PROFILE_ENABLED.load(Ordering::SeqCst) == 0 {
            return None;
        }
        Some(writer)
    }
}

impl Drop for Writer {
    #[inline]
    fn drop(&mut self) {
        KERNELET_GETPID_PROFILE_ACTIVE_WRITERS.fetch_sub(1, Ordering::SeqCst);
    }
}

// The fetch-add's wrap is intentional only to keep recording bounded and
// lock-free. OVERFLOWS makes such a diagnostic window explicitly invalid.
#[inline]
fn add(counter: &AtomicU64, value: u64) -> u64 {
    let previous = counter.fetch_add(value, Ordering::Relaxed);
    if previous.checked_add(value).is_none() {
        KERNELET_GETPID_PROFILE_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
    }
    previous
}

#[inline]
fn read_tsc_ordered() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: RDTSC and LFENCE are available on the x86-64 diagnostic target.
    // Omitting `nomem` keeps compiler memory accesses within their boundaries.
    // No virtual clock, CPU-local lookup or service call is used by this clock.
    unsafe {
        core::arch::asm!(
            "lfence",
            "rdtsc",
            "lfence",
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags),
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Bounded, task-owned records for a diagnostic getpid kernel round.
///
/// These records are independent of the legacy, per-stage sampled aggregates.
/// A caller arms its own Task before executing getpid and consumes the batch
/// after all calls return. No pointer or record crosses the Host/image ABI.
#[cfg(kernelet_rq1_diagnostics)]
pub mod timeline {
    use alloc::vec::Vec;

    use super::read_tsc_ordered;
    use crate::kernelet::fpu_profile::{self, EVENT_COUNT, TaskSnapshot, Window, WindowReport};

    /// Maximum complete calls in one diagnostic batch.
    pub const MAX_RECORDS: usize = 64;
    /// Ordered boundaries: kernel round, dispatch, body entry/exit,
    /// dispatch completion, and completion of the next pre-user hook.
    /// Ordered semantic boundaries shared by call sites and report labels.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(usize)]
    pub enum Boundary {
        KernelRoundEnter = 0,
        DispatcherEnter,
        BodyEnter,
        BodyLeave,
        DispatcherLeave,
        PreUserHookComplete,
    }

    impl Boundary {
        pub const ALL: [Self; 6] = [
            Self::KernelRoundEnter,
            Self::DispatcherEnter,
            Self::BodyEnter,
            Self::BodyLeave,
            Self::DispatcherLeave,
            Self::PreUserHookComplete,
        ];

        pub const fn name(self) -> &'static str {
            match self {
                Self::KernelRoundEnter => "kernel_round_enter",
                Self::DispatcherEnter => "dispatcher_enter",
                Self::BodyEnter => "body_enter",
                Self::BodyLeave => "body_leave",
                Self::DispatcherLeave => "dispatcher_leave",
                Self::PreUserHookComplete => "pre_user_hook_complete",
            }
        }
    }

    pub const BOUNDARIES: usize = Boundary::ALL.len();

    /// One call's ordered timestamps. Ticks are elapsed TSC units, not cycles.
    pub struct Record {
        pub sequence: u64,
        pub timestamps: [u64; BOUNDARIES],
        pub empty_probe_ticks: u64,
        pub cpu: u32,
        pub returned_pid: u64,
        /// Counter snapshots enclose, rather than exactly match, the TSC round.
        pub fpu_counts: [u64; EVENT_COUNT],
        fpu_start: TaskSnapshot,
        next_boundary: usize,
    }

    /// A complete, validated batch. Every adjacent interval has the same calls.
    pub struct Batch {
        pub records: Vec<Record>,
        pub sums: [u64; BOUNDARIES - 1],
        pub total_ticks: u64,
        pub empty_probe_ticks: u64,
        pub fpu_counts: [u64; EVENT_COUNT],
    }

    /// Diagnostic state accessed only by the current POSIX Task.
    pub struct Timeline {
        target: usize,
        expected_pid: u64,
        active: Option<Record>,
        records: Vec<Record>,
        invalid: bool,
        event_window: Option<Window>,
    }

    impl Timeline {
        pub const fn new() -> Self {
            Self {
                target: 0,
                expected_pid: 0,
                active: None,
                records: Vec::new(),
                invalid: false,
                event_window: None,
            }
        }

        /// Allocates before capture; an active batch cannot be replaced.
        pub fn arm(&mut self, count: usize, expected_pid: u64) -> bool {
            if self.is_armed() || count == 0 || count > MAX_RECORDS || expected_pid == 0 {
                return false;
            }
            self.target = count;
            self.expected_pid = expected_pid;
            self.records = Vec::with_capacity(count);
            true
        }

        pub fn is_armed(&self) -> bool {
            self.target != 0 || self.event_window.is_some()
        }

        pub fn has_event_window(&self) -> bool {
            self.event_window.is_some()
        }

        /// Starts a count-only window without resetting any shared counter.
        pub fn arm_event_window(&mut self) -> bool {
            if self.is_armed() {
                return false;
            }
            self.event_window = Window::begin();
            self.event_window.is_some()
        }

        pub fn take_event_window(&mut self) -> Option<WindowReport> {
            self.event_window.take()?.finish()
        }

        /// Starts after the task loop identifies a returned getpid trap.
        pub fn begin(&mut self, cpu: u32) {
            if !self.is_armed() || self.records.len() == self.target {
                return;
            }
            if self.active.is_some() {
                self.invalid = true;
                return;
            }
            // A separate empty pair reports the ordered-clock primitive's
            // cost. It precedes, and is excluded from, the kernel round.
            let probe_start = read_tsc_ordered();
            let probe_end = read_tsc_ordered();
            let Some(empty_probe_ticks) = probe_end.checked_sub(probe_start) else {
                self.invalid = true;
                return;
            };
            let Some(fpu_start) = fpu_profile::task_snapshot() else {
                self.invalid = true;
                return;
            };
            let mut timestamps = [0; BOUNDARIES];
            timestamps[0] = read_tsc_ordered();
            self.active = Some(Record {
                sequence: self.records.len() as u64 + 1,
                timestamps,
                empty_probe_ticks,
                cpu,
                returned_pid: 0,
                fpu_counts: [0; EVENT_COUNT],
                fpu_start,
                next_boundary: 1,
            });
        }

        /// Marks one exact, forward-only boundary in the current call.
        pub fn mark(&mut self, boundary: Boundary) {
            let boundary = boundary as usize;
            let Some(record) = self.active.as_mut() else {
                return;
            };
            if boundary != record.next_boundary || boundary >= BOUNDARIES {
                self.invalid = true;
                return;
            }
            record.timestamps[boundary] = read_tsc_ordered();
            record.next_boundary += 1;
        }

        pub fn dispatch_complete(&mut self, returned_pid: u64) {
            self.mark(Boundary::DispatcherLeave);
            if let Some(record) = self.active.as_mut() {
                record.returned_pid = returned_pid;
            }
        }

        /// Commits only after the next pre-user hook has completed.
        pub fn complete(&mut self, cpu: u32) {
            if self.active.is_none() {
                return;
            }
            self.mark(Boundary::PreUserHookComplete);
            let mut record = self.active.take().unwrap();
            if let Some(counts) =
                fpu_profile::task_snapshot().and_then(|end| end.delta_since(&record.fpu_start))
            {
                record.fpu_counts = counts;
            } else {
                self.invalid = true;
            }
            if record.next_boundary != BOUNDARIES
                || record.cpu != cpu
                || record.returned_pid != self.expected_pid
                || record.timestamps.windows(2).any(|pair| pair[1] < pair[0])
            {
                self.invalid = true;
            }
            // Capacity was reserved by arm(), outside every timed interval.
            self.records.push(record);
        }

        /// Disarms and consumes the batch; incomplete/invalid data is rejected.
        pub fn take_batch(&mut self) -> Option<Batch> {
            let captured = core::mem::replace(self, Self::new());
            if captured.invalid
                || captured.target == 0
                || captured.records.len() != captured.target
                || captured.active.is_some()
            {
                return None;
            }
            let mut sums = [0u64; BOUNDARIES - 1];
            let mut total_ticks = 0u64;
            let mut empty_probe_ticks = 0u64;
            let mut fpu_counts = [0u64; EVENT_COUNT];
            for record in &captured.records {
                for (sum, count) in fpu_counts.iter_mut().zip(record.fpu_counts) {
                    *sum = sum.checked_add(count)?;
                }
                for (sum, pair) in sums.iter_mut().zip(record.timestamps.windows(2)) {
                    *sum = sum.checked_add(pair[1].checked_sub(pair[0])?)?;
                }
                total_ticks = total_ticks.checked_add(
                    record.timestamps[BOUNDARIES - 1].checked_sub(record.timestamps[0])?,
                )?;
                empty_probe_ticks = empty_probe_ticks.checked_add(record.empty_probe_ticks)?;
            }
            Some(Batch {
                records: captured.records,
                sums,
                total_ticks,
                empty_probe_ticks,
                fpu_counts,
            })
        }
    }

    impl Default for Timeline {
        fn default() -> Self {
            Self::new()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn call(timeline: &mut Timeline, cpu: u32, returned_pid: u64) {
            timeline.begin(cpu);
            timeline.mark(Boundary::DispatcherEnter);
            timeline.mark(Boundary::BodyEnter);
            timeline.mark(Boundary::BodyLeave);
            timeline.dispatch_complete(returned_pid);
            timeline.complete(cpu);
        }

        #[test]
        fn adjacent_intervals_and_total_use_the_same_complete_records() {
            let mut timeline = Timeline::new();
            assert!(timeline.arm(2, 42));
            call(&mut timeline, 3, 42);
            call(&mut timeline, 3, 42);
            let batch = timeline.take_batch().unwrap();
            assert_eq!(batch.records.len(), 2);
            assert_eq!(batch.sums.iter().sum::<u64>(), batch.total_ticks);
            for (index, record) in batch.records.iter().enumerate() {
                assert_eq!(record.sequence, index as u64 + 1);
                assert_eq!(record.cpu, 3);
                assert_eq!(record.returned_pid, 42);
                assert!(record.timestamps.windows(2).all(|pair| pair[1] >= pair[0]));
            }
            assert!(!timeline.is_armed());
            assert!(timeline.arm(1, 43));
        }

        #[test]
        fn task_events_are_paired_and_batch_counts_are_additive() {
            use crate::kernelet::fpu_profile::{Event, event};

            let mut timeline = Timeline::new();
            assert!(timeline.arm(2, 42));
            event(Event::Xsave); // Outside both per-record counter windows.
            for _ in 0..2 {
                timeline.begin(0);
                event(Event::ScheduleOnCpu);
                event(Event::SaveSchedule);
                event(Event::Xsave);
                timeline.mark(Boundary::DispatcherEnter);
                timeline.mark(Boundary::BodyEnter);
                timeline.mark(Boundary::BodyLeave);
                timeline.dispatch_complete(42);
                event(Event::UserEntryInMemory);
                event(Event::LoadUserEntry);
                event(Event::Xrstor);
                timeline.complete(0);
            }
            let batch = timeline.take_batch().unwrap();
            for kind in [
                Event::ScheduleOnCpu,
                Event::SaveSchedule,
                Event::Xsave,
                Event::UserEntryInMemory,
                Event::LoadUserEntry,
                Event::Xrstor,
            ] {
                assert_eq!(batch.fpu_counts[kind as usize], 2);
                assert!(
                    batch
                        .records
                        .iter()
                        .all(|record| record.fpu_counts[kind as usize] == 1)
                );
            }
        }

        #[test]
        fn incomplete_or_out_of_order_calls_cannot_form_a_batch() {
            let mut timeline = Timeline::new();
            assert!(timeline.arm(2, 42));
            call(&mut timeline, 0, 42);
            assert!(timeline.take_batch().is_none());
            assert!(!timeline.is_armed());
            assert!(timeline.arm(1, 42));
            timeline.begin(0);
            timeline.mark(Boundary::BodyEnter);
            timeline.complete(0);
            assert!(timeline.take_batch().is_none());
        }

        #[test]
        fn cpu_and_return_value_mismatches_invalidate_the_batch() {
            let mut timeline = Timeline::new();
            assert!(timeline.arm(1, 42));
            call(&mut timeline, 0, 43);
            assert!(timeline.take_batch().is_none());
            assert!(timeline.arm(1, 42));
            timeline.begin(0);
            for boundary in [
                Boundary::DispatcherEnter,
                Boundary::BodyEnter,
                Boundary::BodyLeave,
            ] {
                timeline.mark(boundary);
            }
            timeline.dispatch_complete(42);
            timeline.complete(1);
            assert!(timeline.take_batch().is_none());
        }

        #[test]
        fn capture_is_bounded_and_unarmed_calls_leave_no_records() {
            let mut timeline = Timeline::new();
            call(&mut timeline, 0, 42);
            assert!(timeline.take_batch().is_none());
            assert!(!timeline.arm(0, 42));
            assert!(!timeline.arm(MAX_RECORDS + 1, 42));
            assert!(!timeline.arm(1, 0));
            assert!(timeline.arm(1, 42));
            assert!(!timeline.arm(1, 42));
            call(&mut timeline, 0, 42);
            call(&mut timeline, 0, 42);
            assert_eq!(timeline.take_batch().unwrap().records.len(), 1);
        }
    }
}
