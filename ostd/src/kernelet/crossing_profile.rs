// SPDX-License-Identifier: MPL-2.0

//! Batch clocks and bounded echo-body diagnostics for the ordinary service gate.
//!
//! The Image pairs its call-site clocks with Host body clocks by capture nonce
//! and the existing echo token. These are inclusive elapsed-TSC records.
//! Matching CPU endpoints do not exclude interrupts or an away-and-back switch.

/// Maximum admitted echo calls in one capture.
pub const CALL_CAPACITY: usize = 64;
/// Interrupt and scheduling disturbance has not been fully observed.
pub const DISTURBANCE: &str = "unknown";
/// This first interface supplies no complete interrupt-coverage protocol.
pub const INTERRUPT_COVERAGE: &str = "incomplete";

/// Reads an ordered elapsed-time clock without a virtual service or allocation.
///
/// The memory clobber prevents the compiler from moving memory operations across
/// the clock. The final linked instruction positions still require inspection.
/// TSC ticks are elapsed time, not CPU execution cycles.
#[inline(always)]
pub fn read_tsc_ordered() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: This diagnostic module is restricted to x86-64, where LFENCE and
    // RDTSC are available. Outputs describe both clobbered registers; omitting
    // `nomem` retains the compiler memory barrier. No stack or FPU state is used.
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

/// Reads the batch clock with the same store and load fences as the KVM fixture.
///
/// The compiler memory barrier is retained. TSC ticks measure elapsed time,
/// including interruptions; the target CPU's ordering guarantees need checking.
#[inline(always)]
pub fn read_batch_tsc_ordered() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: This module is restricted to x86-64. The instructions do not
    // access caller memory or change privilege, IRQ, stack, or FPU state. The
    // outputs account for both RDTSC registers; omitting `nomem` retains the
    // compiler memory barrier.
    unsafe {
        core::arch::asm!(
            "mfence",
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

/// Caller context sampled outside a batch's clock interval.
///
/// These observations are not atomic and do not prove uninterrupted execution.
pub struct BatchContext {
    cpu: u32,
    rflags: u64,
    virtual_irq_enabled: Option<bool>,
}

impl BatchContext {
    /// Returns the Host CPU or, for an Image, its virtual CPU.
    pub fn cpu(&self) -> u32 {
        self.cpu
    }

    /// Returns the physical RFLAGS sample, including the hardware IF bit.
    pub fn rflags(&self) -> u64 {
        self.rflags
    }

    /// Returns Image virtual-IRQ admission, or `None` in a Native build.
    pub fn virtual_irq_enabled(&self) -> Option<bool> {
        self.virtual_irq_enabled
    }
}

/// Samples caller CPU and IRQ state without changing IRQ or preemption state.
pub fn read_batch_context() -> BatchContext {
    let cpu = crate::cpu::CpuId::current_racy().into();
    let rflags = x86_64::registers::rflags::read_raw();
    #[cfg(feature = "kernelet")]
    let virtual_irq_enabled = Some(crate::arch::irq::is_local_enabled());
    #[cfg(not(feature = "kernelet"))]
    let virtual_irq_enabled = None;
    BatchContext {
        cpu,
        rflags,
        virtual_irq_enabled,
    }
}

#[cfg(all(kernelet_rq1_crossing_diag, feature = "kernelet-host"))]
pub(crate) use host::{BodyStamp, CrossingProfile};
#[cfg(all(kernelet_rq1_crossing_diag, feature = "kernelet-host"))]
pub use host::{CallRecord, CaptureError, CaptureHandle, CaptureSnapshot, InstanceIdentity};

#[cfg(all(kernelet_rq1_crossing_diag, feature = "kernelet-host"))]
mod host {
    use alloc::{sync::Arc, vec::Vec};

    use super::{CALL_CAPACITY, read_tsc_ordered};
    use crate::{
        cpu::CpuId,
        kernelet::abi::CpuSlot,
        sync::{LocalIrqDisabled, SpinLock},
    };

    /// Failure to arm a capture or copy a closed, drained snapshot.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum CaptureError {
        /// The nonce must be nonzero.
        Invalid,
        /// Admission is still open, or admitted calls have not completed.
        Busy,
        /// Diagnostic record storage could not be allocated.
        NoMemory,
        /// The instance was not running at the capability's lifecycle check.
        Unavailable,
    }

    /// Authenticated instance identity, independent of the actual caller vCPU.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct InstanceIdentity {
        /// Registered instance slot.
        pub slot: u16,
        /// Generation distinguishes slot reuse.
        pub generation: u32,
    }

    impl InstanceIdentity {
        fn from_slot(identity: CpuSlot) -> Self {
            Self {
                slot: identity.kernelet,
                generation: identity.generation,
            }
        }
    }

    /// One admitted call, including partial evidence if its guard was abandoned.
    #[derive(Clone, Copy, Debug)]
    pub struct CallRecord {
        /// One-based admission order within this capture.
        pub sequence: u64,
        /// The unmodified argument and return value of the echo service.
        pub token: u64,
        /// Actual authenticated calling vCPU, not the arm-time identity's vCPU.
        pub vcpu: u16,
        /// Actual Host physical CPU sampled after H0, not an APIC ID.
        pub host_cpu_before: u32,
        /// Actual Host physical CPU sampled after H1, absent if abandoned.
        pub host_cpu_after: Option<u32>,
        /// First explicit clock point in the Rust echo body, after its prologue.
        pub h0_tsc: u64,
        /// Final explicit body clock, before publication and the Rust epilogue.
        pub h1_tsc: Option<u64>,
        /// Both body clocks were supplied; protocol flags still require checking.
        pub complete: bool,
    }

    /// Owned evidence that remains readable after its instance is destroyed.
    #[derive(Debug)]
    pub struct CaptureSnapshot {
        /// Instance selected by the sandbox capability.
        pub instance: InstanceIdentity,
        /// Nonzero, caller-provided capture label; it grants no authority.
        pub nonce: u64,
        /// Retained records in admission order; invalid evidence is not discarded.
        pub records: Vec<CallRecord>,
        /// Capacity was exceeded; the retained records are incomplete evidence.
        pub overflow: bool,
        /// Identity, token uniqueness, CPU or clock consistency failed.
        pub protocol_error: bool,
        /// A call was abandoned, a slot is missing, or the capture is empty.
        pub incomplete: bool,
    }

    impl CaptureSnapshot {
        /// Checks the captured protocol, without asserting absence of disturbance.
        pub fn is_valid(&self) -> bool {
            !self.records.is_empty() && !self.overflow && !self.protocol_error && !self.incomplete
        }
    }

    /// Cloning a handle retains diagnostic memory only, without tenant resources.
    /// Dropping its last clone closes new admission without waiting or allocating.
    #[derive(Clone)]
    pub struct CaptureHandle(Arc<CaptureLease>);

    struct CaptureLease {
        capture: Arc<Capture>,
    }

    impl Drop for CaptureLease {
        fn drop(&mut self) {
            self.capture.state.lock().closed = true;
        }
    }

    impl CaptureHandle {
        /// Closes admission and copies evidence without consuming it.
        ///
        /// `Busy` leaves admission closed while existing calls drain. Allocation
        /// failure also leaves all records available for retry. Invalid evidence
        /// returns its original records and flags, not a fabricated success.
        pub fn finish(&self) -> Result<CaptureSnapshot, CaptureError> {
            let capture = &self.0.capture;
            let count = {
                let mut state = capture.state.lock();
                state.closed = true;
                if state.inflight != 0 {
                    return Err(CaptureError::Busy);
                }
                state.count
            };

            // Closed and drained means no future writer. Allocate outside the
            // spinlock, then copy only fixed-size records under the lock.
            let mut records = Vec::new();
            reserve(&mut records, count)?;
            let (overflow, mut protocol_error, mut incomplete) = {
                let state = capture.state.lock();
                for slot in &state.slots[..count] {
                    if let Some(record) = slot {
                        records.push(*record);
                    }
                }
                (
                    state.overflow,
                    state.protocol_error,
                    state.abandoned || count == 0 || records.len() != count,
                )
            };

            // The bounded uniqueness check is on cold export, never the service
            // path. There is no allocation or callback during record publication.
            for (index, record) in records.iter().enumerate() {
                incomplete |= !record.complete;
                protocol_error |= records[..index]
                    .iter()
                    .any(|previous| previous.token == record.token);
            }
            Ok(CaptureSnapshot {
                instance: capture.instance,
                nonce: capture.nonce,
                records,
                overflow,
                protocol_error,
                incomplete,
            })
        }
    }

    /// Lock order: profile -> capture. Completion/export never acquires profile.
    /// No guard protects I/O, allocation, waiting, logging or tenant memory access.
    pub(crate) struct CrossingProfile {
        capture: SpinLock<Option<Arc<Capture>>, LocalIrqDisabled>,
    }

    impl CrossingProfile {
        pub(crate) const fn new() -> Self {
            Self {
                capture: SpinLock::new(None),
            }
        }

        pub(crate) fn arm(
            &self,
            identity: CpuSlot,
            nonce: u64,
        ) -> Result<CaptureHandle, CaptureError> {
            if nonce == 0 {
                return Err(CaptureError::Invalid);
            }
            let capture = Capture::new(InstanceIdentity::from_slot(identity), nonce)?;
            let retired = {
                let mut current = self.capture.lock();
                if let Some(previous) = current.as_ref() {
                    let state = previous.state.lock();
                    if !state.closed || state.inflight != 0 {
                        return Err(CaptureError::Busy);
                    }
                }
                current.replace(capture.clone())
            };
            drop(retired);
            Ok(CaptureHandle(Arc::new(CaptureLease { capture })))
        }

        /// Reserves one slot only after the ordinary carrier authentication.
        /// The entry stamp stays in the source-owned guard until after H1.
        pub(crate) fn begin(
            &self,
            identity: CpuSlot,
            token: u64,
            entry: BodyStamp,
        ) -> Option<Call> {
            let current = self.capture.lock();
            let capture = current.as_ref()?;
            let mut state = capture.state.lock();
            if state.closed {
                return None;
            }
            if capture.instance != InstanceIdentity::from_slot(identity) {
                state.protocol_error = true;
                return None;
            }
            if state.count == CALL_CAPACITY {
                state.overflow = true;
                return None;
            }
            let index = state.count;
            // Both counters are bounded by CALL_CAPACITY before this increment.
            state.count += 1;
            state.inflight += 1;
            Some(Call {
                capture: capture.clone(),
                index,
                token,
                vcpu: identity.vcpu,
                entry,
                finished: false,
            })
        }
    }

    struct Capture {
        instance: InstanceIdentity,
        nonce: u64,
        state: SpinLock<CaptureState, LocalIrqDisabled>,
    }

    impl Capture {
        fn new(instance: InstanceIdentity, nonce: u64) -> Result<Arc<Self>, CaptureError> {
            let mut slots = Vec::new();
            reserve(&mut slots, CALL_CAPACITY)?;
            slots.resize(CALL_CAPACITY, None);
            Ok(Arc::new(Self {
                instance,
                nonce,
                state: SpinLock::new(CaptureState {
                    slots,
                    count: 0,
                    inflight: 0,
                    closed: false,
                    overflow: false,
                    protocol_error: false,
                    abandoned: false,
                }),
            }))
        }
    }

    struct CaptureState {
        slots: Vec<Option<CallRecord>>,
        count: usize,
        inflight: usize,
        closed: bool,
        overflow: bool,
        protocol_error: bool,
        abandoned: bool,
    }

    fn reserve<T>(values: &mut Vec<T>, capacity: usize) -> Result<(), CaptureError> {
        values
            .try_reserve_exact(capacity)
            .map_err(|_| CaptureError::NoMemory)
    }

    /// Actual clock and CPU sample; the CPU read follows the timestamp.
    /// Physical IRQ masking in the normal echo body pins these source accesses.
    /// Equal samples do not prove no outer-window interruption or migration.
    pub(crate) struct BodyStamp {
        tsc: u64,
        cpu: u32,
    }

    impl BodyStamp {
        #[inline(always)]
        pub(crate) fn now() -> Self {
            let tsc = read_tsc_ordered();
            let cpu = CpuId::current_racy().into();
            Self { tsc, cpu }
        }
    }

    /// A diagnostic-only lifetime guard, without pointers to Image or resources.
    pub(crate) struct Call {
        capture: Arc<Capture>,
        index: usize,
        token: u64,
        vcpu: u16,
        entry: BodyStamp,
        finished: bool,
    }

    impl Call {
        /// Publishes both body clocks after H1; publication belongs to suffix.
        pub(crate) fn complete(mut self, exit: BodyStamp) {
            self.commit(Some(exit));
        }

        fn commit(&mut self, exit: Option<BodyStamp>) {
            let record = CallRecord {
                sequence: self.index as u64 + 1,
                token: self.token,
                vcpu: self.vcpu,
                host_cpu_before: self.entry.cpu,
                host_cpu_after: exit.as_ref().map(|stamp| stamp.cpu),
                h0_tsc: self.entry.tsc,
                h1_tsc: exit.as_ref().map(|stamp| stamp.tsc),
                complete: exit.is_some(),
            };
            let mut state = self.capture.state.lock();
            state.protocol_error |= exit
                .as_ref()
                .is_some_and(|end| end.tsc < self.entry.tsc || end.cpu != self.entry.cpu);
            state.abandoned |= exit.is_none();
            state.slots[self.index] = Some(record);
            // This guard owns exactly one admission, and commits only once.
            debug_assert!(state.inflight != 0);
            state.inflight -= 1;
            self.finished = true;
        }
    }

    impl Drop for Call {
        fn drop(&mut self) {
            if !self.finished {
                self.commit(None);
            }
        }
    }

    #[cfg(ktest)]
    mod test {
        use super::*;
        use crate::prelude::*;

        fn identity(vcpu: u16) -> CpuSlot {
            CpuSlot {
                kernelet: 7,
                vcpu,
                generation: 3,
                _reserved: 0,
            }
        }

        fn stamp(tsc: u64, cpu: u32) -> BodyStamp {
            BodyStamp { tsc, cpu }
        }

        #[ktest]
        fn finish_closes_admission_and_preserves_a_draining_call() {
            let profile = CrossingProfile::new();
            let handle = profile.arm(identity(0), 41).unwrap();
            let call = profile.begin(identity(2), 9, stamp(10, 5)).unwrap();
            assert!(matches!(handle.finish(), Err(CaptureError::Busy)));
            assert!(profile.begin(identity(2), 10, stamp(11, 5)).is_none());
            call.complete(stamp(20, 5));
            let first = handle.finish().unwrap();
            assert!(first.is_valid());
            assert_eq!(first.nonce, 41);
            assert_eq!(first.instance.slot, 7);
            assert_eq!(first.records[0].vcpu, 2);
            assert_eq!(first.records[0].host_cpu_before, 5);
            assert_eq!(first.records[0].h1_tsc, Some(20));
            assert_eq!(handle.finish().unwrap().records[0].token, 9);
        }

        #[ktest]
        fn last_handle_drop_closes_admission_and_rearm_keeps_old_evidence() {
            let profile = CrossingProfile::new();
            let handle = profile.arm(identity(0), 41).unwrap();
            let clone = handle.clone();
            drop(handle);
            profile
                .begin(identity(0), 9, stamp(10, 5))
                .unwrap()
                .complete(stamp(20, 5));
            let old = clone.finish().unwrap();
            let next = profile.arm(identity(0), 42).unwrap();
            drop(clone);
            profile
                .begin(identity(0), 10, stamp(30, 5))
                .unwrap()
                .complete(stamp(40, 5));
            let new = next.finish().unwrap();
            assert_eq!(old.nonce, 41);
            assert_eq!(old.records[0].token, 9);
            assert_eq!(new.nonce, 42);
            assert_eq!(new.records[0].token, 10);
            drop(next);
            assert!(profile.begin(identity(0), 11, stamp(50, 5)).is_none());
        }

        #[ktest]
        fn dropping_the_last_open_handle_stops_admission() {
            let profile = CrossingProfile::new();
            let handle = profile.arm(identity(0), 41).unwrap();
            let call = profile.begin(identity(0), 9, stamp(10, 5)).unwrap();
            drop(handle);
            assert!(profile.begin(identity(0), 10, stamp(11, 5)).is_none());
            assert!(matches!(
                profile.arm(identity(0), 42),
                Err(CaptureError::Busy)
            ));
            call.complete(stamp(20, 5));
            assert!(profile.arm(identity(0), 42).is_ok());
        }

        #[ktest]
        fn abandoned_call_retains_partial_record_and_invalidates_capture() {
            let profile = CrossingProfile::new();
            let handle = profile.arm(identity(0), 41).unwrap();
            drop(profile.begin(identity(0), 9, stamp(10, 5)).unwrap());
            let report = handle.finish().unwrap();
            assert!(!report.is_valid());
            assert!(report.incomplete);
            assert_eq!(report.records.len(), 1);
            assert_eq!(report.records[0].h0_tsc, 10);
            assert_eq!(report.records[0].h1_tsc, None);
            assert_eq!(report.records[0].host_cpu_after, None);
        }

        #[ktest]
        fn capacity_overflow_preserves_every_admitted_record() {
            let profile = CrossingProfile::new();
            let handle = profile.arm(identity(0), 41).unwrap();
            for token in 0..CALL_CAPACITY as u64 {
                profile
                    .begin(identity(0), token, stamp(10, 5))
                    .unwrap()
                    .complete(stamp(20, 5));
            }
            assert!(profile.begin(identity(0), 64, stamp(30, 5)).is_none());
            let report = handle.finish().unwrap();
            assert!(report.overflow);
            assert!(!report.is_valid());
            assert_eq!(report.records.len(), CALL_CAPACITY);
            assert_eq!(report.records[63].sequence, 64);
            assert_eq!(report.records[63].token, 63);
        }

        #[ktest]
        fn stale_instance_identity_is_not_admitted() {
            let profile = CrossingProfile::new();
            let handle = profile.arm(identity(0), 41).unwrap();
            let mut stale = identity(0);
            stale.generation += 1;
            assert!(profile.begin(stale, 9, stamp(10, 5)).is_none());
            let report = handle.finish().unwrap();
            assert!(report.protocol_error);
            assert!(report.records.is_empty());
            assert!(!report.is_valid());
        }

        #[ktest]
        fn invalid_nonce_empty_capture_and_open_rearm_are_rejected() {
            let profile = CrossingProfile::new();
            assert!(matches!(
                profile.arm(identity(0), 0),
                Err(CaptureError::Invalid)
            ));
            let handle = profile.arm(identity(0), 41).unwrap();
            assert!(matches!(
                profile.arm(identity(0), 42),
                Err(CaptureError::Busy)
            ));
            let empty = handle.finish().unwrap();
            assert!(empty.incomplete);
            assert!(!empty.is_valid());
            assert_eq!(empty.nonce, 41);
        }

        #[ktest]
        fn backward_clock_keeps_invalid_evidence() {
            let profile = CrossingProfile::new();
            let handle = profile.arm(identity(0), 41).unwrap();
            profile
                .begin(identity(0), 9, stamp(20, 5))
                .unwrap()
                .complete(stamp(10, 5));
            let report = handle.finish().unwrap();
            assert!(report.protocol_error);
            assert!(!report.is_valid());
            assert_eq!(report.records.len(), 1);
            assert_eq!(report.records[0].h1_tsc, Some(10));
        }

        #[ktest]
        fn cpu_change_keeps_invalid_evidence() {
            let profile = CrossingProfile::new();
            let handle = profile.arm(identity(0), 41).unwrap();
            profile
                .begin(identity(0), 10, stamp(30, 5))
                .unwrap()
                .complete(stamp(40, 6));
            let report = handle.finish().unwrap();
            assert!(report.protocol_error);
            assert!(!report.is_valid());
            assert_eq!(report.records.len(), 1);
            assert_eq!(report.records[0].host_cpu_after, Some(6));
        }

        #[ktest]
        fn duplicate_tokens_keep_both_records_without_other_errors() {
            let profile = CrossingProfile::new();
            let handle = profile.arm(identity(0), 41).unwrap();
            profile
                .begin(identity(0), 10, stamp(30, 5))
                .unwrap()
                .complete(stamp(40, 5));
            profile
                .begin(identity(0), 10, stamp(50, 5))
                .unwrap()
                .complete(stamp(60, 5));
            let report = handle.finish().unwrap();
            assert!(report.protocol_error);
            assert!(!report.incomplete);
            assert!(!report.overflow);
            assert!(!report.is_valid());
            assert_eq!(report.records.len(), 2);
            assert_eq!(report.records[0].token, 10);
            assert_eq!(report.records[1].token, 10);
        }
    }
}
