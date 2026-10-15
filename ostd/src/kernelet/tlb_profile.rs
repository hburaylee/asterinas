// SPDX-License-Identifier: MPL-2.0

//! Bounded, instance-owned Host TLB diagnostics for RQ1 builds.
//!
//! Tokens travel with the actual flush queue. Completion denotes a flush batch
//! covering the request, followed by the existing source wait; it is not a
//! separate ACK or an instruction-latency measurement. Capture handles retain
//! diagnostic memory only, without retaining an instance, root, or grant.

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use super::abi::CpuSlot;
use crate::{
    cpu::{CpuId, CpuSet},
    sync::{LocalIrqDisabled, SpinLock},
};

/// Maximum requests in one capture, and tokens in one physical CPU's batch.
pub const REQUEST_CAPACITY: usize = 64;

static NEXT_ROOT_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_root_id() -> Option<u64> {
    NEXT_ROOT_ID
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .ok()
}

/// A failure to arm or finish a diagnostic capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureError {
    /// Another capture is open, or admitted requests have not finished.
    Busy,
    /// Diagnostic storage could not be allocated.
    NoMemory,
    /// The instance was not running when capture was requested.
    Unavailable,
}

/// Generation-checked instance identity, independent of any vCPU number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstanceIdentity {
    /// Registered instance slot, independent of a vCPU or physical CPU.
    pub slot: u16,
    /// Instance generation that distinguishes reuse of the slot.
    pub generation: u32,
}

/// Immutable fields of an accepted user-root shootdown.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestDescriptor {
    /// `None` denotes diagnostic identity exhaustion, not a valid root ID.
    pub root_id: Option<u64>,
    /// Host physical address of the registered user page-table root.
    pub root_paddr: u64,
    /// Root generation captured with the active physical CPU set.
    pub root_generation: u64,
    /// Image vCPU that requested the shootdown.
    pub source_vcpu: u16,
    /// Host physical CPU index serving the request, not an APIC ID.
    pub source_cpu: u32,
    /// First user virtual address in bytes for a ranged request.
    pub start: u64,
    /// Range length in bytes, or `u64::MAX` for all non-global entries.
    pub len: u64,
}

/// Hardware flush type of a batch, which may cover multiple requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchFlushKind {
    /// One or more address or range invalidations on the target CPU.
    Ranges,
    /// Invalidation of all non-global translations on the target CPU.
    FullNonGlobal,
}

/// Completion evidence for one requested physical CPU.
#[derive(Clone, Copy, Debug)]
pub struct TargetCompletion {
    /// Target Host physical CPU index, not an image vCPU or APIC ID.
    pub cpu: u32,
    /// Whether the callback completed the hardware flush covering this request.
    pub flush_done: bool,
    /// Actual merged batch type; `None` means no valid flush completion.
    pub batch_kind: Option<BatchFlushKind>,
}

/// One captured request, with a one-based sequence within this capture.
#[derive(Debug)]
pub struct RequestRecord {
    /// One-based admission order within this capture.
    pub sequence: u64,
    /// Root, source and range accepted for this request.
    pub request: RequestDescriptor,
    /// Requested physical CPUs and their corresponding completion evidence.
    pub targets: Vec<TargetCompletion>,
    /// Whether the source returned from the existing synchronous IPI wait.
    pub wait_returned: bool,
}

/// A closed capture. Invalid captures retain their records and failure flags.
#[derive(Debug)]
pub struct CaptureSnapshot {
    /// Instance selected when this capture was armed.
    pub instance: InstanceIdentity,
    /// Retained requests in admission order, including invalid evidence.
    pub records: Vec<RequestRecord>,
    /// Whether the request or batch-token capacity discarded diagnostic evidence.
    pub overflow: bool,
    /// Whether any request lacked a diagnostic root-lifetime identity.
    pub identity_exhausted: bool,
    /// Whether completion evidence was missing, duplicate or inconsistent.
    pub protocol_error: bool,
    /// Whether a request was abandoned or lacked a wait or target completion.
    pub incomplete: bool,
}

impl CaptureSnapshot {
    /// Returns whether every captured request has complete, consistent evidence.
    /// An empty capture is valid but supplies no remote-flush evidence.
    pub fn is_valid(&self) -> bool {
        !self.overflow && !self.identity_exhausted && !self.protocol_error && !self.incomplete
    }
}

/// A diagnostic-only handle that remains readable after instance destruction.
/// Dropping its last clone closes capture admission without allocating.
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
    /// Closes new request admission and returns a non-consuming snapshot.
    ///
    /// `Busy` means existing requests still run; admission remains closed and
    /// the caller can retry. Allocation or user-copy failure cannot consume the
    /// records. No waiting or user-memory access occurs in this method.
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

        // A closed, drained capture has no writers. Allocate before locking,
        // then copy into reserved buffers without allocating under the lock.
        let mut records = Vec::new();
        reserve(&mut records, count)?;
        for index in 0..count {
            let mut targets = Vec::new();
            reserve(&mut targets, capture.num_cpus)?;
            records.push(RequestRecord {
                sequence: index as u64 + 1,
                request: RequestDescriptor::default(),
                targets,
                wait_returned: false,
            });
        }
        let state = capture.state.lock();
        let mut incomplete = state.abandoned;
        for (record, slot) in records.iter_mut().zip(&state.slots) {
            record.request = slot.request;
            record.wait_returned = slot.wait_returned;
            incomplete |= !slot.wait_returned;
            for (cpu, target) in slot.targets.iter().enumerate() {
                if target.is_target {
                    incomplete |= !target.flush_done;
                    record.targets.push(TargetCompletion {
                        cpu: cpu as u32,
                        flush_done: target.flush_done,
                        batch_kind: target.batch_kind,
                    });
                }
            }
        }
        Ok(CaptureSnapshot {
            instance: capture.instance,
            records,
            overflow: state.overflow,
            identity_exhausted: state.identity_exhausted,
            protocol_error: state.protocol_error,
            incomplete,
        })
    }
}

fn reserve<T>(values: &mut Vec<T>, capacity: usize) -> Result<(), CaptureError> {
    values
        .try_reserve_exact(capacity)
        .map_err(|_| CaptureError::NoMemory)
}

/// Lock order: profile -> capture; flush queue -> capture only on overflow.
/// Capture operations never acquire a profile, flush queue, or root lock.
pub(crate) struct TlbProfile {
    capture: SpinLock<Option<Arc<Capture>>, LocalIrqDisabled>,
}

impl TlbProfile {
    pub(crate) const fn new() -> Self {
        Self {
            capture: SpinLock::new(None),
        }
    }

    pub(crate) fn arm(&self, identity: CpuSlot) -> Result<CaptureHandle, CaptureError> {
        let capture = Capture::new(InstanceIdentity {
            slot: identity.kernelet,
            generation: identity.generation,
        })?;
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

    pub(crate) fn begin(&self, request: RequestDescriptor, targets: &CpuSet) -> Option<Request> {
        let capture = self.capture.lock().clone()?;
        let index = {
            let mut state = capture.state.lock();
            if state.closed {
                return None;
            }
            if state.count == REQUEST_CAPACITY {
                state.overflow = true;
                return None;
            }
            state.identity_exhausted |= request.root_id.is_none();
            let index = state.count;
            let slot = &mut state.slots[index];
            slot.request = request;
            for cpu in targets.iter() {
                slot.targets[u32::from(cpu) as usize].is_target = true;
            }
            state.count += 1;
            state.inflight += 1;
            index
        };
        Some(Request {
            token: FlushToken { capture, index },
            waited: false,
        })
    }
}

struct Capture {
    instance: InstanceIdentity,
    num_cpus: usize,
    state: SpinLock<CaptureState, LocalIrqDisabled>,
}

impl Capture {
    fn new(instance: InstanceIdentity) -> Result<Arc<Self>, CaptureError> {
        let num_cpus = crate::cpu::num_cpus();
        let mut slots = Vec::new();
        reserve(&mut slots, REQUEST_CAPACITY)?;
        for _ in 0..REQUEST_CAPACITY {
            let mut targets = Vec::new();
            reserve(&mut targets, num_cpus)?;
            targets.resize(num_cpus, TargetState::default());
            slots.push(RecordSlot {
                request: RequestDescriptor::default(),
                targets,
                wait_returned: false,
            });
        }
        Ok(Arc::new(Self {
            instance,
            num_cpus,
            state: SpinLock::new(CaptureState {
                slots,
                count: 0,
                inflight: 0,
                closed: false,
                overflow: false,
                identity_exhausted: false,
                protocol_error: false,
                abandoned: false,
            }),
        }))
    }
}

struct CaptureState {
    slots: Vec<RecordSlot>,
    count: usize,
    inflight: usize,
    closed: bool,
    overflow: bool,
    identity_exhausted: bool,
    protocol_error: bool,
    abandoned: bool,
}

struct RecordSlot {
    request: RequestDescriptor,
    targets: Vec<TargetState>,
    wait_returned: bool,
}

#[derive(Clone, Copy, Default)]
struct TargetState {
    is_target: bool,
    flush_done: bool,
    batch_kind: Option<BatchFlushKind>,
}

/// Source-owned lifetime guard. Its token never retains tenant resources.
pub(crate) struct Request {
    token: FlushToken,
    waited: bool,
}

impl Request {
    pub(crate) fn token(&self) -> FlushToken {
        self.token.clone()
    }

    pub(crate) fn wait_returned(mut self) {
        let mut state = self.token.capture.state.lock();
        let slot = &mut state.slots[self.token.index];
        slot.wait_returned = true;
        let missing = slot
            .targets
            .iter()
            .any(|target| target.is_target && !target.flush_done);
        state.protocol_error |= missing;
        self.waited = true;
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        let mut state = self.token.capture.state.lock();
        state.abandoned |= !self.waited;
        state.inflight -= 1;
    }
}

#[derive(Clone)]
pub(crate) struct FlushToken {
    capture: Arc<Capture>,
    index: usize,
}

impl FlushToken {
    fn complete(&self, cpu: CpuId, kind: Option<BatchFlushKind>) {
        let mut state = self.capture.state.lock();
        let target = &mut state.slots[self.index].targets[u32::from(cpu) as usize];
        if !target.is_target || target.flush_done || kind.is_none() {
            state.protocol_error = true;
            return;
        }
        target.batch_kind = kind;
        target.flush_done = true;
    }
}

/// Fixed storage exchanged with the operation queue; callback completion never
/// allocates. Overflow invalidates evidence without dropping a flush operation.
pub(crate) struct FlushTokens {
    tokens: [Option<FlushToken>; REQUEST_CAPACITY],
    len: usize,
}

impl FlushTokens {
    pub(crate) const fn new() -> Self {
        Self {
            tokens: [const { None }; REQUEST_CAPACITY],
            len: 0,
        }
    }

    pub(crate) fn push(&mut self, token: FlushToken) {
        if self.len == REQUEST_CAPACITY {
            token.capture.state.lock().overflow = true;
            return;
        }
        self.tokens[self.len] = Some(token);
        self.len += 1;
    }

    pub(crate) fn complete(self, cpu: CpuId, kind: Option<BatchFlushKind>) {
        for token in self.tokens.into_iter().take(self.len).flatten() {
            token.complete(cpu, kind);
        }
    }
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::prelude::ktest;

    fn identity() -> CpuSlot {
        CpuSlot {
            kernelet: 7,
            vcpu: 0,
            generation: 3,
            _reserved: 0,
        }
    }

    fn descriptor() -> RequestDescriptor {
        RequestDescriptor {
            root_id: Some(1),
            root_generation: 1,
            ..RequestDescriptor::default()
        }
    }

    #[ktest]
    fn finish_closes_admission_and_waits_for_existing_request() {
        let profile = TlbProfile::new();
        let handle = profile.arm(identity()).unwrap();
        let mut targets = CpuSet::new_empty();
        targets.add(CpuId::bsp());
        let request = profile.begin(descriptor(), &targets).unwrap();
        assert!(matches!(handle.finish(), Err(CaptureError::Busy)));
        assert!(profile.begin(descriptor(), &targets).is_none());
        assert!(matches!(profile.arm(identity()), Err(CaptureError::Busy)));
        request
            .token()
            .complete(CpuId::bsp(), Some(BatchFlushKind::Ranges));
        request.wait_returned();
        let snapshot = handle.finish().unwrap();
        assert!(snapshot.is_valid());
        assert_eq!(snapshot.instance.slot, 7);
        assert_eq!(snapshot.records[0].targets[0].cpu, 0);
        assert!(snapshot.records[0].targets[0].flush_done);
        assert!(handle.finish().unwrap().is_valid());
        assert!(profile.arm(identity()).is_ok());
    }

    #[ktest]
    fn overflow_and_missing_flush_invalidate_without_reusing_records() {
        let profile = TlbProfile::new();
        let handle = profile.arm(identity()).unwrap();
        let targets = CpuSet::new_empty();
        for _ in 0..REQUEST_CAPACITY {
            profile
                .begin(descriptor(), &targets)
                .unwrap()
                .wait_returned();
        }
        assert!(profile.begin(descriptor(), &targets).is_none());
        let snapshot = handle.finish().unwrap();
        assert!(snapshot.overflow);
        assert!(!snapshot.is_valid());
        assert_eq!(snapshot.records.len(), REQUEST_CAPACITY);

        let handle = profile.arm(identity()).unwrap();
        let mut targets = CpuSet::new_empty();
        targets.add(CpuId::bsp());
        profile
            .begin(descriptor(), &targets)
            .unwrap()
            .wait_returned();
        let snapshot = handle.finish().unwrap();
        assert!(snapshot.protocol_error && snapshot.incomplete);
        assert!(!snapshot.is_valid());
    }

    #[ktest]
    fn last_handle_drop_closes_admission_without_resetting_an_old_capture() {
        let profile = TlbProfile::new();
        let handle = profile.arm(identity()).unwrap();
        let retained = handle.clone();
        drop(handle);
        assert!(matches!(profile.arm(identity()), Err(CaptureError::Busy)));
        drop(retained);
        let replacement = profile.arm(identity()).unwrap();
        assert!(replacement.finish().unwrap().records.is_empty());
    }

    #[ktest]
    fn merged_queue_overflow_invalidates_only_the_capture_that_lost_a_token() {
        let first = TlbProfile::new();
        let second = TlbProfile::new();
        let first_handle = first.arm(identity()).unwrap();
        let second_handle = second.arm(identity()).unwrap();
        let mut targets = CpuSet::new_empty();
        targets.add(CpuId::bsp());
        let mut tokens = FlushTokens::new();
        let mut requests = Vec::new();
        for _ in 0..REQUEST_CAPACITY {
            let request = first.begin(descriptor(), &targets).unwrap();
            tokens.push(request.token());
            requests.push(request);
        }
        let lost = second.begin(descriptor(), &targets).unwrap();
        tokens.push(lost.token());
        // This tests association bookkeeping, not a hardware flush or IPI.
        tokens.complete(CpuId::bsp(), Some(BatchFlushKind::FullNonGlobal));
        for request in requests {
            request.wait_returned();
        }
        lost.wait_returned();
        assert!(first_handle.finish().unwrap().is_valid());
        let snapshot = second_handle.finish().unwrap();
        assert!(snapshot.overflow && snapshot.protocol_error && snapshot.incomplete);
        assert!(!snapshot.is_valid());
    }

    #[ktest]
    fn abandoned_request_and_exhausted_root_identity_are_explicit() {
        let profile = TlbProfile::new();
        let handle = profile.arm(identity()).unwrap();
        let mut request = descriptor();
        request.root_id = None;
        drop(profile.begin(request, &CpuSet::new_empty()).unwrap());
        let snapshot = handle.finish().unwrap();
        assert!(snapshot.identity_exhausted && snapshot.incomplete);
        assert!(!snapshot.records[0].wait_returned);
        assert!(!snapshot.is_valid());
    }
}
