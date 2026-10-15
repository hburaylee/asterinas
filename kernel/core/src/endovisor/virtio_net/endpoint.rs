// SPDX-License-Identifier: MPL-2.0

//! Network configuration capability and bounded device-to-backend frame queues.

use core::{
    fmt::Display,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
#[cfg(kernelet_nat_failure_diag_host)]
use core::{net::SocketAddrV4, time::Duration};

use kernelet_abi::{NET_PROTOCOL_TCP, NetConfigArgs};
use ostd::kernelet::control::Kernelet;

#[cfg(kernelet_nat_failure_diag_host)]
use super::super::policy::{
    NatQuotaSnapshot, QUOTA_DIAGNOSTIC_LAYOUT, QuotaCategorySnapshot, QuotaClass, QuotaTag,
};
use super::{
    super::policy::PrestartEndpointReservation, ENDPOINT_SLOTS, Frame, nat::NatBackend,
    sockets::TCP_LISTENER_RESERVATION_BYTES,
};
use crate::{
    dispatch_ioctl,
    events::IoEvents,
    fs::{
        file::{AccessMode, FileCommon, FileLike, StatusFlags, file_table::FdFlags},
        pseudofs::AnonInodeFs,
    },
    ioc,
    prelude::*,
    process::{
        Uid,
        signal::{PollHandle, Pollable, Pollee},
    },
    util::ioctl::{InData, RawIoctl},
};

// These slots retain the first event of each kind, independently of repeats.
#[cfg(kernelet_nat_failure_diag_host)]
const NAT_DIAGNOSTIC_SLOTS: usize = 18;

#[cfg(kernelet_nat_failure_diag_host)]
#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub(super) enum NatEvent {
    UidReservation,
    HostReservation,
    FlowCapacity,
    SourcePorts,
    StreamCreate,
    Accept,
    AcceptLinger,
    AcceptType,
    AcceptCharge,
    Adopt,
    BackendAbsent,
    CancelObserved,
    BackendReturned,
    ListenersOwned,
    ListenersReleased,
    ReservationReleased,
    FlowFailure,
    NativeError,
}

#[cfg(kernelet_nat_failure_diag_host)]
const _: () = {
    assert!(NatEvent::NativeError as usize + 1 == NAT_DIAGNOSTIC_SLOTS);
    assert!(NAT_DIAGNOSTIC_SLOTS <= u32::BITS as usize);
};

#[cfg(kernelet_nat_failure_diag_host)]
#[derive(Clone, Copy, Debug)]
pub(super) struct NatContext {
    pub(super) stage: &'static str,
    pub(super) listener: Option<SocketAddrV4>,
    pub(super) guest_port: Option<u16>,
    pub(super) requested: Option<(SocketAddrV4, SocketAddrV4)>,
    pub(super) translated: Option<SocketAddrV4>,
    pub(super) native_local: Option<SocketAddrV4>,
    pub(super) native_local_errno: Option<Errno>,
    pub(super) native_peer: Option<SocketAddrV4>,
    pub(super) flow_handle: Option<smoltcp::iface::SocketHandle>,
    pub(super) guest_local: Option<SocketAddrV4>,
    pub(super) guest_remote: Option<SocketAddrV4>,
    pub(super) guest_state: Option<smoltcp::socket::tcp::State>,
    pub(super) error: Option<Error>,
    pub(super) native_diagnostic: Option<super::sockets::TcpErrorDiagnostic>,
}

#[cfg(kernelet_nat_failure_diag_host)]
impl NatContext {
    pub(super) const fn new(stage: &'static str) -> Self {
        Self {
            stage,
            listener: None,
            guest_port: None,
            requested: None,
            translated: None,
            native_local: None,
            native_local_errno: None,
            native_peer: None,
            flow_handle: None,
            guest_local: None,
            guest_remote: None,
            guest_state: None,
            error: None,
            native_diagnostic: None,
        }
    }
}

#[cfg(kernelet_nat_failure_diag_host)]
#[derive(Clone, Copy, Debug)]
struct NatRecord {
    sequence: u64,
    // Host monotonic publication time; no Linux-clock or cancellation ordering.
    observed_at: Duration,
    event: NatEvent,
    context: NatContext,
    errno: Option<Errno>,
    host_error: Option<ostd::Error>,
    requested_bytes: usize,
    quota: Option<NatQuotaSnapshot>,
    cancelled_observed: bool,
    revoked_observed: bool,
}

#[cfg(kernelet_nat_failure_diag_host)]
struct NatDiagnostics {
    sequence: u64,
    overflow: bool,
    records: [Option<NatRecord>; NAT_DIAGNOSTIC_SLOTS],
    emitted: u32,
    pending: u32,
    suppressed: [u64; NAT_DIAGNOSTIC_SLOTS],
    // Bound atomically to records[UidReservation], never one copy per event.
    quota_categories: Option<QuotaCategorySnapshot>,
    quota_category_missing: bool,
    quota_category_binding_error: bool,
}

#[cfg(kernelet_nat_failure_diag_host)]
impl NatDiagnostics {
    const fn new() -> Self {
        Self {
            sequence: 0,
            overflow: false,
            records: [None; NAT_DIAGNOSTIC_SLOTS],
            emitted: 0,
            pending: 0,
            suppressed: [0; NAT_DIAGNOSTIC_SLOTS],
            quota_categories: None,
            quota_category_missing: false,
            quota_category_binding_error: false,
        }
    }
}

type Configure = ioc!(KERNELET_NET_CONFIG, 0xc7, 0x12, InData<NetConfigArgs>);

// Preserve the reservation for UDP mappings and endpoints without mappings.
const MAPPING_RESERVATION_BYTES: usize = 640 * 1024;

enum BackendState {
    Unconfigured,
    Prepared(Box<NatBackend>, BackendReservation),
    Running,
}

/// Follows listener buffers from configuration through worker shutdown.
pub(super) struct BackendReservation {
    _user: PrestartEndpointReservation,
    bytes: usize,
    kernelet: Option<Arc<Kernelet>>,
}

impl Drop for BackendReservation {
    fn drop(&mut self) {
        if let Some(kernelet) = &self.kernelet {
            kernelet.uncharge_host_bytes(self.bytes);
        }
    }
}

/// Owns the device queues and transfers its prepared backend to the worker.
pub(in crate::endovisor) struct NetEndpoint {
    owner: Uid,
    #[cfg(kernelet_nat_failure_diag_host)]
    diagnostic_cid: u32,
    #[cfg(kernelet_nat_failure_diag_host)]
    diagnostics: SpinLock<NatDiagnostics>,
    input: Mutex<VecDeque<Frame>>,
    output: Mutex<VecDeque<Frame>>,
    backend: Mutex<BackendState>,
    pollee: Pollee,
    control_pollee: Pollee,
    generation: AtomicU64,
    pub(super) revoked: AtomicBool,
    account: Mutex<Option<(Arc<Kernelet>, usize)>>,
}

impl NetEndpoint {
    pub(in crate::endovisor) fn new(
        owner: Uid,
        #[cfg(kernelet_nat_failure_diag_host)] cid: u32,
    ) -> Arc<Self> {
        Arc::new(Self {
            owner,
            #[cfg(kernelet_nat_failure_diag_host)]
            diagnostic_cid: cid,
            #[cfg(kernelet_nat_failure_diag_host)]
            diagnostics: SpinLock::new(NatDiagnostics::new()),
            input: Mutex::new(VecDeque::with_capacity(ENDPOINT_SLOTS)),
            output: Mutex::new(VecDeque::with_capacity(ENDPOINT_SLOTS)),
            backend: Mutex::new(BackendState::Unconfigured),
            pollee: Pollee::new(),
            control_pollee: Pollee::new(),
            generation: AtomicU64::new(0),
            revoked: AtomicBool::new(false),
            account: Mutex::new(None),
        })
    }

    pub(in crate::endovisor) fn file(self: &Arc<Self>) -> Arc<NetEndpointFile> {
        Arc::new(NetEndpointFile {
            common: FileCommon::new(
                AnonInodeFs::new_path(|_| "anon_inode:[kernelet-net]".into()),
                AccessMode::O_RDWR,
                StatusFlags::empty(),
            ),
            endpoint: self.clone(),
        })
    }

    pub(in crate::endovisor) fn reservation_bytes(&self) -> usize {
        let capacity = self.input.lock().capacity() + self.output.lock().capacity();
        capacity * size_of::<Frame>() + size_of::<Self>()
    }

    fn configure(&self, config: NetConfigArgs) -> Result<()> {
        let mut backend = self.backend.lock();
        if self.revoked.load(Ordering::Acquire) {
            return_errno_with_message!(Errno::ENODEV, "the network endpoint is revoked");
        }
        if !matches!(*backend, BackendState::Unconfigured) {
            return_errno_with_message!(Errno::EBUSY, "the network endpoint is configured");
        }
        // Binding occurs in the ioctl caller's context and returns the actual
        // socket error before START can publish a running instance.
        if usize::from(config.num_ports) > kernelet_abi::MAX_NET_PORTS {
            return_errno_with_message!(Errno::EINVAL, "too many network port mappings");
        }
        // Reserve bounded native listener queues before binding ports. This
        // guard follows the sockets into the worker, beyond endpoint revoke.
        let bytes = config.ports[..usize::from(config.num_ports)]
            .iter()
            .map(|port| {
                if port.protocol == NET_PROTOCOL_TCP {
                    TCP_LISTENER_RESERVATION_BYTES
                } else {
                    MAPPING_RESERVATION_BYTES
                }
            })
            .sum::<usize>()
            .max(MAPPING_RESERVATION_BYTES);
        let reservation = BackendReservation {
            _user: self.reserve_backend_bytes(bytes)?,
            bytes,
            kernelet: None,
        };
        *backend = BackendState::Prepared(Box::new(NatBackend::new(config)?), reservation);
        Ok(())
    }

    pub(in crate::endovisor) fn bind_account(&self, kernelet: Arc<Kernelet>) -> ostd::Result<()> {
        let mut backend = self.backend.lock();
        if self.revoked.load(Ordering::Acquire) {
            return Err(ostd::Error::InvalidArgs);
        }
        let BackendState::Prepared(_, reservation) = &mut *backend else {
            return Err(ostd::Error::InvalidArgs);
        };
        let bytes = self.reservation_bytes();
        let mut account = self.account.lock();
        if account.is_some() {
            return Err(ostd::Error::InvalidArgs);
        }
        kernelet.charge_host_bytes(bytes)?;
        if let Err(error) = kernelet.charge_host_bytes(reservation.bytes) {
            kernelet.uncharge_host_bytes(bytes);
            return Err(error);
        }
        reservation.kernelet = Some(kernelet.clone());
        *account = Some((kernelet, bytes));
        Ok(())
    }

    pub(in crate::endovisor) fn is_configured(&self) -> bool {
        matches!(*self.backend.lock(), BackendState::Prepared(..))
            && !self.revoked.load(Ordering::Acquire)
    }

    pub(super) fn take_backend(&self) -> Option<(NatBackend, BackendReservation)> {
        let mut backend = self.backend.lock();
        if self.revoked.load(Ordering::Acquire) {
            return None;
        }
        match core::mem::replace(&mut *backend, BackendState::Running) {
            BackendState::Prepared(backend, reservation) => Some((*backend, reservation)),
            _ => None,
        }
    }

    pub(in crate::endovisor) fn revoke(&self) {
        let mut backend = self.backend.lock();
        if self.revoked.swap(true, Ordering::AcqRel) {
            return;
        }
        let prepared = core::mem::replace(&mut *backend, BackendState::Running);
        drop(backend);
        // Running sockets are owned by the worker, which wakes and drops them
        // before disowning its Task. Prepared sockets have no worker yet.
        drop(prepared);
        let input = core::mem::take(&mut *self.input.lock());
        let output = core::mem::take(&mut *self.output.lock());
        drop((input, output));
        if let Some((kernelet, bytes)) = self.account.lock().take() {
            kernelet.uncharge_host_bytes(bytes);
        }
        self.wake_backend();
        self.control_pollee.notify(IoEvents::HUP | IoEvents::ERR);
    }

    pub(super) fn reserve_backend_bytes(
        &self,
        bytes: usize,
    ) -> Result<PrestartEndpointReservation> {
        PrestartEndpointReservation::reserve(
            self.owner,
            bytes,
            #[cfg(kernelet_nat_failure_diag_host)]
            QuotaTag::new(QuotaClass::NatBackend, Some(self.diagnostic_cid)),
        )
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    pub(super) fn owner(&self) -> Uid {
        self.owner
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    pub(super) fn diagnostic_cid(&self) -> u32 {
        self.diagnostic_cid
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    pub(super) fn wants_quota_categories(&self) -> bool {
        self.diagnostics.lock().records[NatEvent::UidReservation as usize].is_none()
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    pub(super) fn record_quota_failure(
        &self,
        context: NatContext,
        errno: Option<Errno>,
        host_error: Option<ostd::Error>,
        requested_bytes: usize,
        quota: Option<NatQuotaSnapshot>,
        categories: Option<QuotaCategorySnapshot>,
        cancelled: bool,
    ) {
        self.record_diagnostic_inner(
            NatEvent::UidReservation,
            context,
            errno,
            host_error,
            requested_bytes,
            quota,
            categories,
            cancelled,
        );
    }

    /// Saves fixed metadata only; callers release socket/ledger guards first.
    #[cfg(kernelet_nat_failure_diag_host)]
    pub(super) fn record_diagnostic(
        &self,
        event: NatEvent,
        context: NatContext,
        errno: Option<Errno>,
        host_error: Option<ostd::Error>,
        requested_bytes: usize,
        quota: Option<NatQuotaSnapshot>,
        cancelled: bool,
    ) {
        self.record_diagnostic_inner(
            event,
            context,
            errno,
            host_error,
            requested_bytes,
            quota,
            None,
            cancelled,
        );
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    fn record_diagnostic_inner(
        &self,
        event: NatEvent,
        context: NatContext,
        errno: Option<Errno>,
        host_error: Option<ostd::Error>,
        requested_bytes: usize,
        quota: Option<NatQuotaSnapshot>,
        categories: Option<QuotaCategorySnapshot>,
        cancelled: bool,
    ) {
        let observed_at = aster_time::read_monotonic_time();
        let revoked = self.revoked.load(Ordering::Acquire);
        let mut diagnostic = self.diagnostics.lock();
        let slot = event as usize;
        diagnostic.overflow |= quota.is_some_and(|snapshot| snapshot.attempt_overflow);
        if diagnostic.records[slot].is_some() {
            match diagnostic.suppressed[slot].checked_add(1) {
                Some(next) => diagnostic.suppressed[slot] = next,
                None => diagnostic.overflow = true,
            }
            return;
        }
        match diagnostic.sequence.checked_add(1) {
            Some(next) => diagnostic.sequence = next,
            None => diagnostic.overflow = true,
        }
        if slot == NatEvent::UidReservation as usize {
            diagnostic.quota_category_missing = categories.is_none();
            diagnostic.quota_category_binding_error = match (quota, categories) {
                (Some(quota), Some(categories)) => {
                    !categories.matches(quota)
                        || quota.owner != self.owner
                        || quota.requested_bytes != requested_bytes
                        || categories.requested_tag.origin_cid != Some(self.diagnostic_cid)
                        || !matches!(
                            categories.requested_tag.class,
                            QuotaClass::NatFlow | QuotaClass::NatExtraDrain
                        )
                }
                _ => true,
            };
            diagnostic.quota_categories = categories;
        }
        diagnostic.pending |= 1 << slot;
        diagnostic.records[slot] = Some(NatRecord {
            sequence: diagnostic.sequence,
            observed_at,
            event,
            context,
            errno,
            host_error,
            requested_bytes,
            quota,
            cancelled_observed: cancelled,
            revoked_observed: revoked,
        });
    }

    /// Only the NAT worker calls this, with no socket or outer device guard.
    #[cfg(kernelet_nat_failure_diag_host)]
    pub(super) fn emit_diagnostics(&self) {
        let pending = self.diagnostics.lock().pending;
        for slot in 0..NAT_DIAGNOSTIC_SLOTS {
            if pending & (1 << slot) == 0 {
                continue;
            }
            let record = {
                let mut diagnostic = self.diagnostics.lock();
                if diagnostic.emitted & (1 << slot) != 0 {
                    None
                } else if let Some(record) = diagnostic.records[slot] {
                    diagnostic.emitted |= 1 << slot;
                    diagnostic.pending &= !(1 << slot);
                    Some((
                        record,
                        if slot == NatEvent::UidReservation as usize {
                            diagnostic.quota_categories
                        } else {
                            None
                        },
                        diagnostic.quota_category_missing,
                        diagnostic.quota_category_binding_error,
                    ))
                } else {
                    None
                }
            };
            if let Some((record, categories, category_missing, category_binding_error)) = record {
                if slot == NatEvent::UidReservation as usize {
                    let category_valid = !category_missing
                        && !category_binding_error
                        && categories.is_some_and(|snapshot| snapshot.is_consistent());
                    error!(
                        "kernelet NAT diagnostic version=1 cid={} uid={:?} record={:?} quota_categories={:?} category_missing={} category_binding_error={} category_valid={}",
                        self.diagnostic_cid,
                        self.owner,
                        record,
                        categories,
                        category_missing,
                        category_binding_error,
                        category_valid,
                    );
                } else {
                    error!(
                        "kernelet NAT diagnostic version=1 cid={} uid={:?} record={:?}",
                        self.diagnostic_cid, self.owner, record,
                    );
                }
            }
        }
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    pub(super) fn emit_diagnostic_summary(&self) {
        self.emit_diagnostics();
        let (seen, emitted, suppressed, overflow) = {
            let diagnostic = self.diagnostics.lock();
            let seen = diagnostic
                .records
                .iter()
                .enumerate()
                .fold(0u32, |mask, (slot, record)| {
                    mask | if record.is_some() { 1 << slot } else { 0 }
                });
            (
                seen,
                diagnostic.emitted,
                diagnostic.suppressed,
                diagnostic.overflow,
            )
        };
        error!(
            "kernelet NAT diagnostic_summary version=1 cid={} uid={:?} capacity={} seen={} emitted={} missing={} suppressed={:?} overflow={} delivery=unacknowledged endpoint_struct_bytes={} diagnostic_bytes={} category_snapshot_bytes={} quota_layout_ledger_user_instance_guard={:?}",
            self.diagnostic_cid,
            self.owner,
            NAT_DIAGNOSTIC_SLOTS,
            seen,
            emitted,
            seen & !emitted,
            suppressed,
            overflow,
            size_of::<Self>(),
            size_of::<NatDiagnostics>(),
            size_of::<QuotaCategorySnapshot>(),
            QUOTA_DIAGNOSTIC_LAYOUT,
        );
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub(super) fn wake_backend(&self) {
        self.generation.fetch_add(1, Ordering::Release);
        self.pollee.notify(IoEvents::IN);
    }

    pub(super) fn poll_change(&self, old: u64, handle: &mut PollHandle) -> IoEvents {
        // Readiness depends on the worker's captured generation. Do not reuse
        // a readiness value cached for a previous generation.
        self.pollee.invalidate();
        self.pollee.poll_with(IoEvents::IN, Some(handle), || {
            if self.generation() != old || self.revoked.load(Ordering::Acquire) {
                IoEvents::IN
            } else {
                IoEvents::empty()
            }
        })
    }

    pub(super) fn input_available(&self) -> bool {
        !self.input.lock().is_empty()
    }

    pub(super) fn input_has_space(&self) -> bool {
        self.input.lock().len() < ENDPOINT_SLOTS
    }

    pub(super) fn output_has_space(&self) -> bool {
        self.output.lock().len() < ENDPOINT_SLOTS
    }

    pub(super) fn pop_input(&self) -> Option<Frame> {
        self.input.lock().pop_front()
    }

    pub(super) fn pop_output(&self) -> Option<Frame> {
        self.output.lock().pop_front()
    }

    pub(super) fn push_input(&self, frame: Frame) -> bool {
        Self::push(&self.input, &self.revoked, frame)
    }

    pub(super) fn push_output(&self, frame: Frame) -> bool {
        Self::push(&self.output, &self.revoked, frame)
    }

    fn push(queue: &Mutex<VecDeque<Frame>>, revoked: &AtomicBool, frame: Frame) -> bool {
        let mut queue = queue.lock();
        if revoked.load(Ordering::Acquire) || queue.len() == ENDPOINT_SLOTS {
            return false;
        }
        queue.push_back(frame);
        true
    }
}

impl Drop for NetEndpoint {
    fn drop(&mut self) {
        if let Some((kernelet, bytes)) = self.account.lock().take() {
            kernelet.uncharge_host_bytes(bytes);
        }
    }
}

/// Configuration descriptor; packet payloads stay in the Host kernel.
pub(in crate::endovisor) struct NetEndpointFile {
    common: FileCommon,
    endpoint: Arc<NetEndpoint>,
}

impl NetEndpointFile {
    pub(in crate::endovisor) fn endpoint(&self) -> &Arc<NetEndpoint> {
        &self.endpoint
    }
}

impl Pollable for NetEndpointFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.endpoint.control_pollee.poll_with(mask, poller, || {
            if self.endpoint.revoked.load(Ordering::Acquire) {
                IoEvents::HUP | IoEvents::ERR
            } else {
                IoEvents::empty()
            }
        })
    }
}

impl FileLike for NetEndpointFile {
    fn ioctl(&self, raw_ioctl: RawIoctl) -> Result<i32> {
        dispatch_ioctl!(match raw_ioctl {
            cmd @ Configure => {
                self.endpoint.configure(cmd.read()?)?;
            }
            _ => return_errno_with_message!(Errno::ENOTTY, "unknown network endpoint ioctl"),
        });
        Ok(0)
    }

    fn common(&self) -> &FileCommon {
        &self.common
    }

    fn dump_proc_fdinfo(self: Arc<Self>, _fd_flags: FdFlags) -> Box<dyn Display> {
        Box::new("kernelet-net:\tconfiguration\n".to_string())
    }
}

#[cfg(all(ktest, kernelet_nat_failure_diag_host))]
mod diagnostic_tests {
    use ostd::prelude::*;

    use super::*;

    #[ktest]
    fn repeated_diagnostic_preserves_first_event_and_other_slots() {
        aster_time::init_for_ktest();
        let endpoint = NetEndpoint::new(Uid::new(2001), 123);
        endpoint.record_diagnostic(
            NatEvent::FlowCapacity,
            NatContext::new("first"),
            None,
            None,
            0,
            None,
            false,
        );
        endpoint.record_diagnostic(
            NatEvent::FlowCapacity,
            NatContext::new("repeated"),
            None,
            None,
            0,
            None,
            true,
        );
        endpoint.record_diagnostic(
            NatEvent::BackendReturned,
            NatContext::new("returned"),
            Some(Errno::EIO),
            None,
            0,
            None,
            true,
        );
        let (first, returned, suppressed, overflow) = {
            let diagnostic = endpoint.diagnostics.lock();
            (
                diagnostic.records[NatEvent::FlowCapacity as usize],
                diagnostic.records[NatEvent::BackendReturned as usize],
                diagnostic.suppressed[NatEvent::FlowCapacity as usize],
                diagnostic.overflow,
            )
        };
        assert_eq!(first.unwrap().context.stage, "first");
        assert!(!first.unwrap().cancelled_observed);
        assert_eq!(returned.unwrap().errno, Some(Errno::EIO));
        assert_eq!(suppressed, 1);
        assert!(!overflow);
    }

    #[ktest]
    fn diagnostic_suppression_saturates_without_overwriting_the_first_event() {
        aster_time::init_for_ktest();
        let endpoint = NetEndpoint::new(Uid::new(2002), 124);
        endpoint.record_diagnostic(
            NatEvent::FlowCapacity,
            NatContext::new("first"),
            None,
            None,
            0,
            None,
            false,
        );
        {
            // Seed only the bookkeeping counter's reachable boundary; this
            // does not construct or stand in for a resource-quota failure.
            let mut diagnostic = endpoint.diagnostics.lock();
            diagnostic.suppressed[NatEvent::FlowCapacity as usize] = u64::MAX;
        }
        endpoint.record_diagnostic(
            NatEvent::FlowCapacity,
            NatContext::new("repeated"),
            None,
            None,
            0,
            None,
            true,
        );
        let (first, suppressed, overflow) = {
            let diagnostic = endpoint.diagnostics.lock();
            (
                diagnostic.records[NatEvent::FlowCapacity as usize],
                diagnostic.suppressed[NatEvent::FlowCapacity as usize],
                diagnostic.overflow,
            )
        };
        assert_eq!(first.unwrap().context.stage, "first");
        assert_eq!(suppressed, u64::MAX);
        assert!(overflow);
    }

    #[ktest]
    fn highest_diagnostic_slot_preserves_all_eighteen_bitmap_bits() {
        aster_time::init_for_ktest();
        let endpoint = NetEndpoint::new(Uid::new(2003), 125);
        endpoint.record_diagnostic(
            NatEvent::NativeError,
            NatContext::new("highest"),
            Some(Errno::ECONNRESET),
            None,
            0,
            None,
            false,
        );
        let (pending, emitted, last) = {
            let diagnostic = endpoint.diagnostics.lock();
            (
                diagnostic.pending,
                diagnostic.emitted,
                diagnostic.records[NAT_DIAGNOSTIC_SLOTS - 1],
            )
        };
        assert_eq!(NAT_DIAGNOSTIC_SLOTS, 18);
        assert_eq!(pending, 1u32 << 17);
        assert_eq!(emitted, 0);
        assert_eq!(last.unwrap().context.stage, "highest");
    }

    #[ktest]
    fn first_quota_side_slot_matches_the_winning_real_failure_attempt() {
        aster_time::init_for_ktest();
        let owner = Uid::new(u32::MAX - 47);
        let cid = 129;
        let endpoint = NetEndpoint::new(owner, cid);
        let tag = QuotaTag::new(QuotaClass::NatFlow, Some(cid));
        let held = PrestartEndpointReservation::reserve(owner, 16 * 1024 * 1024, tag).unwrap();
        let (mut first, mut first_categories, mut second, mut second_categories) =
            (None, None, None, None);
        assert!(endpoint.wants_quota_categories());
        assert!(
            matches!(PrestartEndpointReservation::reserve_diagnostic(owner, 1, tag,
            &mut first, Some(&mut first_categories)), Err(e) if e.error() == Errno::ENOSPC)
        );
        assert!(
            matches!(PrestartEndpointReservation::reserve_diagnostic(owner, 2, tag,
            &mut second, Some(&mut second_categories)), Err(e) if e.error() == Errno::ENOSPC)
        );
        assert_ne!(first.unwrap().attempt, second.unwrap().attempt);
        endpoint.record_quota_failure(
            NatContext::new("second_captured_first_published"),
            Some(Errno::ENOSPC),
            None,
            2,
            second,
            second_categories,
            false,
        );
        endpoint.record_quota_failure(
            NatContext::new("first_captured_second_published"),
            Some(Errno::ENOSPC),
            None,
            1,
            first,
            first_categories,
            false,
        );
        assert!(!endpoint.wants_quota_categories());
        {
            let diagnostic = endpoint.diagnostics.lock();
            let record = diagnostic.records[NatEvent::UidReservation as usize].unwrap();
            let category = diagnostic.quota_categories.unwrap();
            assert_eq!(record.quota.unwrap().attempt, second.unwrap().attempt);
            assert!(category.matches(record.quota.unwrap()));
            assert!(!diagnostic.quota_category_missing);
            assert!(!diagnostic.quota_category_binding_error);
            assert_eq!(diagnostic.suppressed[NatEvent::UidReservation as usize], 1);
        }
        drop(held);
    }

    #[ktest]
    fn missing_or_mixed_quota_side_snapshot_is_explicit_and_preserves_raw_failure() {
        aster_time::init_for_ktest();
        let owner = Uid::new(u32::MAX - 48);
        let cid = 130;
        let tag = QuotaTag::new(QuotaClass::NatFlow, Some(cid));
        let held = PrestartEndpointReservation::reserve(owner, 16 * 1024 * 1024, tag).unwrap();
        let (mut first, mut first_categories, mut second, mut second_categories) =
            (None, None, None, None);
        assert!(
            PrestartEndpointReservation::reserve_diagnostic(
                owner,
                1,
                tag,
                &mut first,
                Some(&mut first_categories)
            )
            .is_err()
        );
        assert!(
            PrestartEndpointReservation::reserve_diagnostic(
                owner,
                2,
                tag,
                &mut second,
                Some(&mut second_categories)
            )
            .is_err()
        );
        let mixed = NetEndpoint::new(owner, cid);
        mixed.record_quota_failure(
            NatContext::new("mixed"),
            Some(Errno::ENOSPC),
            None,
            1,
            first,
            second_categories,
            false,
        );
        {
            let diagnostic = mixed.diagnostics.lock();
            assert!(diagnostic.quota_category_binding_error);
            assert!(!diagnostic.quota_category_missing);
            assert_eq!(
                diagnostic.records[NatEvent::UidReservation as usize]
                    .unwrap()
                    .quota
                    .unwrap()
                    .attempt,
                first.unwrap().attempt
            );
            assert_eq!(
                diagnostic.quota_categories.unwrap().quota.attempt,
                second.unwrap().attempt
            );
        }
        let missing = NetEndpoint::new(owner, cid);
        missing.record_quota_failure(
            NatContext::new("missing"),
            Some(Errno::ENOSPC),
            None,
            1,
            first,
            None,
            false,
        );
        assert!(missing.diagnostics.lock().quota_category_missing);
        assert!(missing.diagnostics.lock().quota_category_binding_error);
        drop(held);
    }
}
