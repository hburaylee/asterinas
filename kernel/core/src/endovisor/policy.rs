// SPDX-License-Identifier: MPL-2.0

//! Per-user admission for kernelet memory ceilings, carriers and endpoints.
//!
//! Instance reservations are made at START, before OSTD creates an instance.
//! Once creation succeeds, the reservation remains charged until OSTD has
//! destroyed that instance. The initial memory reservation includes the rounded
//! bounded Host storage as well as the Guest grant ceiling.
//! Endpoint structures created before START have
//! separate guards charged to the same user's endpoint limit. Grant
//! authorizations are pending charges in the same ledger; settlement transfers
//! the committed part to the live ceiling and refunds the remainder.
//!
//! All ledger updates use one IRQ-disabled lock. No allocation, OSTD call or
//! wait occurs while it is held. The preallocated user and instance tables make
//! the memory-exhaustion hook safe to call from a carrier's Host service path.

use ostd::{
    kernelet::{abi::MAX_GRAINS_PER_REQUEST, control::HostByteCharge},
    sync::LocalIrqDisabled,
};

use crate::{prelude::*, process::Uid};

// These are operator defaults for the first version of the endovisor. They
// limit reservations, so the Host can still decline physical allocations.
const MAX_USERS: usize = 64;
const MAX_INSTANCES: usize = 64;
const MAX_LIVE_PER_USER: u16 = 8;
const MAX_GRAINS_PER_USER: u32 = 512; // 1 GiB at 2 MiB per grain.
const MAX_VCPUS_PER_USER: u16 = 32;
const MAX_ENDPOINT_BYTES_PER_USER: usize = 16 * 1024 * 1024;

static LEDGER: SpinLock<Ledger, LocalIrqDisabled> = SpinLock::new(Ledger::new());

#[cfg(ktest)]
pub(super) fn endpoint_bytes_for_test(owner: Uid) -> usize {
    LEDGER
        .lock()
        .users
        .iter()
        .find(|entry| entry.owner == Some(owner))
        .map_or(0, |entry| entry.endpoint_bytes)
}

/// A charge retained by the sandbox and its retry reaper until destruction.
pub(super) struct Admission {
    slot: usize,
    generation: u64,
}

impl Admission {
    /// Reserves the initial ceiling and other fixed resources before creation.
    pub(super) fn reserve(
        owner: Uid,
        max_grains: u32,
        vcpus: u16,
        endpoint_bytes: usize,
    ) -> Result<Arc<Self>> {
        if max_grains == 0 || vcpus == 0 {
            return_errno_with_message!(Errno::EINVAL, "invalid kernelet reservation");
        }

        let (slot, generation) = LEDGER
            .lock()
            .reserve(owner, max_grains, vcpus, endpoint_bytes)?;
        // If Arc allocation unwinds, dropping this value refunds the still
        // uncreated instance. No allocator is entered under the policy lock.
        Ok(Arc::new(Self { slot, generation }))
    }

    /// Reserves the Guest ceiling and all bounded Host storage before creation.
    /// Future grant metadata is reserved against the user's lifetime grain cap;
    /// growth then charges only newly authorized Guest grains in the same ledger.
    pub(super) fn reserve_instance(
        owner: Uid,
        kind: &ostd::kernelet::control::KerneletKind,
        config: &ostd::kernelet::control::KerneletConfig<'_>,
    ) -> Result<Arc<Self>> {
        let bytes = kind.instance_reservation_bytes(config, MAX_GRAINS_PER_USER)?;
        Self::reserve_storage(
            owner,
            config.max_grains,
            config.cpus.count() as u16,
            0,
            bytes,
        )
    }

    #[cfg(ktest)]
    fn reserve_execution(
        owner: Uid,
        max_grains: u32,
        vcpus: u16,
        endpoint_bytes: usize,
        max_tasks: u32,
    ) -> Result<Arc<Self>> {
        let bytes = ostd::kernelet::control::execution_reservation_bytes(max_tasks, vcpus)?;
        Self::reserve_storage(owner, max_grains, vcpus, endpoint_bytes, bytes)
    }

    fn reserve_storage(
        owner: Uid,
        max_grains: u32,
        vcpus: u16,
        endpoint_bytes: usize,
        host_bytes: usize,
    ) -> Result<Arc<Self>> {
        if max_grains == 0 {
            return_errno_with_message!(Errno::EINVAL, "invalid kernelet memory reservation");
        }
        let grain_size = ostd::kernelet::abi::GRAIN_SIZE;
        let host_grains = host_bytes
            .checked_add(grain_size - 1)
            .and_then(|bytes| u32::try_from(bytes / grain_size).ok())
            .ok_or_else(|| {
                Error::with_message(Errno::EINVAL, "kernelet Host reservation overflow")
            })?;
        let total = max_grains.checked_add(host_grains).ok_or_else(|| {
            Error::with_message(Errno::EINVAL, "kernelet memory reservation overflow")
        })?;
        Self::reserve(owner, total, vcpus, endpoint_bytes)
    }

    /// Retains the reservation until successful OSTD destruction.
    pub(super) fn mark_created(&self) {
        let mut ledger = LEDGER.lock();
        let Some(instance) = ledger.instance_mut(self.slot, self.generation) else {
            debug_assert!(false, "kernelet admission disappeared before creation");
            return;
        };
        debug_assert_eq!(instance.phase, Phase::Reserved);
        instance.phase = Phase::Live;
    }

    /// Releases every committed and pending charge after OSTD destroy succeeds.
    ///
    /// Calling this again after a completed release has no effect. A surviving
    /// endpoint or hook reference cannot cause the same charge to be refunded
    /// twice.
    pub(super) fn release_after_destroy(&self) {
        LEDGER.lock().release(self.slot, self.generation);
    }

    /// Reserves at most one crossing of additional ceiling for a Host hook.
    ///
    /// OSTD must call `settle_grains` once for every positive answer, outside
    /// its grant-growth mutex. The committed ceiling remains charged even if
    /// allocation of its frames subsequently fails.
    pub(super) fn reserve_grains(&self, requested: u32) -> u32 {
        LEDGER
            .lock()
            .reserve_grains_up_to(self.slot, self.generation, requested)
    }

    /// Settles one Host-hook authorization after OSTD has raised its ceiling.
    pub(super) fn settle_grains(&self, reserved: u32, committed: u32) {
        LEDGER
            .lock()
            .settle_grains(self.slot, self.generation, reserved, committed);
    }

    /// Reserves an exact control-plane request before entering OSTD.
    ///
    /// Dropping the returned guard refunds its pending charge after an error.
    /// A successful request calls `GrantReservation::settle` with the number of
    /// grains OSTD actually published.
    pub(super) fn reserve_control_grant(
        self: &Arc<Self>,
        requested: u32,
    ) -> Result<GrantReservation> {
        if requested == 0 || requested > MAX_GRAINS_PER_REQUEST {
            return_errno_with_message!(Errno::EINVAL, "invalid kernelet grant size");
        }
        LEDGER
            .lock()
            .reserve_grains_exact(self.slot, self.generation, requested)?;
        Ok(GrantReservation {
            admission: self.clone(),
            reserved: requested,
        })
    }

    /// Reserves additional endpoint capacity in the same per-user ledger.
    ///
    /// The fixed endpoint capacity passed at START remains charged until
    /// destruction. This guard is for capacity acquired later, such as a
    /// bounded connection queue, and refunds when that queue is released.
    pub(super) fn reserve_endpoint_bytes(
        self: &Arc<Self>,
        bytes: usize,
    ) -> Result<EndpointReservation> {
        LEDGER
            .lock()
            .reserve_endpoint_bytes(self.slot, self.generation, bytes)?;
        Ok(EndpointReservation {
            admission: self.clone(),
            bytes,
        })
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        let mut ledger = LEDGER.lock();
        if ledger.phase(self.slot, self.generation) == Some(Phase::Reserved) {
            ledger.release(self.slot, self.generation);
        }
        // A created instance may still have an admitted Host operation after
        // its last ordinary Arc disappears. Keep its reservation rather than
        // undercounting until the destroy owner calls release_after_destroy.
    }
}

/// A pending exact control-plane grant, refunded if OSTD declines it.
pub(super) struct GrantReservation {
    admission: Arc<Admission>,
    reserved: u32,
}

impl GrantReservation {
    /// Transfers published grains to the live ceiling and refunds the rest.
    pub(super) fn settle(mut self, committed: u32) {
        self.admission.settle_grains(self.reserved, committed);
        self.reserved = 0;
    }
}

impl Drop for GrantReservation {
    fn drop(&mut self) {
        if self.reserved != 0 {
            self.admission.settle_grains(self.reserved, 0);
        }
    }
}

/// A dynamic endpoint charge released with its owned queue or connection.
pub(super) struct EndpointReservation {
    admission: Arc<Admission>,
    bytes: usize,
}

impl Drop for EndpointReservation {
    fn drop(&mut self) {
        LEDGER.lock().release_endpoint_bytes(
            self.admission.slot,
            self.admission.generation,
            self.bytes,
        );
    }
}

/// Failure values copied under LEDGER; publishing them never holds its guard.
#[cfg(kernelet_nat_failure_diag_host)]
#[derive(Clone, Copy, Debug)]
pub(super) struct NatQuotaSnapshot {
    pub(super) owner: Uid,
    pub(super) attempt: u64,
    pub(super) attempt_overflow: bool,
    pub(super) requested_bytes: usize,
    pub(super) endpoint_bytes: Option<usize>,
    pub(super) prestart_bytes: Option<usize>,
    pub(super) limit: usize,
    pub(super) reason: NatQuotaReason,
}

#[cfg(kernelet_nat_failure_diag_host)]
#[derive(Clone, Copy, Debug)]
pub(super) enum NatQuotaReason {
    UserTableFull,
    EndpointOverflow,
    PrestartOverflow,
    EndpointLimit,
}

// These diagnostics share LEDGER's lock and never affect admission results.
#[cfg(kernelet_nat_failure_diag_host)]
const QUOTA_CLASSES: usize = 11;

#[cfg(kernelet_nat_failure_diag_host)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(super) enum QuotaClass {
    ConsoleFixed,
    LogFixed,
    NetFixed,
    NatBackend,
    NatFlow,
    NatNativeTcp,
    NatExtraDrain,
    HostVsockFixed,
    InstanceEndpoint,
    InitialEndpoint,
    // Production callers never use this category.
    TestOnly,
}

#[cfg(kernelet_nat_failure_diag_host)]
const _: () = assert!(QuotaClass::TestOnly as usize + 1 == QUOTA_CLASSES);

#[cfg(kernelet_nat_failure_diag_host)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct QuotaTag {
    pub(super) class: QuotaClass,
    pub(super) origin_cid: Option<u32>,
}

#[cfg(kernelet_nat_failure_diag_host)]
impl QuotaTag {
    pub(super) const fn new(class: QuotaClass, origin_cid: Option<u32>) -> Self {
        Self { class, origin_cid }
    }

    #[cfg(ktest)]
    const TEST: Self = Self::new(QuotaClass::TestOnly, None);
}

#[cfg(kernelet_nat_failure_diag_host)]
#[derive(Clone, Copy)]
enum CategoryOwner {
    Instance,
    Independent,
}

#[cfg(kernelet_nat_failure_diag_host)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CategoryBalance {
    current: usize,
    independent_current: usize,
    high_water: usize,
    reserve_count: u64,
    refund_count: u64,
    split_in_count: u64,
    split_out_count: u64,
}

#[cfg(kernelet_nat_failure_diag_host)]
impl CategoryBalance {
    const EMPTY: Self = Self {
        current: 0,
        independent_current: 0,
        high_water: 0,
        reserve_count: 0,
        refund_count: 0,
        split_in_count: 0,
        split_out_count: 0,
    };
}

#[cfg(kernelet_nat_failure_diag_host)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeRefund {
    sequence: Option<u64>,
    origin_cid: Option<u32>,
    bytes: usize,
}

#[cfg(kernelet_nat_failure_diag_host)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UserCategories {
    row_epoch: Option<u64>,
    balances: [CategoryBalance; QUOTA_CLASSES],
    last_native_refund: Option<NativeRefund>,
    counter_overflow: bool,
    accounting_error: bool,
}

#[cfg(kernelet_nat_failure_diag_host)]
impl UserCategories {
    const EMPTY: Self = Self {
        row_epoch: None,
        balances: [CategoryBalance::EMPTY; QUOTA_CLASSES],
        last_native_refund: None,
        counter_overflow: false,
        accounting_error: false,
    };

    fn increment(value: &mut u64, overflow: &mut bool) {
        match value.checked_add(1) {
            Some(next) => *value = next,
            None => *overflow = true,
        }
    }

    fn reserve(&mut self, class: QuotaClass, bytes: usize, owner: CategoryOwner) {
        if bytes == 0 {
            return;
        }
        let mut balance = self.balances[class as usize];
        let Some(current) = balance.current.checked_add(bytes) else {
            self.accounting_error = true;
            return;
        };
        if matches!(owner, CategoryOwner::Independent) {
            let Some(total) = balance.independent_current.checked_add(bytes) else {
                self.accounting_error = true;
                return;
            };
            balance.independent_current = total;
        }
        balance.current = current;
        balance.high_water = balance.high_water.max(current);
        Self::increment(&mut balance.reserve_count, &mut self.counter_overflow);
        self.balances[class as usize] = balance;
    }

    fn refund(&mut self, class: QuotaClass, bytes: usize, owner: CategoryOwner) {
        if bytes == 0 {
            return;
        }
        let mut balance = self.balances[class as usize];
        let Some(current) = balance.current.checked_sub(bytes) else {
            self.accounting_error = true;
            return;
        };
        if matches!(owner, CategoryOwner::Independent) {
            let Some(total) = balance.independent_current.checked_sub(bytes) else {
                self.accounting_error = true;
                return;
            };
            balance.independent_current = total;
        }
        balance.current = current;
        Self::increment(&mut balance.refund_count, &mut self.counter_overflow);
        self.balances[class as usize] = balance;
    }

    fn reclassify(&mut self, source: QuotaClass, target: QuotaClass, bytes: usize) {
        if source == target || bytes == 0 {
            return;
        }
        let mut from = self.balances[source as usize];
        let mut to = self.balances[target as usize];
        let (Some(from_current), Some(from_independent), Some(to_current), Some(to_independent)) = (
            from.current.checked_sub(bytes),
            from.independent_current.checked_sub(bytes),
            to.current.checked_add(bytes),
            to.independent_current.checked_add(bytes),
        ) else {
            self.accounting_error = true;
            return;
        };
        from.current = from_current;
        from.independent_current = from_independent;
        to.current = to_current;
        to.independent_current = to_independent;
        to.high_water = to.high_water.max(to_current);
        Self::increment(&mut from.split_out_count, &mut self.counter_overflow);
        Self::increment(&mut to.split_in_count, &mut self.counter_overflow);
        self.balances[source as usize] = from;
        self.balances[target as usize] = to;
    }

    fn totals_match(&self, endpoint: usize, independent: usize) -> bool {
        let total = self
            .balances
            .iter()
            .try_fold(0usize, |sum, b| sum.checked_add(b.current));
        let prestart = self
            .balances
            .iter()
            .try_fold(0usize, |sum, b| sum.checked_add(b.independent_current));
        total == Some(endpoint)
            && prestart == Some(independent)
            && self
                .balances
                .iter()
                .all(|b| b.independent_current <= b.current)
    }
}

/// One owned failure snapshot, copied before the rejected addition in LEDGER.
/// It is kept in a single endpoint side slot, never in all 18 NatRecords.
#[cfg(kernelet_nat_failure_diag_host)]
#[derive(Clone, Copy, Debug)]
pub(super) struct QuotaCategorySnapshot {
    pub(super) quota: NatQuotaSnapshot,
    pub(super) requested_tag: QuotaTag,
    captured_before_failed_add: bool,
    row_owner: Option<Uid>,
    categories: Option<UserCategories>,
    totals_match: Option<bool>,
    sequence_overflow: bool,
}

#[cfg(kernelet_nat_failure_diag_host)]
impl QuotaCategorySnapshot {
    pub(super) fn is_consistent(&self) -> bool {
        let Some(categories) = self.categories else {
            return false;
        };
        self.captured_before_failed_add
            && self.row_owner == Some(self.quota.owner)
            && categories.row_epoch.is_some()
            && !self.sequence_overflow
            && !self.quota.attempt_overflow
            && self.quota.attempt != 0
            && !categories.counter_overflow
            && !categories.accounting_error
            && categories.balances[QuotaClass::TestOnly as usize].current == 0
            && self.totals_match == Some(true)
            && self
                .quota
                .endpoint_bytes
                .zip(self.quota.prestart_bytes)
                .is_some_and(|(total, independent)| categories.totals_match(total, independent))
    }

    pub(super) fn matches(&self, quota: NatQuotaSnapshot) -> bool {
        self.quota.owner == quota.owner
            && self.quota.attempt == quota.attempt
            && self.quota.attempt_overflow == quota.attempt_overflow
            && self.quota.requested_bytes == quota.requested_bytes
            && self.quota.endpoint_bytes == quota.endpoint_bytes
            && self.quota.prestart_bytes == quota.prestart_bytes
            && self.quota.limit == quota.limit
            && core::mem::discriminant(&self.quota.reason) == core::mem::discriminant(&quota.reason)
    }
}

/// A pre-START endpoint charge retained by the endpoint that owns its memory.
///
/// A listener can outlive the instance's admission. Its charge therefore
/// belongs to the user rather than to an instance slot and is refunded when
/// the listener is dropped.
pub(super) struct PrestartEndpointReservation {
    user_slot: usize,
    owner: Uid,
    bytes: usize,
    #[cfg(kernelet_nat_failure_diag_host)]
    tag: QuotaTag,
}

impl PrestartEndpointReservation {
    pub(super) fn reserve(
        owner: Uid,
        bytes: usize,
        #[cfg(kernelet_nat_failure_diag_host)] tag: QuotaTag,
    ) -> Result<Self> {
        if bytes == 0 {
            return_errno_with_message!(Errno::EINVAL, "empty endpoint reservation");
        }
        let user_slot = LEDGER.lock().reserve_prestart_endpoint_bytes(
            owner,
            bytes,
            #[cfg(kernelet_nat_failure_diag_host)]
            tag,
            #[cfg(kernelet_nat_failure_diag_host)]
            None,
            #[cfg(kernelet_nat_failure_diag_host)]
            None,
        )?;
        Ok(Self {
            user_slot,
            owner,
            bytes,
            #[cfg(kernelet_nat_failure_diag_host)]
            tag,
        })
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    pub(super) fn reserve_diagnostic(
        owner: Uid,
        bytes: usize,
        tag: QuotaTag,
        failure: &mut Option<NatQuotaSnapshot>,
        mut categories: Option<&mut Option<QuotaCategorySnapshot>>,
    ) -> Result<Self> {
        *failure = None;
        if let Some(categories) = categories.as_deref_mut() {
            *categories = None;
        }
        if bytes == 0 {
            return_errno_with_message!(Errno::EINVAL, "empty endpoint reservation");
        }
        let user_slot = {
            let mut ledger = LEDGER.lock();
            ledger.reserve_prestart_endpoint_bytes(owner, bytes, tag, Some(failure), categories)?
        };
        Ok(Self {
            user_slot,
            owner,
            bytes,
            #[cfg(kernelet_nat_failure_diag_host)]
            tag,
        })
    }

    pub(super) fn split_off(
        &mut self,
        bytes: usize,
        #[cfg(kernelet_nat_failure_diag_host)] class: QuotaClass,
    ) -> Option<Self> {
        if bytes == 0 || bytes > self.bytes {
            return None;
        }
        #[cfg(kernelet_nat_failure_diag_host)]
        LEDGER
            .lock()
            .reclassify_prestart(self.user_slot, self.owner, self.tag.class, class, bytes);
        self.bytes -= bytes;
        Some(Self {
            user_slot: self.user_slot,
            owner: self.owner,
            bytes,
            #[cfg(kernelet_nat_failure_diag_host)]
            tag: QuotaTag::new(class, self.tag.origin_cid),
        })
    }
}

/// The native NAT TCP buffers' user and Host charges, owned by native TCP.
pub(crate) struct NativeTcpBufferCharge {
    _host: HostByteCharge,
    _user: PrestartEndpointReservation,
}

impl NativeTcpBufferCharge {
    pub(super) fn new(host: HostByteCharge, user: PrestartEndpointReservation) -> Self {
        Self {
            _host: host,
            _user: user,
        }
    }
}

impl Drop for PrestartEndpointReservation {
    fn drop(&mut self) {
        if self.bytes == 0 {
            return;
        }
        LEDGER.lock().release_prestart_endpoint_bytes(
            self.user_slot,
            self.owner,
            self.bytes,
            #[cfg(kernelet_nat_failure_diag_host)]
            self.tag,
        );
    }
}

#[derive(Clone, Copy)]
struct UserEntry {
    owner: Option<Uid>,
    live: u16,
    grains: u32,
    vcpus: u16,
    // Includes both instance-owned and pre-START endpoint charges.
    endpoint_bytes: usize,
    // Keeps the user slot occupied after its last instance is destroyed.
    prestart_endpoint_bytes: usize,
    #[cfg(kernelet_nat_failure_diag_host)]
    categories: UserCategories,
}

impl UserEntry {
    const EMPTY: Self = Self {
        owner: None,
        live: 0,
        grains: 0,
        vcpus: 0,
        endpoint_bytes: 0,
        prestart_endpoint_bytes: 0,
        #[cfg(kernelet_nat_failure_diag_host)]
        categories: UserCategories::EMPTY,
    };

    #[cfg(kernelet_nat_failure_diag_host)]
    fn category_snapshot(
        &self,
        quota: NatQuotaSnapshot,
        tag: QuotaTag,
        overflow: bool,
    ) -> QuotaCategorySnapshot {
        QuotaCategorySnapshot {
            quota,
            requested_tag: tag,
            captured_before_failed_add: true,
            row_owner: self.owner,
            categories: Some(self.categories),
            totals_match: Some(
                self.categories
                    .totals_match(self.endpoint_bytes, self.prestart_endpoint_bytes),
            ),
            sequence_overflow: overflow,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Empty,
    Reserved,
    Live,
}

#[derive(Clone, Copy)]
struct InstanceEntry {
    generation: u64,
    user_slot: usize,
    phase: Phase,
    committed_grains: u32,
    pending_grains: u32,
    vcpus: u16,
    endpoint_bytes: usize,
    #[cfg(kernelet_nat_failure_diag_host)]
    initial_endpoint_bytes: usize,
}

impl InstanceEntry {
    const EMPTY: Self = Self {
        generation: 0,
        user_slot: 0,
        phase: Phase::Empty,
        committed_grains: 0,
        pending_grains: 0,
        vcpus: 0,
        endpoint_bytes: 0,
        #[cfg(kernelet_nat_failure_diag_host)]
        initial_endpoint_bytes: 0,
    };
}

struct Ledger {
    users: [UserEntry; MAX_USERS],
    instances: [InstanceEntry; MAX_INSTANCES],
    next_generation: u64,
    #[cfg(kernelet_nat_failure_diag_host)]
    nat_attempt: u64,
    #[cfg(kernelet_nat_failure_diag_host)]
    nat_attempt_overflow: bool,
    #[cfg(kernelet_nat_failure_diag_host)]
    diagnostic_sequence: u64,
    #[cfg(kernelet_nat_failure_diag_host)]
    diagnostic_sequence_overflow: bool,
}

#[cfg(kernelet_nat_failure_diag_host)]
pub(super) const QUOTA_DIAGNOSTIC_LAYOUT: [usize; 4] = [
    size_of::<Ledger>(),
    size_of::<UserCategories>(),
    size_of::<InstanceEntry>(),
    size_of::<PrestartEndpointReservation>(),
];

impl Ledger {
    const fn new() -> Self {
        Self {
            users: [UserEntry::EMPTY; MAX_USERS],
            instances: [InstanceEntry::EMPTY; MAX_INSTANCES],
            next_generation: 1,
            #[cfg(kernelet_nat_failure_diag_host)]
            nat_attempt: 0,
            #[cfg(kernelet_nat_failure_diag_host)]
            nat_attempt_overflow: false,
            #[cfg(kernelet_nat_failure_diag_host)]
            diagnostic_sequence: 0,
            #[cfg(kernelet_nat_failure_diag_host)]
            diagnostic_sequence_overflow: false,
        }
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    fn next_diagnostic_sequence(&mut self) -> Option<u64> {
        match self.diagnostic_sequence.checked_add(1) {
            Some(next) => {
                self.diagnostic_sequence = next;
                Some(next)
            }
            None => {
                self.diagnostic_sequence_overflow = true;
                None
            }
        }
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    fn reclassify_prestart(
        &mut self,
        user_slot: usize,
        owner: Uid,
        source: QuotaClass,
        target: QuotaClass,
        bytes: usize,
    ) {
        let Some(user) = self.users.get_mut(user_slot) else {
            return;
        };
        if user.owner != Some(owner) {
            return;
        }
        user.categories.reclassify(source, target, bytes);
    }

    fn user_slot_for(&self, owner: Uid) -> Result<usize> {
        self.users
            .iter()
            .position(|entry| entry.owner == Some(owner))
            .or_else(|| self.users.iter().position(|entry| entry.owner.is_none()))
            .ok_or_else(|| Error::with_message(Errno::ENOSPC, "kernelet user table is full"))
    }

    fn reserve(
        &mut self,
        owner: Uid,
        grains: u32,
        vcpus: u16,
        endpoint_bytes: usize,
    ) -> Result<(usize, u64)> {
        let Some(instance_slot) = self
            .instances
            .iter()
            .position(|entry| entry.phase == Phase::Empty)
        else {
            return_errno_with_message!(Errno::ENOSPC, "kernelet instance table is full");
        };
        let user_slot = self.user_slot_for(owner)?;
        let user = self.users[user_slot];
        let Some(new_live) = user.live.checked_add(1) else {
            return_errno_with_message!(Errno::ENOSPC, "kernelet count limit reached");
        };
        let Some(new_grains) = user.grains.checked_add(grains) else {
            return_errno_with_message!(Errno::ENOSPC, "kernelet grain limit reached");
        };
        let Some(new_vcpus) = user.vcpus.checked_add(vcpus) else {
            return_errno_with_message!(Errno::ENOSPC, "kernelet vCPU limit reached");
        };
        let Some(new_endpoint_bytes) = user.endpoint_bytes.checked_add(endpoint_bytes) else {
            return_errno_with_message!(Errno::ENOSPC, "kernelet endpoint limit reached");
        };
        if new_live > MAX_LIVE_PER_USER
            || new_grains > MAX_GRAINS_PER_USER
            || new_vcpus > MAX_VCPUS_PER_USER
            || new_endpoint_bytes > MAX_ENDPOINT_BYTES_PER_USER
        {
            return_errno_with_message!(Errno::ENOSPC, "kernelet user quota exhausted");
        }
        let Some(next_generation) = self.next_generation.checked_add(1) else {
            return_errno_with_message!(Errno::ENOSPC, "kernelet admission IDs exhausted");
        };

        #[cfg(kernelet_nat_failure_diag_host)]
        let categories = {
            let mut categories = user.categories;
            if user.owner.is_none() {
                categories.row_epoch = self.next_diagnostic_sequence();
            }
            categories.reserve(
                QuotaClass::InitialEndpoint,
                endpoint_bytes,
                CategoryOwner::Instance,
            );
            categories
        };
        self.next_generation = next_generation;
        self.users[user_slot] = UserEntry {
            owner: Some(owner),
            live: new_live,
            grains: new_grains,
            vcpus: new_vcpus,
            endpoint_bytes: new_endpoint_bytes,
            prestart_endpoint_bytes: user.prestart_endpoint_bytes,
            #[cfg(kernelet_nat_failure_diag_host)]
            categories,
        };
        self.instances[instance_slot] = InstanceEntry {
            generation: next_generation,
            user_slot,
            phase: Phase::Reserved,
            committed_grains: grains,
            pending_grains: 0,
            vcpus,
            endpoint_bytes,
            #[cfg(kernelet_nat_failure_diag_host)]
            initial_endpoint_bytes: endpoint_bytes,
        };
        Ok((instance_slot, next_generation))
    }

    fn instance_mut(&mut self, slot: usize, generation: u64) -> Option<&mut InstanceEntry> {
        let instance = self.instances.get_mut(slot)?;
        (instance.generation == generation && instance.phase != Phase::Empty).then_some(instance)
    }

    fn phase(&self, slot: usize, generation: u64) -> Option<Phase> {
        let instance = self.instances.get(slot)?;
        (instance.generation == generation && instance.phase != Phase::Empty)
            .then_some(instance.phase)
    }

    fn reserve_grains_up_to(&mut self, slot: usize, generation: u64, requested: u32) -> u32 {
        let Some(instance) = self.instances.get(slot) else {
            return 0;
        };
        if instance.generation != generation || instance.phase != Phase::Live {
            return 0;
        }
        let user = &self.users[instance.user_slot];
        let available = MAX_GRAINS_PER_USER.saturating_sub(user.grains);
        let amount = requested.min(MAX_GRAINS_PER_REQUEST).min(available);
        if amount == 0 {
            return 0;
        }
        self.add_pending(slot, amount);
        amount
    }

    fn reserve_grains_exact(&mut self, slot: usize, generation: u64, requested: u32) -> Result<()> {
        let Some(instance) = self.instances.get(slot) else {
            return_errno_with_message!(Errno::EINVAL, "kernelet admission is unavailable");
        };
        if instance.generation != generation || instance.phase != Phase::Live {
            return_errno_with_message!(Errno::EINVAL, "kernelet admission is unavailable");
        }
        let user = &self.users[instance.user_slot];
        if requested > MAX_GRAINS_PER_USER.saturating_sub(user.grains) {
            return_errno_with_message!(Errno::ENOSPC, "kernelet grain limit reached");
        }
        self.add_pending(slot, requested);
        Ok(())
    }

    fn add_pending(&mut self, slot: usize, amount: u32) {
        let instance = &mut self.instances[slot];
        let user = &mut self.users[instance.user_slot];
        instance.pending_grains += amount;
        user.grains += amount;
    }

    fn settle_grains(&mut self, slot: usize, generation: u64, reserved: u32, committed: u32) {
        if reserved == 0 {
            return;
        }
        let Some(instance) = self.instances.get_mut(slot) else {
            // Destroy waits for all admitted operations before release.
            debug_assert!(false, "grant settled after kernelet destruction");
            return;
        };
        if instance.generation != generation || instance.phase == Phase::Empty {
            debug_assert!(false, "grant settled after kernelet destruction");
            return;
        }
        debug_assert_eq!(instance.phase, Phase::Live);
        debug_assert!(committed <= reserved && reserved <= instance.pending_grains);
        if committed > reserved || reserved > instance.pending_grains {
            // A violated OSTD callback contract must not reduce a live charge.
            return;
        }
        instance.pending_grains -= reserved;
        instance.committed_grains += committed;
        self.users[instance.user_slot].grains -= reserved - committed;
    }

    fn reserve_endpoint_bytes(&mut self, slot: usize, generation: u64, bytes: usize) -> Result<()> {
        let Some(instance) = self.instances.get(slot) else {
            return_errno_with_message!(Errno::EINVAL, "kernelet admission is unavailable");
        };
        if instance.generation != generation || instance.phase != Phase::Live {
            return_errno_with_message!(Errno::EINVAL, "kernelet admission is unavailable");
        }
        let user = &mut self.users[instance.user_slot];
        let Some(total) = user.endpoint_bytes.checked_add(bytes) else {
            return_errno_with_message!(Errno::ENOSPC, "kernelet endpoint limit reached");
        };
        if total > MAX_ENDPOINT_BYTES_PER_USER {
            return_errno_with_message!(Errno::ENOSPC, "kernelet endpoint limit reached");
        }
        user.endpoint_bytes = total;
        #[cfg(kernelet_nat_failure_diag_host)]
        user.categories
            .reserve(QuotaClass::InstanceEndpoint, bytes, CategoryOwner::Instance);
        self.instances[slot].endpoint_bytes += bytes;
        Ok(())
    }

    fn reserve_prestart_endpoint_bytes(
        &mut self,
        owner: Uid,
        bytes: usize,
        #[cfg(kernelet_nat_failure_diag_host)] tag: QuotaTag,
        #[cfg(kernelet_nat_failure_diag_host)] mut failure: Option<&mut Option<NatQuotaSnapshot>>,
        #[cfg(kernelet_nat_failure_diag_host)] mut categories: Option<
            &mut Option<QuotaCategorySnapshot>,
        >,
    ) -> Result<usize> {
        #[cfg(kernelet_nat_failure_diag_host)]
        let mut snapshot = {
            if failure.is_some() {
                match self.nat_attempt.checked_add(1) {
                    Some(next) => self.nat_attempt = next,
                    None => self.nat_attempt_overflow = true,
                }
            }
            NatQuotaSnapshot {
                owner,
                attempt: self.nat_attempt,
                attempt_overflow: self.nat_attempt_overflow,
                requested_bytes: bytes,
                endpoint_bytes: None,
                prestart_bytes: None,
                limit: MAX_ENDPOINT_BYTES_PER_USER,
                reason: NatQuotaReason::UserTableFull,
            }
        };
        #[cfg(not(kernelet_nat_failure_diag_host))]
        let user_slot = self.user_slot_for(owner)?;
        #[cfg(kernelet_nat_failure_diag_host)]
        let user_slot = match self.user_slot_for(owner) {
            Ok(slot) => slot,
            Err(error) => {
                if let Some(failure) = failure.as_deref_mut() {
                    *failure = Some(snapshot);
                }
                if let Some(categories) = categories.as_deref_mut() {
                    *categories = Some(QuotaCategorySnapshot {
                        quota: snapshot,
                        requested_tag: tag,
                        captured_before_failed_add: true,
                        row_owner: None,
                        categories: None,
                        totals_match: None,
                        sequence_overflow: self.diagnostic_sequence_overflow,
                    });
                }
                return Err(error);
            }
        };
        let user = &mut self.users[user_slot];
        #[cfg(kernelet_nat_failure_diag_host)]
        {
            snapshot.endpoint_bytes = Some(user.endpoint_bytes);
            snapshot.prestart_bytes = Some(user.prestart_endpoint_bytes);
        }
        let Some(total) = user.endpoint_bytes.checked_add(bytes) else {
            #[cfg(kernelet_nat_failure_diag_host)]
            {
                snapshot.reason = NatQuotaReason::EndpointOverflow;
                if let Some(failure) = failure.as_deref_mut() {
                    *failure = Some(snapshot);
                }
            }
            #[cfg(kernelet_nat_failure_diag_host)]
            if let Some(categories) = categories.as_deref_mut() {
                *categories =
                    Some(user.category_snapshot(snapshot, tag, self.diagnostic_sequence_overflow));
            }
            return_errno_with_message!(Errno::ENOSPC, "kernelet endpoint limit reached");
        };
        let Some(prestart_total) = user.prestart_endpoint_bytes.checked_add(bytes) else {
            #[cfg(kernelet_nat_failure_diag_host)]
            {
                snapshot.reason = NatQuotaReason::PrestartOverflow;
                if let Some(failure) = failure.as_deref_mut() {
                    *failure = Some(snapshot);
                }
            }
            #[cfg(kernelet_nat_failure_diag_host)]
            if let Some(categories) = categories.as_deref_mut() {
                *categories =
                    Some(user.category_snapshot(snapshot, tag, self.diagnostic_sequence_overflow));
            }
            return_errno_with_message!(Errno::ENOSPC, "kernelet endpoint limit reached");
        };
        if total > MAX_ENDPOINT_BYTES_PER_USER {
            #[cfg(kernelet_nat_failure_diag_host)]
            {
                snapshot.reason = NatQuotaReason::EndpointLimit;
                if let Some(failure) = failure.as_deref_mut() {
                    *failure = Some(snapshot);
                }
            }
            #[cfg(kernelet_nat_failure_diag_host)]
            if let Some(categories) = categories.as_deref_mut() {
                *categories =
                    Some(user.category_snapshot(snapshot, tag, self.diagnostic_sequence_overflow));
            }
            return_errno_with_message!(Errno::ENOSPC, "kernelet endpoint limit reached");
        }
        #[cfg(kernelet_nat_failure_diag_host)]
        if user.owner.is_none() {
            match self.diagnostic_sequence.checked_add(1) {
                Some(next) => {
                    self.diagnostic_sequence = next;
                    user.categories.row_epoch = Some(next);
                }
                None => self.diagnostic_sequence_overflow = true,
            }
        }
        user.owner = Some(owner);
        user.endpoint_bytes = total;
        user.prestart_endpoint_bytes = prestart_total;
        #[cfg(kernelet_nat_failure_diag_host)]
        user.categories
            .reserve(tag.class, bytes, CategoryOwner::Independent);
        Ok(user_slot)
    }

    fn release_prestart_endpoint_bytes(
        &mut self,
        user_slot: usize,
        owner: Uid,
        bytes: usize,
        #[cfg(kernelet_nat_failure_diag_host)] tag: QuotaTag,
    ) {
        #[cfg(kernelet_nat_failure_diag_host)]
        let refund_sequence = if tag.class == QuotaClass::NatNativeTcp
            && bytes != 0
            && self.users.get(user_slot).is_some_and(|user| {
                user.owner == Some(owner)
                    && user.prestart_endpoint_bytes >= bytes
                    && user.endpoint_bytes >= bytes
            }) {
            self.next_diagnostic_sequence()
        } else {
            None
        };
        let Some(user) = self.users.get_mut(user_slot) else {
            debug_assert!(false, "invalid pre-START endpoint user slot");
            return;
        };
        if user.owner != Some(owner)
            || user.prestart_endpoint_bytes < bytes
            || user.endpoint_bytes < bytes
        {
            debug_assert!(false, "pre-START endpoint reservation refunded twice");
            return;
        }
        user.prestart_endpoint_bytes -= bytes;
        user.endpoint_bytes -= bytes;
        #[cfg(kernelet_nat_failure_diag_host)]
        {
            user.categories
                .refund(tag.class, bytes, CategoryOwner::Independent);
            if tag.class == QuotaClass::NatNativeTcp && bytes != 0 {
                user.categories.last_native_refund = Some(NativeRefund {
                    sequence: refund_sequence,
                    origin_cid: tag.origin_cid,
                    bytes,
                });
            }
        }
        if user.live == 0 && user.prestart_endpoint_bytes == 0 {
            debug_assert_eq!(user.endpoint_bytes, 0);
            *user = UserEntry::EMPTY;
        }
    }

    fn release_endpoint_bytes(&mut self, slot: usize, generation: u64, bytes: usize) {
        let Some(instance) = self.instances.get_mut(slot) else {
            return;
        };
        if instance.generation != generation || instance.phase == Phase::Empty {
            return;
        }
        if bytes > instance.endpoint_bytes {
            debug_assert!(false, "endpoint reservation refunded twice");
            return;
        }
        let user_slot = instance.user_slot;
        instance.endpoint_bytes -= bytes;
        self.users[user_slot].endpoint_bytes -= bytes;
        #[cfg(kernelet_nat_failure_diag_host)]
        self.users[user_slot].categories.refund(
            QuotaClass::InstanceEndpoint,
            bytes,
            CategoryOwner::Instance,
        );
    }

    fn release(&mut self, slot: usize, generation: u64) {
        let Some(instance) = self.instances.get(slot).copied() else {
            return;
        };
        if instance.generation != generation || instance.phase == Phase::Empty {
            return;
        }
        let user = &mut self.users[instance.user_slot];
        debug_assert!(
            user.live != 0
                && user.grains >= instance.committed_grains + instance.pending_grains
                && user.vcpus >= instance.vcpus
                && user.endpoint_bytes >= instance.endpoint_bytes
        );
        user.live -= 1;
        user.grains -= instance.committed_grains + instance.pending_grains;
        user.vcpus -= instance.vcpus;
        user.endpoint_bytes -= instance.endpoint_bytes;
        #[cfg(kernelet_nat_failure_diag_host)]
        {
            user.categories.refund(
                QuotaClass::InitialEndpoint,
                instance.initial_endpoint_bytes,
                CategoryOwner::Instance,
            );
            match instance
                .endpoint_bytes
                .checked_sub(instance.initial_endpoint_bytes)
            {
                Some(dynamic) => user.categories.refund(
                    QuotaClass::InstanceEndpoint,
                    dynamic,
                    CategoryOwner::Instance,
                ),
                None => user.categories.accounting_error = true,
            }
        }
        if user.live == 0 && user.prestart_endpoint_bytes == 0 {
            debug_assert_eq!(user.endpoint_bytes, 0);
            *user = UserEntry::EMPTY;
        }
        self.instances[slot] = InstanceEntry::EMPTY;
    }
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::*;

    use super::*;

    #[ktest]
    fn host_execution_storage_shares_and_refunds_the_uid_memory_budget() {
        let owner = Uid::new(u32::MAX - 60);
        assert!(
            matches!(Admission::reserve_execution(owner, MAX_GRAINS_PER_USER, 1, 0, 1),
            Err(error) if error.error() == Errno::ENOSPC)
        );
        let first = Admission::reserve_execution(owner, 1, 1, 0, 8).unwrap();
        let charged = LEDGER.lock().instances[first.slot].committed_grains;
        assert!(charged > 1);
        let remaining = MAX_GRAINS_PER_USER - charged;
        let second = Admission::reserve(owner, remaining, 1, 0).unwrap();
        assert!(matches!(Admission::reserve(owner, 1, 1, 0),
            Err(error) if error.error() == Errno::ENOSPC));
        drop((first, second));
        // Both uncreated reservations refund their full charge, including Host storage.
        let replacement = Admission::reserve(owner, MAX_GRAINS_PER_USER, 1, 0).unwrap();
        drop(replacement);
        assert!(
            Admission::reserve_execution(owner, 1, 1, 0, ostd::kernelet::control::MAX_TASKS + 1)
                .is_err()
        );
    }

    #[ktest]
    fn prestart_endpoint_charge_survives_instance_destruction() {
        let mut ledger = Ledger::new();
        let owner = Uid::new(1000);
        let user_slot = ledger
            .reserve_prestart_endpoint_bytes(
                owner,
                64,
                #[cfg(kernelet_nat_failure_diag_host)]
                QuotaTag::TEST,
                #[cfg(kernelet_nat_failure_diag_host)]
                None,
                #[cfg(kernelet_nat_failure_diag_host)]
                None,
            )
            .unwrap();
        let (instance_slot, generation) = ledger.reserve(owner, 1, 1, 32).unwrap();

        assert_eq!(ledger.users[user_slot].endpoint_bytes, 96);
        ledger.release(instance_slot, generation);
        assert_eq!(ledger.users[user_slot].owner, Some(owner));
        assert_eq!(ledger.users[user_slot].endpoint_bytes, 64);

        ledger.release_prestart_endpoint_bytes(
            user_slot,
            owner,
            64,
            #[cfg(kernelet_nat_failure_diag_host)]
            QuotaTag::TEST,
        );
        assert_eq!(ledger.users[user_slot].owner, None);
    }

    #[ktest]
    fn prestart_endpoint_charge_shares_the_instance_limit() {
        let mut ledger = Ledger::new();
        let owner = Uid::new(1001);
        let user_slot = ledger
            .reserve_prestart_endpoint_bytes(
                owner,
                64,
                #[cfg(kernelet_nat_failure_diag_host)]
                QuotaTag::TEST,
                #[cfg(kernelet_nat_failure_diag_host)]
                None,
                #[cfg(kernelet_nat_failure_diag_host)]
                None,
            )
            .unwrap();
        assert!(
            ledger
                .reserve(owner, 1, 1, MAX_ENDPOINT_BYTES_PER_USER - 63)
                .is_err()
        );

        ledger.release_prestart_endpoint_bytes(
            user_slot,
            owner,
            64,
            #[cfg(kernelet_nat_failure_diag_host)]
            QuotaTag::TEST,
        );
        assert!(
            ledger
                .reserve(owner, 1, 1, MAX_ENDPOINT_BYTES_PER_USER)
                .is_ok()
        );
    }

    #[ktest]
    fn late_native_charge_holds_user_quota_and_slot_until_release() {
        const TOTAL: usize = 512 * 1024;
        const NATIVE: usize = 288 * 1024;

        // Use the same local ledger isolation as the existing policy tests.
        // This exercises ledger release, not the global guard's Drop path.
        let mut ledger = Ledger::new();
        let owner = Uid::new(2000);
        let user_slot = ledger
            .reserve_prestart_endpoint_bytes(
                owner,
                TOTAL,
                #[cfg(kernelet_nat_failure_diag_host)]
                QuotaTag::TEST,
                #[cfg(kernelet_nat_failure_diag_host)]
                None,
                #[cfg(kernelet_nat_failure_diag_host)]
                None,
            )
            .unwrap();
        let (instance_slot, generation) = ledger.reserve(owner, 1, 1, 32).unwrap();
        ledger.release(instance_slot, generation);
        ledger.release_prestart_endpoint_bytes(
            user_slot,
            owner,
            TOTAL - NATIVE,
            #[cfg(kernelet_nat_failure_diag_host)]
            QuotaTag::TEST,
        );
        assert_eq!(ledger.users[user_slot].owner, Some(owner));
        assert_eq!(ledger.users[user_slot].live, 0);
        assert_eq!(ledger.users[user_slot].endpoint_bytes, NATIVE);
        assert_eq!(ledger.users[user_slot].prestart_endpoint_bytes, NATIVE);
        assert!(matches!(
            ledger.reserve(owner, 1, 1, MAX_ENDPOINT_BYTES_PER_USER - NATIVE + 1),
            Err(error) if error.error() == Errno::ENOSPC
        ));

        // Occupy the other user slots without mutating the global ledger.
        for index in 1..MAX_USERS {
            let other = Uid::new(2000 + index as u32);
            let slot = ledger
                .reserve_prestart_endpoint_bytes(
                    other,
                    1,
                    #[cfg(kernelet_nat_failure_diag_host)]
                    QuotaTag::TEST,
                    #[cfg(kernelet_nat_failure_diag_host)]
                    None,
                    #[cfg(kernelet_nat_failure_diag_host)]
                    None,
                )
                .unwrap();
            assert_ne!(slot, user_slot);
        }
        let replacement = Uid::new(3000);
        assert!(matches!(
                    ledger.reserve_prestart_endpoint_bytes(
        replacement,
        1,
        #[cfg(kernelet_nat_failure_diag_host)] QuotaTag::TEST,
        #[cfg(kernelet_nat_failure_diag_host)]
                        None,
        #[cfg(kernelet_nat_failure_diag_host)] None,
        ),
                    Err(error) if error.error() == Errno::ENOSPC
                ));

        ledger.release_prestart_endpoint_bytes(
            user_slot,
            owner,
            NATIVE,
            #[cfg(kernelet_nat_failure_diag_host)]
            QuotaTag::TEST,
        );
        assert_eq!(ledger.users[user_slot].owner, None);
        assert_eq!(ledger.users[user_slot].endpoint_bytes, 0);
        assert_eq!(ledger.users[user_slot].prestart_endpoint_bytes, 0);
        let reused = ledger
            .reserve_prestart_endpoint_bytes(
                replacement,
                1,
                #[cfg(kernelet_nat_failure_diag_host)]
                QuotaTag::TEST,
                #[cfg(kernelet_nat_failure_diag_host)]
                None,
                #[cfg(kernelet_nat_failure_diag_host)]
                None,
            )
            .unwrap();
        assert_eq!(reused, user_slot);
        assert_eq!(ledger.users[reused].owner, Some(replacement));
        assert_eq!(ledger.users[reused].endpoint_bytes, 1);
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    #[ktest]
    fn nat_quota_failure_copies_locked_values_without_charging() {
        let mut ledger = Ledger::new();
        let owner = Uid::new(4000);
        let slot = ledger
            .reserve_prestart_endpoint_bytes(
                owner,
                MAX_ENDPOINT_BYTES_PER_USER - 1,
                #[cfg(kernelet_nat_failure_diag_host)]
                QuotaTag::TEST,
                None,
                #[cfg(kernelet_nat_failure_diag_host)]
                None,
            )
            .unwrap();
        let mut failure = None;
        let result = ledger.reserve_prestart_endpoint_bytes(
            owner,
            2,
            #[cfg(kernelet_nat_failure_diag_host)]
            QuotaTag::TEST,
            Some(&mut failure),
            #[cfg(kernelet_nat_failure_diag_host)]
            None,
        );
        assert!(matches!(result, Err(error) if error.error() == Errno::ENOSPC));
        let snapshot = failure.unwrap();
        assert_eq!(snapshot.owner, owner);
        assert_eq!(snapshot.requested_bytes, 2);
        assert_eq!(
            snapshot.endpoint_bytes,
            Some(MAX_ENDPOINT_BYTES_PER_USER - 1)
        );
        assert_eq!(
            snapshot.prestart_bytes,
            Some(MAX_ENDPOINT_BYTES_PER_USER - 1)
        );
        assert_eq!(snapshot.limit, MAX_ENDPOINT_BYTES_PER_USER);
        assert!(matches!(snapshot.reason, NatQuotaReason::EndpointLimit));
        assert_eq!(snapshot.attempt, 1);
        assert!(!snapshot.attempt_overflow);
        assert_eq!(
            ledger.users[slot].endpoint_bytes,
            MAX_ENDPOINT_BYTES_PER_USER - 1
        );
        assert_eq!(
            ledger.users[slot].prestart_endpoint_bytes,
            MAX_ENDPOINT_BYTES_PER_USER - 1
        );
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    #[ktest]
    fn nat_quota_snapshot_identifies_user_table_exhaustion() {
        let mut ledger = Ledger::new();
        for index in 0..MAX_USERS {
            ledger
                .reserve_prestart_endpoint_bytes(
                    Uid::new(5000 + index as u32),
                    1,
                    #[cfg(kernelet_nat_failure_diag_host)]
                    QuotaTag::TEST,
                    None,
                    #[cfg(kernelet_nat_failure_diag_host)]
                    None,
                )
                .unwrap();
        }
        let owner = Uid::new(6000);
        let mut failure = None;
        let result = ledger.reserve_prestart_endpoint_bytes(
            owner,
            1,
            #[cfg(kernelet_nat_failure_diag_host)]
            QuotaTag::TEST,
            Some(&mut failure),
            #[cfg(kernelet_nat_failure_diag_host)]
            None,
        );
        assert!(matches!(result, Err(error) if error.error() == Errno::ENOSPC));
        let snapshot = failure.unwrap();
        assert_eq!(snapshot.owner, owner);
        assert!(matches!(snapshot.reason, NatQuotaReason::UserTableFull));
        assert_eq!(snapshot.endpoint_bytes, None);
        assert_eq!(snapshot.prestart_bytes, None);
        assert_eq!(snapshot.requested_bytes, 1);
        assert_eq!(snapshot.limit, MAX_ENDPOINT_BYTES_PER_USER);
        assert_eq!(snapshot.attempt, 1);
        assert!(ledger.users.iter().all(|user| user.endpoint_bytes == 1));
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    #[ktest]
    fn nat_quota_snapshot_identifies_actual_addition_overflow() {
        let mut ledger = Ledger::new();
        let owner = Uid::new(6001);
        let slot = ledger
            .reserve_prestart_endpoint_bytes(
                owner,
                1,
                #[cfg(kernelet_nat_failure_diag_host)]
                QuotaTag::TEST,
                None,
                #[cfg(kernelet_nat_failure_diag_host)]
                None,
            )
            .unwrap();
        let mut failure = None;
        // A real request overflows the addition; no ledger value is fabricated.
        let result = ledger.reserve_prestart_endpoint_bytes(
            owner,
            usize::MAX,
            #[cfg(kernelet_nat_failure_diag_host)]
            QuotaTag::TEST,
            Some(&mut failure),
            #[cfg(kernelet_nat_failure_diag_host)]
            None,
        );
        assert!(matches!(result, Err(error) if error.error() == Errno::ENOSPC));
        let snapshot = failure.unwrap();
        assert!(matches!(snapshot.reason, NatQuotaReason::EndpointOverflow));
        assert_eq!(snapshot.owner, owner);
        assert_eq!(snapshot.requested_bytes, usize::MAX);
        assert_eq!(snapshot.endpoint_bytes, Some(1));
        assert_eq!(snapshot.prestart_bytes, Some(1));
        assert_eq!(ledger.users[slot].endpoint_bytes, 1);
        assert_eq!(ledger.users[slot].prestart_endpoint_bytes, 1);
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    #[ktest]
    fn diagnostic_reservation_drop_refunds_the_real_ledger() {
        let owner = Uid::new(u32::MAX - 40);
        let before = {
            let ledger = LEDGER.lock();
            ledger.users.iter().any(|user| user.owner == Some(owner))
        };
        assert!(!before, "diagnostic test UID is already reserved");
        let mut failure = None;
        let reservation = PrestartEndpointReservation::reserve_diagnostic(
            owner,
            32,
            QuotaTag::TEST,
            &mut failure,
            None,
        )
        .unwrap();
        let charged = {
            let ledger = LEDGER.lock();
            ledger
                .users
                .iter()
                .find(|user| user.owner == Some(owner))
                .map(|user| (user.endpoint_bytes, user.prestart_endpoint_bytes))
        };
        assert!(failure.is_none());
        assert_eq!(charged, Some((32, 32)));
        drop(reservation);
        let after = {
            let ledger = LEDGER.lock();
            ledger.users.iter().any(|user| user.owner == Some(owner))
        };
        assert!(!after, "reservation Drop did not refund its UID slot");
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    fn assert_categories(ledger: &Ledger, slot: usize) {
        let user = &ledger.users[slot];
        assert!(
            user.categories
                .totals_match(user.endpoint_bytes, user.prestart_endpoint_bytes)
        );
        assert!(!user.categories.accounting_error);
        assert!(!user.categories.counter_overflow);
        assert!(!ledger.diagnostic_sequence_overflow);
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    #[ktest]
    fn all_independent_categories_share_the_real_endpoint_limit() {
        let mut ledger = Ledger::new();
        let owner = Uid::new(6100);
        let classes = [
            QuotaClass::ConsoleFixed,
            QuotaClass::LogFixed,
            QuotaClass::NetFixed,
            QuotaClass::NatBackend,
            QuotaClass::NatFlow,
            QuotaClass::NatNativeTcp,
            QuotaClass::NatExtraDrain,
            QuotaClass::HostVsockFixed,
            QuotaClass::TestOnly,
        ];
        for class in classes {
            let slot = ledger
                .reserve_prestart_endpoint_bytes(
                    owner,
                    32,
                    QuotaTag::new(class, Some(3)),
                    None,
                    None,
                )
                .unwrap();
            assert_categories(&ledger, slot);
            assert_eq!(
                ledger.users[slot].categories.balances[class as usize].current,
                32
            );
        }
        let (instance, generation) = ledger.reserve(owner, 1, 1, 64).unwrap();
        ledger.instance_mut(instance, generation).unwrap().phase = Phase::Live;
        ledger
            .reserve_endpoint_bytes(instance, generation, 96)
            .unwrap();
        let slot = ledger.instances[instance].user_slot;
        let initial = QuotaClass::InitialEndpoint as usize;
        let dynamic = QuotaClass::InstanceEndpoint as usize;
        assert_eq!(ledger.users[slot].categories.balances[initial].current, 64);
        assert_eq!(ledger.users[slot].categories.balances[dynamic].current, 96);
        assert_categories(&ledger, slot);
        ledger.release(instance, generation);
        assert_eq!(ledger.users[slot].categories.balances[initial].current, 0);
        assert_eq!(ledger.users[slot].categories.balances[dynamic].current, 0);
        for class in classes {
            ledger.release_prestart_endpoint_bytes(slot, owner, 32, QuotaTag::new(class, Some(3)));
            if ledger.users[slot].owner.is_some() {
                assert_categories(&ledger, slot);
            }
        }
        assert_eq!(ledger.users[slot].owner, None);
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    #[ktest]
    fn category_snapshot_is_from_the_real_failed_add_without_charging() {
        let mut ledger = Ledger::new();
        let owner = Uid::new(6101);
        let tag = QuotaTag::new(QuotaClass::NatFlow, Some(4));
        let slot = ledger
            .reserve_prestart_endpoint_bytes(
                owner,
                MAX_ENDPOINT_BYTES_PER_USER - 1,
                tag,
                None,
                None,
            )
            .unwrap();
        let before = ledger.users[slot].categories;
        let mut scalar = None;
        let mut category = None;
        let failure = ledger.reserve_prestart_endpoint_bytes(
            owner,
            2,
            tag,
            Some(&mut scalar),
            Some(&mut category),
        );
        assert!(matches!(failure, Err(e) if e.error() == Errno::ENOSPC));
        let scalar = scalar.unwrap();
        let category = category.unwrap();
        assert!(category.matches(scalar));
        assert_eq!(category.requested_tag, tag);
        assert_eq!(category.row_owner, Some(owner));
        assert_eq!(category.categories, Some(before));
        assert_eq!(category.totals_match, Some(true));
        assert!(category.captured_before_failed_add);
        assert!(category.is_consistent());
        assert_eq!(ledger.users[slot].categories, before);
        assert_categories(&ledger, slot);
        ledger.release_prestart_endpoint_bytes(slot, owner, MAX_ENDPOINT_BYTES_PER_USER - 1, tag);
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    #[ktest]
    fn real_guard_split_reclassifies_and_refunds_in_both_orders() {
        const TOTAL: usize = 512 * 1024;
        const NATIVE: usize = 288 * 1024;
        for native_first in [false, true] {
            let owner = Uid::new(u32::MAX - 43 - u32::from(native_first));
            let tag = QuotaTag::new(QuotaClass::NatFlow, Some(27));
            let mut front = PrestartEndpointReservation::reserve(owner, TOTAL, tag).unwrap();
            let slot = front.user_slot;
            let before = { LEDGER.lock().users[slot].categories };
            assert!(front.split_off(0, QuotaClass::NatNativeTcp).is_none());
            assert!(
                front
                    .split_off(TOTAL + 1, QuotaClass::NatNativeTcp)
                    .is_none()
            );
            assert_eq!(LEDGER.lock().users[slot].categories, before);
            let native = front.split_off(NATIVE, QuotaClass::NatNativeTcp).unwrap();
            assert_eq!(native.tag.origin_cid, Some(27));
            assert_eq!(front.bytes, TOTAL - NATIVE);
            {
                let ledger = LEDGER.lock();
                let user = &ledger.users[slot];
                assert_eq!(user.endpoint_bytes, TOTAL);
                assert_eq!(user.prestart_endpoint_bytes, TOTAL);
                assert_eq!(
                    user.categories.balances[QuotaClass::NatFlow as usize].current,
                    TOTAL - NATIVE
                );
                assert_eq!(
                    user.categories.balances[QuotaClass::NatNativeTcp as usize].current,
                    NATIVE
                );
                assert_eq!(
                    user.categories.balances[QuotaClass::NatFlow as usize].reserve_count,
                    1
                );
                assert_eq!(
                    user.categories.balances[QuotaClass::NatNativeTcp as usize].reserve_count,
                    0
                );
                assert_eq!(
                    user.categories.balances[QuotaClass::NatNativeTcp as usize].split_in_count,
                    1
                );
                assert_categories(&ledger, slot);
            }
            if native_first {
                drop(native);
                {
                    let ledger = LEDGER.lock();
                    let refund = ledger.users[slot].categories.last_native_refund.unwrap();
                    assert_eq!(refund.bytes, NATIVE);
                    assert_eq!(refund.origin_cid, Some(27));
                    assert!(refund.sequence.is_some());
                    assert_eq!(ledger.users[slot].endpoint_bytes, TOTAL - NATIVE);
                    assert_categories(&ledger, slot);
                }
                drop(front);
            } else {
                drop(front);
                assert_eq!(LEDGER.lock().users[slot].endpoint_bytes, NATIVE);
                drop(native);
            }
            assert_eq!(LEDGER.lock().users[slot].owner, None);
        }
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    #[ktest]
    fn destroy_and_stale_dynamic_drop_preserve_independent_epoch_and_balance() {
        let owner = Uid::new(u32::MAX - 45);
        let guard = PrestartEndpointReservation::reserve(
            owner,
            128,
            QuotaTag::new(QuotaClass::NatNativeTcp, Some(28)),
        )
        .unwrap();
        let slot = guard.user_slot;
        let epoch = LEDGER.lock().users[slot].categories.row_epoch.unwrap();
        let admission = Admission::reserve(owner, 1, 1, 64).unwrap();
        admission.mark_created();
        let dynamic = admission.reserve_endpoint_bytes(32).unwrap();
        admission.release_after_destroy();
        let before_stale = LEDGER.lock().users[slot].categories;
        drop(dynamic);
        assert_eq!(LEDGER.lock().users[slot].categories, before_stale);
        {
            let ledger = LEDGER.lock();
            assert_eq!(ledger.users[slot].endpoint_bytes, 128);
            assert_eq!(ledger.users[slot].categories.row_epoch, Some(epoch));
            assert_categories(&ledger, slot);
        }
        drop(admission);
        drop(guard);
        assert_eq!(LEDGER.lock().users[slot].owner, None);
        let replacement = PrestartEndpointReservation::reserve(owner, 1, QuotaTag::TEST).unwrap();
        assert!(
            LEDGER.lock().users[replacement.user_slot]
                .categories
                .row_epoch
                .unwrap()
                > epoch
        );
        drop(replacement);
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    #[ktest]
    fn category_counter_overflow_does_not_change_reservation_or_refund() {
        let mut ledger = Ledger::new();
        let owner = Uid::new(6102);
        let slot = ledger
            .reserve_prestart_endpoint_bytes(owner, 1, QuotaTag::TEST, None, None)
            .unwrap();
        // Seed only the diagnostic operation counter, never quota balances.
        ledger.users[slot].categories.balances[QuotaClass::TestOnly as usize].reserve_count =
            u64::MAX;
        ledger
            .reserve_prestart_endpoint_bytes(owner, 1, QuotaTag::TEST, None, None)
            .unwrap();
        assert_eq!(ledger.users[slot].endpoint_bytes, 2);
        assert_eq!(
            ledger.users[slot].categories.balances[QuotaClass::TestOnly as usize].current,
            2
        );
        assert!(ledger.users[slot].categories.counter_overflow);
        ledger.release_prestart_endpoint_bytes(slot, owner, 2, QuotaTag::TEST);
        assert_eq!(ledger.users[slot].owner, None);
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    #[ktest]
    fn category_failure_snapshots_stay_consistent_across_real_task_mutations() {
        use core::sync::atomic::{AtomicBool, Ordering};

        use ostd::task::{Task, TaskOptions};

        aster_time::init_for_ktest();
        let owner = Uid::new(u32::MAX - 49);
        let tag = QuotaTag::new(QuotaClass::NatFlow, Some(29));
        let held =
            PrestartEndpointReservation::reserve(owner, MAX_ENDPOINT_BYTES_PER_USER - 1024, tag)
                .unwrap();
        let worker_entered = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker_done = done.clone();
        let entered = worker_entered.clone();
        let task = TaskOptions::new(move || {
            while !worker_stop.load(Ordering::Acquire) {
                let mut flow = PrestartEndpointReservation::reserve(owner, 512, tag).unwrap();
                let native = flow.split_off(288, QuotaClass::NatNativeTcp).unwrap();
                entered.store(true, Ordering::Release);
                Task::yield_now();
                drop(native);
                drop(flow);
            }
            worker_done.store(true, Ordering::Release);
        })
        .data(())
        .spawn()
        .unwrap();
        let start = aster_time::read_monotonic_time();
        while !worker_entered.load(Ordering::Acquire)
            && aster_time::read_monotonic_time().saturating_sub(start)
                < core::time::Duration::from_secs(2)
        {
            Task::yield_now();
        }
        let entered_before_deadline = worker_entered.load(Ordering::Acquire);
        let mut valid = entered_before_deadline;
        for _ in 0..16 {
            let mut failure = None;
            let mut categories = None;
            let result = PrestartEndpointReservation::reserve_diagnostic(
                owner,
                2048,
                tag,
                &mut failure,
                Some(&mut categories),
            );
            valid &= matches!(result, Err(e) if e.error() == Errno::ENOSPC);
            valid &= failure
                .zip(categories)
                .is_some_and(|(failure, categories)| {
                    categories.matches(failure) && categories.is_consistent()
                });
            Task::yield_now();
        }
        stop.store(true, Ordering::Release);
        let start = aster_time::read_monotonic_time();
        while !done.load(Ordering::Acquire)
            && aster_time::read_monotonic_time().saturating_sub(start)
                < core::time::Duration::from_secs(2)
        {
            Task::yield_now();
        }
        let worker_finished = done.load(Ordering::Acquire);
        let ledger_consistent = {
            let ledger = LEDGER.lock();
            let user = &ledger.users[held.user_slot];
            user.endpoint_bytes == MAX_ENDPOINT_BYTES_PER_USER - 1024
                && user
                    .categories
                    .totals_match(user.endpoint_bytes, user.prestart_endpoint_bytes)
                && !user.categories.accounting_error
        };
        drop((held, task));
        assert!(entered_before_deadline && worker_finished);
        assert!(valid && ledger_consistent);
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    #[ktest]
    fn full_user_table_category_failure_has_no_fabricated_owner_or_zero_balance() {
        let mut ledger = Ledger::new();
        for index in 0..MAX_USERS {
            ledger
                .reserve_prestart_endpoint_bytes(
                    Uid::new(6200 + index as u32),
                    1,
                    QuotaTag::new(QuotaClass::NetFixed, Some(3)),
                    None,
                    None,
                )
                .unwrap();
        }
        let mut failure = None;
        let mut category = None;
        let result = ledger.reserve_prestart_endpoint_bytes(
            Uid::new(6300),
            1,
            QuotaTag::new(QuotaClass::NatFlow, Some(4)),
            Some(&mut failure),
            Some(&mut category),
        );
        assert!(matches!(result, Err(e) if e.error() == Errno::ENOSPC));
        let category = category.unwrap();
        assert!(category.matches(failure.unwrap()));
        assert!(matches!(
            category.quota.reason,
            NatQuotaReason::UserTableFull
        ));
        assert_eq!(category.row_owner, None);
        assert_eq!(category.categories, None);
        assert_eq!(category.totals_match, None);
        assert!(!category.is_consistent());
        assert!(ledger.users.iter().all(|user| user.endpoint_bytes == 1));
    }
}
