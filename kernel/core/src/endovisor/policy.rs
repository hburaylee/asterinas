// SPDX-License-Identifier: MPL-2.0

//! Per-user admission for kernelet memory ceilings, carriers and endpoints.
//!
//! Instance reservations are made at START, before OSTD creates an instance.
//! Once creation succeeds, the reservation remains charged until OSTD has
//! destroyed that instance. Endpoint structures created before START have
//! separate guards charged to the same user's endpoint limit. Grant
//! authorizations are pending charges in the same ledger; settlement transfers
//! the committed part to the live ceiling and refunds the remainder.
//!
//! All ledger updates use one IRQ-disabled lock. No allocation, OSTD call or
//! wait occurs while it is held. The preallocated user and instance tables make
//! the memory-exhaustion hook safe to call from a carrier's Host service path.

use ostd::{kernelet::abi::MAX_GRAINS_PER_REQUEST, sync::LocalIrqDisabled};

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

/// A pre-START endpoint charge retained by the endpoint that owns its memory.
///
/// A listener can outlive the instance's admission. Its charge therefore
/// belongs to the user rather than to an instance slot and is refunded when
/// the listener is dropped.
pub(super) struct PrestartEndpointReservation {
    user_slot: usize,
    owner: Uid,
    bytes: usize,
}

impl PrestartEndpointReservation {
    pub(super) fn reserve(owner: Uid, bytes: usize) -> Result<Self> {
        if bytes == 0 {
            return_errno_with_message!(Errno::EINVAL, "empty endpoint reservation");
        }
        let user_slot = LEDGER
            .lock()
            .reserve_prestart_endpoint_bytes(owner, bytes)?;
        Ok(Self {
            user_slot,
            owner,
            bytes,
        })
    }
}

impl Drop for PrestartEndpointReservation {
    fn drop(&mut self) {
        LEDGER
            .lock()
            .release_prestart_endpoint_bytes(self.user_slot, self.owner, self.bytes);
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
}

impl UserEntry {
    const EMPTY: Self = Self {
        owner: None,
        live: 0,
        grains: 0,
        vcpus: 0,
        endpoint_bytes: 0,
        prestart_endpoint_bytes: 0,
    };
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
    };
}

struct Ledger {
    users: [UserEntry; MAX_USERS],
    instances: [InstanceEntry; MAX_INSTANCES],
    next_generation: u64,
}

impl Ledger {
    const fn new() -> Self {
        Self {
            users: [UserEntry::EMPTY; MAX_USERS],
            instances: [InstanceEntry::EMPTY; MAX_INSTANCES],
            next_generation: 1,
        }
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

        self.next_generation = next_generation;
        self.users[user_slot] = UserEntry {
            owner: Some(owner),
            live: new_live,
            grains: new_grains,
            vcpus: new_vcpus,
            endpoint_bytes: new_endpoint_bytes,
            prestart_endpoint_bytes: user.prestart_endpoint_bytes,
        };
        self.instances[instance_slot] = InstanceEntry {
            generation: next_generation,
            user_slot,
            phase: Phase::Reserved,
            committed_grains: grains,
            pending_grains: 0,
            vcpus,
            endpoint_bytes,
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
        self.instances[slot].endpoint_bytes += bytes;
        Ok(())
    }

    fn reserve_prestart_endpoint_bytes(&mut self, owner: Uid, bytes: usize) -> Result<usize> {
        let user_slot = self.user_slot_for(owner)?;
        let user = &mut self.users[user_slot];
        let Some(total) = user.endpoint_bytes.checked_add(bytes) else {
            return_errno_with_message!(Errno::ENOSPC, "kernelet endpoint limit reached");
        };
        let Some(prestart_total) = user.prestart_endpoint_bytes.checked_add(bytes) else {
            return_errno_with_message!(Errno::ENOSPC, "kernelet endpoint limit reached");
        };
        if total > MAX_ENDPOINT_BYTES_PER_USER {
            return_errno_with_message!(Errno::ENOSPC, "kernelet endpoint limit reached");
        }
        user.owner = Some(owner);
        user.endpoint_bytes = total;
        user.prestart_endpoint_bytes = prestart_total;
        Ok(user_slot)
    }

    fn release_prestart_endpoint_bytes(&mut self, user_slot: usize, owner: Uid, bytes: usize) {
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
    fn prestart_endpoint_charge_survives_instance_destruction() {
        let mut ledger = Ledger::new();
        let owner = Uid::new(1000);
        let user_slot = ledger.reserve_prestart_endpoint_bytes(owner, 64).unwrap();
        let (instance_slot, generation) = ledger.reserve(owner, 1, 1, 32).unwrap();

        assert_eq!(ledger.users[user_slot].endpoint_bytes, 96);
        ledger.release(instance_slot, generation);
        assert_eq!(ledger.users[user_slot].owner, Some(owner));
        assert_eq!(ledger.users[user_slot].endpoint_bytes, 64);

        ledger.release_prestart_endpoint_bytes(user_slot, owner, 64);
        assert_eq!(ledger.users[user_slot].owner, None);
    }

    #[ktest]
    fn prestart_endpoint_charge_shares_the_instance_limit() {
        let mut ledger = Ledger::new();
        let owner = Uid::new(1001);
        let user_slot = ledger.reserve_prestart_endpoint_bytes(owner, 64).unwrap();
        assert!(
            ledger
                .reserve(owner, 1, 1, MAX_ENDPOINT_BYTES_PER_USER - 63)
                .is_err()
        );

        ledger.release_prestart_endpoint_bytes(user_slot, owner, 64);
        assert!(
            ledger
                .reserve(owner, 1, 1, MAX_ENDPOINT_BYTES_PER_USER)
                .is_ok()
        );
    }
}
