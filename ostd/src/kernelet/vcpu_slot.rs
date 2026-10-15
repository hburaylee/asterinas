// SPDX-License-Identifier: MPL-2.0

//! Host-owned virtual-CPU identity published at the native GS base.
//!
//! Carrier restore and pause update this cell with physical IRQs masked. The
//! image only reads it through the offset in its immutable boot page; the
//! native current-CPU cell remains independent.

use core::arch::asm;

use super::abi::CpuSlot;
use crate::cpu_local_cell;

cpu_local_cell! {
    static CURRENT_SLOT: CpuSlot = CpuSlot::NONE;
}

/// Returns the GS offset of the Host-written current virtual-CPU slot.
pub(super) fn gs_offset() -> u32 {
    CURRENT_SLOT
        .static_offset()
        .try_into()
        .expect("virtual CPU slot offset exceeds ABI")
}

/// Publishes the current carrier, or clears the slot outside a carrier.
pub(super) fn restore(identity: Option<CpuSlot>) {
    debug_assert!(!crate::arch::irq::is_local_enabled());
    let identity = identity.unwrap_or(CpuSlot::NONE);
    // SAFETY: The offset names this CPU's aligned 16-byte cell. IRQ masking
    // pins its GS base. All authentication fields occupy one aligned QWORD,
    // so an NMI sees either complete identity; the other QWORD stays zero.
    unsafe {
        asm!(
            "mov qword ptr gs:[{offset} + 8], 0",
            "mov gs:[{offset}], {identity}",
            offset = in(reg) gs_offset() as usize,
            identity = in(reg) identity.identity_word(),
            options(nostack, preserves_flags),
        );
    }
}

/// Reads the complete authentication identity with one native GS load.
pub(super) fn current() -> CpuSlot {
    let identity: u64;
    // SAFETY: Native GS remains the Host CPU-local base even in image code.
    // This aligned QWORD is updated atomically on carrier restore and pause.
    unsafe {
        asm!(
            "mov {identity}, gs:[{offset}]",
            identity = out(reg) identity,
            offset = in(reg) gs_offset() as usize,
            options(nostack, readonly, preserves_flags),
        );
    }
    CpuSlot::from_identity_word(identity)
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::prelude::*;

    #[ktest]
    fn published_slot_preserves_native_cpu_identity() {
        let _irq_guard = crate::irq::disable_local();
        let saved = current();
        let native_cpu = crate::cpu::CpuId::current_racy();
        let read_slot = || {
            let identity: u64;
            let reserved: u64;
            // SAFETY: The published offset names this CPU's live CpuSlot,
            // and masked physical IRQs keep its GS base and carrier stable.
            unsafe {
                asm!(
                    "mov {identity}, gs:[{offset}]",
                    "mov {reserved}, gs:[{offset} + 8]",
                    identity = out(reg) identity,
                    reserved = out(reg) reserved,
                    offset = in(reg) gs_offset() as usize,
                    options(nostack, readonly, preserves_flags),
                );
            }
            assert_eq!(reserved, 0);
            CpuSlot::from_identity_word(identity)
        };

        let identity = CpuSlot {
            kernelet: 19,
            vcpu: 7,
            generation: 0x12345678,
            _reserved: 0,
        };
        restore(Some(identity));
        assert_eq!(read_slot(), identity);
        assert_eq!(crate::cpu::CpuId::current_racy(), native_cpu);
        let next = CpuSlot {
            kernelet: 23,
            vcpu: 0,
            generation: 0x87654321,
            _reserved: 0,
        };
        restore(Some(next));
        assert_eq!(read_slot(), next);
        restore(None);
        assert_eq!(read_slot(), CpuSlot::NONE);
        assert_eq!(crate::cpu::CpuId::current_racy(), native_cpu);
        restore(Some(saved));
    }
}
