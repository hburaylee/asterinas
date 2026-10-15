// SPDX-License-Identifier: MPL-2.0 OR MIT
//
// The original source code is from [trapframe-rs](https://github.com/rcore-os/trapframe-rs),
// which is released under the following license:
//
// SPDX-License-Identifier: MIT
//
// Copyright (c) 2020 - 2024 Runji Wang
//
// We make the following new changes:
// * Revise some comments.
//
// These changes are released under the following license:
//
// SPDX-License-Identifier: MPL-2.0

//! Configure fast syscall.

use core::arch::global_asm;

use x86_64::{
    VirtAddr,
    registers::{
        model_specific::{Efer, EferFlags, LStar, SFMask, Star},
        rflags::RFlags,
    },
};

use super::{RawUserContext, gdt};
#[cfg(kernelet_getpid_profile)]
use crate::kernelet::getpid_profile as profile;
use crate::{irq::DisabledLocalIrqGuard, mm::PagingConstsTrait};

global_asm!(
    include_str!("syscall.S"),
    USER_CS = const gdt::USER_CS.0,
    USER_SS = const gdt::USER_SS.0,
    ADDRESS_WIDTH = const crate::arch::mm::PagingConsts::ADDRESS_WIDTH,
);

/// # Safety
///
/// The caller must ensure that:
/// 1. No preemption can occur during the method.
/// 2. `gdt::init_on_cpu` has been called before.
pub(super) unsafe fn init_on_cpu() {
    // We now assume that all x86-64 CPUs should support the `syscall` and `sysret` instructions.
    // Otherwise, we should check `has_extensions(IsaExtensions::SYSCALL)` here.

    // No races because the caller guarantees that no preemption can occur.
    configure_msrs_racy();

    // SAFETY: Enabling the `syscall` and `sysret` instructions is safe because:
    //  - `configure_msrs_racy` has configured the related MSRs.
    //  - `gdt::init_on_cpu` has configured the kernel's GDT.
    unsafe {
        Efer::update(|efer| {
            efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS);
        });
    }
}

/// Configures the kernel's syscall selectors, entry point, and flags mask.
pub(in crate::arch) fn configure_msrs(_irq_guard: &DisabledLocalIrqGuard) {
    // No races due to `_irq_guard`.
    configure_msrs_racy();
}

fn configure_msrs_racy() {
    // Flags to clear on syscall.
    //
    // Linux 5.0 uses TF|DF|IF|IOPL|AC|NT. Reference:
    // <https://github.com/torvalds/linux/blob/v5.0/arch/x86/kernel/cpu/common.c#L1559-L1562>
    const RFLAGS_MASK: u64 = 0x47700;

    // SAFETY: The syscall selectors, entry point, and flags mask are set
    // correctly according to the kernel implementation.
    unsafe {
        Star::write_raw(gdt::SYSRET_SEL.0, gdt::SYSCALL_SEL.0);
        LStar::write(VirtAddr::new(syscall_entry as *const () as usize as u64));
        SFMask::write(RFlags::from_bits(RFLAGS_MASK).unwrap());
    }
}

unsafe extern "C" {
    unsafe fn syscall_entry();
    unsafe fn syscall_return(regs: &mut RawUserContext);
}

impl RawUserContext {
    /// Goes to user space with the context, and comes back when a trap occurs.
    ///
    /// On return, the context will be reset to the status before the trap.
    /// Trap reason and error code will be placed at `trap_num` and `error_code`.
    ///
    /// If the trap was triggered by `syscall` instruction, the `trap_num` will be set to `0x100`.
    ///
    /// If `trap_num` is `0x100`, it will go user by `sysret` (`rcx` and `r11` are dropped),
    /// otherwise it will use `iret`.
    // Keep the small native entry wrapper inside its hot caller; optional
    // per-call profiling has a separate, larger body.
    #[cfg_attr(not(kernelet_getpid_profile), inline(always))]
    pub(in crate::arch) fn run(&mut self, guard: DisabledLocalIrqGuard) {
        #[cfg(kernelet_getpid_profile)]
        let raw_span = if profile::enabled() {
            profile::event(profile::event_id::RAW_RUN);
            // These are the actual syscall.S tests. Trap number is not one
            // of them; an IRQ-restored context may also qualify for SYSRET.
            let rcx_matches = self.general.rcx == self.general.rip;
            let r11_matches = self.general.r11 == self.rflags;
            let flags_allow = self.general.r11 & 0x10100 == 0;
            let shift = usize::BITS - crate::arch::mm::PagingConsts::ADDRESS_WIDTH as u32;
            let canonical =
                (((self.general.rip << shift) as isize) >> shift) as usize == self.general.rip;
            if !rcx_matches {
                profile::event(profile::event_id::SYSRET_RCX_MISMATCH);
            }
            if !r11_matches {
                profile::event(profile::event_id::SYSRET_R11_MISMATCH);
            }
            if !flags_allow {
                profile::event(profile::event_id::SYSRET_RF_TF);
            }
            if !canonical {
                profile::event(profile::event_id::SYSRET_NONCANONICAL);
            }
            if rcx_matches && r11_matches && flags_allow && canonical {
                profile::event(profile::event_id::SYSRET_ELIGIBLE);
            }
            profile::span(profile::stage::NATIVE_RAW_RUN)
        } else {
            None
        };
        // Return to userspace with interrupts disabled. Otherwise, interrupts
        // after executing `swapgs` will mess up the CPU state.
        core::mem::forget(guard);

        // SAFETY: The native entry assembly uses the common register layout.
        // The interrupt guard keeps entry atomic, and the context stays live
        // until the matching syscall/trap has saved the register file in it.
        unsafe { syscall_return(self) };
        #[cfg(feature = "kernelet-host")]
        {
            self.fault_addr = if self.trap_num == 14 {
                x86_64::registers::control::Cr2::read_raw() as usize
            } else {
                0
            };
        }
        #[cfg(kernelet_getpid_profile)]
        {
            let _ = profile::end(raw_span);
            if profile::enabled() {
                profile::event(if self.trap_num == 0x100 {
                    profile::event_id::RETURN_SYSCALL
                } else if self.trap_num <= 31 {
                    profile::event_id::RETURN_EXCEPTION
                } else {
                    profile::event_id::RETURN_IRQ
                });
            }
        }
    }
}
