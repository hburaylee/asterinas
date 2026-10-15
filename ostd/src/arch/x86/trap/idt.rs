// SPDX-License-Identifier: MPL-2.0

//! Configure the Interrupt Descriptor Table (IDT).

use core::arch::global_asm;

use spin::Once;
use x86_64::{
    PrivilegeLevel, VirtAddr,
    instructions::tables::lidt,
    structures::{DescriptorTablePointer, idt::Entry},
};

use crate::mm::Vaddr;

global_asm!(include_str!("trap.S"));

const NUM_INTERRUPTS: usize = 256;

unsafe extern "C" {
    #[link_name = "trap_handler_table"]
    static VECTORS: [usize; NUM_INTERRUPTS];
}

static GLOBAL_IDT: Once<[Entry<()>; NUM_INTERRUPTS]> = Once::new();

/// Returns the IDT base address.
pub(in crate::arch) fn idt_base() -> Vaddr {
    GLOBAL_IDT.get().unwrap().as_ptr() as Vaddr
}

fn build_idt() -> [Entry<()>; NUM_INTERRUPTS] {
    let mut idt = [const { Entry::missing() }; NUM_INTERRUPTS];
    // SAFETY: The assembly vector array is immutable and has one entry per vector.
    let vectors = unsafe { &VECTORS };
    for (intr_no, &handler) in vectors.iter().enumerate() {
        // SAFETY: Every target implements the corresponding architectural trap frame.
        let options = unsafe { idt[intr_no].set_handler_addr(VirtAddr::new(handler as u64)) };
        if intr_no == 3 || intr_no == 4 {
            options.set_privilege_level(PrivilegeLevel::Ring3);
        }
        if intr_no == 8 {
            // SAFETY: Each CPU installs its permanent double-fault stack in
            // TSS IST slot zero before loading this shared Host IDT.
            unsafe { options.set_stack_index(0) };
        }
    }
    idt
}

fn pointer(idt: &[Entry<()>]) -> DescriptorTablePointer {
    DescriptorTablePointer {
        limit: (size_of_val(idt) - 1) as u16,
        base: VirtAddr::new(idt.as_ptr().addr() as u64),
    }
}

/// Initializes the shared Host IDT. Only double fault selects an IST stack.
pub(super) fn init_on_cpu() {
    let idt = GLOBAL_IDT.call_once(build_idt);
    // SAFETY: The table is immutable, permanent, and contains the audited handlers.
    unsafe { lidt(&pointer(idt)) };
}
