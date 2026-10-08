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

global_asm!(include_str!("trap.S"), interrupt_level = sym crate::irq::INTERRUPT_LEVEL);

const NUM_INTERRUPTS: usize = 256;

unsafe extern "C" {
    #[link_name = "trap_handler_table"]
    static VECTORS: [usize; NUM_INTERRUPTS];
}

static GLOBAL_IDT: Once<[Entry<()>; NUM_INTERRUPTS]> = Once::new();
static IMAGE_IDT: Once<[Entry<()>; NUM_INTERRUPTS]> = Once::new();

/// Returns the IDT base address.
pub(in crate::arch) fn idt_base() -> Vaddr {
    GLOBAL_IDT.get().unwrap().as_ptr() as Vaddr
}

fn build_idt(image: bool) -> [Entry<()>; NUM_INTERRUPTS] {
    let mut idt = [const { Entry::missing() }; NUM_INTERRUPTS];
    // SAFETY: The assembly vector array is immutable and has one entry per vector.
    let vectors = unsafe { &VECTORS };
    for (intr_no, &handler) in vectors.iter().enumerate() {
        // SAFETY: Every target implements the corresponding architectural trap frame.
        let options = unsafe { idt[intr_no].set_handler_addr(VirtAddr::new(handler as u64)) };
        if intr_no == 3 || intr_no == 4 {
            options.set_privilege_level(PrivilegeLevel::Ring3);
        }
        if image {
            let stack = match intr_no {
                2 => 1,
                8 => 2,
                18 => 3,
                1 => 4,
                _ => 0,
            };
            // SAFETY: The image IDT is installed only after this carrier's five
            // private TSS landing stacks are populated. NMI, double fault,
            // machine check and debug have distinct stacks. The entry adapter
            // restores the native IDT before handlers can enable interrupts.
            unsafe { options.set_stack_index(stack) };
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

/// Returns the native and protected-image IDT descriptors after boot setup.
pub(crate) fn carrier_idtrs() -> (DescriptorTablePointer, DescriptorTablePointer) {
    (
        pointer(GLOBAL_IDT.get().unwrap()),
        pointer(IMAGE_IDT.get().unwrap()),
    )
}

/// Initializes the native IDT and prepares the image-only IST variant.
pub(super) fn init_on_cpu() {
    let idt = GLOBAL_IDT.call_once(|| build_idt(false));
    IMAGE_IDT.call_once(|| build_idt(true));
    // SAFETY: The table is immutable, permanent, and contains the audited handlers.
    unsafe { lidt(&pointer(idt)) };
}
