// SPDX-License-Identifier: MPL-2.0

//! Interrupts.

// Set this module's log prefix for `ostd::log`.
macro_rules! __log_prefix {
    () => {
        "irq: "
    };
}

pub(super) mod chip;
pub(super) mod ipi;
#[cfg_attr(feature = "kernelet", path = "kernelet_ops.rs")]
mod ops;
mod remapping;

#[cfg(not(feature = "kernelet"))]
pub use chip::{IRQ_CHIP, IrqChip, MappedIrqLine};
pub(crate) use ipi::{HwCpuId, send_ipi};
#[cfg(not(feature = "kernelet"))]
pub(crate) use ops::enable_local_and_halt;
pub(crate) use ops::{disable_local, disable_local_and_halt, enable_local, is_local_enabled};
pub(crate) use remapping::IrqRemapping;

#[cfg(not(feature = "kernelet"))]
use crate::arch::{cpu, kernel};
#[cfg(feature = "kernelet")]
pub use crate::irq::IrqLine as MappedIrqLine;

// Intel(R) 64 and IA-32 architectures Software Developer's Manual,
// Volume 3A, Section 6.2 says "Vector numbers in the range 32 to 255
// are designated as user-defined interrupts and are not reserved by
// the Intel 64 and IA-32 architecture."
pub(crate) const IRQ_NUM_MIN: u8 = 32;
pub(crate) const IRQ_NUM_MAX: u8 = 255;

/// An IRQ line with additional information that helps acknowledge the interrupt
/// on hardware.
///
/// On x86-64, it's the hardware (i.e., the I/O APIC and local APIC) that routes
/// the interrupt to the IRQ line. Therefore, the software does not need to
/// maintain additional information about the original hardware interrupt.
pub(crate) struct HwIrqLine {
    irq_num: u8,
}

impl HwIrqLine {
    pub(crate) fn new(irq_num: u8) -> Self {
        Self { irq_num }
    }

    pub(crate) fn irq_num(&self) -> u8 {
        self.irq_num
    }

    pub(crate) fn ack(&self) {
        #[cfg(feature = "kernelet")]
        return;

        #[cfg(not(feature = "kernelet"))]
        {
            debug_assert!(!cpu::context::CpuException::is_cpu_exception(
                self.irq_num as usize
            ));
            // TODO: We're in the interrupt context, so `disable_preempt()` is not
            // really necessary here.
            kernel::apic::get_or_init(&crate::task::disable_preempt() as _).eoi();
        }
    }
}
