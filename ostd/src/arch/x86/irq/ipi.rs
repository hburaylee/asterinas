// SPDX-License-Identifier: MPL-2.0

//! Inter-processor interrupts.

use spin::Once;

use crate::{
    arch::kernel::apic::{self, ApicId, DestinationShorthand, Icr},
    cpu::PinCurrentCpu,
    irq::IrqLine,
    prelude::Result,
    smp,
};

/// Hardware-specific, architecture-dependent CPU ID.
///
/// This is the Local APIC ID in the x86_64 architecture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HwCpuId(u32);

impl HwCpuId {
    pub(crate) fn read_current(guard: &dyn PinCurrentCpu) -> Self {
        let apic = apic::get_or_init(guard);
        Self(apic.id())
    }
}

static IPI_IRQ: Once<IrqLine> = Once::new();

/// Initializes global IPI state.
pub(in crate::arch) fn init() {
    let mut irq = IrqLine::alloc().unwrap();
    // SAFETY: This will be called upon an inter-processor interrupt.
    irq.on_active(|f| unsafe { smp::do_inter_processor_call(f) });
    IPI_IRQ.call_once(|| irq);
}

/// Sends a general inter-processor interrupt (IPI) to the specified CPU.
pub(crate) fn send_ipi(hw_cpu_id: HwCpuId, guard: &dyn PinCurrentCpu) -> Result<()> {
    send_to(
        ApicId::from(hw_cpu_id.0),
        DestinationShorthand::NoShorthand,
        guard,
    )
}

/// Sends a real IPI to the current CPU without reading its APIC ID.
#[cfg(feature = "kernelet-host")]
pub(crate) fn send_self_ipi(guard: &dyn PinCurrentCpu) -> Result<()> {
    // The destination field is ignored when using the self shorthand.
    send_to(ApicId::from(0), DestinationShorthand::MySelf, guard)
}

fn send_to(
    destination: ApicId,
    shorthand: DestinationShorthand,
    guard: &dyn PinCurrentCpu,
) -> Result<()> {
    let irq_num = IPI_IRQ.get().unwrap().num();

    let icr = Icr::new(
        destination,
        shorthand,
        apic::TriggerMode::Edge,
        apic::Level::Assert,
        apic::DeliveryStatus::Idle,
        apic::DestinationMode::Physical,
        apic::DeliveryMode::Fixed,
        irq_num,
    );

    let apic = apic::get_or_init(guard);
    // SAFETY: The ICR is valid to generate the request IPI. Generating the
    // request IPI is safe.
    unsafe { apic.send_ipi(icr) };

    Ok(())
}
