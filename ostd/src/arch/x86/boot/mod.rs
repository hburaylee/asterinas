// SPDX-License-Identifier: MPL-2.0

//! The x86 boot module defines the entrypoints of Asterinas and
//! the corresponding headers for different x86 boot protocols.
//!
//! We directly support
//!
//!  - Multiboot
//!  - Multiboot2
//!  - Linux x86 Boot Protocol
//!  - PVH
//!
//! without any additional configurations.
//!
//! Asterinas differentiates the boot protocol by the entry point
//! chosen by the boot loader. In each entry point function,
//! the universal callback registration method from
//! `crate::boot` will be called. Thus the initialization of
//! boot information is transparent for the upper level kernel.
//!

mod linux_boot;
mod multiboot;
mod multiboot2;
mod pvh;

pub(crate) mod smp;

use core::{arch::global_asm, num::NonZeroUsize};

use acpi::rsdp::Rsdp;

use crate::{arch::kernel::acpi::AcpiMemoryHandler, boot::memory_region::MemoryRegionType};

global_asm!(
    include_str!("bsp_boot.S"),
    KCODE64 = const super::trap::gdt::KCODE64,
    KDATA = const super::trap::gdt::KDATA,
    KCODE32 = const super::trap::gdt::KCODE32,
);
global_asm!(include_str!("ap_boot.S"));

/// Finds the physical address of the ACPI root table.
pub(super) fn find_acpi_root_table_address() -> Option<NonZeroUsize> {
    // Multiboot v1 is BIOS-oriented: its entry state and boot information are
    // based on the legacy PC BIOS model, and it has no standard EFI System
    // Table field. So we use the BIOS RSDP scan as the legacy fallback. The
    // PVH entry path under QEMU also goes through SeaBIOS (the pvh.bin option
    // ROM may leave `rsdp_paddr` zero), so it relies on the same scan.
    //
    // SAFETY: These entry paths are treated as BIOS-compatible.
    let Ok(rsdp) = (unsafe { Rsdp::search_for_on_bios(AcpiMemoryHandler {}) }) else {
        return None;
    };

    if rsdp.revision() == 0 {
        NonZeroUsize::new(rsdp.rsdt_address() as usize)
    } else {
        NonZeroUsize::new(rsdp.xsdt_address() as usize)
    }
}

/// Promotes a reserved region containing the ACPI root table to `Reclaimable`.
pub(super) fn effective_region_type(
    typ: MemoryRegionType,
    base: usize,
    len: usize,
    acpi_root_table_address: Option<NonZeroUsize>,
) -> MemoryRegionType {
    if typ == MemoryRegionType::Reserved
        && acpi_root_table_address.is_some_and(|addr| (base..(base + len)).contains(&addr.get()))
    {
        MemoryRegionType::Reclaimable
    } else {
        typ
    }
}
