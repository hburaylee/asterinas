// SPDX-License-Identifier: MPL-2.0

//! Validates Host configuration and constructs immutable image boot metadata.

use super::KerneletConfig;
use crate::{
    Error,
    kernelet::{abi::BootArgs, host_image::RegisteredImage},
    mm::PAGE_SIZE,
    util::id_set::Id,
};

pub(super) fn validate_config(config: &KerneletConfig<'_>) -> crate::Result<()> {
    config.budget.validate()?;
    if config.cpus.is_empty()
        || config.cpus.count() > super::super::abi::MAX_VCPUS
        || (config.max_tasks as usize) < config.cpus.count()
        || config.devices.len() > 64
    {
        return Err(Error::InvalidArgs);
    }
    let physical_end = crate::mm::frame::max_paddr() as u64;
    for (index, device) in config.devices.iter().enumerate() {
        let end = device
            .mmio_base
            .checked_add(device.reg_bytes as u64)
            .ok_or(Error::InvalidArgs)?;
        if device.kind != 1
            || device.irq < 32
            || device.vcpu as usize >= config.cpus.count()
            || device.reg_bytes == 0
            || !device.reg_bytes.is_multiple_of(PAGE_SIZE as u32)
            || !device.mmio_base.is_multiple_of(PAGE_SIZE as u64)
            || device.mmio_base < physical_end
            || device.reserved != 0
        {
            return Err(Error::InvalidArgs);
        }
        for other in &config.devices[..index] {
            let other_end = other.mmio_base + other.reg_bytes as u64;
            if device.id == other.id
                || device.irq == other.irq
                || (device.mmio_base < other_end && other.mmio_base < end)
            {
                return Err(Error::InvalidArgs);
            }
        }
    }
    Ok(())
}

pub(super) fn boot_args(
    image: &RegisteredImage,
    config: &KerneletConfig<'_>,
) -> crate::Result<BootArgs> {
    let cpu_local_bytes =
        image.entry_table().cpu_local_end_offset - image.entry_table().cpu_local_start_offset;
    let mut vcpu_host_cpu = [0u16; super::super::abi::MAX_VCPUS];
    for (index, cpu) in config.cpus.iter().enumerate() {
        vcpu_host_cpu[index] = cpu.as_usize().try_into().map_err(|_| Error::InvalidArgs)?;
    }
    Ok(BootArgs {
        size: size_of::<BootArgs>() as u32,
        generation: 1,
        source_hash: image.entry_table().source_hash,
        tsc_freq_hz: crate::arch::tsc_freq(),
        kernelet: 1,
        num_vcpus: config.cpus.count() as u16,
        vcpu_host_cpu,
        cpu_slot_gs_offset: crate::cpu::host_cpu_gs_offset(),
        host_preempt_gs_offset: crate::task::carrier_preempt::gs_offset(),
        cpu_local_replica_bytes: cpu_local_bytes.try_into().map_err(|_| Error::InvalidArgs)?,
        linear_map_base: crate::mm::kspace::LINEAR_MAPPING_BASE_VADDR as u64,
        kernel_half_entries: kernel_half_entries(),
        meta_base: 0,
        grant_table: 0,
        meta_section_index: 0,
        meta_block_sections: 0,
        max_meta_sections: config.max_meta_sections,
        clock_page: 0,
        info_page: 0,
        vcpu_records: PAGE_SIZE as u32,
        max_tasks: config.max_tasks,
        fpu_area_bytes: crate::arch::cpu::context::fpu_area_bytes() as u32,
        cmdline_offset: 0,
        cmdline_len: 0,
        devices_offset: 0,
        num_devices: 0,
        reserved: 0,
        realtime_base_ns: 0,
        monotonic_base_ns: 0,
    })
}

fn kernel_half_entries() -> [u64; 256] {
    let root = crate::arch::mm::current_page_table_paddr();
    let ptr = crate::mm::kspace::paddr_to_vaddr(root) as *const u64;
    let mut entries = [0u64; 256];
    for (index, entry) in entries.iter_mut().enumerate() {
        // SAFETY: CR3 names the current, pinned root page and the Host linear
        // map covers it. Only the kernel-half entries are read.
        *entry = unsafe { ptr.add(256 + index).read() };
    }
    entries
}

/// Decodes the source/toolchain hash that OSDK embedded in the Host build.
pub(super) fn host_source_hash() -> crate::Result<[u8; 32]> {
    let hex = option_env!("KERNELET_SOURCE_HASH").ok_or(Error::InvalidArgs)?;
    if hex.len() != 64 {
        return Err(Error::InvalidArgs);
    }
    let mut hash = [0; 32];
    for (byte, digits) in hash
        .iter_mut()
        .zip(hex.as_bytes().as_chunks::<2>().0.iter())
    {
        let high = hex_digit(digits[0]).ok_or(Error::InvalidArgs)?;
        let low = hex_digit(digits[1]).ok_or(Error::InvalidArgs)?;
        *byte = (high << 4) | low;
    }
    Ok(hash)
}

fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}
