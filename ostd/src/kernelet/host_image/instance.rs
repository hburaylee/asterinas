// SPDX-License-Identifier: MPL-2.0

//! Private image-instance construction and its contiguous mapping plan.

use alloc::vec;
use core::mem::offset_of;

use super::{
    super::{
        abi::{BootArgs, DeviceEntry, MAX_VCPUS, VcpuRecord, vcpu_shared_bytes},
        host_grant::Grant,
    },
    *,
};
use crate::arch::mm::tlb_flush_addr_range;

impl RegisteredImage {
    /// Creates a new instance of the kind: one contiguous mapping in the
    /// shared kernel address space that holds the kind's shared read-only
    /// segments and this instance's private, relocated writable segment.
    ///
    /// The instance's writable huge page is a fresh copy of the data template,
    /// and every relocation stores the instance's base plus the entry's
    /// addend, so identical instructions executed through different
    /// instances' mappings reach each instance's own data.
    ///
    /// Frame or kernel virtual address exhaustion returns [`Error::NoMemory`].
    pub(crate) fn instantiate(
        &self,
        boot: &BootArgs,
        cmdline: &str,
        devices: &[DeviceEntry],
        grant: &Grant,
    ) -> Result<ImageInstance> {
        let devices_offset =
            (size_of::<BootArgs>() + cmdline.len()).next_multiple_of(align_of::<DeviceEntry>());
        let devices_bytes = devices
            .len()
            .checked_mul(size_of::<DeviceEntry>())
            .ok_or(Error::Overflow)?;
        if devices_offset
            .checked_add(devices_bytes)
            .is_none_or(|end| end > PAGE_SIZE)
        {
            return Err(Error::InvalidArgs);
        }
        if boot.num_vcpus == 0 || usize::from(boot.num_vcpus) > MAX_VCPUS {
            return Err(Error::InvalidArgs);
        }

        // 1. One fresh, 2 MiB private segment for the writable template,
        //    followed by a page-aligned replica for every virtual CPU.
        let data_segment = self.instantiate_data_segment()?;
        let local_size = (self.entry_table.cpu_local_end_offset
            - self.entry_table.cpu_local_start_offset) as usize;
        let pages_per_vcpu = local_size.div_ceil(PAGE_SIZE);
        let replica_pages = pages_per_vcpu
            .checked_mul(usize::from(boot.num_vcpus))
            .ok_or(Error::Overflow)?;
        let cpu_local_frames: Vec<_> = (0..replica_pages)
            .map(|_| FrameAllocOptions::new().alloc_frame())
            .collect::<Result<_>>()?;
        let shared_offset = self
            .replicas_offset
            .checked_add(
                replica_pages
                    .checked_mul(PAGE_SIZE)
                    .ok_or(Error::Overflow)?,
            )
            .ok_or(Error::Overflow)?;
        let boot_frame = FrameAllocOptions::new().alloc_frame()?;
        let record_pages = vcpu_shared_bytes(boot.num_vcpus as usize).div_ceil(PAGE_SIZE);
        let vcpu_frames: Vec<_> = (0..record_pages)
            .map(|_| FrameAllocOptions::new().alloc_frame())
            .collect::<Result<_>>()?;

        // 2. Map the image, every private CPU-local replica, and Host-shared
        //    pages in one contiguous area. ELF code/data offsets stay fixed;
        //    only the shared-page offset depends on the virtual CPU count.
        let shared_pages = 1usize
            .checked_add(record_pages)
            .and_then(|pages| pages.checked_add(grant.shared_pages()))
            .ok_or(Error::Overflow)?;
        let mapping_size = shared_offset
            .checked_add(shared_pages.checked_mul(PAGE_SIZE).ok_or(Error::Overflow)?)
            .ok_or(Error::Overflow)?;
        let [after_text, after_rodata, after_data] = self.gap_pages;

        // Both virtual and physical image runs are 2 MiB aligned, yielding
        // huge PTEs with distinct text, read-only, and writable permissions.
        // The area owns every mapped segment through its final shootdown.
        let mut kvirt = KVirtArea::try_reserve_aligned(mapping_size, HUGE_PAGE_SIZE)?
            .with_synchronous_reclaim();
        let huge_runs = [
            (self.text_frames.clone(), TEXT_PAGE_PROP),
            (
                filler_segments(self.filler.as_ref(), after_text)?,
                READONLY_PAGE_PROP,
            ),
            (self.rodata_frames.clone(), READONLY_PAGE_PROP),
            (
                filler_segments(self.filler.as_ref(), after_rodata)?,
                READONLY_PAGE_PROP,
            ),
            (data_segment.iter().cloned().collect(), DATA_PAGE_PROP),
            (
                filler_segments(self.filler.as_ref(), after_data)?,
                READONLY_PAGE_PROP,
            ),
        ];
        let mut mapped = 0;
        for (segments, prop) in huge_runs {
            if segments.is_empty() {
                continue;
            }
            let bytes = segments.len() * HUGE_PAGE_SIZE;
            kvirt.map_additional_segments(mapped, segments.into_iter(), prop)?;
            mapped += bytes;
        }
        let base_runs = [
            (cpu_local_frames.clone(), DATA_PAGE_PROP),
            (vec![boot_frame.clone()], READONLY_PAGE_PROP),
            (vcpu_frames.clone(), DATA_PAGE_PROP),
            (grant.shared_frames().collect(), READONLY_PAGE_PROP),
        ];
        for (frames, prop) in base_runs {
            let count = frames.len();
            if count == 0 {
                continue;
            }
            kvirt.map_additional_frames(mapped, frames.into_iter(), prop)?;
            mapped += count * PAGE_SIZE;
        }
        // The runs must cover the reservation exactly, as the layout offsets
        // baked into the registered image presume.
        assert_eq!(mapped, mapping_size);
        let base = kvirt.start();

        let mut boot = *boot;
        boot.meta_base = grant.meta_base();
        boot.info_page = ((1 + record_pages) * PAGE_SIZE) as u32;
        boot.grant_table = ((2 + record_pages) * PAGE_SIZE) as u32;
        boot.meta_section_index = ((2 + record_pages + grant.run_pages()) * PAGE_SIZE) as u32;
        boot.meta_block_sections =
            ((2 + record_pages + grant.run_pages() + grant.index_pages()) * PAGE_SIZE) as u32;
        boot.meta_grain_bitmap =
            ((2 + record_pages + grant.run_pages() + grant.index_pages() + grant.reverse_pages())
                * PAGE_SIZE) as u32;
        boot.cmdline_offset = size_of::<BootArgs>() as u32;
        boot.cmdline_len = cmdline.len() as u32;
        boot.devices_offset = devices_offset as u32;
        boot.num_devices = devices.len() as u32;
        write_boot_args(&boot_frame, &boot)?;
        boot_frame.write_bytes(boot.cmdline_offset as usize, cmdline.as_bytes())?;
        for (index, device) in devices.iter().enumerate() {
            let offset = devices_offset + index * size_of::<DeviceEntry>();
            boot_frame.write_bytes(offset, &device.id.to_le_bytes())?;
            boot_frame.write_bytes(offset + 2, &device.kind.to_le_bytes())?;
            boot_frame.write_bytes(offset + 4, &[device.irq, device.reserved])?;
            boot_frame.write_bytes(offset + 6, &device.vcpu.to_le_bytes())?;
            boot_frame.write_bytes(offset + 8, &device.reg_bytes.to_le_bytes())?;
            boot_frame.write_bytes(offset + 12, &device.device_type.to_le_bytes())?;
            boot_frame.write_bytes(offset + 16, &device.mmio_base.to_le_bytes())?;
        }

        // 3. The kernel virtual area contract requires the caller to ensure
        //    TLB coherence before using the new mapping on a CPU. The range
        //    was freshly allocated, but a previous owner of the same range
        //    may have left translations on this CPU.
        tlb_flush_addr_range(&kvirt.range());

        // 4. Relocate this instance's private data: store `base + addend` at
        //    `base + target_offset`. The writes go through each frame's own
        //    linear-map alias, so no further TLB interaction is involved.
        if let Some(data) = &self.data {
            let base = base as u64;
            for relocation in &self.relocations {
                let in_segment = relocation.target_offset - data.vaddr;
                let index = (in_segment / PAGE_SIZE_U64) as usize;
                let in_frame = (in_segment % PAGE_SIZE_U64) as usize;
                let value = base
                    .checked_add_signed(relocation.addend)
                    .ok_or(Error::Overflow)?;
                // Registration has validated that every relocation target
                // lies inside the private data segment.
                let segment = data_segment.as_ref().ok_or(Error::InvalidArgs)?;
                let frame = segment
                    .slice(&(index * PAGE_SIZE..(index + 1) * PAGE_SIZE))
                    .into_iter()
                    .next()
                    .ok_or(Error::InvalidArgs)?;
                frame.write_bytes(in_frame, &value.to_le_bytes())?;
            }
        }

        for vcpu in 0..boot.num_vcpus as usize {
            let local_base = if local_size == 0 {
                base + self.entry_table.cpu_local_start_offset as usize
            } else {
                let addr = base + self.replicas_offset + vcpu * pages_per_vcpu * PAGE_SIZE;
                // SAFETY: Both ranges are private mapped bytes. The source is
                // the initialized, relocated CPU-local template; the
                // destination is this vCPU's mapped replica, before entry.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (base + self.entry_table.cpu_local_start_offset as usize) as *const u8,
                        addr as *mut u8,
                        local_size,
                    )
                };
                addr
            };
            let offset = vcpu * size_of::<VcpuRecord>();
            let frame = &vcpu_frames[offset / PAGE_SIZE];
            let offset = offset % PAGE_SIZE;
            frame.write_bytes(
                offset + offset_of!(VcpuRecord, cpu_local_base),
                &(local_base as u64).to_le_bytes(),
            )?;
            frame.write_bytes(
                offset + offset_of!(VcpuRecord, vcpu),
                &(vcpu as u32).to_le_bytes(),
            )?;
        }

        Ok(ImageInstance {
            kvirt,
            _data_segment: data_segment,
            _boot_frame: boot_frame,
            _vcpu_frames: vcpu_frames,
            _cpu_local_frames: cpu_local_frames,
            vcpu_entry: base + self.entry_table.vcpu_entry_offset as usize,
            entry_offset: usize::try_from(self.entry_offset).map_err(|_| Error::Overflow)?,
            text_start: base + usize::try_from(self.text.vaddr).map_err(|_| Error::Overflow)?,
            text_end: base
                + usize::try_from(
                    self.text
                        .vaddr
                        .checked_add(self.text.memsz)
                        .ok_or(Error::Overflow)?,
                )
                .map_err(|_| Error::Overflow)?,
            virq_entry: base
                + usize::try_from(self.entry_table.virq_entry_offset)
                    .map_err(|_| Error::Overflow)?,
            yield_entry: base
                + usize::try_from(self.entry_table.yield_entry_offset)
                    .map_err(|_| Error::Overflow)?,
            exit_entry: base
                + usize::try_from(self.entry_table.exit_entry_offset)
                    .map_err(|_| Error::Overflow)?,
            stub_range: (base
                + usize::try_from(self.entry_table.stub_range_start_offset)
                    .map_err(|_| Error::Overflow)?)
                ..(base
                    + usize::try_from(self.entry_table.stub_range_end_offset)
                        .map_err(|_| Error::Overflow)?),
            cpu_access_range: (base
                + usize::try_from(self.entry_table.cpu_access_start_offset)
                    .map_err(|_| Error::Overflow)?)
                ..(base
                    + usize::try_from(self.entry_table.cpu_access_end_offset)
                        .map_err(|_| Error::Overflow)?),
            ex_table_start: base
                + usize::try_from(self.entry_table.ex_table_start_offset)
                    .map_err(|_| Error::Overflow)?,
            ex_table_end: base
                + usize::try_from(self.entry_table.ex_table_end_offset)
                    .map_err(|_| Error::Overflow)?,
            shared_offset,
        })
    }

    /// Copies the writable template into one fresh, zeroed segment of
    /// [`HUGE_PAGE_SIZE`] bytes.
    /// Only the file-backed head needs copying; the `.bss` tail stays zero.
    fn instantiate_data_segment(&self) -> Result<Option<Segment<()>>> {
        if self.data.is_none() {
            return Ok(None);
        }
        let segment =
            FrameAllocOptions::new().alloc_segment_aligned(FRAMES_PER_HUGE_PAGE, HUGE_PAGE_SIZE)?;
        let mut buf = vec![0u8; PAGE_SIZE];
        for (index, template) in self.data_template.iter().enumerate() {
            let chunk_len = self.template_chunk_len(index);
            if chunk_len > 0 {
                template.read_bytes(0, &mut buf[..chunk_len])?;
                let frame = segment
                    .slice(&(index * PAGE_SIZE..(index + 1) * PAGE_SIZE))
                    .into_iter()
                    .next()
                    .ok_or(Error::InvalidArgs)?;
                frame.write_bytes(0, &buf[..chunk_len])?;
            }
        }
        Ok(Some(segment))
    }

    /// Returns the number of template bytes held by frame `index`.
    fn template_chunk_len(&self, index: usize) -> usize {
        let Some(data) = &self.data else {
            return 0;
        };
        let start = index as u64 * PAGE_SIZE_U64;
        if start >= data.filesz {
            return 0;
        }
        (data.filesz - start).min(PAGE_SIZE_U64) as usize
    }
}

/// Yields the shared read-only filler segments covering one 2 MiB-aligned gap.
///
/// Registration guarantees that a nonzero gap has a filler page to cover it;
/// a missing filler for a nonzero gap is rejected instead of silently
/// collapsing the layout slot.
fn filler_segments(filler: Option<&Segment<()>>, pages: usize) -> Result<Vec<Segment<()>>> {
    let Some(filler) = filler else {
        if pages == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::InvalidArgs);
    };
    let mut segments = Vec::new();
    segments
        .try_reserve_exact(pages)
        .map_err(|_| Error::NoMemory)?;
    segments.resize_with(pages, || filler.clone());
    Ok(segments)
}

/// Serializes the fixed boot ABI into a page without creating an alias to its
/// read-only image mapping.
fn write_boot_args(frame: &Frame<()>, boot: &BootArgs) -> Result<()> {
    frame.write_bytes(offset_of!(BootArgs, size), &boot.size.to_le_bytes())?;
    frame.write_bytes(
        offset_of!(BootArgs, generation),
        &boot.generation.to_le_bytes(),
    )?;
    frame.write_bytes(offset_of!(BootArgs, source_hash), &boot.source_hash)?;
    frame.write_bytes(
        offset_of!(BootArgs, tsc_freq_hz),
        &boot.tsc_freq_hz.to_le_bytes(),
    )?;
    frame.write_bytes(
        offset_of!(BootArgs, clock_origin_tsc),
        &boot.clock_origin_tsc.to_le_bytes(),
    )?;
    frame.write_bytes(offset_of!(BootArgs, kernelet), &boot.kernelet.to_le_bytes())?;
    frame.write_bytes(
        offset_of!(BootArgs, num_vcpus),
        &boot.num_vcpus.to_le_bytes(),
    )?;

    let mut vcpu_host_cpu = [0u8; MAX_VCPUS * size_of::<u16>()];
    for (bytes, cpu) in vcpu_host_cpu.chunks_exact_mut(2).zip(boot.vcpu_host_cpu) {
        bytes.copy_from_slice(&cpu.to_le_bytes());
    }
    frame.write_bytes(offset_of!(BootArgs, vcpu_host_cpu), &vcpu_host_cpu)?;

    frame.write_bytes(
        offset_of!(BootArgs, cpu_slot_gs_offset),
        &boot.cpu_slot_gs_offset.to_le_bytes(),
    )?;
    frame.write_bytes(
        offset_of!(BootArgs, cpu_local_replica_bytes),
        &boot.cpu_local_replica_bytes.to_le_bytes(),
    )?;
    frame.write_bytes(
        offset_of!(BootArgs, linear_map_base),
        &boot.linear_map_base.to_le_bytes(),
    )?;
    for (index, entry) in boot.kernel_half_entries.iter().enumerate() {
        frame.write_bytes(
            offset_of!(BootArgs, kernel_half_entries) + index * size_of::<u64>(),
            &entry.to_le_bytes(),
        )?;
    }
    frame.write_bytes(
        offset_of!(BootArgs, meta_base),
        &boot.meta_base.to_le_bytes(),
    )?;
    frame.write_bytes(
        offset_of!(BootArgs, grant_table),
        &boot.grant_table.to_le_bytes(),
    )?;
    frame.write_bytes(
        offset_of!(BootArgs, meta_section_index),
        &boot.meta_section_index.to_le_bytes(),
    )?;
    frame.write_bytes(
        offset_of!(BootArgs, meta_block_sections),
        &boot.meta_block_sections.to_le_bytes(),
    )?;
    frame.write_bytes(
        offset_of!(BootArgs, meta_grain_bitmap),
        &boot.meta_grain_bitmap.to_le_bytes(),
    )?;
    frame.write_bytes(
        offset_of!(BootArgs, max_meta_sections),
        &boot.max_meta_sections.to_le_bytes(),
    )?;
    frame.write_bytes(
        offset_of!(BootArgs, info_page),
        &boot.info_page.to_le_bytes(),
    )?;
    frame.write_bytes(
        offset_of!(BootArgs, vcpu_records),
        &boot.vcpu_records.to_le_bytes(),
    )?;
    frame.write_bytes(
        offset_of!(BootArgs, max_tasks),
        &boot.max_tasks.to_le_bytes(),
    )?;
    frame.write_bytes(
        offset_of!(BootArgs, fpu_area_bytes),
        &boot.fpu_area_bytes.to_le_bytes(),
    )?;
    frame.write_bytes(
        offset_of!(BootArgs, cmdline_offset),
        &boot.cmdline_offset.to_le_bytes(),
    )?;
    frame.write_bytes(
        offset_of!(BootArgs, cmdline_len),
        &boot.cmdline_len.to_le_bytes(),
    )?;
    frame.write_bytes(
        offset_of!(BootArgs, devices_offset),
        &boot.devices_offset.to_le_bytes(),
    )?;
    frame.write_bytes(
        offset_of!(BootArgs, num_devices),
        &boot.num_devices.to_le_bytes(),
    )?;
    frame.write_bytes(offset_of!(BootArgs, reserved), &boot.reserved.to_le_bytes())?;
    frame.write_bytes(
        offset_of!(BootArgs, realtime_base_ns),
        &boot.realtime_base_ns.to_le_bytes(),
    )?;
    frame.write_bytes(
        offset_of!(BootArgs, monotonic_base_ns),
        &boot.monotonic_base_ns.to_le_bytes(),
    )?;
    Ok(())
}
