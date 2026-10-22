// SPDX-License-Identifier: MPL-2.0

// Kernel-mode tests run the loader against synthetic images built in
// memory, shaped after the design's image format.

use core::mem::offset_of;

use super::{
    super::{
        abi::{BootArgs, MAX_VCPUS, VcpuRecord},
        host_grant::Grant,
    },
    elf::*,
    *,
};
use crate::{mm::kspace::MappedItemRef, prelude::*, task::disable_preempt};

/// Image offsets used by the synthetic image below.
const TEXT_VADDR: u64 = ENTRY_TABLE_OFFSET;
const CODE_VADDR: u64 = TEXT_VADDR + ENTRY_TABLE_SIZE;
const RELA_VADDR: u64 = CODE_VADDR + 16;
const DYN_VADDR: u64 = RELA_VADDR + RELA_ENTRY_SIZE;
const TEXT_FILE_BYTES: u64 = HUGE_PAGE_SIZE_U64 + ENTRY_TABLE_SIZE + 104;
const RODATA_VADDR: u64 = 3 * HUGE_PAGE_SIZE_U64;
const DATA_VADDR: u64 = 5 * HUGE_PAGE_SIZE_U64;

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_phdr(
    bytes: &mut Vec<u8>,
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
) {
    push_u32(bytes, p_type);
    push_u32(bytes, p_flags);
    push_u64(bytes, p_offset);
    push_u64(bytes, p_vaddr);
    push_u64(bytes, 0); // p_paddr
    push_u64(bytes, p_filesz);
    push_u64(bytes, p_memsz);
    push_u64(bytes, HUGE_PAGE_SIZE_U64); // p_align
}

/// Builds an image with 2 MiB-aligned permission transitions and one huge
/// read-only gap after both text and rodata.
fn test_image(reloc_info: u64, reloc_target: u64) -> Vec<u8> {
    let phdrs_end = (ELF_HEADER_SIZE + 4 * PHDR_ENTRY_SIZE) as u64;
    // File offsets and linked addresses have the same remainder modulo the
    // ELF segment alignment, as in the kernelet link image.
    let text_offset = TEXT_VADDR;
    let rodata_offset = 2 * HUGE_PAGE_SIZE_U64;
    let data_offset = 3 * HUGE_PAGE_SIZE_U64;

    let mut bytes = Vec::new();
    // ELF header.
    bytes.extend_from_slice(&[0x7F, b'E', b'L', b'F', ELFCLASS64, ELFDATA2LSB, 1, 0]);
    bytes.extend_from_slice(&[0u8; 8]);
    push_u16(&mut bytes, ET_DYN);
    push_u16(&mut bytes, EM_X86_64);
    push_u32(&mut bytes, 1); // e_version
    push_u64(&mut bytes, CODE_VADDR); // e_entry
    push_u64(&mut bytes, ELF_HEADER_SIZE as u64); // e_phoff
    push_u64(&mut bytes, 0); // e_shoff
    push_u32(&mut bytes, 0); // e_flags
    push_u16(&mut bytes, 64); // e_ehsize
    push_u16(&mut bytes, PHDR_ENTRY_SIZE as u16);
    push_u16(&mut bytes, 4); // e_phnum
    push_u16(&mut bytes, 0); // e_shentsize
    push_u16(&mut bytes, 0); // e_shnum
    push_u16(&mut bytes, 0); // e_shstrndx
    assert_eq!(bytes.len(), ELF_HEADER_SIZE);

    // Program headers.
    push_phdr(
        &mut bytes,
        PT_LOAD,
        PF_R | PF_X,
        text_offset,
        TEXT_VADDR,
        TEXT_FILE_BYTES,
        TEXT_FILE_BYTES,
    );
    push_phdr(&mut bytes, PT_LOAD, PF_R, rodata_offset, RODATA_VADDR, 8, 8);
    push_phdr(
        &mut bytes,
        PT_LOAD,
        PF_R | PF_W,
        data_offset,
        DATA_VADDR,
        8,
        0x100,
    );
    push_phdr(
        &mut bytes,
        PT_DYNAMIC,
        PF_R,
        text_offset + DYN_VADDR - TEXT_VADDR,
        DYN_VADDR,
        64,
        64,
    );
    assert_eq!(bytes.len() as u64, phdrs_end);

    // The entry table begins at offset 4 KiB from the image base, exactly
    // where the text PT_LOAD starts. The first huge mapping starts at base 0.
    bytes.resize(text_offset as usize, 0);
    push_u64(&mut bytes, ENTRY_TABLE_SIZE);
    push_u64(&mut bytes, CODE_VADDR); // vcpu_entry_offset
    push_u64(&mut bytes, CODE_VADDR); // virq_entry_offset
    push_u64(&mut bytes, 0); // cpu_local_start_offset
    push_u64(&mut bytes, 0); // cpu_local_end_offset
    bytes.extend_from_slice(&[0u8; 32]); // source_hash
    push_u64(&mut bytes, 0); // ex_table_start_offset
    push_u64(&mut bytes, 0); // ex_table_end_offset
    push_u64(&mut bytes, CODE_VADDR); // yield_entry_offset
    push_u64(&mut bytes, CODE_VADDR); // exit_entry_offset
    push_u64(&mut bytes, CODE_VADDR); // stub_range_start_offset
    push_u64(&mut bytes, CODE_VADDR + 8); // stub_range_end_offset
    push_u64(&mut bytes, CODE_VADDR + 8); // cpu_access_start_offset
    push_u64(&mut bytes, CODE_VADDR + 16); // cpu_access_end_offset
    assert_eq!(bytes.len() as u64, text_offset + ENTRY_TABLE_SIZE);
    bytes.extend_from_slice(&[0x90; 16]); // trap stub and CPU-local access code
    assert_eq!(bytes.len() as u64, text_offset + RELA_VADDR - TEXT_VADDR);
    push_u64(&mut bytes, reloc_target); // r_offset
    push_u64(&mut bytes, reloc_info); // r_info
    push_u64(&mut bytes, TEXT_VADDR); // r_addend
    assert_eq!(bytes.len() as u64, text_offset + DYN_VADDR - TEXT_VADDR);
    push_u64(&mut bytes, DT_RELA);
    push_u64(&mut bytes, RELA_VADDR);
    push_u64(&mut bytes, DT_RELASZ);
    push_u64(&mut bytes, RELA_ENTRY_SIZE);
    push_u64(&mut bytes, DT_RELAENT);
    push_u64(&mut bytes, RELA_ENTRY_SIZE);
    push_u64(&mut bytes, DT_NULL);
    push_u64(&mut bytes, 0);

    assert_eq!(bytes.len() as u64, text_offset + ENTRY_TABLE_SIZE + 104);
    bytes.resize((text_offset + TEXT_FILE_BYTES) as usize, 0x90);
    bytes.resize(rodata_offset as usize, 0);
    push_u64(&mut bytes, 0x1234_5678_9abc_def0); // read-only data
    bytes.resize(data_offset as usize, 0);
    push_u64(&mut bytes, 0); // the relocated word
    bytes
}

/// A valid image shared by loader and control-lifecycle regression tests.
pub(in crate::kernelet) fn fixture_image() -> Vec<u8> {
    test_image(R_X86_64_RELATIVE, DATA_VADDR)
}

fn test_boot_args(num_vcpus: u16) -> BootArgs {
    BootArgs {
        size: size_of::<BootArgs>() as u32,
        generation: 1,
        source_hash: [0; 32],
        tsc_freq_hz: 1_000_000_000,
        clock_origin_tsc: 0,
        kernelet: 1,
        num_vcpus,
        vcpu_host_cpu: [0; MAX_VCPUS],
        cpu_slot_gs_offset: crate::kernelet::vcpu_slot::gs_offset(),
        cpu_local_replica_bytes: 0,
        linear_map_base: crate::mm::kspace::LINEAR_MAPPING_BASE_VADDR as u64,
        kernel_half_entries: [0; 256],
        meta_base: 0,
        grant_table: 0,
        meta_section_index: 0,
        meta_block_sections: 0,
        meta_grain_bitmap: 0,
        max_meta_sections: 1,
        info_page: 0,
        vcpu_records: PAGE_SIZE as u32,
        max_tasks: 4,
        fpu_area_bytes: 0,
        cmdline_offset: 0,
        cmdline_len: 0,
        devices_offset: 0,
        num_devices: 0,
        reserved: 0,
        realtime_base_ns: 0,
        monotonic_base_ns: 0,
    }
}

#[ktest]
fn instance_relocation_and_sharing() {
    let image = test_image(R_X86_64_RELATIVE, DATA_VADDR);
    let kind = RegisteredImage::register(&image, [0; 32]).unwrap();

    let entry_table = kind.entry_table();
    assert_eq!(entry_table.size, ENTRY_TABLE_SIZE);
    assert_eq!(entry_table.vcpu_entry_offset, CODE_VADDR);
    assert_eq!(entry_table.virq_entry_offset, CODE_VADDR);
    assert_eq!(entry_table.yield_entry_offset, CODE_VADDR);
    assert_eq!(entry_table.exit_entry_offset, CODE_VADDR);
    assert_eq!(entry_table.stub_range_start_offset, CODE_VADDR);
    assert_eq!(entry_table.stub_range_end_offset, CODE_VADDR + 8);
    assert_eq!(entry_table.cpu_access_start_offset, CODE_VADDR + 8);
    assert_eq!(entry_table.cpu_access_end_offset, CODE_VADDR + 16);
    assert_eq!(entry_table.source_hash, [0u8; 32]);
    assert_eq!(kind.text_frames.len(), 2);
    let mut prefix = [0xffu8; 8];
    kind.text_frames[0]
        .slice(&(0..PAGE_SIZE))
        .into_iter()
        .next()
        .unwrap()
        .read_bytes(0, &mut prefix)
        .unwrap();
    assert_eq!(prefix, [0; 8]);
    kind.text_frames[0]
        .slice(&(PAGE_SIZE..2 * PAGE_SIZE))
        .into_iter()
        .next()
        .unwrap()
        .read_bytes(0, &mut prefix)
        .unwrap();
    assert_eq!(u64::from_le_bytes(prefix), ENTRY_TABLE_SIZE);

    let first_boot = BootArgs {
        clock_origin_tsc: 0x1122_3344_5566_7788,
        realtime_base_ns: 1_790_000_000_000_000_000,
        monotonic_base_ns: 123_456,
        ..test_boot_args(1)
    };
    let second_boot = BootArgs {
        generation: 2,
        clock_origin_tsc: first_boot.clock_origin_tsc + 1,
        realtime_base_ns: first_boot.realtime_base_ns + 1_000_000_000,
        monotonic_base_ns: first_boot.monotonic_base_ns + 1_000_000_000,
        ..first_boot
    };
    let first_identity = super::super::control::identity::Registration::new().unwrap();
    let first_grant = Grant::new(first_identity.owner(), 1, 1, 1).unwrap();
    let second_identity = super::super::control::identity::Registration::new().unwrap();
    let second_grant = Grant::new(second_identity.owner(), 1, 1, 1).unwrap();
    let first = kind
        .instantiate(&first_boot, "", &[], &first_grant)
        .unwrap();
    let second = kind
        .instantiate(&second_boot, "", &[], &second_grant)
        .unwrap();
    assert_ne!(first.base_vaddr(), second.base_vaddr());
    // The image uses this published GS offset, not the Host's source object.
    // Forgetting it in boot-page serialization would read an unrelated cell.
    let mut cpu_slot_offset = [0u8; 8];
    first
        ._boot_frame
        .read_bytes(
            offset_of!(BootArgs, cpu_slot_gs_offset),
            &mut cpu_slot_offset,
        )
        .unwrap();
    assert_eq!(
        u64::from_le_bytes(cpu_slot_offset),
        first_boot.cpu_slot_gs_offset
    );
    // The virtual RTC needs both anchors from this instance's boot page.
    for (instance, boot) in [(&first, &first_boot), (&second, &second_boot)] {
        let mut calibration = [0u8; 16];
        instance
            ._boot_frame
            .read_bytes(offset_of!(BootArgs, tsc_freq_hz), &mut calibration)
            .unwrap();
        assert_eq!(&calibration[..8], &boot.tsc_freq_hz.to_le_bytes());
        assert_eq!(&calibration[8..], &boot.clock_origin_tsc.to_le_bytes());
        let mut anchors = [0u8; 16];
        instance
            ._boot_frame
            .read_bytes(offset_of!(BootArgs, realtime_base_ns), &mut anchors)
            .unwrap();
        assert_eq!(&anchors[..8], &boot.realtime_base_ns.to_le_bytes());
        assert_eq!(&anchors[8..], &boot.monotonic_base_ns.to_le_bytes());
    }
    assert_eq!(
        first.entry_address(),
        first.base_vaddr() + CODE_VADDR as usize
    );
    assert_eq!(
        second.entry_address(),
        second.base_vaddr() + CODE_VADDR as usize
    );

    // Each instance's relocated word names its own base plus the addend.
    for (instance, base) in [&first, &second]
        .into_iter()
        .zip([first.base_vaddr(), second.base_vaddr()])
    {
        let mut word = [0u8; 8];
        instance
            ._data_segment
            .as_ref()
            .unwrap()
            .slice(&(0..PAGE_SIZE))
            .into_iter()
            .next()
            .unwrap()
            .read_bytes(0, &mut word)
            .unwrap();
        assert_eq!(u64::from_le_bytes(word), base as u64 + TEXT_VADDR);
    }

    // The image uses real 2 MiB leaves, with shared text/rodata, private
    // writable data, and shared read-only filler for the gaps.
    let guard = disable_preempt();
    assert!(first.base_vaddr().is_multiple_of(HUGE_PAGE_SIZE));
    assert!(second.base_vaddr().is_multiple_of(HUGE_PAGE_SIZE));
    let text_prop = match first
        .kvirt
        .query(&guard, first.base_vaddr() + TEXT_VADDR as usize)
    {
        Some(MappedItemRef::Untracked(text_paddr, 2, prop)) => {
            assert_eq!(text_paddr, kind.text_frames[0].paddr());
            assert!(text_paddr.is_multiple_of(HUGE_PAGE_SIZE));
            assert_eq!(text_paddr, {
                match second
                    .kvirt
                    .query(&guard, second.base_vaddr() + TEXT_VADDR as usize)
                {
                    Some(MappedItemRef::Untracked(shared_paddr, 2, _)) => shared_paddr,
                    _ => panic!("the second instance must map a huge text page"),
                }
            });
            prop
        }
        _ => panic!("the first instance must map a huge text page"),
    };
    assert_eq!(text_prop.flags, PageFlags::RX);
    match first
        .kvirt
        .query(&guard, first.base_vaddr() + HUGE_PAGE_SIZE + PAGE_SIZE)
    {
        Some(MappedItemRef::Untracked(paddr, 2, prop)) => {
            assert_eq!(paddr, kind.text_frames[1].paddr());
            assert!(paddr.is_multiple_of(HUGE_PAGE_SIZE));
            assert_eq!(prop.flags, PageFlags::RX);
        }
        _ => panic!("the interior text chunk must use a huge PTE"),
    }
    match first
        .kvirt
        .query(&guard, first.base_vaddr() + HUGE_PAGE_SIZE - PAGE_SIZE)
    {
        Some(MappedItemRef::Untracked(paddr, 2, _)) => {
            assert_eq!(paddr, kind.text_frames[0].paddr());
        }
        _ => panic!("the last base page of the first text leaf must remain huge"),
    }

    let rodata_prop = match first
        .kvirt
        .query(&guard, first.base_vaddr() + RODATA_VADDR as usize)
    {
        Some(MappedItemRef::Untracked(rodata_paddr, 2, prop)) => {
            assert_eq!(rodata_paddr, kind.rodata_frames[0].paddr());
            assert!(rodata_paddr.is_multiple_of(HUGE_PAGE_SIZE));
            match second
                .kvirt
                .query(&guard, second.base_vaddr() + RODATA_VADDR as usize)
            {
                Some(MappedItemRef::Untracked(shared_paddr, 2, shared_prop)) => {
                    assert_eq!(shared_paddr, rodata_paddr);
                    assert_eq!(shared_prop, prop);
                }
                _ => panic!("the second instance must share rodata"),
            }
            prop
        }
        _ => panic!("the read-only segment must use a huge PTE"),
    };
    assert_eq!(rodata_prop.flags, PageFlags::R);

    let data_prop = match first
        .kvirt
        .query(&guard, first.base_vaddr() + DATA_VADDR as usize)
    {
        Some(MappedItemRef::Untracked(data_paddr, 2, prop)) => {
            assert_eq!(data_paddr, first._data_segment.as_ref().unwrap().paddr());
            assert!(data_paddr.is_multiple_of(HUGE_PAGE_SIZE));
            match second
                .kvirt
                .query(&guard, second.base_vaddr() + DATA_VADDR as usize)
            {
                Some(MappedItemRef::Untracked(second_paddr, 2, second_prop)) => {
                    assert_eq!(second_paddr, second._data_segment.as_ref().unwrap().paddr());
                    assert_ne!(data_paddr, second_paddr);
                    assert_eq!(second_prop, prop);
                }
                _ => panic!("the second instance must map a private huge data page"),
            }
            prop
        }
        _ => panic!("the first instance must map its data"),
    };
    assert_eq!(data_prop.flags, PageFlags::RW);

    // Each instance owns its boot page after the writable data slot;
    // the image sees it through a read-only mapping.
    assert_eq!(
        first.boot_args_address(),
        first.base_vaddr() + 6 * HUGE_PAGE_SIZE
    );
    let boot_prop = match first.kvirt.query(&guard, first.boot_args_address()) {
        Some(MappedItemRef::Tracked(frame, prop)) => {
            assert_ne!(frame.paddr(), second._boot_frame.paddr());
            prop
        }
        _ => panic!("the first instance must map its boot page"),
    };
    assert_eq!(boot_prop.flags, PageFlags::R);
    let mut boot_prefix = [0; 8];
    second._boot_frame.read_bytes(0, &mut boot_prefix).unwrap();
    assert_eq!(&boot_prefix[0..4], &second_boot.size.to_le_bytes());
    assert_eq!(&boot_prefix[4..8], &second_boot.generation.to_le_bytes());

    // Calibration lives in BootArgs. The info page immediately follows the
    // vCPU records, with no intervening clock frame or writable mapping.
    for (instance, grant) in [(&first, &first_grant), (&second, &second_grant)] {
        let mut offset_bytes = [0u8; 4];
        instance
            ._boot_frame
            .read_bytes(offset_of!(BootArgs, info_page), &mut offset_bytes)
            .unwrap();
        let info_offset = u32::from_le_bytes(offset_bytes) as usize;
        assert_eq!(info_offset, 2 * PAGE_SIZE);
        match instance
            .kvirt
            .query(&guard, instance.boot_args_address() + info_offset)
        {
            Some(MappedItemRef::Tracked(frame, prop)) => {
                assert_eq!(prop.flags, PageFlags::R);
                assert_eq!(frame.paddr(), grant.shared_frames().next().unwrap().paddr());
            }
            _ => panic!("the instance info page must be mapped"),
        }
        instance
            ._boot_frame
            .read_bytes(offset_of!(BootArgs, grant_table), &mut offset_bytes)
            .unwrap();
        assert_eq!(u32::from_le_bytes(offset_bytes) as usize, 3 * PAGE_SIZE);
    }

    for offset in [2 * HUGE_PAGE_SIZE, 4 * HUGE_PAGE_SIZE] {
        match first.kvirt.query(&guard, first.base_vaddr() + offset) {
            Some(MappedItemRef::Untracked(paddr, 2, prop)) => {
                assert_eq!(paddr, kind.filler.as_ref().unwrap().paddr());
                assert!(paddr.is_multiple_of(HUGE_PAGE_SIZE));
                assert_eq!(prop.flags, PageFlags::R);
            }
            _ => panic!("the gap must be mapped by a read-only huge PTE"),
        }
    }
    drop(guard);

    // The registration can disappear before either instance. Each mapping
    // owns a segment reference independently of the registration and of the
    // other instance, and releases it after its acknowledged shootdown.
    let text_frame = kind.text_frames[0]
        .slice(&(0..PAGE_SIZE))
        .into_iter()
        .next()
        .unwrap();
    let data_frame = first
        ._data_segment
        .as_ref()
        .unwrap()
        .slice(&(0..PAGE_SIZE))
        .into_iter()
        .next()
        .unwrap();
    let text_refs = text_frame.reference_count();
    assert_eq!(text_refs, 4);
    drop(kind);
    assert_eq!(text_frame.reference_count(), text_refs - 1);
    drop(first);
    assert_eq!(text_frame.reference_count(), text_refs - 2);
    assert_eq!(data_frame.reference_count(), 1);
    drop(second);
    assert_eq!(text_frame.reference_count(), 1);
}

#[ktest]
fn cpu_local_replicas_precede_shared_pages() {
    let mut image = test_image(R_X86_64_RELATIVE, DATA_VADDR);
    let table = ENTRY_TABLE_OFFSET as usize;
    image[table + 24..table + 32].copy_from_slice(&(DATA_VADDR + 16).to_le_bytes());
    image[table + 32..table + 40].copy_from_slice(&(DATA_VADDR + 48).to_le_bytes());
    let data_header = ELF_HEADER_SIZE + 2 * PHDR_ENTRY_SIZE;
    image[data_header + 32..data_header + 40].copy_from_slice(&48u64.to_le_bytes());
    let data_file_offset = 3 * HUGE_PAGE_SIZE;
    image.resize(data_file_offset + 48, 0);
    let seed: [u8; 32] = core::array::from_fn(|index| index as u8 + 1);
    image[data_file_offset + 16..data_file_offset + 48].copy_from_slice(&seed);

    let kind = RegisteredImage::register(&image, [0; 32]).unwrap();
    let identity = super::super::control::identity::Registration::new().unwrap();
    let grant = Grant::new(identity.owner(), 1, 1, 1).unwrap();
    let instance = kind
        .instantiate(&test_boot_args(2), "", &[], &grant)
        .unwrap();
    let replicas_start = instance.base_vaddr() + kind.replicas_offset;
    assert_eq!(instance._cpu_local_frames.len(), 2);
    assert_eq!(instance.boot_args_address(), replicas_start + 2 * PAGE_SIZE);
    assert_eq!(
        instance.private_bytes(),
        HUGE_PAGE_SIZE + (1 + instance._vcpu_frames.len() + 2) * PAGE_SIZE
    );

    for (vcpu, frame) in instance._cpu_local_frames.iter().enumerate() {
        let replica = replicas_start + vcpu * PAGE_SIZE;
        let mut record_base = [0u8; 8];
        instance._vcpu_frames[0]
            .read_bytes(
                vcpu * size_of::<VcpuRecord>() + offset_of!(VcpuRecord, cpu_local_base),
                &mut record_base,
            )
            .unwrap();
        assert_eq!(u64::from_le_bytes(record_base), replica as u64);
        let mut copied = [0u8; 32];
        frame.read_bytes(0, &mut copied).unwrap();
        assert_eq!(copied, seed);

        let guard = disable_preempt();
        match instance.kvirt.query(&guard, replica) {
            Some(MappedItemRef::Tracked(mapped, prop)) => {
                assert_eq!(mapped.paddr(), frame.paddr());
                // Copying the template through this mapping can set the
                // hardware accessed and dirty bits before the query.
                assert_eq!(prop.flags & PageFlags::RWX, PageFlags::RW);
            }
            _ => panic!("the CPU-local replica must be mapped in the image"),
        }
    }
}

#[ktest]
fn invalid_cpu_access_ranges_are_rejected() {
    for (start, end) in [
        (0, 0),
        (CODE_VADDR + 8, CODE_VADDR + 8),
        (CODE_VADDR + 16, CODE_VADDR + 8),
        (DATA_VADDR, DATA_VADDR + 8),
        (CODE_VADDR, CODE_VADDR + 8),
    ] {
        let mut image = fixture_image();
        let table = ENTRY_TABLE_OFFSET as usize;
        let first = table + offset_of!(EntryTable, cpu_access_start_offset);
        let last = table + offset_of!(EntryTable, cpu_access_end_offset);
        image[first..first + 8].copy_from_slice(&start.to_le_bytes());
        image[last..last + 8].copy_from_slice(&end.to_le_bytes());
        assert!(matches!(
            RegisteredImage::register(&image, [0; 32]),
            Err(Error::InvalidArgs)
        ));
    }
}

#[ktest]
fn invalid_trap_stub_ranges_are_rejected() {
    for (start, end) in [
        (CODE_VADDR, CODE_VADDR),
        (CODE_VADDR + 1, CODE_VADDR + 8),
        (CODE_VADDR, DATA_VADDR),
        (CODE_VADDR + 8, CODE_VADDR),
    ] {
        let mut image = test_image(R_X86_64_RELATIVE, DATA_VADDR);
        let table = ENTRY_TABLE_OFFSET as usize;
        let start_field = table + offset_of!(EntryTable, stub_range_start_offset);
        let end_field = table + offset_of!(EntryTable, stub_range_end_offset);
        image[start_field..start_field + 8].copy_from_slice(&start.to_le_bytes());
        image[end_field..end_field + 8].copy_from_slice(&end.to_le_bytes());
        assert_rejected(image);
    }
}

#[ktest]
fn non_executable_redirect_target_is_rejected() {
    for field in [
        offset_of!(EntryTable, yield_entry_offset),
        offset_of!(EntryTable, exit_entry_offset),
    ] {
        let mut image = test_image(R_X86_64_RELATIVE, DATA_VADDR);
        let field = ENTRY_TABLE_OFFSET as usize + field;
        image[field..field + 8].copy_from_slice(&DATA_VADDR.to_le_bytes());
        assert_rejected(image);
    }
}

#[ktest]
fn empty_cpu_local_template_needs_no_replica_pages() {
    let image = test_image(R_X86_64_RELATIVE, DATA_VADDR);
    let kind = RegisteredImage::register(&image, [0; 32]).unwrap();
    let identity = super::super::control::identity::Registration::new().unwrap();
    let grant = Grant::new(identity.owner(), 1, 1, 1).unwrap();
    let instance = kind
        .instantiate(&test_boot_args(2), "", &[], &grant)
        .unwrap();
    assert!(instance._cpu_local_frames.is_empty());
    assert_eq!(
        instance.boot_args_address(),
        instance.base_vaddr() + kind.replicas_offset
    );
}

fn assert_rejected(image: Vec<u8>) {
    assert!(matches!(
        RegisteredImage::register(&image, [0; 32]),
        Err(Error::InvalidArgs)
    ));
}

#[ktest]
fn rejects_malformed_images() {
    // A wrong ELF magic.
    let mut image = test_image(R_X86_64_RELATIVE, DATA_VADDR);
    image[0] = 0;
    assert_rejected(image);

    // The Host and image must have been built from the same OSTD source.
    assert!(matches!(
        RegisteredImage::register(&test_image(R_X86_64_RELATIVE, DATA_VADDR), [1; 32]),
        Err(Error::InvalidArgs)
    ));

    // A non-position-independent type (ET_EXEC).
    let mut image = test_image(R_X86_64_RELATIVE, DATA_VADDR);
    image[16..18].copy_from_slice(&2u16.to_le_bytes());
    assert_rejected(image);

    // A permission transition not at a 2 MiB boundary violates the image
    // layout contract, even though the segment is base-page aligned.
    let mut image = test_image(R_X86_64_RELATIVE, DATA_VADDR);
    let rodata_header = ELF_HEADER_SIZE + PHDR_ENTRY_SIZE;
    image[rodata_header + 16..rodata_header + 24]
        .copy_from_slice(&(RODATA_VADDR + PAGE_SIZE_U64).to_le_bytes());
    assert_rejected(image);

    // A relocation type the flat loader does not implement, and one
    // that carries a symbol index.
    assert_rejected(test_image(9, DATA_VADDR));
    assert_rejected(test_image(1 << 32 | R_X86_64_RELATIVE, DATA_VADDR));

    // A relocation size without a relocation table must not be ignored.
    let mut image = test_image(R_X86_64_RELATIVE, DATA_VADDR);
    let dynamic_offset = DYN_VADDR as usize;
    image[dynamic_offset..dynamic_offset + 8].copy_from_slice(&0x6fff_ffffu64.to_le_bytes());
    assert_rejected(image);

    // A relocation into the shared text, which must stay relocation-free.
    assert_rejected(test_image(R_X86_64_RELATIVE, TEXT_VADDR));

    // A relocated word that would straddle a frame boundary.
    assert_rejected(test_image(
        R_X86_64_RELATIVE,
        DATA_VADDR + PAGE_SIZE_U64 - 4,
    ));

    // An entry table whose size field names a different ABI.
    let mut image = test_image(R_X86_64_RELATIVE, DATA_VADDR);
    let table_offset = ENTRY_TABLE_OFFSET as usize;
    image[table_offset..table_offset + 8].copy_from_slice(&87u64.to_le_bytes());
    assert_rejected(image);

    // An entry outside the executable segment.
    let mut image = test_image(R_X86_64_RELATIVE, DATA_VADDR);
    image[24..32].copy_from_slice(&DATA_VADDR.to_le_bytes());
    assert_rejected(image);
}
