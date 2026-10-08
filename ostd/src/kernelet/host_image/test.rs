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
const RELA_VADDR: u64 = CODE_VADDR + 8;
const DYN_VADDR: u64 = RELA_VADDR + RELA_ENTRY_SIZE;
const TEXT_FILE_BYTES: u64 = HUGE_PAGE_SIZE_U64 + 184;
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
    assert_eq!(bytes.len() as u64, text_offset + ENTRY_TABLE_SIZE);
    bytes.extend_from_slice(&[0x90; 8]); // code
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

    assert_eq!(bytes.len() as u64, text_offset + 184);
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
        tsc_freq_hz: 0,
        kernelet: 1,
        num_vcpus,
        vcpu_host_cpu: [0; MAX_VCPUS],
        cpu_slot_gs_offset: 0,
        host_preempt_gs_offset: crate::task::carrier_preempt::gs_offset(),
        cpu_local_replica_bytes: 0,
        linear_map_base: crate::mm::kspace::LINEAR_MAPPING_BASE_VADDR as u64,
        kernel_half_entries: [0; 256],
        meta_base: 0,
        grant_table: 0,
        meta_section_index: 0,
        meta_block_sections: 0,
        max_meta_sections: 1,
        clock_page: 0,
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
    assert_eq!(entry_table.source_hash, [0u8; 32]);
    assert_eq!(kind.text_frames.len(), 2);
    let mut prefix = [0xffu8; 8];
    kind.text_frames[0]
        .slice(&(0..PAGE_SIZE))
        .next()
        .unwrap()
        .read_bytes(0, &mut prefix)
        .unwrap();
    assert_eq!(prefix, [0; 8]);
    kind.text_frames[0]
        .slice(&(PAGE_SIZE..2 * PAGE_SIZE))
        .next()
        .unwrap()
        .read_bytes(0, &mut prefix)
        .unwrap();
    assert_eq!(u64::from_le_bytes(prefix), ENTRY_TABLE_SIZE);

    let first_boot = BootArgs {
        realtime_base_ns: 1_790_000_000_000_000_000,
        monotonic_base_ns: 123_456,
        ..test_boot_args(1)
    };
    let second_boot = BootArgs {
        generation: 2,
        realtime_base_ns: first_boot.realtime_base_ns + 1_000_000_000,
        monotonic_base_ns: first_boot.monotonic_base_ns + 1_000_000_000,
        ..first_boot
    };
    let first_grant = Grant::new(1, 1, 1).unwrap();
    let second_grant = Grant::new(1, 1, 1).unwrap();
    let first = kind
        .instantiate(&first_boot, "", &[], &first_grant)
        .unwrap();
    let second = kind
        .instantiate(&second_boot, "", &[], &second_grant)
        .unwrap();
    assert_ne!(first.base_vaddr(), second.base_vaddr());
    // The image uses this published GS offset, not the Host's source object.
    // Forgetting it in boot-page serialization would write an unrelated cell.
    let mut preempt_offset = [0u8; 4];
    first
        ._boot_frame
        .read_bytes(
            offset_of!(BootArgs, host_preempt_gs_offset),
            &mut preempt_offset,
        )
        .unwrap();
    assert_eq!(
        u32::from_le_bytes(preempt_offset),
        first_boot.host_preempt_gs_offset
    );
    // The virtual RTC needs both anchors from this instance's boot page.
    for (instance, boot) in [(&first, &first_boot), (&second, &second_boot)] {
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
            .next()
            .unwrap()
            .read_bytes(0, &mut word)
            .unwrap();
        assert_eq!(u64::from_le_bytes(word), base as u64 + TEXT_VADDR);
    }

    // Text and rodata frames are shared tracked pages, while each
    // instance's data pages are private. The gaps are shared read-only
    // filler pages.
    let guard = disable_preempt();
    assert!(first.base_vaddr().is_multiple_of(PAGE_SIZE));
    assert!(second.base_vaddr().is_multiple_of(PAGE_SIZE));
    let text_prop = match first
        .kvirt
        .query(&guard, first.base_vaddr() + TEXT_VADDR as usize)
    {
        Some(MappedItemRef::Tracked(text_frame, prop)) => {
            assert_eq!(text_frame.paddr(), kind.text_frames[0].paddr() + PAGE_SIZE);
            assert_eq!(text_frame.paddr(), {
                match second
                    .kvirt
                    .query(&guard, second.base_vaddr() + TEXT_VADDR as usize)
                {
                    Some(MappedItemRef::Tracked(shared_frame, _)) => shared_frame.paddr(),
                    _ => panic!("the second instance must map the text"),
                }
            });
            prop
        }
        _ => panic!("the first instance must map the text"),
    };
    assert_eq!(text_prop.flags, PageFlags::RX);
    match first
        .kvirt
        .query(&guard, first.base_vaddr() + HUGE_PAGE_SIZE + PAGE_SIZE)
    {
        Some(MappedItemRef::Tracked(frame, prop)) => {
            assert_eq!(frame.paddr(), kind.text_frames[1].paddr() + PAGE_SIZE);
            assert_eq!(prop.flags, PageFlags::RX);
        }
        _ => panic!("the interior text chunk must be tracked"),
    }

    let rodata_prop = match first
        .kvirt
        .query(&guard, first.base_vaddr() + RODATA_VADDR as usize)
    {
        Some(MappedItemRef::Tracked(rodata_frame, prop)) => {
            assert_eq!(rodata_frame.paddr(), kind.rodata_frames[0].paddr());
            match second
                .kvirt
                .query(&guard, second.base_vaddr() + RODATA_VADDR as usize)
            {
                Some(MappedItemRef::Tracked(shared_frame, shared_prop)) => {
                    assert_eq!(shared_frame.paddr(), rodata_frame.paddr());
                    assert_eq!(shared_prop, prop);
                }
                _ => panic!("the second instance must share rodata"),
            }
            prop
        }
        _ => panic!("the read-only segment must be tracked"),
    };
    assert_eq!(rodata_prop.flags, PageFlags::R);

    let data_prop = match first
        .kvirt
        .query(&guard, first.base_vaddr() + DATA_VADDR as usize)
    {
        Some(MappedItemRef::Tracked(data_frame, prop)) => {
            assert_ne!(
                data_frame.paddr(),
                second._data_segment.as_ref().unwrap().paddr()
            );
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

    // Both instances see the one Host clock frame through a read-only
    // mapping at the nonzero offset published in their boot pages.
    let mut clock_offset_bytes = [0u8; 4];
    first
        ._boot_frame
        .read_bytes(
            core::mem::offset_of!(BootArgs, clock_page),
            &mut clock_offset_bytes,
        )
        .unwrap();
    let clock_offset = u32::from_le_bytes(clock_offset_bytes) as usize;
    assert_eq!(clock_offset, 2 * PAGE_SIZE);
    let first_clock = match first
        .kvirt
        .query(&guard, first.boot_args_address() + clock_offset)
    {
        Some(MappedItemRef::Tracked(frame, prop)) => {
            assert_eq!(prop.flags, PageFlags::R);
            frame.paddr()
        }
        _ => panic!("the shared clock page must be mapped"),
    };
    let second_clock = match second
        .kvirt
        .query(&guard, second.boot_args_address() + clock_offset)
    {
        Some(MappedItemRef::Tracked(frame, prop)) => {
            assert_eq!(prop.flags, PageFlags::R);
            frame.paddr()
        }
        _ => panic!("the second clock page must be mapped"),
    };
    assert_eq!(first_clock, second_clock);

    let filler_prop = match first
        .kvirt
        .query(&guard, first.base_vaddr() + 2 * HUGE_PAGE_SIZE)
    {
        Some(MappedItemRef::Tracked(_, prop)) => prop,
        _ => panic!("the gap must be mapped read-only"),
    };
    assert_eq!(filler_prop.flags, PageFlags::R);
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
    let grant = Grant::new(1, 1, 1).unwrap();
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
fn empty_cpu_local_template_needs_no_replica_pages() {
    let image = test_image(R_X86_64_RELATIVE, DATA_VADDR);
    let kind = RegisteredImage::register(&image, [0; 32]).unwrap();
    let grant = Grant::new(1, 1, 1).unwrap();
    let instance = kind
        .instantiate(&test_boot_args(2), "", &[], &grant)
        .unwrap();
    assert!(instance._cpu_local_frames.is_empty());
    assert_eq!(
        instance.boot_args_address(),
        instance.base_vaddr() + kind.replicas_offset
    );
}

#[ktest]
fn rejects_malformed_images() {
    let assert_rejected = |image: Vec<u8>| {
        assert!(matches!(
            RegisteredImage::register(&image, [0; 32]),
            Err(Error::InvalidArgs)
        ));
    };

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
