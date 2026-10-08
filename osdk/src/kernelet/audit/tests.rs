// SPDX-License-Identifier: MPL-2.0

//! Tests for the kernelet image audit, built on a synthetic ELF64 image that
//! mirrors the layout the kernelet linker script produces.

use super::prefixes::{CONTEXT_SAVE, VIRQ_AFTER_CALL, VIRQ_BEFORE_CALL};
use super::{EX_TABLE_ITEM_SIZE, audit_kernelet_image};
use crate::kernelet::abi;
use crate::kernelet::elf::{PF_R, PF_W, PF_X};

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const SHDR_SIZE: usize = 64;
const SYM_SIZE: usize = 24;
const RELA_SIZE: usize = 24;
const DYN_SIZE: usize = 16;

// The fixed layout of the synthetic image. File offsets are chosen congruent
// to the virtual addresses modulo the segment alignment, as the linker script
// produces them.
const ENTRY_TABLE_VADDR: u64 = 0x1000;
const TEXT_VADDR: u64 = 0x2000;
const RODATA_VADDR: u64 = 0x40_0000;
const RODATA_FILE_OFFSET: u64 = 0x3000;
const DATA_VADDR: u64 = 0x60_0000;
const DATA_FILE_OFFSET: u64 = 0x4000;

const EX_TABLE_VADDR: u64 = RODATA_VADDR;
const RELA_VADDR: u64 = RODATA_VADDR + 0x10;
const DYNSYM_VADDR: u64 = RODATA_VADDR + 0x40;
const DYNAMIC_VADDR: u64 = RODATA_VADDR + 0x60;
const GOT_VADDR: u64 = DATA_VADDR;
const CPU_LOCAL_VADDR: u64 = DATA_VADDR + 0x18;
const BSS_VADDR: u64 = DATA_VADDR + 0x20;

const SYMTAB_FILE_OFFSET: u64 = 0x5000;
const STRTAB_FILE_OFFSET: u64 = 0x5300;
const SHSTRTAB_FILE_OFFSET: u64 = 0x5500;
const SHDR_FILE_OFFSET: usize = 0x5800;
const SHDR_COUNT: usize = 15;

// Mutatable byte positions, exposed by the fixture.
const E_TYPE_OFFSET: usize = 16;
const ENTRY_TABLE_FILE_OFFSET: usize = ENTRY_TABLE_VADDR as usize;
const RELA_ENTRY_FILE_OFFSET: usize = RODATA_FILE_OFFSET as usize + 0x10;
const TEXT_PHDR_FLAGS_OFFSET: usize = EHDR_SIZE + PHDR_SIZE + 4;
const DATA_PHDR_MEMSZ_OFFSET: usize = EHDR_SIZE + 2 * PHDR_SIZE + 40;

const SOURCE_HASH: [u8; 32] = [0x5a; 32];

/// A mutable byte position inside the fixture image.
struct Mutation {
    offset: usize,
    bytes: Vec<u8>,
}

/// Builds the valid fixture image and applies `mutations` to it.
fn image_with(mutations: &[Mutation]) -> Vec<u8> {
    let mut bytes = fixture();
    for mutation in mutations {
        bytes[mutation.offset..mutation.offset + mutation.bytes.len()]
            .copy_from_slice(&mutation.bytes);
    }
    bytes
}

/// Returns a valid kernelet image as the kernelet linker script produces it:
/// three PT_LOAD segments (text R E, rodata R, data RW), a PT_DYNAMIC segment,
/// a relative relocation into `.got`, and an entry table of link-time offsets.
fn fixture() -> Vec<u8> {
    let mut bytes = vec![0u8; SHDR_FILE_OFFSET + SHDR_COUNT * SHDR_SIZE];

    let text_segment_size = TEXT_VADDR + 0x400 - ENTRY_TABLE_VADDR;
    let rodata_size: u64 = 0x90;
    let data_filesz: u64 = 0x20;
    let data_memsz: u64 = 0x120;

    // ---- The ELF header ---------------------------------------------------
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // ELFDATA2LSB
    bytes[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    bytes[24..32].copy_from_slice(&TEXT_VADDR.to_le_bytes()); // e_entry
    bytes[32..40].copy_from_slice(&(EHDR_SIZE as u64).to_le_bytes()); // e_phoff
    bytes[40..48].copy_from_slice(&(SHDR_FILE_OFFSET as u64).to_le_bytes()); // e_shoff
    bytes[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes()); // e_phentsize
    bytes[56..58].copy_from_slice(&4u16.to_le_bytes()); // e_phnum
    bytes[58..60].copy_from_slice(&(SHDR_SIZE as u16).to_le_bytes()); // e_shentsize
    bytes[60..62].copy_from_slice(&(SHDR_COUNT as u16).to_le_bytes()); // e_shnum
    bytes[62..64].copy_from_slice(&13u16.to_le_bytes()); // e_shstrndx

    // ---- The program headers ----------------------------------------------
    let mut write_phdr = |index: usize,
                          typ: u32,
                          flags: u32,
                          offset: u64,
                          vaddr: u64,
                          filesz: u64,
                          memsz: u64,
                          align: u64| {
        let base = EHDR_SIZE + index * PHDR_SIZE;
        bytes[base..base + 4].copy_from_slice(&typ.to_le_bytes());
        bytes[base + 4..base + 8].copy_from_slice(&flags.to_le_bytes());
        bytes[base + 8..base + 16].copy_from_slice(&offset.to_le_bytes());
        bytes[base + 16..base + 24].copy_from_slice(&vaddr.to_le_bytes());
        bytes[base + 32..base + 40].copy_from_slice(&filesz.to_le_bytes());
        bytes[base + 40..base + 48].copy_from_slice(&memsz.to_le_bytes());
        bytes[base + 48..base + 56].copy_from_slice(&align.to_le_bytes());
    };
    // text: the entry table followed by the code.
    write_phdr(
        0,
        1,
        PF_R | PF_X,
        ENTRY_TABLE_VADDR,
        ENTRY_TABLE_VADDR,
        text_segment_size,
        text_segment_size,
        0x1000,
    );
    // rodata: the exception table and the dynamic linking machinery.
    write_phdr(
        1,
        1,
        PF_R,
        RODATA_FILE_OFFSET,
        RODATA_VADDR,
        rodata_size,
        rodata_size,
        0x1000,
    );
    // data: .got, .cpu_local and a .bss tail.
    write_phdr(
        2,
        1,
        PF_R | PF_W,
        DATA_FILE_OFFSET,
        DATA_VADDR,
        data_filesz,
        data_memsz,
        0x1000,
    );
    // dynamic.
    write_phdr(
        3,
        2,
        PF_R | PF_W,
        RODATA_FILE_OFFSET + 0x60,
        DYNAMIC_VADDR,
        3 * DYN_SIZE as u64,
        3 * DYN_SIZE as u64,
        8,
    );

    // ---- The entry table ---------------------------------------------------
    let mut write_entry_table_field = |field_offset: usize, value: u64| {
        let base = ENTRY_TABLE_FILE_OFFSET + field_offset;
        bytes[base..base + 8].copy_from_slice(&value.to_le_bytes());
    };
    write_entry_table_field(abi::entry_table::SIZE_FIELD_OFFSET, abi::entry_table::SIZE);
    write_entry_table_field(abi::entry_table::VCPU_ENTRY_OFFSET, TEXT_VADDR + 0x20);
    write_entry_table_field(abi::entry_table::VIRQ_ENTRY_OFFSET, TEXT_VADDR + 0x100);
    write_entry_table_field(abi::entry_table::CPU_LOCAL_START_OFFSET, CPU_LOCAL_VADDR);
    write_entry_table_field(abi::entry_table::CPU_LOCAL_END_OFFSET, BSS_VADDR);
    write_entry_table_field(abi::entry_table::EX_TABLE_START_OFFSET, EX_TABLE_VADDR);
    write_entry_table_field(
        abi::entry_table::EX_TABLE_END_OFFSET,
        EX_TABLE_VADDR + EX_TABLE_ITEM_SIZE,
    );
    let hash_base = ENTRY_TABLE_FILE_OFFSET + abi::entry_table::SOURCE_HASH_OFFSET;
    bytes[hash_base..hash_base + 32].copy_from_slice(&SOURCE_HASH);

    // ---- The read-only data segment ------------------------------------------
    let rodata = RODATA_FILE_OFFSET as usize;
    // .ex_table: each field is relative to its own address (D87).
    let fault_delta = TEXT_VADDR as i64 - EX_TABLE_VADDR as i64;
    let recovery_delta = (TEXT_VADDR + 9) as i64 - (EX_TABLE_VADDR + 8) as i64;
    bytes[rodata..rodata + 8].copy_from_slice(&fault_delta.to_le_bytes());
    bytes[rodata + 8..rodata + 16].copy_from_slice(&recovery_delta.to_le_bytes());
    // .rela.dyn: one relocation into `.got`.
    bytes[RELA_ENTRY_FILE_OFFSET..RELA_ENTRY_FILE_OFFSET + 8]
        .copy_from_slice(&GOT_VADDR.to_le_bytes());
    bytes[RELA_ENTRY_FILE_OFFSET + 8..RELA_ENTRY_FILE_OFFSET + 16]
        .copy_from_slice(&8u64.to_le_bytes());
    // The RELATIVE addend is zero, so it denotes the image base.
    // .dynsym: only the null symbol.
    // .dynamic: the entries that locate the relocation table.
    for (index, (tag, value)) in [
        (7u64, RELA_VADDR),
        (8u64, RELA_SIZE as u64),
        (9u64, RELA_SIZE as u64),
    ]
    .into_iter()
    .enumerate()
    {
        let base = rodata + 0x60 + index * DYN_SIZE;
        bytes[base..base + 8].copy_from_slice(&tag.to_le_bytes());
        bytes[base + 8..base + 16].copy_from_slice(&value.to_le_bytes());
    }

    // ---- The writable data segment -------------------------------------------
    bytes[DATA_FILE_OFFSET as usize..DATA_FILE_OFFSET as usize + data_filesz as usize].fill(0xaa);
    bytes[DATA_FILE_OFFSET as usize + 0x10..DATA_FILE_OFFSET as usize + 0x18].fill(0);

    // ---- The code --------------------------------------------------------------
    bytes[TEXT_VADDR as usize..TEXT_VADDR as usize + 0x400].fill(0x90);
    // Compiler-generated fixed entries retain the indirect-branch marker.
    for offset in [0, 0x20] {
        bytes[TEXT_VADDR as usize + offset..TEXT_VADDR as usize + offset + 4]
            .copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa]); // ENDBR64
    }
    let virq = TEXT_VADDR as usize + 0x100;
    bytes[virq..virq + VIRQ_BEFORE_CALL.len()].copy_from_slice(VIRQ_BEFORE_CALL);
    let call_end = virq + VIRQ_BEFORE_CALL.len() + 4;
    bytes[virq + VIRQ_BEFORE_CALL.len()..call_end]
        .copy_from_slice(&((TEXT_VADDR + 0x20) as i64 - call_end as i64).to_le_bytes()[..4]);
    bytes[call_end..call_end + VIRQ_AFTER_CALL.len()].copy_from_slice(VIRQ_AFTER_CALL);
    let context = TEXT_VADDR as usize + 0x200;
    bytes[context..context + CONTEXT_SAVE.len()].copy_from_slice(CONTEXT_SAVE);
    let wrapper = TEXT_VADDR as usize + 0x260;
    bytes[wrapper..wrapper + 9]
        .copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa, 0x48, 0x83, 0xc4, 0x08, 0xe8]);
    bytes[wrapper + 9..wrapper + 13]
        .copy_from_slice(&((TEXT_VADDR + 0x20) as i64 - (wrapper + 13) as i64).to_le_bytes()[..4]);
    // ---- The symbol table --------------------------------------------------------
    let strtab = build_string_table();
    let mut symtab = vec![0u8; SYM_SIZE]; // the null symbol
    for (name, info, shndx, value, size) in [
        ("_kernelet_entry", 0x12u8, 2u16, TEXT_VADDR, 4),
        ("vcpu_entry", 0x12, 2, TEXT_VADDR + 0x20, 0),
        ("virq_entry", 0x12, 2, TEXT_VADDR + 0x100, 77),
        ("context_switch", 0x12, 2, TEXT_VADDR + 0x200, 81),
        ("first_context_switch", 0x12, 2, TEXT_VADDR + 0x229, 40),
        ("kernel_task_entry_wrapper", 0x12, 2, TEXT_VADDR + 0x260, 13),
        ("kernel_task_entry", 0x12, 2, TEXT_VADDR + 0x20, 0),
        ("__cpu_local_start", 0x10, 9, CPU_LOCAL_VADDR, 0),
        ("__cpu_local_end", 0x10, 10, BSS_VADDR, 0),
        ("__ex_table", 0x10, 4, EX_TABLE_VADDR, 0),
        (
            "__ex_table_end",
            0x10,
            4,
            EX_TABLE_VADDR + EX_TABLE_ITEM_SIZE,
            0,
        ),
        ("__bss", 0x10, 10, BSS_VADDR, 0),
    ] {
        let mut symbol = vec![0u8; SYM_SIZE];
        symbol[0..4].copy_from_slice(&(strtab.offset_of(name) as u32).to_le_bytes());
        symbol[4] = info;
        symbol[6..8].copy_from_slice(&shndx.to_le_bytes());
        symbol[8..16].copy_from_slice(&value.to_le_bytes());
        symbol[16..24].copy_from_slice(&(size as u64).to_le_bytes());
        symtab.extend_from_slice(&symbol);
    }
    bytes[SYMTAB_FILE_OFFSET as usize..SYMTAB_FILE_OFFSET as usize + symtab.len()]
        .copy_from_slice(&symtab);
    bytes[STRTAB_FILE_OFFSET as usize..STRTAB_FILE_OFFSET as usize + strtab.bytes.len()]
        .copy_from_slice(&strtab.bytes);

    // ---- The section headers --------------------------------------------------------
    let shstrtab = build_section_string_table();
    let mut shdr = |index: usize,
                    name: &str,
                    typ: u32,
                    addr: u64,
                    offset: u64,
                    size: u64,
                    link: u32,
                    entsize: u64| {
        let base = SHDR_FILE_OFFSET + index * SHDR_SIZE;
        bytes[base..base + 4].copy_from_slice(&(shstrtab.offset_of(name) as u32).to_le_bytes());
        bytes[base + 4..base + 8].copy_from_slice(&typ.to_le_bytes());
        bytes[base + 16..base + 24].copy_from_slice(&addr.to_le_bytes());
        bytes[base + 24..base + 32].copy_from_slice(&offset.to_le_bytes());
        bytes[base + 32..base + 40].copy_from_slice(&size.to_le_bytes());
        bytes[base + 40..base + 44].copy_from_slice(&link.to_le_bytes());
        bytes[base + 56..base + 64].copy_from_slice(&entsize.to_le_bytes());
    };
    shdr(
        1,
        ".kernelet_entry_table",
        1,
        ENTRY_TABLE_VADDR,
        ENTRY_TABLE_VADDR,
        abi::entry_table::SIZE,
        0,
        0,
    );
    shdr(2, ".text", 1, TEXT_VADDR, TEXT_VADDR, 0x400, 0, 0);
    shdr(
        3,
        ".ex_table",
        1,
        EX_TABLE_VADDR,
        RODATA_FILE_OFFSET,
        EX_TABLE_ITEM_SIZE,
        0,
        0,
    );
    shdr(
        4,
        ".rela.dyn",
        4,
        RELA_VADDR,
        RODATA_FILE_OFFSET + 0x10,
        RELA_SIZE as u64,
        6,
        0,
    );
    shdr(
        5,
        ".dynsym",
        11,
        DYNSYM_VADDR,
        RODATA_FILE_OFFSET + 0x40,
        SYM_SIZE as u64,
        12,
        SYM_SIZE as u64,
    );
    shdr(
        6,
        ".dynstr",
        3,
        RODATA_VADDR + 0x58,
        RODATA_FILE_OFFSET + 0x58,
        1,
        0,
        0,
    );
    shdr(
        7,
        ".dynamic",
        6,
        DYNAMIC_VADDR,
        RODATA_FILE_OFFSET + 0x60,
        3 * DYN_SIZE as u64,
        5,
        DYN_SIZE as u64,
    );
    shdr(8, ".got", 1, GOT_VADDR, DATA_FILE_OFFSET, 0x10, 0, 0);
    shdr(
        9,
        ".cpu_local",
        1,
        CPU_LOCAL_VADDR,
        DATA_FILE_OFFSET + 0x18,
        8,
        0,
        0,
    );
    shdr(
        10,
        ".bss",
        8,
        BSS_VADDR,
        DATA_FILE_OFFSET + 0x20,
        0x100,
        0,
        0,
    );
    shdr(
        11,
        ".symtab",
        2,
        0,
        SYMTAB_FILE_OFFSET,
        symtab.len() as u64,
        12,
        SYM_SIZE as u64,
    );
    shdr(
        12,
        ".strtab",
        3,
        0,
        STRTAB_FILE_OFFSET,
        strtab.bytes.len() as u64,
        0,
        0,
    );
    shdr(
        13,
        ".shstrtab",
        3,
        0,
        SHSTRTAB_FILE_OFFSET,
        shstrtab.bytes.len() as u64,
        0,
        0,
    );
    bytes[SHSTRTAB_FILE_OFFSET as usize..SHSTRTAB_FILE_OFFSET as usize + shstrtab.bytes.len()]
        .copy_from_slice(&shstrtab.bytes);

    bytes
}

/// A string table with offset bookkeeping.
struct StringTable {
    bytes: Vec<u8>,
}

impl StringTable {
    fn new() -> Self {
        Self { bytes: vec![0] }
    }

    fn push(&mut self, name: &str) {
        self.bytes.extend_from_slice(name.as_bytes());
        self.bytes.push(0);
    }

    fn offset_of(&self, name: &str) -> usize {
        let needle = [name.as_bytes(), b"\0"].concat();
        self.bytes
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("the name was pushed before")
    }
}

fn build_string_table() -> StringTable {
    let mut strtab = StringTable::new();
    for name in [
        "_kernelet_entry",
        "vcpu_entry",
        "virq_entry",
        "context_switch",
        "first_context_switch",
        "kernel_task_entry_wrapper",
        "kernel_task_entry",
        "__cpu_local_start",
        "__cpu_local_end",
        "__ex_table",
        "__ex_table_end",
        "__bss",
    ] {
        strtab.push(name);
    }
    strtab
}

fn build_section_string_table() -> StringTable {
    let mut shstrtab = StringTable::new();
    for name in [
        "",
        ".kernelet_entry_table",
        ".text",
        ".ex_table",
        ".rela.dyn",
        ".dynsym",
        ".dynstr",
        ".dynamic",
        ".got",
        ".cpu_local",
        ".bss",
        ".symtab",
        ".strtab",
        ".shstrtab",
    ] {
        shstrtab.push(name);
    }
    shstrtab
}

fn audit(bytes: &[u8]) -> Result<(), Vec<String>> {
    audit_kernelet_image(bytes, &SOURCE_HASH)
}

fn set_e_type(value: u16) -> Mutation {
    Mutation {
        offset: E_TYPE_OFFSET,
        bytes: value.to_le_bytes().to_vec(),
    }
}

#[test]
fn valid_image_passes() {
    let bytes = fixture();
    assert_eq!(audit(&bytes), Ok(()));
}

#[test]
fn indirect_entry_without_endbr_fails() {
    let bytes = image_with(&[Mutation {
        offset: TEXT_VADDR as usize,
        bytes: vec![0x90],
    }]);
    let violations = audit(&bytes).unwrap_err();
    assert!(
        violations
            .iter()
            .any(|v| v.contains("audit item 10") && v.contains("lacks ENDBR64")),
        "expected an indirect-entry violation, got: {violations:#?}"
    );
}

#[test]
fn virtual_interrupt_dispatcher_without_entry_marker_fails() {
    let bytes = image_with(&[Mutation {
        offset: TEXT_VADDR as usize + 0x20,
        bytes: vec![0x90],
    }]);
    let violations = audit(&bytes).unwrap_err();
    assert!(
        violations
            .iter()
            .any(|v| { v.contains("audit item 11") && v.contains("dispatcher") })
    );
}

#[test]
fn task_switch_without_stack_limit_publication_fails() {
    let bytes = image_with(&[Mutation {
        offset: TEXT_VADDR as usize + 0x200 + 44,
        bytes: vec![0x90],
    }]);
    let violations = audit(&bytes).unwrap_err();
    assert!(
        violations
            .iter()
            .any(|v| { v.contains("audit item 11") && v.contains("stack-limit publication") })
    );
}

#[test]
fn et_exec_fails() {
    let bytes = image_with(&[set_e_type(2)]);
    let violations = audit(&bytes).unwrap_err();
    assert!(
        violations.iter().any(|v| v.contains("ET_DYN")),
        "expected an ET_DYN violation, got: {violations:#?}"
    );
}

#[test]
fn wrong_entry_table_size_fails() {
    let bytes = image_with(&[Mutation {
        offset: ENTRY_TABLE_FILE_OFFSET,
        bytes: 87u64.to_le_bytes().to_vec(),
    }]);
    let violations = audit(&bytes).unwrap_err();
    assert!(
        violations
            .iter()
            .any(|v| v.contains("size field") && v.contains("audit item 4")),
        "expected an entry table size violation, got: {violations:#?}"
    );
}

#[test]
fn relocation_into_text_fails() {
    let bytes = image_with(&[Mutation {
        offset: RELA_ENTRY_FILE_OFFSET,
        bytes: TEXT_VADDR.to_le_bytes().to_vec(),
    }]);
    let violations = audit(&bytes).unwrap_err();
    assert!(
        violations.iter().any(|v| v.contains("audit item 8")),
        "expected a relocation target violation, got: {violations:#?}"
    );
}

#[test]
fn relocation_into_entry_table_fails() {
    let bytes = image_with(&[Mutation {
        offset: RELA_ENTRY_FILE_OFFSET,
        bytes: (ENTRY_TABLE_VADDR + 16).to_le_bytes().to_vec(),
    }]);
    let violations = audit(&bytes).unwrap_err();
    assert!(
        violations
            .iter()
            .any(|v| v.contains("audit item 4") && v.contains("entry table")),
        "expected an entry table relocation violation, got: {violations:#?}"
    );
}

#[test]
fn writable_text_segment_fails() {
    let bytes = image_with(&[Mutation {
        offset: TEXT_PHDR_FLAGS_OFFSET,
        bytes: (PF_R | PF_W | PF_X).to_le_bytes().to_vec(),
    }]);
    let violations = audit(&bytes).unwrap_err();
    assert!(
        violations
            .iter()
            .any(|v| v.contains("audit item 3") && v.contains("p_flags")),
        "expected a segment flags violation, got: {violations:#?}"
    );
}

#[test]
fn oversized_writable_template_fails() {
    let bytes = image_with(&[Mutation {
        offset: DATA_PHDR_MEMSZ_OFFSET,
        bytes: (HUGE_PAGE + 1).to_le_bytes().to_vec(),
    }]);
    let violations = audit(&bytes).unwrap_err();
    assert!(
        violations
            .iter()
            .any(|v| v.contains("audit item 5") && v.contains("2 MiB page")),
        "expected a writable template size violation, got: {violations:#?}"
    );
}

#[test]
fn undefined_symbol_fails() {
    let mut bytes = fixture();
    // Append a named but undefined symbol in the space after `.symtab`.
    let mut symbol = vec![0u8; SYM_SIZE];
    symbol[0..4].copy_from_slice(&1u32.to_le_bytes()); // the first name in `.strtab`
    symbol[6..8].copy_from_slice(&0u16.to_le_bytes()); // SHN_UNDEF
    let symtab_shdr = SHDR_FILE_OFFSET + 11 * SHDR_SIZE;
    let size = u64::from_le_bytes(
        bytes[symtab_shdr + 32..symtab_shdr + 40]
            .try_into()
            .unwrap(),
    );
    let base = SYMTAB_FILE_OFFSET as usize + size as usize;
    bytes[base..base + SYM_SIZE].copy_from_slice(&symbol);
    bytes[symtab_shdr + 32..symtab_shdr + 40]
        .copy_from_slice(&(size + SYM_SIZE as u64).to_le_bytes());
    let violations = audit(&bytes).unwrap_err();
    assert!(
        violations
            .iter()
            .any(|v| v.contains("audit item 1") && v.contains("undefined")),
        "expected an undefined symbol violation, got: {violations:#?}"
    );
}

#[test]
fn source_hash_mismatch_fails() {
    let mut bytes = fixture();
    let offset = ENTRY_TABLE_FILE_OFFSET + abi::entry_table::SOURCE_HASH_OFFSET;
    bytes[offset] ^= 0xff;
    let violations = audit(&bytes).unwrap_err();
    assert!(
        violations
            .iter()
            .any(|v| v.contains("audit item 7") && v.contains("source hash")),
        "expected a source hash violation, got: {violations:#?}"
    );
}

#[test]
fn absolute_exception_address_fails() {
    let bytes = image_with(&[Mutation {
        offset: RODATA_FILE_OFFSET as usize,
        bytes: (TEXT_VADDR + 8).to_le_bytes().to_vec(),
    }]);
    let violations = audit(&bytes).unwrap_err();
    assert!(
        violations
            .iter()
            .any(|v| v.contains("audit item 9") && v.contains("executable text")),
        "expected a self-relative exception table violation, got: {violations:#?}"
    );
}

#[test]
fn entry_table_cpu_local_bounds_mismatch_fails() {
    let bytes = image_with(&[Mutation {
        offset: ENTRY_TABLE_FILE_OFFSET + abi::entry_table::CPU_LOCAL_END_OFFSET,
        bytes: (CPU_LOCAL_VADDR + 4).to_le_bytes().to_vec(),
    }]);
    let violations = audit(&bytes).unwrap_err();
    assert!(
        violations
            .iter()
            .any(|v| v.contains("audit item 5") && v.contains("CPU-local bounds")),
        "expected a CPU-local bounds violation, got: {violations:#?}"
    );
}

#[test]
fn file_backed_section_inside_cpu_local_bounds_fails() {
    let mut bytes = fixture();
    // Name a stray file-backed section `.cpu_local_tss` and place it inside
    // the CPU-local bounds: both the absence check and the ordering check
    // must fire.
    let shstrtab = build_section_string_table();
    let mut names = shstrtab;
    names.push(".cpu_local_tss");
    let tss_name_offset = names.offset_of(".cpu_local_tss");
    bytes[SHSTRTAB_FILE_OFFSET as usize..SHSTRTAB_FILE_OFFSET as usize + names.bytes.len()]
        .copy_from_slice(&names.bytes);
    let base = SHDR_FILE_OFFSET + 14 * SHDR_SIZE;
    bytes[base..base + 4].copy_from_slice(&(tss_name_offset as u32).to_le_bytes());
    bytes[base + 4..base + 8].copy_from_slice(&1u32.to_le_bytes()); // PROGBITS
    bytes[base + 16..base + 24].copy_from_slice(&(CPU_LOCAL_VADDR + 4).to_le_bytes()); // sh_addr
    bytes[base + 24..base + 32].copy_from_slice(&(DATA_FILE_OFFSET + 0x14).to_le_bytes());
    bytes[base + 32..base + 40].copy_from_slice(&4u64.to_le_bytes()); // sh_size

    let violations = audit(&bytes).unwrap_err();
    assert!(
        violations
            .iter()
            .any(|v| v.contains("audit item 5") && v.contains(".cpu_local_tss")),
        "expected a .cpu_local_tss violation, got: {violations:#?}"
    );
}

const HUGE_PAGE: u64 = 0x20_0000;
