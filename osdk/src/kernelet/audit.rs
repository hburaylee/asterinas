// SPDX-License-Identifier: MPL-2.0

//! The kernelet image audit.
//!
//! After the kernelet image is linked and before the host image is built, OSDK
//! checks the image and fails the build on any violation. The checks implement
//! the artifact-level audit items listed in `kernelet/ABI.md`; each violation
//! message names the item it belongs to.

use super::{
    abi,
    elf::{self, DynamicEntry, ElfImage, ProgramHeader, Relocation, SectionHeader, Symbol},
};

mod prefixes;

/// The alignment that lets the read-only and the writable mappings of an
/// instance coexist with huge pages.
const HUGE_PAGE: u64 = 0x20_0000;

/// The size of one `ExTableItem` (`ostd/src/mm/fault/ex_table.rs`).
const EX_TABLE_ITEM_SIZE: u64 = 16;

/// Audits a linked kernelet image against the book's artifact checks.
///
/// `expected_source_hash` is the hash OSDK generated into the image's entry
/// table from the OSTD source tree and the toolchain version.
pub fn audit_kernelet_image(
    bytes: &[u8],
    expected_source_hash: &[u8; 32],
) -> Result<(), Vec<String>> {
    let mut violations = Vec::new();
    let image = match ElfImage::parse(bytes) {
        Ok(image) => image,
        Err(err) => return Err(vec![err]),
    };
    let Ok(program_headers) = image.program_headers() else {
        return Err(vec!["the program headers are unreadable".to_string()]);
    };
    let Ok(sections) = image.section_headers() else {
        violations.push("the section headers are missing or unreadable".to_string());
        return Err(violations);
    };
    let section_names: Vec<String> = (0..sections.len())
        .map(|i| image.section_name(&sections, i).unwrap_or_default())
        .collect();
    let (symbols, symbol_names) = match parse_symbol_table(&image, &sections) {
        Ok(parsed) => parsed,
        Err(err) => {
            violations.push(err);
            return Err(violations);
        }
    };
    let Some(loads) = classified_load_segments(&program_headers, &mut violations) else {
        return Err(violations);
    };
    let relocations = match image.relocations() {
        Ok(relocations) => relocations,
        Err(err) => {
            violations.push(format!("the relocation table is unreadable: {err}"));
            return Err(violations);
        }
    };
    let dynamic_entries = match image.dynamic_entries() {
        Ok(entries) => entries,
        Err(err) => return Err(vec![format!("the dynamic table is unreadable: {err}")]),
    };
    let Some(entry_table) = EntryTableBytes::parse(&image, &mut violations) else {
        return Err(violations);
    };

    check_1_no_imports(
        &image,
        &program_headers,
        &dynamic_entries,
        &symbols,
        &symbol_names,
        &mut violations,
    );
    check_2_relocation_types(&relocations, &dynamic_entries, &mut violations);
    check_3_segments(&image, &loads, &mut violations);
    check_4_entry_table(&entry_table, &loads, &relocations, &mut violations);
    check_5_data_template(
        &entry_table,
        &loads,
        &sections,
        &section_names,
        &symbols,
        &symbol_names,
        &mut violations,
    );
    check_7_source_hash(&entry_table, expected_source_hash, &mut violations);
    check_8_relocation_targets(&relocations, &loads.data, &mut violations);
    check_9_ex_table(
        &image,
        &entry_table,
        &sections,
        &section_names,
        &loads,
        &mut violations,
    );
    check_10_indirect_targets(&image, &entry_table, &loads, &relocations, &mut violations);
    if let Err(err) = prefixes::audit(
        &image,
        &symbols,
        &symbol_names,
        image.e_entry().unwrap_or_default(),
        entry_table.vcpu_entry(),
        entry_table.virq_entry(),
    ) {
        violations.push(err);
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

/// Audit item 10: all fixed image entry targets must begin with ENDBR64.
/// The relocation-backed indirect targets are checked below as well.
fn check_10_indirect_targets(
    image: &ElfImage<'_>,
    table: &EntryTableBytes<'_>,
    loads: &LoadSegments,
    relocations: &[Relocation],
    violations: &mut Vec<String>,
) {
    const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];
    let entry = match image.e_entry() {
        Ok(entry) => entry,
        Err(err) => {
            violations.push(format!("audit item 10: entry address unreadable: {err}"));
            return;
        }
    };
    let fixed = [
        ("image entry".to_string(), entry),
        ("secondary vCPU entry".to_string(), table.vcpu_entry()),
        ("virtual interrupt entry".to_string(), table.virq_entry()),
    ];
    let relocated = relocations.iter().filter_map(|relocation| {
        if relocation.rtype != elf::R_X86_64_RELATIVE {
            return None;
        }
        let target = u64::try_from(relocation.addend).ok()?;
        loads
            .text
            .covers_vaddr_range(target, target.saturating_add(ENDBR64.len() as u64))
            .then(|| {
                (
                    format!("relocated indirect target from {:#x}", relocation.offset),
                    target,
                )
            })
    });
    for (name, target) in fixed.into_iter().chain(relocated) {
        if !loads
            .text
            .covers_vaddr_range(target, target.saturating_add(ENDBR64.len() as u64))
        {
            violations.push(format!(
                "audit item 10: {name} target {target:#x} is outside executable text"
            ));
            continue;
        }
        match image.bytes_at_vaddr(target, ENDBR64.len() as u64) {
            Ok(prefix) if prefix == ENDBR64 => {}
            Ok(_) => violations.push(format!(
                "audit item 10: {name} target {target:#x} lacks ENDBR64"
            )),
            Err(err) => violations.push(format!(
                "audit item 10: {name} target {target:#x} is unreadable: {err}"
            )),
        }
    }
}

/// The three `PT_LOAD` segments of a kernelet image, in the order the book
/// fixes: text (R E), read-only data (R), and writable data (RW).
#[derive(Clone, Copy)]
struct LoadSegments {
    text: ProgramHeader,
    rodata: ProgramHeader,
    data: ProgramHeader,
}

/// The entry-table bytes read from their fixed offset in the image.
struct EntryTableBytes<'a> {
    bytes: &'a [u8],
}

impl<'a> EntryTableBytes<'a> {
    fn parse(image: &'a ElfImage, violations: &mut Vec<String>) -> Option<Self> {
        match image.bytes_at_vaddr(abi::ENTRY_TABLE_OFFSET, abi::entry_table::SIZE) {
            Ok(bytes) => Some(Self { bytes }),
            Err(err) => {
                violations.push(format!(
                    "audit item 4: the entry table is not file-backed at offset {:#x}: {}",
                    abi::ENTRY_TABLE_OFFSET,
                    err
                ));
                None
            }
        }
    }

    fn field(&self, offset: usize) -> u64 {
        u64::from_le_bytes(
            self.bytes[offset..offset + 8]
                .try_into()
                .expect("field offset is within the table"),
        )
    }

    fn size(&self) -> u64 {
        self.field(abi::entry_table::SIZE_FIELD_OFFSET)
    }

    fn vcpu_entry(&self) -> u64 {
        self.field(abi::entry_table::VCPU_ENTRY_OFFSET)
    }

    fn virq_entry(&self) -> u64 {
        self.field(abi::entry_table::VIRQ_ENTRY_OFFSET)
    }

    fn cpu_local_start(&self) -> u64 {
        self.field(abi::entry_table::CPU_LOCAL_START_OFFSET)
    }

    fn cpu_local_end(&self) -> u64 {
        self.field(abi::entry_table::CPU_LOCAL_END_OFFSET)
    }

    fn source_hash(&self) -> &[u8] {
        &self.bytes[abi::entry_table::SOURCE_HASH_OFFSET..abi::entry_table::SOURCE_HASH_OFFSET + 32]
    }

    fn ex_table_start(&self) -> u64 {
        self.field(abi::entry_table::EX_TABLE_START_OFFSET)
    }

    fn ex_table_end(&self) -> u64 {
        self.field(abi::entry_table::EX_TABLE_END_OFFSET)
    }
}

fn classified_load_segments(
    program_headers: &[ProgramHeader],
    violations: &mut Vec<String>,
) -> Option<LoadSegments> {
    let mut loads: Vec<&ProgramHeader> = program_headers
        .iter()
        .filter(|ph| ph.typ == elf::PT_LOAD)
        .collect();
    loads.sort_by_key(|ph| ph.vaddr);
    if loads.len() != 3 {
        violations.push(format!(
            "audit item 3: the image has {} PT_LOAD segments, expected exactly 3",
            loads.len()
        ));
        return None;
    }
    Some(LoadSegments {
        text: *loads[0],
        rodata: *loads[1],
        data: *loads[2],
    })
}

fn parse_symbol_table(
    image: &ElfImage,
    sections: &[SectionHeader],
) -> Result<(Vec<Symbol>, Vec<String>), String> {
    let symbols = image.symbols(sections)?;
    let strtab = image.symbol_string_table(sections)?;
    let names = symbols
        .iter()
        .map(|symbol| {
            image
                .symbol_name(&strtab, symbol)
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    Ok((symbols, names))
}

fn find_symbol<'a>(symbols: &'a [Symbol], names: &[String], name: &str) -> Option<&'a Symbol> {
    symbols
        .iter()
        .zip(names)
        .find(|(_, symbol_name)| symbol_name.as_str() == name)
        .map(|(symbol, _)| symbol)
}

/// Audit item 1: the image imports nothing.
fn check_1_no_imports(
    image: &ElfImage,
    program_headers: &[ProgramHeader],
    dynamic_entries: &[DynamicEntry],
    symbols: &[Symbol],
    symbol_names: &[String],
    violations: &mut Vec<String>,
) {
    match image.e_type() {
        Ok(elf::ET_DYN) => {}
        Ok(e_type) => violations.push(format!(
            "audit item 1: the image's `e_type` is {e_type}, expected ET_DYN ({}) from a position-independent link",
            elf::ET_DYN
        )),
        Err(err) => violations.push(format!("audit item 1: {err}")),
    }
    match image.e_machine() {
        Ok(elf::EM_X86_64) => {}
        Ok(machine) => violations.push(format!(
            "audit item 1: the image targets machine {machine}, expected x86-64 ({})",
            elf::EM_X86_64
        )),
        Err(err) => violations.push(format!("audit item 1: {err}")),
    }
    if program_headers.iter().any(|ph| ph.typ == elf::PT_INTERP) {
        violations.push("audit item 1: the image has a PT_INTERP segment".to_string());
    }
    if dynamic_entries
        .iter()
        .any(|entry| entry.tag == elf::DT_NEEDED)
    {
        violations.push("audit item 1: the image has a DT_NEEDED entry".to_string());
    }
    for (symbol, name) in symbols.iter().zip(symbol_names) {
        if symbol.shndx == 0 && !symbol.is_null() {
            violations.push(format!(
                "audit item 1: the image imports the undefined symbol `{name}`"
            ));
        }
    }
}

/// Audit item 2: every relocation is `R_X86_64_RELATIVE` and none is packed
/// into the compressed RELR encoding.
fn check_2_relocation_types(
    relocations: &[Relocation],
    dynamic_entries: &[DynamicEntry],
    violations: &mut Vec<String>,
) {
    let has_relr = |tag: u64| {
        dynamic_entries
            .iter()
            .any(|entry| entry.tag == tag && entry.value != 0)
    };
    if dynamic_entries
        .iter()
        .any(|entry| entry.tag == elf::DT_RELR)
        || has_relr(elf::DT_RELRSZ)
    {
        violations.push(
            "audit item 2: the image packs relocations into the compressed RELR encoding, which the relocation loop cannot read"
                .to_string(),
        );
    }
    for relocation in relocations {
        if relocation.rtype != elf::R_X86_64_RELATIVE {
            violations.push(format!(
                "audit item 2: the image carries a relocation of type {}, expected only R_X86_64_RELATIVE ({})",
                relocation.rtype, elf::R_X86_64_RELATIVE
            ));
        } else if relocation.addend < 0 {
            violations.push(format!(
                "audit item 2: relative relocation at {:#x} has a negative image offset {}",
                relocation.offset, relocation.addend
            ));
        }
    }
}

/// Audit item 3: the PT_LOAD segments, their permissions, their alignment and
/// the ELF entry point follow the fixed region layout.
fn check_3_segments(image: &ElfImage, loads: &LoadSegments, violations: &mut Vec<String>) {
    let LoadSegments { text, rodata, data } = *loads;
    let mut check_flags = |name: &str, ph: &ProgramHeader, expected: u32| {
        if ph.flags != expected {
            violations.push(format!(
                "audit item 3: the {name} segment has p_flags {:#x}, expected {:#x}",
                ph.flags, expected
            ));
        }
    };
    check_flags("text", &text, elf::PF_R | elf::PF_X);
    check_flags("read-only data", &rodata, elf::PF_R);
    check_flags("writable data", &data, elf::PF_R | elf::PF_W);

    let text_end = text.vaddr.saturating_add(text.memsz);
    let rodata_end = rodata.vaddr.saturating_add(rodata.memsz);
    if text_end > data.vaddr {
        violations.push(
            "audit item 3: the text segment does not lie inside the KW_TEXT range".to_string(),
        );
    }
    if rodata.vaddr < text_end {
        violations
            .push("audit item 3: the read-only data segment overlaps the text segment".to_string());
    }
    if rodata_end > data.vaddr {
        violations.push(
            "audit item 3: the read-only data segment does not lie inside the KW_TEXT range"
                .to_string(),
        );
    }
    if data.vaddr % HUGE_PAGE != 0 {
        violations.push(format!(
            "audit item 3: the writable segment base {:#x} is not {}-aligned",
            data.vaddr, HUGE_PAGE
        ));
    }
    if rodata.vaddr % HUGE_PAGE != 0 {
        violations.push(format!(
            "audit item 3: the text-to-read-only-data permission transition at {:#x} is not {}-aligned",
            rodata.vaddr, HUGE_PAGE
        ));
    }
    if data.memsz > HUGE_PAGE {
        violations
            .push("audit item 3: the writable segment spans more than one 2 MiB page".to_string());
    }
    for (name, ph) in [
        ("text", &text),
        ("read-only data", &rodata),
        ("writable data", &data),
    ] {
        if ph.align < 0x1000 || ph.offset % ph.align != ph.vaddr % ph.align {
            violations.push(format!(
                "audit item 3: the {name} segment's file offset {:#x} is not congruent to its virtual address {:#x} modulo its alignment {:#x}",
                ph.offset, ph.vaddr, ph.align
            ));
        }
    }
    match image.e_entry() {
        Ok(entry) if text.covers_vaddr_range(entry, entry + 1) => {}
        Ok(entry) => violations.push(format!(
            "audit item 3: the entry point {entry:#x} lies outside the executable text segment"
        )),
        Err(err) => violations.push(format!("audit item 3: {err}")),
    }
}

/// Audit item 4: the entry table lies at the fixed offset, its size matches the
/// ABI OSTD was compiled against, its address-like fields decode into the right
/// regions, and no dynamic relocation targets it.
fn check_4_entry_table(
    table: &EntryTableBytes,
    loads: &LoadSegments,
    relocations: &[Relocation],
    violations: &mut Vec<String>,
) {
    let size = table.size();
    if size != abi::entry_table::SIZE {
        violations.push(format!(
            "audit item 4: the entry table's size field is {size}, expected {}",
            abi::entry_table::SIZE
        ));
    }
    for (name, entry) in [
        ("vcpu_entry", table.vcpu_entry()),
        ("virq_entry", table.virq_entry()),
    ] {
        if !loads.text.covers_vaddr_range(entry, entry + 1) {
            violations.push(format!(
                "audit item 4: the entry table's {name} offset {entry:#x} does not decode inside the executable text segment"
            ));
        }
    }
    let (cpu_local_start, cpu_local_end) = (table.cpu_local_start(), table.cpu_local_end());
    if cpu_local_start > cpu_local_end
        || !loads
            .data
            .covers_vaddr_range(cpu_local_start, cpu_local_end)
    {
        violations.push(format!(
            "audit item 4: the entry table's CPU-local bounds [{cpu_local_start:#x}, {cpu_local_end:#x}) do not decode inside the writable segment"
        ));
    }
    let (ex_table_start, ex_table_end) = (table.ex_table_start(), table.ex_table_end());
    if ex_table_start > ex_table_end
        || ex_table_start < abi::ENTRY_TABLE_OFFSET
        || ex_table_end > loads.data.vaddr
    {
        violations.push(format!(
            "audit item 4: the entry table's exception-table bounds [{ex_table_start:#x}, {ex_table_end:#x}) do not decode inside the KW_TEXT range"
        ));
    }
    for relocation in relocations {
        if relocation.offset >= abi::ENTRY_TABLE_OFFSET
            && relocation.offset < abi::ENTRY_TABLE_OFFSET + abi::entry_table::SIZE
        {
            violations.push(format!(
                "audit item 4: a dynamic relocation targets {:#x} inside the entry table, whose bytes must be link-time offsets",
                relocation.offset
            ));
        }
    }
}

/// Audit item 5: the CPU-local template and the exception table lie where the
/// entry table's bounds say; `.cpu_local` ends the file-backed writable run,
/// with only `.bss` after it; the Host-only `.cpu_local_tss` is absent; and the
/// whole writable template fits one huge page.
fn check_5_data_template(
    table: &EntryTableBytes,
    loads: &LoadSegments,
    sections: &[SectionHeader],
    section_names: &[String],
    symbols: &[Symbol],
    symbol_names: &[String],
    violations: &mut Vec<String>,
) {
    if section_names.iter().any(|name| name == ".cpu_local_tss") {
        violations.push(
            "audit item 5: the image contains a `.cpu_local_tss` section, but a kernelet uses the Host's TSS"
                .to_string(),
        );
    }
    if loads.data.memsz > HUGE_PAGE {
        violations.push(
            "audit item 5: the writable template, including zero-filled `.bss`, does not fit one 2 MiB page"
                .to_string(),
        );
    }

    let mut read_symbol = |name: &str| match find_symbol(symbols, symbol_names, name) {
        Some(symbol) => Some(symbol.value),
        None => {
            violations.push(format!("audit item 5: the image lacks the `{name}` symbol"));
            None
        }
    };
    let Some(sym_cpu_local_start) = read_symbol("__cpu_local_start") else {
        return;
    };
    let Some(sym_cpu_local_end) = read_symbol("__cpu_local_end") else {
        return;
    };
    let Some(sym_ex_table) = read_symbol("__ex_table") else {
        return;
    };
    let Some(sym_ex_table_end) = read_symbol("__ex_table_end") else {
        return;
    };

    // The bounds must agree with the entry table the Host will decode.
    if sym_cpu_local_start != table.cpu_local_start() || sym_cpu_local_end != table.cpu_local_end()
    {
        violations.push(
            "audit item 5: the entry table's CPU-local bounds do not match `__cpu_local_start`/`__cpu_local_end`"
                .to_string(),
        );
    }
    if sym_ex_table != table.ex_table_start() || sym_ex_table_end != table.ex_table_end() {
        violations.push(
            "audit item 5: the entry table's exception-table bounds do not match `__ex_table`/`__ex_table_end`"
                .to_string(),
        );
    }

    if !loads
        .data
        .covers_vaddr_range(sym_cpu_local_start, sym_cpu_local_end)
    {
        violations.push(
            "audit item 5: `__cpu_local_start`/`__cpu_local_end` do not lie inside the writable segment"
                .to_string(),
        );
    }

    // `.cpu_local` ends the file-backed writable run: every non-empty
    // PROGBITS section at or after `__cpu_local_start` must be `.cpu_local`
    // itself, and everything after `__cpu_local_end` must be zero-filled.
    let template_end = loads.data.vaddr.saturating_add(loads.data.memsz);
    for (section, name) in sections.iter().zip(section_names) {
        if section.size == 0 || section.addr < sym_cpu_local_start || section.addr >= template_end {
            continue;
        }
        if section.addr < sym_cpu_local_end
            && section.typ == elf::SHT_PROGBITS
            && name != ".cpu_local"
        {
            violations.push(format!(
                "audit item 5: the file-backed section `{name}` at {:#x} lies inside the CPU-local bounds",
                section.addr
            ));
        }
        if section.addr >= sym_cpu_local_end && section.typ != elf::SHT_NOBITS {
            violations.push(format!(
                "audit item 5: the section `{name}` at {:#x} follows `__cpu_local_end` but is not zero-filled",
                section.addr
            ));
        }
    }
}

/// Audit item 7: the entry table's source hash equals the hash OSDK computed
/// from the OSTD source tree and the toolchain version.
fn check_7_source_hash(
    table: &EntryTableBytes,
    expected_source_hash: &[u8; 32],
    violations: &mut Vec<String>,
) {
    if table.source_hash() != expected_source_hash {
        violations.push(
            "audit item 7: the entry table's source hash does not match the OSTD source tree and toolchain hash"
                .to_string(),
        );
    }
}

/// Audit item 8: every relocation lies inside the writable segment, which the
/// host copies and fixes up per instance; `.text` and `.rodata` carry none.
fn check_8_relocation_targets(
    relocations: &[Relocation],
    data: &ProgramHeader,
    violations: &mut Vec<String>,
) {
    for relocation in relocations {
        let in_data = relocation
            .offset
            .checked_add(size_of::<u64>() as u64)
            .is_some_and(|end| data.covers_vaddr_range(relocation.offset, end));
        if !in_data {
            violations.push(format!(
                "audit item 8: a relocation targets {:#x}, outside the writable segment [{:#x}, {:#x}); the shared regions must carry no relocations",
                relocation.offset,
                data.vaddr,
                data.vaddr + data.memsz
            ));
        }
    }
}

/// Audit item 9 (the artifact-level portion): the exception table holds an
/// integral number of fixed-size entries and lies in the shared read-only data,
/// so it can carry no per-instance relocation.
///
/// OSDK and the Host both decode the self-relative entries (decision D87),
/// check their order, and confine their targets to executable text.
fn check_9_ex_table(
    image: &ElfImage,
    table: &EntryTableBytes,
    sections: &[SectionHeader],
    section_names: &[String],
    loads: &LoadSegments,
    violations: &mut Vec<String>,
) {
    if table.ex_table_start() == table.ex_table_end() {
        // An image with no fallible copies has an empty exception table; the
        // bounds were validated against the symbols by item 5.
        return;
    }
    let Some((section, _)) = sections
        .iter()
        .zip(section_names)
        .find(|(section, name)| *name == ".ex_table" && section.typ == elf::SHT_PROGBITS)
    else {
        violations.push(
            "audit item 9: the entry table names a non-empty exception table, but the image has no `.ex_table` section"
                .to_string(),
        );
        return;
    };
    if section.size % EX_TABLE_ITEM_SIZE != 0 {
        violations.push(format!(
            "audit item 9: `.ex_table` is {} bytes, not a multiple of the {}-byte entry size",
            section.size, EX_TABLE_ITEM_SIZE
        ));
        return;
    }
    let rodata_end = loads.rodata.vaddr.saturating_add(loads.rodata.memsz);
    if section.addr < loads.rodata.vaddr
        || section
            .addr
            .checked_add(section.size)
            .is_none_or(|end| end > rodata_end)
    {
        violations.push(
            "audit item 9: `.ex_table` does not lie in the shared read-only data segment"
                .to_string(),
        );
        return;
    }
    if section.addr != table.ex_table_start()
        || table.ex_table_end().checked_sub(table.ex_table_start()) != Some(section.size)
    {
        violations
            .push("audit item 9: `.ex_table` does not match the entry-table bounds".to_string());
        return;
    }
    let Ok(bytes) = image.bytes_at_vaddr(section.addr, section.size) else {
        violations.push("audit item 9: `.ex_table` is not file-backed".to_string());
        return;
    };
    let mut previous_fault = None;
    for (index, entry) in bytes
        .as_chunks::<{ EX_TABLE_ITEM_SIZE as usize }>()
        .0
        .iter()
        .enumerate()
    {
        let field_addr = section.addr + index as u64 * EX_TABLE_ITEM_SIZE;
        let decode = |field: &[u8], addr: u64| {
            let delta = i64::from_le_bytes(field.try_into().unwrap());
            addr.checked_add_signed(delta)
        };
        let fault = decode(&entry[..8], field_addr);
        let recovery = decode(&entry[8..], field_addr + 8);
        let valid_target = |target: Option<u64>| {
            target.is_some_and(|addr| {
                addr.checked_add(1)
                    .is_some_and(|end| loads.text.covers_vaddr_range(addr, end))
            })
        };
        if !valid_target(fault) || !valid_target(recovery) {
            violations.push(format!(
                "audit item 9: exception-table entry {index} does not decode into executable text"
            ));
        }
        if let Some(fault) = fault {
            if previous_fault.is_some_and(|previous| fault <= previous) {
                violations.push(format!(
                    "audit item 9: exception-table entry {index} is not sorted by a unique fault address"
                ));
            }
            previous_fault = Some(fault);
        }
    }
}

#[cfg(test)]
mod tests;
