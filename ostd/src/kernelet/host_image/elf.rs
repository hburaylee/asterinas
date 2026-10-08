// SPDX-License-Identifier: MPL-2.0

//! Validates the position-independent kernelet ELF image.

use super::*;

// ---- Image format constants, from the ELF specification and the design ----

/// Offset of the entry table from the image base (`ENTRY_TABLE_OFFSET`).
pub(super) const ENTRY_TABLE_OFFSET: u64 = 0x1000;
/// Size of the [`EntryTable`] in bytes.
pub(super) const ENTRY_TABLE_SIZE: u64 = size_of::<EntryTable>() as u64;
/// Size of one exception-table entry: two self-relative `i64` offsets (D87).
pub(super) const EX_TABLE_ENTRY_SIZE: u64 = 16;
/// Size of one ELF64 `Rela` relocation entry.
pub(super) const RELA_ENTRY_SIZE: u64 = 24;
/// The only relocation type the loader applies: `R_X86_64_RELATIVE`, whose
/// entry carries no symbol index.
pub(super) const R_X86_64_RELATIVE: u64 = 8;
/// ELF identification: 64-bit objects (`ELFCLASS64`).
pub(super) const ELFCLASS64: u8 = 2;
/// ELF identification: little-endian two's complement (`ELFDATA2LSB`).
pub(super) const ELFDATA2LSB: u8 = 1;
/// ELF type: position-independent shared object (`ET_DYN`).
pub(super) const ET_DYN: u16 = 3;
/// ELF machine: AMD x86-64 (`EM_X86_64`).
pub(super) const EM_X86_64: u16 = 0x3E;
/// Program header type: a loadable segment (`PT_LOAD`).
pub(super) const PT_LOAD: u32 = 1;
/// Program header type: the dynamic linking information (`PT_DYNAMIC`).
pub(super) const PT_DYNAMIC: u32 = 2;
/// Segment permission flag: readable (`PF_R`).
pub(super) const PF_R: u32 = 0x4;
/// Segment permission flag: writable (`PF_W`).
pub(super) const PF_W: u32 = 0x2;
/// Segment permission flag: executable (`PF_X`).
pub(super) const PF_X: u32 = 0x1;
/// Dynamic tag: `DT_NULL`, the end marker of the dynamic table.
pub(super) const DT_NULL: u64 = 0;
/// Dynamic tag: `DT_NEEDED`, a dependency on another object.
pub(super) const DT_NEEDED: u64 = 1;
/// Dynamic tag: `DT_PLTRELSZ`, the size in bytes of the PLT relocation table.
pub(super) const DT_PLTRELSZ: u64 = 2;
/// Dynamic tag: `DT_RELA`, the address of the Rela relocation table.
pub(super) const DT_RELA: u64 = 7;
/// Dynamic tag: `DT_RELASZ`, the size in bytes of the `DT_RELA` table.
pub(super) const DT_RELASZ: u64 = 8;
/// Dynamic tag: `DT_RELAENT`, the size in bytes of one `DT_RELA` entry.
pub(super) const DT_RELAENT: u64 = 9;
/// Dynamic tag: `DT_REL`, the address of an int32-based relocation table.
pub(super) const DT_REL: u64 = 17;
/// Dynamic tag: `DT_RELSZ`, the size of the `DT_REL` table.
pub(super) const DT_RELSZ: u64 = 18;
/// Dynamic tag: `DT_RELENT`, the size of one `DT_REL` entry.
pub(super) const DT_RELENT: u64 = 19;
/// Dynamic tag: `DT_JMPREL`, the address of the PLT relocation table.
pub(super) const DT_JMPREL: u64 = 23;
/// Dynamic tag: `DT_RELRSZ`, the size of the packed relative relocation table.
pub(super) const DT_RELRSZ: u64 = 35;
/// Dynamic tag: `DT_RELR`, the address of a packed relative relocation table.
pub(super) const DT_RELR: u64 = 36;
/// Dynamic tag: `DT_RELRENT`, the size of one packed relative relocation entry.
pub(super) const DT_RELRENT: u64 = 37;
/// Size of one ELF64 dynamic entry (`d_tag` plus `d_un`).
pub(super) const DYN_ENTRY_SIZE: u64 = 16;
/// Size of the ELF64 file header (`Elf64_Ehdr`).
pub(super) const ELF_HEADER_SIZE: usize = 64;
/// Size of one ELF64 program header entry (`Elf64_Phdr`).
pub(super) const PHDR_ENTRY_SIZE: usize = 56;
/// The upper bound this loader accepts for any image offset. Nothing real
/// approaches it; it bounds arithmetic and boot-time work on corrupt input.
pub(super) const MAX_IMAGE_VADDR: u64 = 1 << 30;
/// The entire writable template, including zero-filled `.bss`, must fit one
/// 2 MiB huge page; a larger image fails this version's build audit.
pub(super) const DATA_TEMPLATE_MAX_BYTES: u64 = 2 << 20;

impl ParsedImage {
    /// Parses and fully validates the embedded image bytes.
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < ELF_HEADER_SIZE {
            return Err(Error::InvalidArgs);
        }
        if bytes[..4] != [0x7F, b'E', b'L', b'F'] {
            return Err(Error::InvalidArgs);
        }
        if bytes[4] != ELFCLASS64 || bytes[5] != ELFDATA2LSB {
            return Err(Error::InvalidArgs);
        }
        if read_le_u16(bytes, 16)? != ET_DYN || read_le_u16(bytes, 18)? != EM_X86_64 {
            return Err(Error::InvalidArgs);
        }

        let entry_offset = read_le_u64(bytes, 24)?;
        let phdr_table_offset = read_le_u64(bytes, 32)?;
        let phdr_entry_size = read_le_u16(bytes, 54)? as usize;
        let phdr_count = read_le_u16(bytes, 56)? as usize;
        if phdr_entry_size != PHDR_ENTRY_SIZE {
            return Err(Error::InvalidArgs);
        }
        let phdr_table_size = (phdr_count as u64)
            .checked_mul(PHDR_ENTRY_SIZE as u64)
            .ok_or(Error::Overflow)?;
        let phdr_table_end = phdr_table_offset
            .checked_add(phdr_table_size)
            .ok_or(Error::Overflow)?;
        if phdr_table_end > bytes.len() as u64 {
            return Err(Error::InvalidArgs);
        }

        // Classify the loadable segments. The image has at most one segment
        // per permission class, in the order text, read-only data, data.
        let mut text = None;
        let mut rodata = None;
        let mut data = None;
        let mut dynamic = None;
        let mut prev_end = 0;
        for index in 0..phdr_count {
            let phdr = phdr_table_offset as usize + index * PHDR_ENTRY_SIZE;
            let p_type = read_le_u32(bytes, phdr)?;
            let p_flags = read_le_u32(bytes, phdr + 4)?;
            let p_offset = read_le_u64(bytes, phdr + 8)?;
            let p_vaddr = read_le_u64(bytes, phdr + 16)?;
            let p_filesz = read_le_u64(bytes, phdr + 32)?;
            let p_memsz = read_le_u64(bytes, phdr + 40)?;

            match p_type {
                PT_LOAD => {
                    let span = validate_load(
                        bytes, p_flags, p_offset, p_vaddr, p_filesz, p_memsz, prev_end,
                    )?;
                    prev_end = span.vaddr.checked_add(span.memsz).ok_or(Error::Overflow)?;
                    let slot = if p_flags & PF_X != 0 {
                        // The text segment must come first, and it is fully
                        // file-backed: no anonymous zero pages are executable.
                        if text.is_some()
                            || rodata.is_some()
                            || data.is_some()
                            || p_memsz != p_filesz
                        {
                            return Err(Error::InvalidArgs);
                        }
                        &mut text
                    } else if p_flags & PF_W != 0 {
                        if data.is_some() {
                            return Err(Error::InvalidArgs);
                        }
                        &mut data
                    } else {
                        // Readable and non-executable, and the read-only
                        // segments are fully file-backed as well.
                        if rodata.is_some() || data.is_some() || p_memsz != p_filesz {
                            return Err(Error::InvalidArgs);
                        }
                        &mut rodata
                    };
                    *slot = Some(span);
                }
                PT_DYNAMIC => {
                    if dynamic.is_some() {
                        return Err(Error::InvalidArgs);
                    }
                    let end = p_offset.checked_add(p_filesz).ok_or(Error::Overflow)?;
                    if end > bytes.len() as u64 {
                        return Err(Error::InvalidArgs);
                    }
                    dynamic = Some((p_offset, p_filesz));
                }
                _ => {}
            }
        }
        let text = text.ok_or(Error::InvalidArgs)?;
        if prev_end > MAX_IMAGE_VADDR {
            return Err(Error::InvalidArgs);
        }
        if let Some(data) = &data {
            // This version's audit requires the whole writable template,
            // `.bss` included, to fit one huge page.
            if data.memsz > DATA_TEMPLATE_MAX_BYTES {
                return Err(Error::InvalidArgs);
            }
        }

        // The entry point must lie in the executable text segment.
        if text.file_offset_of(entry_offset, 1).is_none() {
            return Err(Error::InvalidArgs);
        }

        let entry_table = parse_entry_table(bytes, &text, &rodata, &data)?;
        let relocations = parse_relocations(bytes, &text, &rodata, &data, dynamic)?;

        Ok(Self {
            entry_offset,
            text,
            rodata,
            data,
            relocations,
            entry_table,
        })
    }

    /// Returns the end of the last load segment.
    pub(super) fn last_load_end(&self) -> u64 {
        self.data
            .as_ref()
            .map(|span| span.vaddr + span.memsz)
            .or_else(|| self.rodata.as_ref().map(|span| span.vaddr + span.memsz))
            .unwrap_or_else(|| self.text.vaddr + self.text.memsz)
    }

    /// Returns the end of the 2 MiB slot containing the last load byte.
    /// Per-vCPU replicas begin here; `KW_SHARED` follows those replicas.
    pub(super) fn data_end_offset(&self) -> Result<usize> {
        let aligned =
            align_up(self.last_load_end(), DATA_TEMPLATE_MAX_BYTES).ok_or(Error::Overflow)?;
        usize::try_from(aligned).map_err(|_| Error::Overflow)
    }
}

/// Validates one loadable segment's placement and permissions. Classification
/// into the text, rodata, or data role is the caller's job. Returns the
/// segment's placement in the image.
fn validate_load(
    bytes: &[u8],
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    prev_end: u64,
) -> Result<SegmentSpan> {
    // Every segment begins at a page boundary so that instances map the
    // image with page granularity while preserving link-time distances.
    if !p_vaddr.is_multiple_of(PAGE_SIZE_U64) {
        return Err(Error::InvalidArgs);
    }
    // Segments occupy ascending, non-overlapping image offsets.
    if p_vaddr < prev_end {
        return Err(Error::InvalidArgs);
    }
    if p_memsz < p_filesz {
        return Err(Error::InvalidArgs);
    }
    let file_end = p_offset.checked_add(p_filesz).ok_or(Error::Overflow)?;
    if file_end > bytes.len() as u64 {
        return Err(Error::InvalidArgs);
    }
    // The image format gives each segment exactly one permission class.
    if p_flags != PF_R && p_flags != (PF_R | PF_X) && p_flags != (PF_R | PF_W) {
        return Err(Error::InvalidArgs);
    }
    Ok(SegmentSpan {
        file_offset: p_offset,
        vaddr: p_vaddr,
        filesz: p_filesz,
        memsz: p_memsz,
    })
}

/// Parses and validates the entry table at the fixed image offset, checking
/// every decoded target against the segment bounds.
fn parse_entry_table(
    bytes: &[u8],
    text: &SegmentSpan,
    rodata: &Option<SegmentSpan>,
    data: &Option<SegmentSpan>,
) -> Result<EntryTable> {
    // The table is found without a symbol table at its fixed offset; it is
    // file-backed by one of the read-only segments.
    let containing = read_only_segment_at(ENTRY_TABLE_OFFSET, ENTRY_TABLE_SIZE, text, rodata)
        .ok_or(Error::InvalidArgs)?;
    let table_offset = containing
        .file_offset_of(ENTRY_TABLE_OFFSET, ENTRY_TABLE_SIZE)
        .ok_or(Error::InvalidArgs)?;

    let read_field = |offset: usize| read_le_u64(bytes, table_offset + offset);
    let mut source_hash = [0u8; 32];
    source_hash.copy_from_slice(read_le_bytes(bytes, table_offset + 40, 32)?);
    let entry_table = EntryTable {
        size: read_field(0)?,
        vcpu_entry_offset: read_field(8)?,
        virq_entry_offset: read_field(16)?,
        cpu_local_start_offset: read_field(24)?,
        cpu_local_end_offset: read_field(32)?,
        source_hash,
        ex_table_start_offset: read_field(72)?,
        ex_table_end_offset: read_field(80)?,
    };

    if entry_table.size != ENTRY_TABLE_SIZE {
        return Err(Error::InvalidArgs);
    }

    // The fixed entries are code addresses inside the executable segment.
    for entry in [entry_table.vcpu_entry_offset, entry_table.virq_entry_offset] {
        if text.file_offset_of(entry, 1).is_none() {
            return Err(Error::InvalidArgs);
        }
    }

    // The CPU-local template lives in the private writable segment, inside
    // its file-backed contents.
    let cpu_local_len = entry_table
        .cpu_local_end_offset
        .checked_sub(entry_table.cpu_local_start_offset)
        .ok_or(Error::InvalidArgs)?;
    if cpu_local_len > 0 {
        let cpu_local_ok = data
            .as_ref()
            .and_then(|data| data.file_offset_of(entry_table.cpu_local_start_offset, cpu_local_len))
            .is_some();
        if !cpu_local_ok {
            return Err(Error::InvalidArgs);
        }
    }

    validate_ex_table(bytes, text, rodata, &entry_table)?;

    Ok(entry_table)
}

/// Validates the exception table whose bounds the entry table carries (D87):
/// an integral number of self-relative entries, strictly sorted by unique
/// decoded fault address, with every decoded address inside the executable
/// text segment.
fn validate_ex_table(
    bytes: &[u8],
    text: &SegmentSpan,
    rodata: &Option<SegmentSpan>,
    entry_table: &EntryTable,
) -> Result<()> {
    let table_len = entry_table
        .ex_table_end_offset
        .checked_sub(entry_table.ex_table_start_offset)
        .ok_or(Error::InvalidArgs)?;
    if table_len % EX_TABLE_ENTRY_SIZE != 0 {
        return Err(Error::InvalidArgs);
    }
    if table_len == 0 {
        return Ok(());
    }
    let containing = rodata.as_ref().ok_or(Error::InvalidArgs)?;
    if containing
        .file_offset_of(entry_table.ex_table_start_offset, table_len)
        .is_none()
    {
        return Err(Error::InvalidArgs);
    }

    let text_end = text.vaddr + text.filesz;
    let mut prev_fault = None;
    for index in 0..table_len / EX_TABLE_ENTRY_SIZE {
        let entry_vaddr = entry_table.ex_table_start_offset + index * EX_TABLE_ENTRY_SIZE;
        let entry_offset = containing
            .file_offset_of(entry_vaddr, EX_TABLE_ENTRY_SIZE)
            .ok_or(Error::InvalidArgs)?;
        // Self-relative encoding: the stored value is the offset from the
        // entry field's own address to the target instruction.
        let fault = decode_self_relative(bytes, entry_offset, entry_vaddr)?;
        let recovery = decode_self_relative(bytes, entry_offset + 8, entry_vaddr + 8)?;
        let in_text = |target: i64| {
            target >= 0 && (target as u64) >= text.vaddr && (target as u64) < text_end
        };
        if !in_text(fault) || !in_text(recovery) {
            return Err(Error::InvalidArgs);
        }
        if prev_fault.is_some_and(|prev| fault <= prev) {
            return Err(Error::InvalidArgs);
        }
        prev_fault = Some(fault);
    }
    Ok(())
}

/// Decodes one self-relative `i64` field stored at `entry_offset` for the
/// entry that sits at image offset `entry_vaddr`.
fn decode_self_relative(bytes: &[u8], entry_offset: usize, entry_vaddr: u64) -> Result<i64> {
    let stored = read_le_u64(bytes, entry_offset)? as i64;
    let base = i64::try_from(entry_vaddr).map_err(|_| Error::InvalidArgs)?;
    base.checked_add(stored).ok_or(Error::InvalidArgs)
}

/// Parses the `PT_DYNAMIC` table, if any, and collects the relocations.
///
/// The image imports nothing, so the only dynamic-linking machinery it may
/// carry is what its own relocations need: a `DT_RELA` table of
/// `R_X86_64_RELATIVE` entries. Int32 relocations, packed (RELR) relative
/// relocations, and non-empty PLT relocations are rejected, as are
/// relocations that target anything outside the writable segment.
fn parse_relocations(
    bytes: &[u8],
    text: &SegmentSpan,
    rodata: &Option<SegmentSpan>,
    data: &Option<SegmentSpan>,
    dynamic: Option<(u64, u64)>,
) -> Result<Vec<Relocation>> {
    let Some((dynamic_offset, dynamic_len)) = dynamic else {
        return Ok(Vec::new());
    };
    if dynamic_len % DYN_ENTRY_SIZE != 0 {
        return Err(Error::InvalidArgs);
    }

    let mut rela_vaddr = None;
    let mut rela_size = None;
    let mut rela_ent_size = None;
    let mut plt_reloc_size = None;
    let mut jmprel_present = false;
    for index in 0..dynamic_len / DYN_ENTRY_SIZE {
        let entry_offset = dynamic_offset as usize
            + usize::try_from(index * DYN_ENTRY_SIZE).map_err(|_| Error::Overflow)?;
        let tag = read_le_u64(bytes, entry_offset)?;
        let val = read_le_u64(bytes, entry_offset + 8)?;
        match tag {
            DT_NULL => break,
            // The image imports nothing; a dependency would make the shared
            // read-only regions a lie and is rejected outright.
            DT_NEEDED => return Err(Error::InvalidArgs),
            // Reject every relocation format other than RELA. Packed
            // (RELR) tables in particular would be invisible to the flat
            // fix-up loop below.
            DT_REL | DT_RELSZ | DT_RELENT => return Err(Error::InvalidArgs),
            DT_RELR | DT_RELRSZ | DT_RELRENT => return Err(Error::InvalidArgs),
            DT_PLTRELSZ => plt_reloc_size = Some(val),
            DT_JMPREL => jmprel_present = true,
            DT_RELA => {
                if rela_vaddr.is_some() {
                    return Err(Error::InvalidArgs);
                }
                rela_vaddr = Some(val);
            }
            DT_RELASZ => {
                if rela_size.is_some() {
                    return Err(Error::InvalidArgs);
                }
                rela_size = Some(val);
            }
            DT_RELAENT => {
                if rela_ent_size.is_some() {
                    return Err(Error::InvalidArgs);
                }
                rela_ent_size = Some(val);
            }
            _ => {}
        }
    }
    // A non-empty PLT relocation table means the image enters through a PLT,
    // which these relocation-free shared regions do not carry.
    if jmprel_present && plt_reloc_size.unwrap_or(0) != 0 {
        return Err(Error::InvalidArgs);
    }

    let Some(rela_vaddr) = rela_vaddr else {
        return if rela_size.unwrap_or(0) == 0 && rela_ent_size.is_none() {
            Ok(Vec::new())
        } else {
            Err(Error::InvalidArgs)
        };
    };
    let rela_size = rela_size.ok_or(Error::InvalidArgs)?;
    let rela_ent_size = rela_ent_size.unwrap_or(RELA_ENTRY_SIZE);
    if rela_ent_size != RELA_ENTRY_SIZE || rela_size % RELA_ENTRY_SIZE != 0 {
        return Err(Error::InvalidArgs);
    }
    // The relocation table is read from the file, so it must be file-backed
    // by one segment's contents.
    let table_offset = [Some(*text), *rodata, *data]
        .into_iter()
        .find_map(|span| span.and_then(|span| span.file_offset_of(rela_vaddr, rela_size)))
        .ok_or(Error::InvalidArgs)?;

    let data = data.as_ref().ok_or(Error::InvalidArgs)?;
    let word_size = size_of::<u64>() as u64;
    let mut relocations = Vec::new();
    for index in 0..rela_size / RELA_ENTRY_SIZE {
        let entry_offset =
            table_offset + usize::try_from(index * RELA_ENTRY_SIZE).map_err(|_| Error::Overflow)?;
        let r_offset = read_le_u64(bytes, entry_offset)?;
        let r_info = read_le_u64(bytes, entry_offset + 8)?;
        let r_addend = read_le_u64(bytes, entry_offset + 16)? as i64;
        // A relative relocation carries no symbol index; any other type or
        // a non-zero index is a format this flat loader does not implement.
        if r_info != R_X86_64_RELATIVE {
            return Err(Error::InvalidArgs);
        }
        // Every relocation lies inside the writable segment, which the Host
        // copies and fixes up per instance; shared text and rodata carry none.
        let in_segment = r_offset.checked_sub(data.vaddr).ok_or(Error::InvalidArgs)?;
        if in_segment.checked_add(word_size).ok_or(Error::Overflow)? > data.memsz {
            return Err(Error::InvalidArgs);
        }
        // The target word must not straddle a frame boundary, since the
        // fix-up writes it through one frame's mapping.
        if in_segment % PAGE_SIZE_U64 > PAGE_SIZE_U64 - word_size {
            return Err(Error::InvalidArgs);
        }
        relocations.push(Relocation {
            target_offset: r_offset,
            addend: r_addend,
        });
    }
    Ok(relocations)
}

/// Returns the read-only segment whose file contents back `len` bytes at
/// image offset `vaddr`, if any.
fn read_only_segment_at(
    vaddr: u64,
    len: u64,
    text: &SegmentSpan,
    rodata: &Option<SegmentSpan>,
) -> Option<SegmentSpan> {
    if text.file_offset_of(vaddr, len).is_some() {
        return Some(*text);
    }
    let rodata = rodata.as_ref()?;
    if rodata.file_offset_of(vaddr, len).is_some() {
        return Some(*rodata);
    }
    None
}

/// Reads a little-endian `u64` at `offset` without alignment requirements.
fn read_le_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let mut array = [0u8; 8];
    array.copy_from_slice(read_le_bytes(bytes, offset, 8)?);
    Ok(u64::from_le_bytes(array))
}

/// Reads a little-endian `u32` at `offset` without alignment requirements.
fn read_le_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let mut array = [0u8; 4];
    array.copy_from_slice(read_le_bytes(bytes, offset, 4)?);
    Ok(u32::from_le_bytes(array))
}

/// Reads a little-endian `u16` at `offset` without alignment requirements.
fn read_le_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let mut array = [0u8; 2];
    array.copy_from_slice(read_le_bytes(bytes, offset, 2)?);
    Ok(u16::from_le_bytes(array))
}

/// Returns a slice of exactly `len` bytes at `offset`, or an error if the
/// image is too short or the offset overflows.
fn read_le_bytes(bytes: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    let end = offset.checked_add(len).ok_or(Error::Overflow)?;
    bytes.get(offset..end).ok_or(Error::InvalidArgs)
}
