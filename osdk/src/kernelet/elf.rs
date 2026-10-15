// SPDX-License-Identifier: MPL-2.0

//! A minimal read-only parser for ELF64 little-endian images.
//!
//! It parses exactly what the kernelet image audit needs: the ELF header, the
//! program headers, the dynamic table with the relocation entries it locates,
//! the section headers with their names, and the symbol table.

/// The `ET_DYN` ELF file type, produced by a position-independent link.
pub(super) const ET_DYN: u16 = 3;
pub(super) const EM_X86_64: u16 = 62;

pub(super) const PT_LOAD: u32 = 1;
pub(super) const PT_DYNAMIC: u32 = 2;
pub(super) const PT_INTERP: u32 = 3;

pub(super) const PF_X: u32 = 1;
pub(super) const PF_W: u32 = 2;
pub(super) const PF_R: u32 = 4;

pub(super) const SHT_PROGBITS: u32 = 1;
pub(super) const SHT_SYMTAB: u32 = 2;
pub(super) const SHT_NOBITS: u32 = 8;

pub(super) const DT_NEEDED: u64 = 1;
pub(super) const DT_RELA: u64 = 7;
pub(super) const DT_RELASZ: u64 = 8;
pub(super) const DT_RELAENT: u64 = 9;
pub(super) const DT_RELRSZ: u64 = 35;
pub(super) const DT_RELR: u64 = 36;

/// The only relocation type a position-independent image with no imports needs.
pub(super) const R_X86_64_RELATIVE: u64 = 8;

#[derive(Clone, Copy)]
pub(super) struct ProgramHeader {
    pub typ: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

impl ProgramHeader {
    pub fn covers_vaddr_range(&self, start: u64, end: u64) -> bool {
        self.vaddr <= start
            && self
                .vaddr
                .checked_add(self.memsz)
                .is_some_and(|limit| end <= limit)
    }
}

pub(super) struct SectionHeader {
    pub name_offset: u32,
    pub typ: u32,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub entsize: u64,
}

pub(super) struct Symbol {
    pub name_offset: u32,
    pub info: u8,
    pub shndx: u16,
    pub value: u64,
    pub size: u64,
}

impl Symbol {
    /// Whether the symbol is the reserved all-zero null symbol.
    pub fn is_null(&self) -> bool {
        self.name_offset == 0
            && self.info == 0
            && self.shndx == 0
            && self.value == 0
            && self.size == 0
    }
}

pub(super) struct Relocation {
    /// The virtual address of the word the relocation applies to.
    pub offset: u64,
    /// The relocation type, i.e. the low 32 bits of `r_info`.
    pub rtype: u64,
    /// The signed addend stored in the RELA entry.
    pub addend: i64,
}

pub(super) struct DynamicEntry {
    pub tag: u64,
    pub value: u64,
}

pub(super) struct ElfImage<'a> {
    bytes: &'a [u8],
}

impl<'a> ElfImage<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.len() < 64 {
            return Err(format!(
                "the file is {} bytes long, shorter than an ELF64 header",
                bytes.len()
            ));
        }
        if bytes[0..4] != *b"\x7fELF" {
            return Err("the file lacks the ELF magic bytes".to_string());
        }
        if bytes[4] != 2 {
            return Err("the image is not a 64-bit ELF".to_string());
        }
        if bytes[5] != 1 {
            return Err("the image is not little-endian".to_string());
        }
        Ok(Self { bytes })
    }

    fn u16(&self, offset: usize) -> Result<u16, String> {
        Ok(u16::from_le_bytes(
            self.slice(offset, 2)?
                .try_into()
                .expect("slice has the requested length"),
        ))
    }

    fn u32(&self, offset: usize) -> Result<u32, String> {
        Ok(u32::from_le_bytes(
            self.slice(offset, 4)?
                .try_into()
                .expect("slice has the requested length"),
        ))
    }

    fn u64(&self, offset: usize) -> Result<u64, String> {
        Ok(u64::from_le_bytes(
            self.slice(offset, 8)?
                .try_into()
                .expect("slice has the requested length"),
        ))
    }

    fn slice(&self, offset: usize, len: usize) -> Result<&'a [u8], String> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| format!("file range overflows at offset {offset:#x}"))?;
        self.bytes
            .get(offset..end)
            .ok_or_else(|| format!("the file is truncated at offset {offset:#x}"))
    }

    pub fn e_type(&self) -> Result<u16, String> {
        self.u16(16)
    }

    pub fn e_machine(&self) -> Result<u16, String> {
        self.u16(18)
    }

    pub fn e_entry(&self) -> Result<u64, String> {
        self.u64(24)
    }

    fn e_phoff(&self) -> Result<usize, String> {
        usize::try_from(self.u64(32)?).map_err(|_| "program header offset exceeds usize".into())
    }

    fn e_phnum(&self) -> Result<usize, String> {
        Ok(self.u16(56)? as usize)
    }

    fn e_shoff(&self) -> Result<usize, String> {
        usize::try_from(self.u64(40)?).map_err(|_| "section header offset exceeds usize".into())
    }

    fn e_shnum(&self) -> Result<usize, String> {
        Ok(self.u16(60)? as usize)
    }

    fn e_shstrndx(&self) -> Result<usize, String> {
        Ok(self.u16(62)? as usize)
    }

    pub fn program_headers(&self) -> Result<Vec<ProgramHeader>, String> {
        const ENTRY_SIZE: usize = 56;
        let phoff = self.e_phoff()?;
        let phnum = self.e_phnum()?;
        let table = self.table(phoff, phnum, ENTRY_SIZE)?;
        let mut headers = Vec::with_capacity(phnum);
        for bytes in table.chunks_exact(ENTRY_SIZE) {
            let entry = Self { bytes };
            headers.push(ProgramHeader {
                typ: entry.u32(0)?,
                flags: entry.u32(4)?,
                offset: entry.u64(8)?,
                vaddr: entry.u64(16)?,
                filesz: entry.u64(32)?,
                memsz: entry.u64(40)?,
                align: entry.u64(48)?,
            });
        }
        Ok(headers)
    }

    pub fn section_headers(&self) -> Result<Vec<SectionHeader>, String> {
        const ENTRY_SIZE: usize = 64;
        let shoff = self.e_shoff()?;
        if shoff == 0 {
            return Err("the image has no section headers".to_string());
        }
        let shnum = self.e_shnum()?;
        let table = self.table(shoff, shnum, ENTRY_SIZE)?;
        let mut headers = Vec::with_capacity(shnum);
        for bytes in table.chunks_exact(ENTRY_SIZE) {
            let entry = Self { bytes };
            headers.push(SectionHeader {
                name_offset: entry.u32(0)?,
                typ: entry.u32(4)?,
                addr: entry.u64(16)?,
                offset: entry.u64(24)?,
                size: entry.u64(32)?,
                link: entry.u32(40)?,
                entsize: entry.u64(56)?,
            });
        }
        Ok(headers)
    }

    /// Returns the name of the section at `index`, looked up in the section
    /// header string table.
    pub fn section_name(&self, sections: &[SectionHeader], index: usize) -> Result<String, String> {
        let shstrndx = self.e_shstrndx()?;
        let strtab = sections.get(shstrndx).ok_or_else(|| {
            format!("the section header string table index {shstrndx} is out of range")
        })?;
        let name_offset = sections
            .get(index)
            .ok_or_else(|| format!("section index {index} is out of range"))?
            .name_offset as usize;
        let table = self.file_range(strtab.offset, strtab.size)?;
        let rest = table
            .get(name_offset..)
            .ok_or_else(|| "the section header string table is truncated".to_string())?;
        let end = rest
            .iter()
            .position(|&byte| byte == 0)
            .ok_or_else(|| "an unterminated section name".to_string())?;
        Ok(String::from_utf8_lossy(&rest[..end]).into_owned())
    }

    /// Returns the symbols of the `.symtab` section together with the string
    /// table the section's `sh_link` field names.
    pub fn symbols(&self, sections: &[SectionHeader]) -> Result<Vec<Symbol>, String> {
        let Some(symtab_index) = sections.iter().position(|s| s.typ == SHT_SYMTAB) else {
            return Err("the image has no symbol table".to_string());
        };
        let symtab = &sections[symtab_index];
        let strtab = sections.get(symtab.link as usize).ok_or_else(|| {
            format!(
                "the symbol table's string table index {} is out of range",
                symtab.link
            )
        })?;
        let strtab_bytes = self.file_range(strtab.offset, strtab.size)?;

        let entry_size = symtab.entsize;
        if entry_size != 24 {
            return Err(format!(
                "symbol table entries are {entry_size} bytes, expected 24"
            ));
        }
        let table = self.file_range(symtab.offset, symtab.size)?;
        if table.len() % 24 != 0 {
            return Err("the symbol table has an incomplete entry".into());
        }
        let mut symbols = Vec::with_capacity(table.len() / 24);
        for (i, bytes) in table.chunks_exact(24).enumerate() {
            let entry = Self { bytes };
            let name_offset = entry.u32(0)?;
            let info = entry.slice(4, 1)?[0];
            let shndx = entry.u16(6)?;
            let value = entry.u64(8)?;
            let size = entry.u64(16)?;
            // Bounds-check the name so that consumers can slice it safely.
            if name_offset as usize >= strtab_bytes.len() && name_offset != 0 {
                return Err(format!("symbol {i} has an out-of-range name offset"));
            }
            symbols.push(Symbol {
                name_offset,
                info,
                shndx,
                value,
                size,
            });
        }
        Ok(symbols)
    }

    /// Returns the name of the symbol, looked up in the given string table bytes.
    pub fn symbol_name<'b>(
        &self,
        strtab_bytes: &'b [u8],
        symbol: &Symbol,
    ) -> Result<&'b str, String> {
        let start = symbol.name_offset as usize;
        let rest = strtab_bytes
            .get(start..)
            .ok_or_else(|| "the symbol string table is truncated".to_string())?;
        let end = rest
            .iter()
            .position(|&byte| byte == 0)
            .ok_or_else(|| "an unterminated symbol name".to_string())?;
        std::str::from_utf8(&rest[..end]).map_err(|err| format!("a non-UTF-8 symbol name: {err}"))
    }

    /// Returns the string table bytes that the `.symtab` section's `sh_link`
    /// field names.
    pub fn symbol_string_table(&self, sections: &[SectionHeader]) -> Result<Vec<u8>, String> {
        let symtab = sections
            .iter()
            .find(|s| s.typ == SHT_SYMTAB)
            .ok_or_else(|| "the image has no symbol table".to_string())?;
        let strtab = sections.get(symtab.link as usize).ok_or_else(|| {
            format!(
                "the symbol table's string table index {} is out of range",
                symtab.link
            )
        })?;
        Ok(self.file_range(strtab.offset, strtab.size)?.to_vec())
    }

    /// Returns the entries of the dynamic table located through `PT_DYNAMIC`,
    /// or an empty vector if the image has none.
    pub fn dynamic_entries(&self) -> Result<Vec<DynamicEntry>, String> {
        let Some(dynamic) = self
            .program_headers()?
            .into_iter()
            .find(|ph| ph.typ == PT_DYNAMIC)
        else {
            return Ok(Vec::new());
        };
        let data = self.bytes_at_vaddr(dynamic.vaddr, dynamic.filesz)?;
        let (pairs, remainder) = data.as_chunks::<16>();
        if !remainder.is_empty() {
            return Err("the dynamic table has an incomplete entry".to_string());
        }
        let mut entries = Vec::with_capacity(pairs.len());
        for pair in pairs {
            entries.push(DynamicEntry {
                tag: u64::from_le_bytes(pair[0..8].try_into().unwrap()),
                value: u64::from_le_bytes(pair[8..16].try_into().unwrap()),
            });
        }
        Ok(entries)
    }

    /// Returns the relocation entries located through `PT_DYNAMIC` and
    /// `DT_RELA`, which is how the image's own loader finds them.
    pub fn relocations(&self) -> Result<Vec<Relocation>, String> {
        let entries = self.dynamic_entries()?;
        let lookup = |tag: u64| {
            entries
                .iter()
                .find(|entry| entry.tag == tag)
                .map(|entry| entry.value)
        };
        let Some(rela_addr) = lookup(DT_RELA) else {
            return Ok(Vec::new());
        };
        let Some(rela_size) = lookup(DT_RELASZ) else {
            return Err("DT_RELA is present but DT_RELASZ is missing".to_string());
        };
        if lookup(DT_RELAENT) != Some(24) {
            return Err("the DT_RELAENT entry is not 24 bytes".to_string());
        }
        let data = self.bytes_at_vaddr(rela_addr, rela_size)?;
        let (entries, remainder) = data.as_chunks::<24>();
        if !remainder.is_empty() {
            return Err("the relocation table has an incomplete entry".to_string());
        }
        let mut relocations = Vec::with_capacity(entries.len());
        for entry in entries {
            let info = u64::from_le_bytes(entry[8..16].try_into().unwrap());
            relocations.push(Relocation {
                offset: u64::from_le_bytes(entry[0..8].try_into().unwrap()),
                rtype: info & 0xffff_ffff,
                addend: i64::from_le_bytes(entry[16..24].try_into().unwrap()),
            });
        }
        Ok(relocations)
    }

    /// Returns the `len` file bytes backing the virtual address range
    /// `[vaddr, vaddr + len)`, which must lie within one `PT_LOAD` segment.
    pub fn bytes_at_vaddr(&self, vaddr: u64, len: u64) -> Result<&'a [u8], String> {
        let end = vaddr
            .checked_add(len)
            .ok_or("virtual address range overflows")?;
        for ph in self.program_headers()? {
            if ph.typ != PT_LOAD {
                continue;
            }
            let file_end = ph
                .vaddr
                .checked_add(ph.filesz)
                .ok_or("segment virtual range overflows")?;
            if vaddr >= ph.vaddr && len <= ph.memsz && end <= file_end {
                let file_offset = ph
                    .offset
                    .checked_add(vaddr - ph.vaddr)
                    .ok_or("segment file offset overflows")?;
                return self.file_range(file_offset, len);
            }
        }
        Err(format!(
            "the virtual address range [{vaddr:#x}, {end:#x}) is not file-backed in any PT_LOAD segment"
        ))
    }

    fn file_range(&self, offset: u64, len: u64) -> Result<&'a [u8], String> {
        let offset = usize::try_from(offset).map_err(|_| "file offset exceeds usize")?;
        let len = usize::try_from(len).map_err(|_| "file size exceeds usize")?;
        self.slice(offset, len)
    }

    fn table(&self, offset: usize, count: usize, entry_size: usize) -> Result<&'a [u8], String> {
        let len = count
            .checked_mul(entry_size)
            .ok_or("ELF table size overflows")?;
        self.slice(offset, len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> Vec<u8> {
        let mut bytes = vec![0; 120];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        bytes
    }

    #[test]
    fn malformed_file_ranges_return_errors_without_panicking() {
        for field in [32, 40] {
            let mut bytes = header();
            bytes[field..field + 8].copy_from_slice(&(u64::MAX - 3).to_le_bytes());
            bytes[60..62].copy_from_slice(&1u16.to_le_bytes());
            let image = ElfImage::parse(&bytes).unwrap();
            assert!(if field == 32 {
                image.program_headers().is_err()
            } else {
                image.section_headers().is_err()
            });
        }
        let bytes = header();
        let image = ElfImage::parse(&bytes).unwrap();
        assert!(image.slice(usize::MAX, 2).is_err());
        assert!(image.table(64, usize::MAX, 24).is_err());
        assert!(image.bytes_at_vaddr(u64::MAX, 2).is_err());
    }

    #[test]
    fn malformed_load_and_symbol_tables_return_errors_before_allocation() {
        let mut bytes = header();
        bytes[64..68].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[80..88].copy_from_slice(&(u64::MAX - 8).to_le_bytes());
        bytes[96..104].copy_from_slice(&32u64.to_le_bytes());
        let image = ElfImage::parse(&bytes).unwrap();
        assert!(image.bytes_at_vaddr(u64::MAX - 7, 1).is_err());
        let sections = [
            SectionHeader {
                name_offset: 0,
                typ: SHT_SYMTAB,
                addr: 0,
                offset: u64::MAX - 8,
                size: u64::MAX,
                link: 1,
                entsize: 24,
            },
            SectionHeader {
                name_offset: 0,
                typ: 3,
                addr: 0,
                offset: 0,
                size: 1,
                link: 0,
                entsize: 0,
            },
        ];
        assert!(image.symbols(&sections).is_err());
    }
}
