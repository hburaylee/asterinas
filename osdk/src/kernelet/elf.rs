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
        self.vaddr <= start && end <= self.vaddr.saturating_add(self.memsz)
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
        self.bytes
            .get(offset..offset + len)
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
        Ok(self.u64(32)? as usize)
    }

    fn e_phnum(&self) -> Result<usize, String> {
        Ok(self.u16(56)? as usize)
    }

    fn e_shoff(&self) -> Result<usize, String> {
        Ok(self.u64(40)? as usize)
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
        let mut headers = Vec::with_capacity(phnum);
        for i in 0..phnum {
            let base = phoff + i * ENTRY_SIZE;
            headers.push(ProgramHeader {
                typ: self.u32(base)?,
                flags: self.u32(base + 4)?,
                offset: self.u64(base + 8)?,
                vaddr: self.u64(base + 16)?,
                filesz: self.u64(base + 32)?,
                memsz: self.u64(base + 40)?,
                align: self.u64(base + 48)?,
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
        let mut headers = Vec::with_capacity(shnum);
        for i in 0..shnum {
            let base = shoff + i * ENTRY_SIZE;
            headers.push(SectionHeader {
                name_offset: self.u32(base)?,
                typ: self.u32(base + 4)?,
                addr: self.u64(base + 16)?,
                offset: self.u64(base + 24)?,
                size: self.u64(base + 32)?,
                link: self.u32(base + 40)?,
                entsize: self.u64(base + 56)?,
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
        let start = strtab.offset as usize + name_offset;
        let rest = self
            .bytes
            .get(start..)
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
        let strtab_bytes = self.slice(strtab.offset as usize, strtab.size as usize)?;

        let entry_size = symtab.entsize as usize;
        if entry_size != 24 {
            return Err(format!(
                "symbol table entries are {entry_size} bytes, expected 24"
            ));
        }
        let count = symtab.size as usize / entry_size;
        let mut symbols = Vec::with_capacity(count);
        for i in 0..count {
            let base = symtab.offset as usize + i * entry_size;
            let name_offset = self.u32(base)?;
            let info = self.slice(base + 4, 1)?[0];
            let shndx = self.u16(base + 6)?;
            let value = self.u64(base + 8)?;
            let size = self.u64(base + 16)?;
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
        Ok(self
            .slice(strtab.offset as usize, strtab.size as usize)?
            .to_vec())
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
        for ph in self.program_headers()? {
            if ph.typ != PT_LOAD {
                continue;
            }
            if vaddr >= ph.vaddr && len <= ph.memsz && vaddr + len <= ph.vaddr + ph.filesz {
                let file_offset = ph.offset as usize + (vaddr - ph.vaddr) as usize;
                return self.slice(file_offset, len as usize);
            }
        }
        Err(format!(
            "the virtual address range [{:#x}, {:#x}) is not file-backed in any PT_LOAD segment",
            vaddr,
            vaddr + len
        ))
    }
}
