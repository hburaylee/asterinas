// SPDX-License-Identifier: MPL-2.0

//! Host-side registration and instantiation of kernelet ELF images.
//!
//! A kernelet image is a position-independent (`ET_DYN`) ELF that links at
//! base 0 and imports nothing. The Host embeds the image's bytes, registers
//! them once per kind with [`RegisteredImage::register`], and creates
//! running instances of the kind with [`RegisteredImage::instantiate`].
//!
//! The loader implements the image format fixed by the design document
//! (`kernelet/ABI.md`):
//!
//! - The image consists of at most three `PT_LOAD` segments: an executable
//!   text segment (`R E`), an optional read-only data segment (`R`), and an
//!   optional writable data segment (`RW`), in this order at ascending,
//!   page-aligned image offsets.
//! - One physical copy of the read-only segments serves every instance of
//!   the kind. Each instance owns private frames for the writable segment,
//!   copied from the image's data template and relocated for that instance.
//! - Every dynamic relocation is `R_X86_64_RELATIVE`, located through the
//!   `PT_DYNAMIC` segment's `DT_RELA`, `DT_RELASZ` and `DT_RELAENT` entries,
//!   and targets the writable segment only. The loader applies each as
//!   *store the instance's base plus the entry's own addend*.
//! - The entry table lies at offset `0x1000` from the image base, and all of
//!   its address-like fields are link-time image-relative offsets.
//!
//! The parser reads only the ELF header, the program headers, and the
//! dynamic entries it needs; it reads no symbol table and no section
//! headers, which are not part of what a loader sees. Parsing never panics:
//! malformed input is rejected with [`Error::InvalidArgs`]. The parser is
//! alignment-agnostic, so the embedded bytes need no particular alignment.
//!
//! The control transfer into an instance belongs to the Host runtime's
//! validated entry stub, which obtains its target from
//! [`ImageInstance::entry_address`].

use alloc::vec::Vec;
use core::ops::Range;

use super::abi::EntryTable;
use crate::{
    Error, Result,
    mm::{
        CachePolicy, Frame, FrameAllocOptions, PAGE_SIZE, PageFlags, PageProperty,
        PrivilegedPageFlags, Vaddr, VmIo, frame::Segment, kspace::kvirt_area::KVirtArea,
    },
};

mod elf;
mod instance;
#[cfg(ktest)]
mod test;
#[cfg(ktest)]
pub(super) use test::fixture_image;

const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;
const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;
const HUGE_PAGE_SIZE_U64: u64 = HUGE_PAGE_SIZE as u64;
const FRAMES_PER_HUGE_PAGE: usize = HUGE_PAGE_SIZE / PAGE_SIZE;

/// Page properties of the shared, executable text mapping.
const TEXT_PAGE_PROP: PageProperty = PageProperty {
    flags: PageFlags::RX,
    cache: CachePolicy::Writeback,
    priv_flags: PrivilegedPageFlags::GLOBAL,
};
/// Page properties of shared, non-executable read-only mappings.
const READONLY_PAGE_PROP: PageProperty = PageProperty {
    flags: PageFlags::R,
    cache: CachePolicy::Writeback,
    priv_flags: PrivilegedPageFlags::GLOBAL,
};
/// Page properties of one instance's private, non-executable data mapping.
const DATA_PAGE_PROP: PageProperty = PageProperty {
    flags: PageFlags::RW,
    cache: CachePolicy::Writeback,
    priv_flags: PrivilegedPageFlags::GLOBAL,
};

// ---- Public API ----

/// A registered kernelet image: a validated **kind** whose read-only
/// contents are held in frames that can be shared by all of its instances.
///
/// Registration copies each `PT_LOAD` segment out of the embedded bytes into
/// fresh frames, so the input slice is released after the call and carried
/// no alignment requirement. It also validates the entry table and the
/// relocations; an image that fails validation never becomes a kind.
pub(super) struct RegisteredImage {
    /// Link-time address of the image entry point (`e_entry`).
    entry_offset: u64,
    /// The executable text segment, the image's first `PT_LOAD`.
    text: SegmentSpan,
    /// The optional writable data segment.
    data: Option<SegmentSpan>,
    /// Shared 2 MiB segments holding the text segment.
    text_frames: Vec<Segment<()>>,
    /// Shared 2 MiB segments holding the read-only data segment.
    rodata_frames: Vec<Segment<()>>,
    /// Frames holding the writable segment's template, from which each
    /// instance's private data frames are copied.
    data_template: Vec<Frame<()>>,
    /// One zeroed 2 MiB segment shared read-only across layout gaps, if any.
    filler: Option<Segment<()>>,
    /// The validated `R_X86_64_RELATIVE` relocations, in file order.
    relocations: Vec<Relocation>,
    /// The validated copy of the image's entry table.
    entry_table: EntryTable,
    /// Start of the per-vCPU replicas after the padded ELF data template.
    replicas_offset: usize,
    /// Number of huge pages between successive image regions.
    gap_pages: [usize; 3],
}

impl RegisteredImage {
    /// Validates and registers an embedded kernelet image.
    ///
    /// The bytes are an ordinary byte string: the parser reads them with
    /// unaligned little-endian loads, so `include_bytes!` output works as
    /// is. `source_hash` comes from the Host's OSDK build and must match the
    /// image's entry table. On success the image's read-only segments and its
    /// data template have been copied into fresh frames that this object owns.
    pub(super) fn register(bytes: &[u8], source_hash: [u8; 32]) -> Result<Self> {
        let parsed = ParsedImage::parse(bytes)?;
        if parsed.entry_table.source_hash != source_hash {
            return Err(Error::InvalidArgs);
        }

        // The linker and frame layout place permission transitions at
        // 2 MiB boundaries. The text PT_LOAD begins at offset 4 KiB, leaving
        // zero padding before the entry table. Validate this layout before
        // copying the segments and constructing their base-page mappings.
        if parsed.text.memsz == 0
            || parsed.rodata.as_ref().is_some_and(|span| {
                span.memsz == 0 || !span.vaddr.is_multiple_of(HUGE_PAGE_SIZE_U64)
            })
            || parsed.data.as_ref().is_some_and(|span| {
                span.memsz == 0 || !span.vaddr.is_multiple_of(HUGE_PAGE_SIZE_U64)
            })
        {
            return Err(Error::InvalidArgs);
        }

        let text_frames = copy_segment_huge_pages(bytes, &parsed.text)?;
        let rodata_frames = match &parsed.rodata {
            Some(span) => copy_segment_huge_pages(bytes, span)?,
            None => Vec::new(),
        };
        let data_template = match &parsed.data {
            Some(span) => copy_segment_frames(bytes, span)?,
            None => Vec::new(),
        };
        let replicas_offset = parsed.data_end_offset()?;
        let gap_pages =
            image_gap_huge_pages(&parsed.text, &parsed.rodata, &parsed.data, replicas_offset)?;
        let filler = if gap_pages.into_iter().any(|pages| pages > 0) {
            Some(FrameAllocOptions::new().alloc_segment(FRAMES_PER_HUGE_PAGE)?)
        } else {
            None
        };

        let entry_table = parsed.entry_table;
        Ok(Self {
            entry_offset: parsed.entry_offset,
            text: parsed.text,
            data: parsed.data,
            text_frames,
            rodata_frames,
            data_template,
            filler,
            relocations: parsed.relocations,
            entry_table,
            replicas_offset,
            gap_pages,
        })
    }

    /// Returns resident sizes from validated load segments and entry metadata.
    pub(crate) fn image_info(&self) -> super::control::ImageInfo {
        super::control::ImageInfo {
            text_bytes: self.text.memsz as usize,
            template_bytes: self.data.as_ref().map_or(0, |data| data.memsz as usize),
            cpu_local_bytes: (self.entry_table.cpu_local_end_offset
                - self.entry_table.cpu_local_start_offset) as usize,
        }
    }

    /// Returns the validated copy of the image's entry table.
    ///
    /// The Host compares the hash the table carries against its own build
    /// and publishes the hash in `BootArgs`; the offsets in it are those
    /// registration has already validated against the segment bounds.
    pub(super) fn entry_table(&self) -> &EntryTable {
        &self.entry_table
    }
}

/// Counts the 2 MiB gaps between mapped ELF regions and the CPU-local replicas.
///
/// The registration checks ensure each boundary is aligned. A segment's
/// zero-filled tail occupies its final huge page, so gaps begin after the
/// rounded-up segment rather than after its byte-level `p_memsz`.
fn image_gap_huge_pages(
    text: &SegmentSpan,
    rodata: &Option<SegmentSpan>,
    data: &Option<SegmentSpan>,
    replicas_offset: usize,
) -> Result<[usize; 3]> {
    let replicas_start = replicas_offset as u64;
    let mapped_end = |span: &SegmentSpan| {
        align_up(
            span.vaddr.checked_add(span.memsz).ok_or(Error::Overflow)?,
            HUGE_PAGE_SIZE_U64,
        )
        .ok_or(Error::Overflow)
    };
    let gap = |start: u64, end: u64| {
        let bytes = end.checked_sub(start).ok_or(Error::InvalidArgs)?;
        if !bytes.is_multiple_of(HUGE_PAGE_SIZE_U64) {
            return Err(Error::InvalidArgs);
        }
        usize::try_from(bytes / HUGE_PAGE_SIZE_U64).map_err(|_| Error::Overflow)
    };
    let after_text = gap(
        mapped_end(text)?,
        rodata
            .as_ref()
            .or(data.as_ref())
            .map_or(replicas_start, |span| span.vaddr),
    )?;
    let after_rodata = if let Some(rodata) = rodata {
        gap(
            mapped_end(rodata)?,
            data.as_ref().map_or(replicas_start, |span| span.vaddr),
        )?
    } else {
        0
    };
    let after_data = if let Some(data) = data {
        gap(mapped_end(data)?, replicas_start)?
    } else {
        0
    };
    Ok([after_text, after_rodata, after_data])
}

/// One running instance of a [`RegisteredImage`].
///
/// The instance owns its kernel virtual area and its private data page.
/// Dropping it unmaps the image range and flushes the local TLB before the
/// data page is released, so the physical memory is never freed while
/// still mapped on this CPU.
pub(super) struct ImageInstance {
    /// The instance's image mapping. Dropped before `_data_segment`.
    kvirt: KVirtArea,
    /// The instance's private 2 MiB data page, kept alive until unmapping.
    _data_segment: Option<Segment<()>>,
    /// Host-owned boot page, pinned until its read-only image mapping is gone.
    _boot_frame: Frame<()>,
    /// Shared cooperation record pages for this instance's virtual CPUs.
    _vcpu_frames: Vec<Frame<()>>,
    /// Private CPU-local replica pages in the image mapping.
    _cpu_local_frames: Vec<Frame<()>>,
    vcpu_entry: Vaddr,
    /// Link-time address of the image entry point.
    entry_offset: usize,
    /// Validated executable range used for interrupt-return redirection.
    text_start: Vaddr,
    text_end: Vaddr,
    /// The fixed virtual-interrupt entry inside `KW_TEXT`.
    virq_entry: Vaddr,
    /// Validated exception-table bounds in the shared read-only mapping.
    ex_table_start: Vaddr,
    ex_table_end: Vaddr,
    /// Offset of the first page of `KW_SHARED` from the instance base.
    shared_offset: usize,
}

impl ImageInstance {
    pub(crate) fn private_bytes(&self) -> usize {
        self._data_segment.as_ref().map_or(0, |_| HUGE_PAGE_SIZE)
            + (1 + self._vcpu_frames.len()) * PAGE_SIZE
            + self._cpu_local_frames.len() * PAGE_SIZE
    }

    /// Returns the instance's base address in the shared kernel address
    /// space, which every image offset is relative to.
    pub(crate) fn base_vaddr(&self) -> Vaddr {
        self.kvirt.start()
    }

    /// Returns the address of the image's entry point in this instance.
    ///
    /// Crate-visible on purpose: transferring control to a kernelet is an
    /// `unsafe` operation that belongs to the Host runtime's validated entry
    /// stub, not to arbitrary callers.
    pub(crate) fn vcpu_entry_address(&self) -> Vaddr {
        self.vcpu_entry
    }

    pub(crate) fn entry_address(&self) -> Vaddr {
        self.base_vaddr() + self.entry_offset
    }

    pub(crate) fn text_range(&self) -> Range<Vaddr> {
        self.text_start..self.text_end
    }

    pub(crate) fn virq_entry_address(&self) -> Vaddr {
        self.virq_entry
    }

    /// Returns the image's validated, self-relative copy-recovery table.
    pub(crate) fn ex_table_range(&self) -> Range<Vaddr> {
        self.ex_table_start..self.ex_table_end
    }

    /// Returns the address of the read-only boot page in this instance.
    pub(crate) fn boot_args_address(&self) -> Vaddr {
        self.base_vaddr() + self.shared_offset
    }

    /// Returns the shared cooperation record for virtual CPU zero.
    pub(crate) fn vcpu_record_address(&self) -> Vaddr {
        self.boot_args_address() + PAGE_SIZE
    }

    /// Returns the virtual range covered by the instance's image mapping.
    ///
    /// The Host runtime needs the range to shoot down remote translations
    /// before the range may be reused.
    pub(crate) fn range(&self) -> Range<Vaddr> {
        self.kvirt.range()
    }
}

// ---- Image representation ----

/// The placement of one `PT_LOAD` segment in the image.
///
/// All fields describe the image as linked at base 0, so a segment's link
/// address doubles as its image-relative offset.
#[derive(Clone, Copy, Debug)]
struct SegmentSpan {
    /// File offset of the segment's initialized contents.
    file_offset: u64,
    /// Link-time address of the segment's first byte.
    vaddr: u64,
    /// Number of bytes initialized from the file.
    filesz: u64,
    /// Number of bytes occupied in memory; bytes beyond `filesz` are zero.
    memsz: u64,
}

impl SegmentSpan {
    /// Returns the file offset that corresponds to the image offset
    /// `vaddr`, provided that `len` bytes starting there are fully backed
    /// by this segment's file contents.
    fn file_offset_of(&self, vaddr: u64, len: u64) -> Option<usize> {
        let end = vaddr.checked_add(len)?;
        // The parse phase bounds every segment end by `MAX_IMAGE_VADDR`, so
        // this addition cannot overflow.
        if vaddr < self.vaddr || end > self.vaddr + self.filesz {
            return None;
        }
        usize::try_from(self.file_offset + (vaddr - self.vaddr)).ok()
    }
}

/// One validated `R_X86_64_RELATIVE` relocation.
#[derive(Clone, Copy, Debug)]
struct Relocation {
    /// Image offset of the target word, inside the writable segment.
    target_offset: u64,
    /// The addend: an instance stores its base plus this value.
    addend: i64,
}

/// The outcome of parsing and validating an embedded image, before any
/// frame is allocated.
struct ParsedImage {
    entry_offset: u64,
    text: SegmentSpan,
    rodata: Option<SegmentSpan>,
    data: Option<SegmentSpan>,
    relocations: Vec<Relocation>,
    entry_table: EntryTable,
}

// ---- Copying and mapping helpers ----

/// Copies one segment's image contents into fresh, zero-initialized frames,
/// one per page the segment occupies in memory.
fn copy_segment_frames(bytes: &[u8], span: &SegmentSpan) -> Result<Vec<Frame<()>>> {
    let page_count = span.memsz.div_ceil(PAGE_SIZE_U64) as usize;
    let mut frames = Vec::with_capacity(page_count);
    for index in 0..page_count {
        let frame = FrameAllocOptions::new().alloc_frame()?;
        let in_segment = index as u64 * PAGE_SIZE_U64;
        if in_segment < span.filesz {
            let chunk_len = (span.filesz - in_segment).min(PAGE_SIZE_U64) as usize;
            let chunk_start = span.file_offset as usize + in_segment as usize;
            let chunk = bytes
                .get(chunk_start..chunk_start + chunk_len)
                .ok_or(Error::InvalidArgs)?;
            frame.write_bytes(0, chunk)?;
        }
        frames.push(frame);
    }
    Ok(frames)
}

/// Copies a read-only segment into shared 2 MiB segments.
///
/// Unused bytes stay zero, preserving the permission boundaries and padding
/// prescribed by the linker. Each segment is mapped as tracked base pages.
fn copy_segment_huge_pages(bytes: &[u8], span: &SegmentSpan) -> Result<Vec<Segment<()>>> {
    let mapped_start = span.vaddr & !(HUGE_PAGE_SIZE_U64 - 1);
    let mapped_end = align_up(
        span.vaddr.checked_add(span.memsz).ok_or(Error::Overflow)?,
        HUGE_PAGE_SIZE_U64,
    )
    .ok_or(Error::Overflow)?;
    let page_count = ((mapped_end - mapped_start) / HUGE_PAGE_SIZE_U64) as usize;
    let mut pages = Vec::with_capacity(page_count);
    for _ in 0..page_count {
        pages.push(FrameAllocOptions::new().alloc_segment(FRAMES_PER_HUGE_PAGE)?);
    }
    let file_bytes = usize::try_from(span.filesz).map_err(|_| Error::Overflow)?;
    for file_offset in (0..file_bytes).step_by(PAGE_SIZE) {
        let mapped_offset =
            usize::try_from(span.vaddr - mapped_start).map_err(|_| Error::Overflow)? + file_offset;
        let huge_index = mapped_offset / HUGE_PAGE_SIZE;
        let within_huge = mapped_offset % HUGE_PAGE_SIZE;
        let chunk_len = (file_bytes - file_offset).min(PAGE_SIZE);
        let src_start = span.file_offset as usize + file_offset;
        let src = bytes
            .get(src_start..src_start + chunk_len)
            .ok_or(Error::InvalidArgs)?;
        let frame = pages[huge_index]
            .slice(&(within_huge..within_huge + PAGE_SIZE))
            .next()
            .ok_or(Error::InvalidArgs)?;
        frame.write_bytes(0, src)?;
    }
    Ok(pages)
}

/// Returns `value` rounded up to `align`, or `None` on overflow. `align`
/// must be a power of two.
fn align_up(value: u64, align: u64) -> Option<u64> {
    let rounded = value.checked_add(align - 1)?;
    Some(rounded & !(align - 1))
}
