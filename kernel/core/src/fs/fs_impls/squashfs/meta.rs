// SPDX-License-Identifier: MPL-2.0

//! On-demand metadata block reading.
//!
//! Squashfs packs inode, directory, and lookup table data into compressed
//! *metadata blocks*. Each block decompresses to at most [`META_MAX`] bytes and
//! is addressed by a 64-bit reference: the upper 48 bits give the byte offset
//! of the block (relative to a table's start), and the low 16 bits give the
//! byte offset within the block's decompressed data.
//!
//! This module provides the primitives the Linux kernel calls
//! `squashfs_read_metadata`:
//!
//! - [`MetaBlock`] decodes and decompresses a single metadata block into page
//!   frames.
//! - [`MetaCache`] keeps a small round-robin cache of decompressed blocks so a
//!   sequence of nearby reads does not repeatedly decompress the same block.
//! - [`MetaReader`] walks a logical byte stream across block boundaries from a
//!   [`MetaCursor`], mirroring how the kernel reads variably-sized records
//!   (inodes, directory headers) that may straddle blocks.
//!
//! Like [`DataBlock`](super::block::DataBlock), blocks are decompressed
//! straight into unzeroed page frames rather than a heap buffer, avoiding a
//! redundant zeroing pass.

use aster_block::BlockDevice;
use ostd::mm::{FrameAllocOptions, Segment, VmIo, io::util::HasVmReaderWriter};

use super::{SquashFsError, compressor::DecompressContext};
use crate::prelude::*;

/// Bit 15 of a metadata block header: 1 = uncompressed, 0 = compressed.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_packing_metadata>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L104>
pub(super) const METADATA_COMPRESSED_BIT: u16 = 1 << 15;

/// Maximum uncompressed size of a metadata block.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_packing_metadata>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L19>
pub(super) const META_MAX: usize = 0x2000;

/// Number of decompressed metadata blocks kept in [`MetaCache`].
///
/// Matches the Linux default (`SQUASHFS_CACHED_BLKS`).
const META_CACHE_SLOTS: usize = 8;

/// A position within the metadata stream: a metadata block plus a byte offset
/// inside its decompressed data.
///
/// `block` is the byte offset of the metadata block relative to the *base* of
/// the [`MetaReader`] that interprets it (e.g. the inode or directory table
/// start), matching the on-disk 64-bit reference encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MetaCursor {
    pub(super) block: u64,
    pub(super) offset: u16,
}

impl MetaCursor {
    /// Decodes a 64-bit on-disk metadata reference into a cursor.
    pub(super) fn from_ref(reference: u64) -> Self {
        Self {
            block: reference >> 16,
            offset: (reference & 0xffff) as u16,
        }
    }
}

/// A single decompressed metadata block.
///
/// The decompressed bytes live in page frames sized to hold `META_MAX` bytes;
/// only the first `len` bytes are valid.
pub(super) struct MetaBlock {
    /// Absolute disk position immediately after this block (start of the next).
    next_pos: u64,
    /// Number of valid decompressed bytes in `seg`.
    len: u16,
    seg: Segment<()>,
}

impl MetaBlock {
    pub(super) fn read(
        device: &Arc<dyn BlockDevice>,
        decompress: &DecompressContext,
        disk_pos: u64,
    ) -> Result<Self, SquashFsError> {
        let mut header_buf = [0u8; 2];
        device
            .read_bytes(disk_pos as usize, &mut header_buf)
            .map_err(|_| SquashFsError::IoError)?;

        let header = u16::from_le_bytes(header_buf);
        let compressed = header & METADATA_COMPRESSED_BIT == 0;
        let data_len = (header & !METADATA_COMPRESSED_BIT) as usize;

        if data_len > META_MAX {
            return Err(SquashFsError::CorruptedImage("metadata block too large"));
        }

        let seg = FrameAllocOptions::new()
            .zeroed(false)
            .alloc_segment(META_MAX.div_ceil(PAGE_SIZE))
            .map_err(|_| SquashFsError::IoError)?;

        let len = if data_len == 0 {
            0
        } else if compressed {
            let src = FrameAllocOptions::new()
                .zeroed(false)
                .alloc_segment(data_len.div_ceil(PAGE_SIZE))
                .map_err(|_| SquashFsError::IoError)?;
            let mut src_writer = src.writer();
            src_writer.limit(data_len);
            device
                .read(disk_pos as usize + 2, &mut src_writer.to_fallible())
                .map_err(|_| SquashFsError::IoError)?;

            let mut src_reader = src.reader();
            src_reader.limit(data_len);

            let mut dst = seg.writer();
            dst.limit(META_MAX);
            decompress.decompress_stream(&mut src_reader, &mut dst)?
        } else {
            let mut dst = seg.writer();
            dst.limit(data_len);
            device
                .read(disk_pos as usize + 2, &mut dst.to_fallible())
                .map_err(|_| SquashFsError::IoError)?;
            data_len
        };

        Ok(Self {
            next_pos: disk_pos + 2 + data_len as u64,
            len: len as u16,
            seg,
        })
    }
}

/// A single decompressed metadata block, keyed by its disk position.
struct CachedMetaBlock {
    /// Absolute disk position of the block's 2-byte header (its identity).
    disk_pos: u64,
    block: MetaBlock,
}

/// A small round-robin cache of decompressed metadata blocks, keyed by their
/// absolute disk position.
pub(super) struct MetaCache {
    slots: [Option<CachedMetaBlock>; META_CACHE_SLOTS],
    /// Next slot to evict.
    next: usize,
}

impl MetaCache {
    pub(super) fn new() -> Self {
        Self {
            slots: [const { None }; META_CACHE_SLOTS],
            next: 0,
        }
    }

    /// Returns the block at `disk_pos`, decompressing and inserting it on a miss.
    fn get(
        &mut self,
        device: &Arc<dyn BlockDevice>,
        decompress: &DecompressContext,
        disk_pos: u64,
    ) -> Result<&MetaBlock, SquashFsError> {
        if let Some(idx) = self
            .slots
            .iter()
            .position(|slot| matches!(slot, Some(cached) if cached.disk_pos == disk_pos))
        {
            return Ok(&self.slots[idx].as_ref().unwrap().block);
        }

        let block = MetaBlock::read(device, decompress, disk_pos)?;
        let idx = self.next;
        self.next = (self.next + 1) % META_CACHE_SLOTS;
        self.slots[idx] = Some(CachedMetaBlock { disk_pos, block });
        Ok(&self.slots[idx].as_ref().unwrap().block)
    }
}

/// A sequential reader over the metadata stream starting from `base`.
///
/// `base` is the absolute disk position that block offset `0` refers to (the
/// inode or directory table start). Reads decompress blocks through the shared
/// [`MetaCache`] and transparently cross block boundaries, so records larger
/// than one block — or straddling two — are read as a single call.
pub(super) struct MetaReader<'a> {
    device: &'a Arc<dyn BlockDevice>,
    decompress: &'a DecompressContext,
    cache: &'a mut MetaCache,
    base: u64,
    cursor: MetaCursor,
}

impl<'a> MetaReader<'a> {
    pub(super) fn new(
        device: &'a Arc<dyn BlockDevice>,
        decompress: &'a DecompressContext,
        cache: &'a mut MetaCache,
        base: u64,
        cursor: MetaCursor,
    ) -> Self {
        Self {
            device,
            decompress,
            cache,
            base,
            cursor,
        }
    }

    /// Advances the cursor to the start of the next metadata block.
    ///
    /// Returns an error if the block does not advance the disk position, which
    /// would otherwise loop forever on a corrupt image.
    fn roll_to_next(&mut self, disk_pos: u64, next_pos: u64) -> Result<(), SquashFsError> {
        if next_pos <= disk_pos {
            return Err(SquashFsError::CorruptedImage("metadata cursor stalled"));
        }
        self.cursor = MetaCursor {
            block: next_pos - self.base,
            offset: 0,
        };
        Ok(())
    }

    /// Fills `buf` from the metadata stream at the current cursor, advancing
    /// across block boundaries as needed.
    ///
    /// This is the equivalent of the Linux kernel's `squashfs_read_metadata`.
    pub(super) fn read_bytes(&mut self, buf: &mut [u8]) -> Result<(), SquashFsError> {
        let mut filled = 0;
        while filled < buf.len() {
            let disk_pos = self.base + self.cursor.block;
            let start = self.cursor.offset as usize;

            let (copied, blk_len, next_pos) = {
                let block = self.cache.get(self.device, self.decompress, disk_pos)?;
                let blk_len = block.len as usize;
                let next_pos = block.next_pos;
                if start >= blk_len {
                    (0, blk_len, next_pos)
                } else {
                    let n = (blk_len - start).min(buf.len() - filled);
                    let mut reader = block.seg.reader();
                    reader.skip(start).limit(n);
                    reader.read(&mut VmWriter::from(&mut buf[filled..filled + n]));
                    (n, blk_len, next_pos)
                }
            };

            if copied == 0 {
                self.roll_to_next(disk_pos, next_pos)?;
                continue;
            }

            filled += copied;
            let new_off = start + copied;
            if new_off >= blk_len {
                self.roll_to_next(disk_pos, next_pos)?;
            } else {
                self.cursor.offset = new_off as u16;
            }
        }
        Ok(())
    }

    /// Advances the cursor by `n` bytes without copying, crossing block
    /// boundaries as needed.
    pub(super) fn skip(&mut self, mut n: usize) -> Result<(), SquashFsError> {
        while n > 0 {
            let disk_pos = self.base + self.cursor.block;
            let start = self.cursor.offset as usize;

            let (blk_len, next_pos) = {
                let block = self.cache.get(self.device, self.decompress, disk_pos)?;
                (block.len as usize, block.next_pos)
            };

            if start >= blk_len {
                self.roll_to_next(disk_pos, next_pos)?;
                continue;
            }

            let take = (blk_len - start).min(n);
            n -= take;
            let new_off = start + take;
            if new_off >= blk_len {
                self.roll_to_next(disk_pos, next_pos)?;
            } else {
                self.cursor.offset = new_off as u16;
            }
        }
        Ok(())
    }

    /// Reads one POD value from the metadata stream, advancing the cursor.
    pub(super) fn read_val<T: Pod>(&mut self) -> Result<T, SquashFsError> {
        let mut val = T::new_zeroed();
        self.read_bytes(val.as_mut_bytes())?;
        Ok(val)
    }
}
