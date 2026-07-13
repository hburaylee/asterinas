// SPDX-License-Identifier: MPL-2.0

//! Fragment table handling.
//!
//! Squashfs supports tail-end packing: the last partial block of a
//! file can be stored in a shared fragment block. The fragment table
//! maps fragment indexes to on-disk locations. Following the Linux kernel,
//! entries are read one at a time on demand (see `SquashFs::frag_lookup`).

use ostd::const_assert;

use super::{
    SquashFsError,
    block::{BlockReader, DataBlock},
    inode::COMPRESSED_BIT_BLOCK,
};
use crate::prelude::*;

/// A decoded fragment table entry: the on-disk location and size of a
/// fragment block, and whether it is stored compressed.
#[derive(Clone, Debug)]
pub(super) struct FragmentEntry {
    pub(super) start: u64,
    pub(super) size: u32,
    pub(super) compressed: bool,
}

/// A single on-disk fragment table entry.
///
/// Reference: <https://dr-emann.github.io/squashfs/squashfs.html#_fragment_table>
#[repr(C)]
#[derive(Clone, Copy, Pod)]
pub(super) struct RawFragmentEntry {
    start: u64,
    /// Raw size field with bit 24 encoding the compression flag.
    size_raw: u32,
    /// On-disk padding; unused.
    unused: u32,
}

const_assert!(size_of::<RawFragmentEntry>() == 16);

impl RawFragmentEntry {
    pub(super) fn into_entry(self) -> FragmentEntry {
        FragmentEntry {
            start: self.start,
            size: self.size_raw & !COMPRESSED_BIT_BLOCK,
            compressed: self.size_raw & COMPRESSED_BIT_BLOCK == 0,
        }
    }
}

/// Number of decompressed fragment blocks kept in [`FragmentCache`].
///
/// Matches the Linux default (`CONFIG_SQUASHFS_FRAGMENT_CACHE_SIZE`).
const FRAG_CACHE_SLOTS: usize = 3;

/// A single decompressed fragment block, keyed by its disk position.
struct CachedFragmentBlock {
    /// Absolute disk byte offset of the fragment block (its identity).
    start: u64,
    block: DataBlock,
}

/// A small round-robin cache of decompressed fragment blocks.
///
/// Tail-end packing lets many files share a single fragment block, so without a
/// cache each of those files would re-read and re-decompress the same block on
/// every page fault. This mirrors the Linux kernel's fragment cache (an instance
/// of its generic `squashfs_cache`), keyed by the block's disk `start` position.
///
/// Like [`MetaCache`](super::meta::MetaCache), the owning `Mutex` is held across
/// a miss's decompression, so a slot is filled exactly once. Linux instead marks
/// entries pending and sleeps on a wait queue to allow concurrent fills; this
/// keeps the simpler discipline already used for metadata blocks.
pub(super) struct FragmentCache {
    slots: [Option<CachedFragmentBlock>; FRAG_CACHE_SLOTS],
    /// Next slot to evict.
    next: usize,
}

impl FragmentCache {
    pub(super) fn new() -> Self {
        Self {
            slots: [const { None }; FRAG_CACHE_SLOTS],
            next: 0,
        }
    }

    /// Returns the fragment block at disk position `frag.start`, reading and
    /// decompressing it through `reader` into the next round-robin slot on a
    /// miss.
    pub(super) fn get(
        &mut self,
        reader: &BlockReader,
        frag: &FragmentEntry,
        block_size: u32,
    ) -> Result<DataBlock, SquashFsError> {
        if let Some(cached) = self
            .slots
            .iter()
            .find(|slot| matches!(slot, Some(c) if c.start == frag.start))
        {
            return Ok(cached.as_ref().unwrap().block.clone());
        }

        let block = reader.read_fragment(
            frag.start,
            frag.size as usize,
            frag.compressed,
            block_size as usize,
        )?;
        let idx = self.next;
        self.next = (self.next + 1) % FRAG_CACHE_SLOTS;
        self.slots[idx] = Some(CachedFragmentBlock {
            start: frag.start,
            block: block.clone(),
        });
        Ok(block)
    }
}
