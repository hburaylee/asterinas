// SPDX-License-Identifier: MPL-2.0

//! Fragment table handling.
//!
//! Squashfs supports tail-end packing: the last partial block of a
//! file can be stored in a shared fragment block. The fragment table
//! maps fragment indexes to on-disk locations. Following the Linux kernel,
//! entries are read one at a time on demand (see `SquashFs::frag_lookup`).

use ostd::const_assert;

use super::inode::COMPRESSED_BIT_BLOCK;
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
