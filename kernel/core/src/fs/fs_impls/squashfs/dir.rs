// SPDX-License-Identifier: MPL-2.0

//! Directory entry parsing for Squashfs.
//!
//! Directory entries store inode references relative to their enclosing
//! header to maximise compression, since most files in a directory live in
//! the same metadata block.

use ostd::const_assert;

use super::{SquashFsError, fs::SquashFsIno, inode::SquashFsInodeType, meta::MetaReader};
use crate::prelude::*;

/// Maximum number of entries per directory header.
const DIR_HEADER_MAX_COUNT: u32 = 256;

/// Maximum length of a directory entry name.
const DIR_NAME_MAX: usize = 256;

/// A directory inode's `file_size` is 3 bytes larger than the real listing:
/// per the spec, the kernel synthesizes "." and ".." for offsets 0..3 and
/// subtracts 3 from the size before reading the on-disk entries.
const DIR_TAIL_PADDING: usize = 3;

/// On-disk directory header.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_directory_table>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L418>
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawDirHeader {
    count: u32,
    start_block: u32,
    inode_number: u32,
}
const_assert!(size_of::<RawDirHeader>() == 12);

/// On-disk directory entry (fixed part, 8 bytes).
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_directory_table>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L410>
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawDirEntry {
    offset: u16,
    inode_offset: u16,
    type_: u16,
    /// One less than the name length; names are not null-terminated.
    size: u16,
}
const_assert!(size_of::<RawDirEntry>() == 8);

/// A single directory entry yielded by [`DirIter`].
///
/// The name borrows the iterator's internal buffer, so it is valid only until
/// the next [`DirIter::next`] call.
pub(super) struct DirEntry<'b> {
    pub(super) inode_num: SquashFsIno,
    /// 64-bit inode reference used to read the child inode on demand.
    pub(super) inode_ref: u64,
    pub(super) inode_type: SquashFsInodeType,
    name: &'b [u8],
}

impl DirEntry<'_> {
    pub(super) fn name(&self) -> &[u8] {
        self.name
    }
}

/// A streaming cursor over a directory's entries.
///
/// Entries are decoded one at a time into a fixed name buffer, so listing a
/// directory allocates no per-entry heap memory.
pub(super) struct DirIter<'a, 'r> {
    reader: &'r mut MetaReader<'a>,
    /// Directory data bytes not yet consumed (already excludes the tail padding).
    remaining: usize,
    /// Base inode number of the current header, for relative entry decoding.
    header_inode: u32,
    /// Inode-table block offset of the current header, for `inode_ref` decoding.
    header_start_block: u32,
    /// Entries left to read under the current header.
    entries_left: u32,
    name_buf: [u8; DIR_NAME_MAX],
}

impl<'a, 'r> DirIter<'a, 'r> {
    /// Creates an iterator over a directory of on-disk size `file_size`.
    pub(super) fn new(reader: &'r mut MetaReader<'a>, file_size: u32) -> Self {
        let remaining = (file_size as usize).saturating_sub(DIR_TAIL_PADDING);
        Self {
            reader,
            remaining,
            header_inode: 0,
            header_start_block: 0,
            entries_left: 0,
            name_buf: [0u8; DIR_NAME_MAX],
        }
    }

    /// Returns the next directory entry, or `None` at the end of the directory.
    pub(super) fn next(&mut self) -> Result<Option<DirEntry<'_>>, SquashFsError> {
        if self.entries_left == 0 {
            if self.remaining < size_of::<RawDirHeader>() {
                return Ok(None);
            }
            let header: RawDirHeader = self.reader.read_val()?;
            self.remaining -= size_of::<RawDirHeader>();

            if header.count > DIR_HEADER_MAX_COUNT - 1 {
                return Err(SquashFsError::CorruptedImage("directory entry count > 256"));
            }
            self.header_inode = header.inode_number;
            self.header_start_block = header.start_block;
            // The on-disk count is one less than the number of entries.
            self.entries_left = header.count + 1;
        }

        if self.remaining < size_of::<RawDirEntry>() {
            return Ok(None);
        }
        let entry: RawDirEntry = self.reader.read_val()?;
        self.remaining -= size_of::<RawDirEntry>();
        self.entries_left -= 1;

        let name_len = (entry.size + 1) as usize;
        if name_len > DIR_NAME_MAX {
            return Err(SquashFsError::CorruptedImage("directory name too long"));
        }
        if self.remaining < name_len {
            return Err(SquashFsError::CorruptedImage("directory name truncated"));
        }
        self.reader.read_bytes(&mut self.name_buf[..name_len])?;
        self.remaining -= name_len;

        // The spec defines inode_offset as s16 (signed), but Pod requires u16 on
        // disk. Cast to i16 first to preserve the sign before widening to i32.
        let inode_num = (self.header_inode as i32 + (entry.inode_offset as i16) as i32) as u32;
        let inode_ref = ((self.header_start_block as u64) << 16) | entry.offset as u64;
        let inode_type = SquashFsInodeType::try_from(entry.type_)?;

        Ok(Some(DirEntry {
            inode_num,
            inode_ref,
            inode_type,
            name: &self.name_buf[..name_len],
        }))
    }
}
