// SPDX-License-Identifier: MPL-2.0

//! Squashfs superblock parsing.
//!
//! The superblock is the first 96 bytes of a Squashfs image.
//! It contains the filesystem magic, version, compression type,
//! and pointers to all on-disk tables.

use aster_block::BlockDevice;
use ostd::{const_assert, mm::VmIo};

use super::compressor::Compressor;
use crate::prelude::*;

/// Squashfs magic number ("hsqs" as little-endian u32).
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_the_superblock>
pub(super) const SQUASHFS_MAGIC: u32 = 0x73717368;

/// Parsed representation of the Squashfs on-disk superblock.
#[derive(Clone)]
pub(super) struct SuperBlock {
    pub(super) inode_count: u32,
    pub(super) block_size: u32,
    pub(super) frag_count: u32,
    pub(super) compressor: Compressor,
    pub(super) flags: u16,
    pub(super) id_count: u16,
    /// 64-bit inode reference to the root directory: the upper 48 bits are
    /// the byte offset of its metadata block relative to the inode table,
    /// and the low 16 bits are the byte offset within that block.
    pub(super) root_inode: u64,
    pub(super) bytes_used: u64,
    pub(super) id_table: u64,
    pub(super) inode_table: u64,
    pub(super) dir_table: u64,
    pub(super) frag_table: u64,
}

impl Debug for SuperBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SuperBlock")
            .field("inode_count", &self.inode_count)
            .field("block_size", &self.block_size)
            .field("compressor", &self.compressor)
            .field("flags", &self.flags)
            .finish()
    }
}

/// The superblock layout.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_the_superblock>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L241>
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawSuperBlock {
    magic: [u8; 4],
    inode_count: u32,
    mod_time: u32,
    block_size: u32,
    frag_count: u32,
    compression: u16,
    block_log: u16,
    flags: u16,
    id_count: u16,
    version_major: u16,
    version_minor: u16,
    root_inode: u64,
    bytes_used: u64,
    id_table: u64,
    xattr_table: u64,
    inode_table: u64,
    dir_table: u64,
    frag_table: u64,
    export_table: u64,
}

const_assert!(size_of::<RawSuperBlock>() == 96);

impl SuperBlock {
    /// Reads and validates the superblock from the block device at the given offset.
    pub(super) fn read(
        device: &Arc<dyn BlockDevice>,
        offset: u64,
    ) -> Result<Self, super::SquashFsError> {
        let raw: RawSuperBlock = device
            .read_val(offset as usize)
            .map_err(|_| super::SquashFsError::IoError)?;

        if &raw.magic != b"hsqs" {
            return Err(super::SquashFsError::InvalidMagic);
        }

        let version_major = raw.version_major;
        let version_minor = raw.version_minor;
        if version_major != 4 || version_minor != 0 {
            return Err(super::SquashFsError::UnsupportedVersion(
                version_major,
                version_minor,
            ));
        }

        let block_size = raw.block_size;
        if !block_size.is_power_of_two() {
            return Err(super::SquashFsError::InvalidBlockSize(block_size));
        }

        let block_log = block_size.ilog2();
        if !(12..=20).contains(&block_log) || block_log != raw.block_log as u32 {
            return Err(super::SquashFsError::InvalidBlockSize(block_size));
        }

        let compressor = Compressor::try_from(raw.compression)?;

        Ok(SuperBlock {
            inode_count: raw.inode_count,
            block_size,
            frag_count: raw.frag_count,
            compressor,
            flags: raw.flags,
            id_count: raw.id_count,
            root_inode: raw.root_inode,
            bytes_used: raw.bytes_used,
            id_table: raw.id_table,
            inode_table: raw.inode_table,
            dir_table: raw.dir_table,
            frag_table: raw.frag_table,
        })
    }
}
