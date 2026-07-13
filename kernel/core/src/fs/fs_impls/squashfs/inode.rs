// SPDX-License-Identifier: MPL-2.0

//! Inode parsing for Squashfs.
//!
//! Squashfs inodes are stored in compressed metadata blocks and identified
//! by a 64-bit reference (see [`super::meta::MetaCursor`]).

use ostd::const_assert;

use super::{SquashFsError, fs::SquashFsIno, meta::MetaReader};
use crate::prelude::*;

/// On-disk inode type.
///
/// Squashfs defines 14 inode types: 7 basic types and 7 extended types.
/// The extended types add xattr support, 64-bit fields, and nlink counts.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_common_inode_header>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L78>
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SquashFsInodeType {
    BasicDirectory = 1,
    BasicFile = 2,
    BasicSymlink = 3,
    BasicBlockDevice = 4,
    BasicCharacterDevice = 5,
    BasicNamedPipe = 6,
    BasicSocket = 7,
    ExtendedDirectory = 8,
    ExtendedFile = 9,
    ExtendedSymlink = 10,
    ExtendedBlockDevice = 11,
    ExtendedCharDevice = 12,
    ExtendedNamedPipe = 13,
    ExtendedSocket = 14,
}

impl TryFrom<u16> for SquashFsInodeType {
    type Error = SquashFsError;

    fn try_from(v: u16) -> Result<Self, SquashFsError> {
        match v {
            1 => Ok(Self::BasicDirectory),
            2 => Ok(Self::BasicFile),
            3 => Ok(Self::BasicSymlink),
            4 => Ok(Self::BasicBlockDevice),
            5 => Ok(Self::BasicCharacterDevice),
            6 => Ok(Self::BasicNamedPipe),
            7 => Ok(Self::BasicSocket),
            8 => Ok(Self::ExtendedDirectory),
            9 => Ok(Self::ExtendedFile),
            10 => Ok(Self::ExtendedSymlink),
            11 => Ok(Self::ExtendedBlockDevice),
            12 => Ok(Self::ExtendedCharDevice),
            13 => Ok(Self::ExtendedNamedPipe),
            14 => Ok(Self::ExtendedSocket),
            _ => Err(SquashFsError::CorruptedImage("unknown inode type")),
        }
    }
}

/// A fully parsed inode with its metadata and type-specific body.
#[derive(Clone)]
pub(super) struct ParsedInode {
    pub(super) meta: InodeMeta,
    pub(super) body: InodeBody,
}

/// An inode as read straight from the metadata stream, before its UID/GID
/// indexes are resolved against the ID table.
///
/// Resolving UID/GID requires another metadata read through the same locked
/// cache, so it is deferred to [`super::fs::SquashFs::read_inode`] until the
/// metadata reader's lock has been released.
pub(super) struct RawInode {
    pub(super) mode: u16,
    /// Index into the UID/GID table, resolved later into a real UID.
    pub(super) uid_idx: u16,
    /// Index into the UID/GID table, resolved later into a real GID.
    pub(super) gid_idx: u16,
    pub(super) mtime: u32,
    pub(super) ino: SquashFsIno,
    pub(super) nlink: u32,
    pub(super) body: InodeBody,
}

/// Common metadata shared by all inode types.
#[derive(Clone)]
pub(super) struct InodeMeta {
    pub(super) mode: u16,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) mtime: u32,
    pub(super) ino: SquashFsIno,
    pub(super) nlink: u32,
}

/// Type-specific inode data.
#[derive(Clone)]
pub(super) enum InodeBody {
    File {
        /// On-disk offset of the first data block.
        blocks_start: u64,
        /// Index into the fragment table, or `INVALID_FRAG` if no fragment.
        frag_index: u32,
        /// Byte offset of this file's data within the fragment block.
        block_offset: u32,
        file_size: u64,
        /// Per-block size and compression info, shared with the page-cache
        /// backend without copying.
        block_sizes: Arc<[BlockSizeInfo]>,
    },
    Dir {
        /// Byte offset of the directory data relative to the start of the
        /// directory table.
        block_start: u32,
        /// Size of the directory data (+3 for padding).
        file_size: u32,
        block_offset: u16,
        /// Inode number of the parent directory (0 for root).
        parent_inode: SquashFsIno,
    },
    Symlink {
        target: Vec<u8>,
    },
    BlockDevice {
        /// Device number in Linux `new_encode_dev` format:
        /// `(minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12)`
        device_number: u32,
    },
    CharDevice {
        /// Device number in Linux `new_encode_dev` format:
        /// `(minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12)`
        device_number: u32,
    },
    NamedPipe,
    Socket,
}

impl InodeBody {
    /// Returns the logical size of this inode in bytes.
    pub(super) fn file_size(&self) -> u64 {
        match self {
            InodeBody::File { file_size, .. } => *file_size,
            InodeBody::Dir { file_size, .. } => *file_size as u64,
            InodeBody::Symlink { target } => target.len() as u64,
            _ => 0,
        }
    }
}

/// Compressed size and compression flag for a single data block.
///
/// The on-disk format uses bit 24 of the 32-bit size field to indicate
/// whether the block is compressed.
#[derive(Clone, Copy, Debug)]
pub(super) struct BlockSizeInfo {
    pub(super) size: u32,
    pub(super) compressed: bool,
}

/// Bit 24 of the block size: set = uncompressed, not set = compressed.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_data_and_fragment_blocks>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L113>
pub(super) const COMPRESSED_BIT_BLOCK: u32 = 1 << 24;

impl BlockSizeInfo {
    fn from_raw(raw: u32) -> Self {
        Self {
            size: raw & !COMPRESSED_BIT_BLOCK,
            compressed: raw & COMPRESSED_BIT_BLOCK == 0,
        }
    }
}

/// Sentinel value indicating no fragment is attached to this inode.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_file_inodes>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L38>
pub(super) const INVALID_FRAG: u32 = 0xffffffff;

/// Upper bound on a symlink target length.
///
/// Linux caps symlink targets at `PATH_MAX` (4096). A target larger than this
/// indicates a corrupt inode, and the cap bounds the transient heap buffer used
/// while reading the target out of the metadata stream.
const MAX_SYMLINK_TARGET: usize = 4096;

/// On-disk common inode header.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_inode_table>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L270>
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawBaseInode {
    inode_type: u16,
    mode: u16,
    uid_idx: u16,
    gid_idx: u16,
    mtime: u32,
    inode_number: u32,
}

const_assert!(size_of::<RawBaseInode>() == 16);

/// On-disk basic directory inode.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawBasicDir {
    block_start: u32,
    nlink: u32,
    file_size: u16,
    block_offset: u16,
    parent_inode: u32,
}

const_assert!(size_of::<RawBasicDir>() == 16);

/// On-disk extended directory inode header.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawExtendedDir {
    nlink: u32,
    file_size: u32,
    block_start: u32,
    parent_inode: u32,
    index_count: u16,
    block_offset: u16,
    xattr_index: u32,
}

const_assert!(size_of::<RawExtendedDir>() == 24);

/// On-disk basic file inode header.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawBasicFile {
    blocks_start: u32,
    frag_index: u32,
    block_offset: u32,
    file_size: u32,
}

const_assert!(size_of::<RawBasicFile>() == 16);

/// On-disk extended file inode header.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawExtendedFile {
    blocks_start: u64,
    file_size: u64,
    sparse: u64,
    nlink: u32,
    frag_index: u32,
    block_offset: u32,
    xattr_index: u32,
}

const_assert!(size_of::<RawExtendedFile>() == 40);

/// On-disk symlink inode header.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawSymlink {
    nlink: u32,
    target_size: u32,
}

const_assert!(size_of::<RawSymlink>() == 8);

/// On-disk device inode header.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawDevice {
    nlink: u32,
    device_number: u32,
}

const_assert!(size_of::<RawDevice>() == 8);

/// On-disk IPC inode header — used for FIFOs and sockets.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RawIpc {
    nlink: u32,
}

const_assert!(size_of::<RawIpc>() == 4);

/// Parses a single inode read on demand through `reader`, which must be
/// positioned at the inode's common header. The reader is left positioned
/// immediately after the inode.
///
/// The returned [`RawInode`] still carries unresolved UID/GID *indexes*.
pub(super) fn read_inode(
    reader: &mut MetaReader,
    block_size: u32,
    inode_count: u32,
) -> Result<RawInode, SquashFsError> {
    let base: RawBaseInode = reader.read_val()?;

    if base.inode_number == 0 || base.inode_number > inode_count {
        return Err(SquashFsError::CorruptedImage("inode number out of range"));
    }

    let inode_type = SquashFsInodeType::try_from(base.inode_type)?;

    let (body, nlink) = match inode_type {
        SquashFsInodeType::BasicDirectory => parse_basic_dir_body(reader)?,
        SquashFsInodeType::ExtendedDirectory => parse_extended_dir_body(reader)?,
        SquashFsInodeType::BasicFile => parse_basic_file_body(reader, block_size)?,
        SquashFsInodeType::ExtendedFile => parse_extended_file_body(reader, block_size)?,
        SquashFsInodeType::BasicSymlink => parse_symlink_body(reader)?,
        SquashFsInodeType::ExtendedSymlink => {
            let body = parse_symlink_body(reader)?;
            skip_xattr_index(reader)?;
            body
        }
        SquashFsInodeType::BasicBlockDevice => {
            let (device_number, nlink) = parse_device_body(reader)?;
            (InodeBody::BlockDevice { device_number }, nlink)
        }
        SquashFsInodeType::BasicCharacterDevice => {
            let (device_number, nlink) = parse_device_body(reader)?;
            (InodeBody::CharDevice { device_number }, nlink)
        }
        SquashFsInodeType::BasicNamedPipe => (InodeBody::NamedPipe, parse_ipc_body(reader)?),
        SquashFsInodeType::BasicSocket => (InodeBody::Socket, parse_ipc_body(reader)?),
        SquashFsInodeType::ExtendedBlockDevice => {
            let (device_number, nlink) = parse_device_body(reader)?;
            skip_xattr_index(reader)?;
            (InodeBody::BlockDevice { device_number }, nlink)
        }
        SquashFsInodeType::ExtendedCharDevice => {
            let (device_number, nlink) = parse_device_body(reader)?;
            skip_xattr_index(reader)?;
            (InodeBody::CharDevice { device_number }, nlink)
        }
        SquashFsInodeType::ExtendedNamedPipe => {
            let nlink = parse_ipc_body(reader)?;
            skip_xattr_index(reader)?;
            (InodeBody::NamedPipe, nlink)
        }
        SquashFsInodeType::ExtendedSocket => {
            let nlink = parse_ipc_body(reader)?;
            skip_xattr_index(reader)?;
            (InodeBody::Socket, nlink)
        }
    };

    let raw = RawInode {
        mode: base.mode,
        uid_idx: base.uid_idx,
        gid_idx: base.gid_idx,
        mtime: base.mtime,
        ino: base.inode_number,
        nlink,
        body,
    };

    Ok(raw)
}

fn parse_basic_dir_body(reader: &mut MetaReader) -> Result<(InodeBody, u32), SquashFsError> {
    let raw: RawBasicDir = reader.read_val()?;
    Ok((
        InodeBody::Dir {
            block_start: raw.block_start,
            file_size: raw.file_size as u32,
            block_offset: raw.block_offset,
            parent_inode: raw.parent_inode,
        },
        raw.nlink,
    ))
}

/// Parses the body of an extended directory inode, skipping its index list.
fn parse_extended_dir_body(reader: &mut MetaReader) -> Result<(InodeBody, u32), SquashFsError> {
    let raw: RawExtendedDir = reader.read_val()?;
    for _ in 0..raw.index_count {
        // Each index entry is: index (u32), start (u32), name_size (u32),
        // followed by `name_size + 1` name bytes. The fast-lookup index is
        // unused here, so skip the whole entry.
        let _index: u32 = reader.read_val()?;
        let _start: u32 = reader.read_val()?;
        let name_size: u32 = reader.read_val()?;
        let name_len = name_size
            .checked_add(1)
            .ok_or(SquashFsError::CorruptedImage(
                "dir index name_size overflow",
            ))? as usize;
        reader.skip(name_len)?;
    }
    Ok((
        InodeBody::Dir {
            block_start: raw.block_start,
            file_size: raw.file_size,
            block_offset: raw.block_offset,
            parent_inode: raw.parent_inode,
        },
        raw.nlink,
    ))
}

fn parse_basic_file_body(
    reader: &mut MetaReader,
    block_size: u32,
) -> Result<(InodeBody, u32), SquashFsError> {
    let raw: RawBasicFile = reader.read_val()?;
    let nblocks = file_block_count(block_size, raw.frag_index, raw.file_size as u64) as usize;
    let block_sizes = read_block_sizes(reader, nblocks)?;
    Ok((
        InodeBody::File {
            blocks_start: raw.blocks_start as u64,
            frag_index: raw.frag_index,
            block_offset: raw.block_offset,
            file_size: raw.file_size as u64,
            block_sizes,
        },
        // Basic files don't support hard-link accounting.
        1,
    ))
}

fn parse_extended_file_body(
    reader: &mut MetaReader,
    block_size: u32,
) -> Result<(InodeBody, u32), SquashFsError> {
    let raw: RawExtendedFile = reader.read_val()?;
    let nblocks = file_block_count(block_size, raw.frag_index, raw.file_size) as usize;
    let block_sizes = read_block_sizes(reader, nblocks)?;
    Ok((
        InodeBody::File {
            blocks_start: raw.blocks_start,
            frag_index: raw.frag_index,
            block_offset: raw.block_offset,
            file_size: raw.file_size,
            block_sizes,
        },
        raw.nlink,
    ))
}

fn read_block_sizes(
    reader: &mut MetaReader,
    nblocks: usize,
) -> Result<Arc<[BlockSizeInfo]>, SquashFsError> {
    let mut block_sizes = Vec::with_capacity(nblocks);
    for _ in 0..nblocks {
        let raw_size: u32 = reader.read_val()?;
        block_sizes.push(BlockSizeInfo::from_raw(raw_size));
    }
    Ok(block_sizes.into())
}

/// Parses the body of a symlink inode (shared by the basic and extended variants).
fn parse_symlink_body(reader: &mut MetaReader) -> Result<(InodeBody, u32), SquashFsError> {
    let raw: RawSymlink = reader.read_val()?;
    let target_size = raw.target_size as usize;
    if target_size > MAX_SYMLINK_TARGET {
        return Err(SquashFsError::CorruptedImage("symlink target too long"));
    }
    let mut target = vec![0u8; target_size];
    reader.read_bytes(&mut target)?;
    Ok((InodeBody::Symlink { target }, raw.nlink))
}

/// Parses the body of a device inode (shared by block and character devices).
///
/// Returns the device number and nlink.
fn parse_device_body(reader: &mut MetaReader) -> Result<(u32, u32), SquashFsError> {
    let raw: RawDevice = reader.read_val()?;
    Ok((raw.device_number, raw.nlink))
}

/// Parses the body of an IPC inode (shared by FIFOs and sockets).
///
/// Returns nlink.
fn parse_ipc_body(reader: &mut MetaReader) -> Result<u32, SquashFsError> {
    let raw: RawIpc = reader.read_val()?;
    Ok(raw.nlink)
}

/// Skips the `xattr_index` field of an extended inode.
///
/// Xattrs are not supported now, so the value is discarded.
fn skip_xattr_index(reader: &mut MetaReader) -> Result<(), SquashFsError> {
    reader.skip(size_of::<u32>())
}

/// Computes the number of data blocks for a file.
///
/// If the file has a fragment, the last partial block is stored in the
/// fragment, so the block count is `file_size / block_size`.
/// Otherwise, the block count is rounded up to cover the full file size.
fn file_block_count(block_size: u32, frag_index: u32, file_size: u64) -> u64 {
    let block_size = u64::from(block_size);
    if frag_index == INVALID_FRAG {
        file_size.div_ceil(block_size)
    } else {
        file_size / block_size
    }
}
