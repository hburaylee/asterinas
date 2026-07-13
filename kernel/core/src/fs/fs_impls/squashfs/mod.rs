// SPDX-License-Identifier: MPL-2.0

//! Squashfs filesystem implementation.
//!
//! Squashfs is a compressed read-only filesystem.
//! This module implements support for Squashfs 4.0 images with zstd compression.
//!
//! # Design notes
//!
//! Following the Linux kernel, inodes and directory entries are read and
//! decompressed on demand through a small cache of decompressed metadata
//! blocks rather than materialised at mount time. The UID/GID and fragment
//! tables are likewise resolved one entry at a time; only their top-level
//! block-pointer arrays are held resident. File data blocks are read on-demand
//! through the page cache; decompressed fragment blocks, which may be shared
//! by many files, are served from a small round-robin fragment cache.

use core::fmt;

use aster_systree::SysNode;
use device_id::DeviceId;

use crate::{
    fs::vfs::{
        file_system::FileSystem,
        registry::{FsCache, FsCreationCtx, FsProperties, FsType},
    },
    prelude::*,
};

mod block;
mod compressor;
mod dir;
mod fragment;
mod fs;
mod impl_for_vfs;
mod inode;
mod meta;
mod super_block;

pub(super) use fs::SquashFs;

/// Errors specific to Squashfs operations.
#[derive(Clone, Debug)]
pub(super) enum SquashFsError {
    IoError,
    InvalidMagic,
    UnsupportedVersion(u16, u16),
    InvalidBlockSize(u32),
    UnsupportedCompression(u16),
    DecompressError,
    CorruptedImage(&'static str),
}

impl fmt::Display for SquashFsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SquashFsError::IoError => write!(f, "i/o error"),
            SquashFsError::InvalidMagic => write!(f, "invalid magic"),
            SquashFsError::UnsupportedVersion(maj, min) => {
                write!(f, "unsupported version {}.{}", maj, min)
            }
            SquashFsError::InvalidBlockSize(sz) => write!(f, "invalid block size {}", sz),
            SquashFsError::UnsupportedCompression(c) => {
                write!(f, "unsupported compression {}", c)
            }
            SquashFsError::DecompressError => write!(f, "decompression error"),
            SquashFsError::CorruptedImage(msg) => write!(f, "corrupted image: {}", msg),
        }
    }
}

impl From<SquashFsError> for Error {
    fn from(e: SquashFsError) -> Self {
        let (errno, msg) = match e {
            SquashFsError::IoError => (Errno::EIO, "I/O error"),
            SquashFsError::InvalidMagic => (Errno::EINVAL, "invalid magic"),
            SquashFsError::UnsupportedVersion(_, _) => (Errno::EINVAL, "unsupported version"),
            SquashFsError::InvalidBlockSize(_) => (Errno::EINVAL, "invalid block size"),
            SquashFsError::UnsupportedCompression(_) => (Errno::EINVAL, "unsupported compression"),
            SquashFsError::DecompressError => (Errno::EIO, "decompression error"),
            SquashFsError::CorruptedImage(detail) => (Errno::EIO, detail),
        };
        Error::with_message(errno, msg)
    }
}

struct SquashFsType {
    cache: FsCache<DeviceId>,
}

static SQUASHFS_TYPE: SquashFsType = SquashFsType {
    cache: FsCache::new(),
};

impl FsType for SquashFsType {
    type Key = DeviceId;

    fn name(&self) -> &'static str {
        "squashfs"
    }

    fn properties(&self) -> FsProperties {
        FsProperties::NEED_DISK
    }

    fn create(&self, fs_creation_ctx: &mut FsCreationCtx) -> Result<Arc<dyn FileSystem>> {
        let disk = fs_creation_ctx.resolve_block_device()?.clone();
        SquashFs::open(disk).map(|fs| fs as Arc<dyn FileSystem>)
    }

    fn obtain_key_and_cache(
        &self,
        fs_creation_ctx: &mut FsCreationCtx,
    ) -> Option<(DeviceId, &FsCache<DeviceId>)> {
        let key = fs_creation_ctx
            .resolve_block_device()
            .ok()
            .map(|disk| disk.id())?;

        Some((key, &self.cache))
    }

    fn sysnode(&self) -> Option<Arc<dyn SysNode>> {
        None
    }
}

pub(super) fn init() {
    crate::fs::vfs::registry::register(&SQUASHFS_TYPE).unwrap();
}
