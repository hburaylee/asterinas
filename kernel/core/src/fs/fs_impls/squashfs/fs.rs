// SPDX-License-Identifier: MPL-2.0

//! Core Squashfs filesystem state and mount logic.

use aster_block::BlockDevice;
use device_id::DeviceId;
use ostd::mm::VmIo;

use super::{
    SquashFsError,
    block::{BlockReader, DataBlock},
    compressor::DecompressContext,
    dir::{DirEntry, DirIter},
    fragment::{FragmentCache, FragmentEntry, RawFragmentEntry},
    impl_for_vfs::inode::SquashFsInode,
    inode::{self, BlockSizeInfo, InodeMeta, ParsedInode},
    meta::{META_MAX, MetaCache, MetaCursor, MetaReader},
    super_block::SuperBlock,
};
use crate::{
    fs::{
        fs_impls::pseudofs::AnonDeviceId,
        vfs::{file_system::FsEventSubscriberStats, inode::Inode},
    },
    prelude::*,
};

/// Indicates that an optional table (xattr, fragment, or export) is not
/// present in the filesystem image. When a superblock field equals this
/// value, the corresponding table is omitted and must not be read.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_the_superblock>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L40>
const INVALID_BLK: u64 = 0xffffffffffffffff;

/// The location of a compressed metadata block: the absolute byte offset of
/// the block from the start of the image.
pub(super) type MetaBlockLocation = u64;

/// On-disk inode number (squashfs format is 32-bit; the VFS widens to u64),
/// also the identity key under which live inodes are cached and reused.
pub(super) type SquashFsIno = u32;

/// In-memory representation of a mounted Squashfs filesystem.
pub(crate) struct SquashFs {
    device: Arc<dyn BlockDevice>,
    pub(super) super_block: SuperBlock,
    /// Block-pointer array of the UID/GID table.
    id_locations: Vec<MetaBlockLocation>,
    /// Block-pointer array of the fragment table; empty if the image has no fragments.
    frag_locations: Vec<MetaBlockLocation>,
    decompress: DecompressContext,
    meta_cache: Mutex<MetaCache>,
    frag_cache: Mutex<FragmentCache>,
    anon_device_id: AnonDeviceId,
    /// Live inodes, held weakly so unreferenced ones can be dropped and
    /// re-read from disk.
    inode_cache: RwMutex<BTreeMap<SquashFsIno, Weak<dyn Inode>>>,
    pub(super) fs_event_subscriber_stats: FsEventSubscriberStats,
    /// Weak self reference so inodes can outlive-check the filesystem.
    self_ref: Weak<SquashFs>,
}

impl SquashFs {
    /// Opens a Squashfs image from a block device.
    pub(super) fn open(device: Arc<dyn BlockDevice>) -> Result<Arc<Self>> {
        let super_block = SuperBlock::read(&device, 0)?;
        let decompress = DecompressContext::new(super_block.compressor);

        let id_locations = Self::read_id_table(&device, &super_block)?;
        let frag_locations = Self::read_frag_table(&device, &super_block)?;

        let anon_device_id = AnonDeviceId::acquire()
            .ok_or_else(|| Error::with_message(Errno::ENOMEM, "no device ID available"))?;

        info!(
            "SquashFS: {} inodes, {} fragments, block_size={}",
            super_block.inode_count, super_block.frag_count, super_block.block_size,
        );

        let fs = Arc::new_cyclic(|weak_self| SquashFs {
            device,
            super_block,
            id_locations,
            frag_locations,
            decompress,
            meta_cache: Mutex::new(MetaCache::new()),
            frag_cache: Mutex::new(FragmentCache::new()),
            anon_device_id,
            inode_cache: RwMutex::new(BTreeMap::new()),
            fs_event_subscriber_stats: FsEventSubscriberStats::new(),
            self_ref: weak_self.clone(),
        });

        // Read the root inode once so that a corrupted root fails the mount
        // with an error instead of failing the first lookup.
        fs.read_inode(fs.super_block.root_inode)?;

        Ok(fs)
    }

    /// Reads the UID/GID table's top-level metadata-block pointer array.
    ///
    /// The ID table is always present, so unlike the fragment table there is
    /// no [`INVALID_BLK`] case.
    fn read_id_table(
        device: &Arc<dyn BlockDevice>,
        sb: &SuperBlock,
    ) -> Result<Vec<MetaBlockLocation>, SquashFsError> {
        Self::read_index_table::<u32>(device, sb.id_table, sb.id_count as u64)
    }

    /// Reads the fragment table's top-level metadata-block pointer array, or an
    /// empty vector when the image has no fragment table.
    ///
    /// The fragment table is optional: an image with no fragments reports a
    /// zero count or an [`INVALID_BLK`] table position.
    fn read_frag_table(
        device: &Arc<dyn BlockDevice>,
        sb: &SuperBlock,
    ) -> Result<Vec<MetaBlockLocation>, SquashFsError> {
        if sb.frag_count == 0 || sb.frag_table == INVALID_BLK {
            return Ok(Vec::new());
        }
        Self::read_index_table::<RawFragmentEntry>(device, sb.frag_table, sb.frag_count as u64)
    }

    /// Reads the top-level pointer array of a two-level lookup table.
    ///
    /// The UID/GID and fragment tables use a two-level structure: a run of
    /// consecutive little-endian u64 pointers at `table_pos`, each pointing to
    /// an independent compressed metadata block that holds the packed entries
    /// of type `T`. Only this pointer array is read at mount time; the entries
    /// themselves are read on demand (see [`Self::get_id`] and
    /// [`Self::frag_lookup`]).
    fn read_index_table<T>(
        device: &Arc<dyn BlockDevice>,
        table_pos: u64,
        entry_count: u64,
    ) -> Result<Vec<MetaBlockLocation>, SquashFsError> {
        let total_size = size_of::<T>() * entry_count as usize;
        let block_count = total_size.div_ceil(META_MAX);

        // The pointers are stored contiguously on disk. Read the whole array in
        // one request: each `read_bytes` is a full block-device bio that reads
        // (at least) a whole sector, so reading the pointers one at a time would
        // re-read the same sector once per pointer.
        let mut raw = vec![0u8; block_count * 8];
        device
            .read_bytes(table_pos as usize, &mut raw)
            .map_err(|_| SquashFsError::IoError)?;

        let locations = raw
            .as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| u64::from_le_bytes(*chunk))
            .collect();
        Ok(locations)
    }

    pub(super) fn container_device_id(&self) -> DeviceId {
        self.anon_device_id.id()
    }

    pub(super) fn root_inode(&self) -> Result<Arc<dyn Inode>> {
        let parsed = self.read_inode(self.super_block.root_inode)?;
        Ok(self.materialize_inode(parsed))
    }

    /// Reads and parses the inode addressed by the 64-bit `inode_ref` on demand,
    /// decompressing metadata blocks through the shared cache.
    pub(super) fn read_inode(&self, inode_ref: u64) -> Result<ParsedInode> {
        let raw = {
            let mut cache = self.meta_cache.lock();
            let mut reader = MetaReader::new(
                &self.device,
                &self.decompress,
                &mut cache,
                self.super_block.inode_table,
                MetaCursor::from_ref(inode_ref),
            );
            inode::read_inode(
                &mut reader,
                self.super_block.block_size,
                self.super_block.inode_count,
            )?
        };

        let uid = self.get_id(raw.uid_idx)?;
        let gid = self.get_id(raw.gid_idx)?;
        Ok(ParsedInode {
            meta: InodeMeta {
                mode: raw.mode,
                uid,
                gid,
                mtime: raw.mtime,
                ino: raw.ino,
                nlink: raw.nlink,
            },
            body: raw.body,
        })
    }

    /// Resolves a UID/GID table `index` into its 32-bit value, mirroring the
    /// Linux kernel's `squashfs_get_id`.
    fn get_id(&self, index: u16) -> Result<u32> {
        const ENTRY_SIZE: usize = size_of::<u32>();
        let byte_pos = index as usize * ENTRY_SIZE;
        let meta_index = byte_pos / META_MAX;
        let offset = (byte_pos % META_MAX) as u16;
        let block_ptr = *self
            .id_locations
            .get(meta_index)
            .ok_or_else(|| Error::with_message(Errno::EIO, "id index out of bounds"))?;

        let mut cache = self.meta_cache.lock();
        let mut reader = MetaReader::new(
            &self.device,
            &self.decompress,
            &mut cache,
            0,
            MetaCursor {
                block: block_ptr,
                offset,
            },
        );
        Ok(reader.read_val::<u32>()?)
    }

    /// Resolves a fragment table `index` into its [`FragmentEntry`], mirroring
    /// the Linux kernel's `squashfs_frag_lookup`.
    pub(super) fn frag_lookup(&self, index: u32) -> Result<FragmentEntry> {
        let byte_pos = index as usize * size_of::<RawFragmentEntry>();
        let meta_index = byte_pos / META_MAX;
        let offset = (byte_pos % META_MAX) as u16;
        let block_ptr = *self
            .frag_locations
            .get(meta_index)
            .ok_or_else(|| Error::with_message(Errno::EIO, "fragment index out of bounds"))?;

        let mut cache = self.meta_cache.lock();
        let mut reader = MetaReader::new(
            &self.device,
            &self.decompress,
            &mut cache,
            0,
            MetaCursor {
                block: block_ptr,
                offset,
            },
        );
        let raw = reader.read_val::<RawFragmentEntry>()?;
        Ok(raw.into_entry())
    }

    /// Returns the VFS inode for a parsed inode, reusing a live cached
    /// instance if one exists so inode identity is preserved.
    fn materialize_inode(&self, parsed: ParsedInode) -> Arc<dyn Inode> {
        let ino = parsed.meta.ino;
        let mut cache = self.inode_cache.write();
        if let Some(inode) = cache.get(&ino).and_then(Weak::upgrade) {
            return inode;
        }
        let inode = SquashFsInode::new_inode(
            ino,
            parsed.body,
            parsed.meta,
            self.self_ref.clone(),
            self.container_device_id(),
        );
        cache.insert(ino, Arc::downgrade(&inode));
        inode
    }

    /// Returns the inode `ino`, reading it from `inode_ref` on a cache miss.
    /// `ino` alone suffices for a cache hit, avoiding disk I/O.
    pub(super) fn get_or_create_inode(
        &self,
        ino: SquashFsIno,
        inode_ref: u64,
    ) -> Result<Arc<dyn Inode>> {
        if let Some(inode) = self.inode_cache.read().get(&ino).and_then(Weak::upgrade) {
            return Ok(inode);
        }
        let parsed = self.read_inode(inode_ref)?;
        Ok(self.materialize_inode(parsed))
    }

    /// Looks up `name` in the directory located at the given directory-table
    /// position, returning the matching child's `(inode_num, inode_ref)`.
    pub(super) fn dir_lookup(
        &self,
        block_start: u32,
        block_offset: u16,
        file_size: u32,
        name: &[u8],
    ) -> Result<Option<(SquashFsIno, u64)>> {
        let mut cache = self.meta_cache.lock();
        let mut reader = MetaReader::new(
            &self.device,
            &self.decompress,
            &mut cache,
            self.super_block.dir_table,
            MetaCursor {
                block: block_start as u64,
                offset: block_offset,
            },
        );
        let mut iter = DirIter::new(&mut reader, file_size);
        while let Some(entry) = iter.next()? {
            if entry.name() == name {
                return Ok(Some((entry.inode_num, entry.inode_ref)));
            }
        }
        Ok(None)
    }

    /// Invokes `f` for each entry of the directory located at the given
    /// directory-table position, skipping the first `skip` entries and passing
    /// each entry's zero-based index. `f` returns `false` to stop early.
    pub(super) fn dir_for_each(
        &self,
        block_start: u32,
        block_offset: u16,
        file_size: u32,
        skip: usize,
        mut f: impl FnMut(usize, &DirEntry) -> Result<bool>,
    ) -> Result<()> {
        let mut cache = self.meta_cache.lock();
        let mut reader = MetaReader::new(
            &self.device,
            &self.decompress,
            &mut cache,
            self.super_block.dir_table,
            MetaCursor {
                block: block_start as u64,
                offset: block_offset,
            },
        );
        let mut iter = DirIter::new(&mut reader, file_size);
        let mut idx = 0;
        while let Some(entry) = iter.next()? {
            if idx >= skip && !f(idx, &entry)? {
                break;
            }
            idx += 1;
        }
        Ok(())
    }

    /// Decompresses the data block at `block_idx` on demand into page frames.
    ///
    /// Data blocks are not cached: they are large and typically read only
    /// once, so every call re-reads and re-decompresses from the device.
    pub(super) fn decompress_data_block(
        &self,
        block_idx: usize,
        blocks_start: u64,
        block_sizes: &[BlockSizeInfo],
        file_size: usize,
    ) -> Result<DataBlock> {
        let info = block_sizes
            .get(block_idx)
            .ok_or_else(|| Error::with_message(Errno::EIO, "block index out of bounds"))?;

        let disk_pos = blocks_start
            + block_sizes[..block_idx]
                .iter()
                .map(|b| b.size as u64)
                .sum::<u64>();

        let block_size = self.super_block.block_size as usize;
        // The block decompresses to a full `block_size`, except the file's final
        // block, which holds only the trailing bytes.
        let capacity = block_size.min(file_size.saturating_sub(block_idx * block_size));

        let block = BlockReader::new(&self.device, &self.decompress).read_data(
            disk_pos,
            info.size as usize,
            info.compressed,
            capacity,
        )?;
        Ok(block)
    }

    /// Returns the decompressed fragment block at `frag_index`, reading and
    /// decompressing it on a cache miss.
    ///
    /// Fragment blocks may be shared by many files, so they are served from
    /// the fragment cache to avoid repeated re-decompression.
    pub(super) fn fragment_block(&self, frag_index: u32) -> Result<DataBlock> {
        let frag = self.frag_lookup(frag_index)?;
        let reader = BlockReader::new(&self.device, &self.decompress);
        let block = self
            .frag_cache
            .lock()
            .get(&reader, &frag, self.super_block.block_size)?;
        Ok(block)
    }
}

impl Debug for SquashFs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SquashFs")
            .field("sb", &self.super_block)
            .field("inodes", &self.super_block.inode_count)
            .finish()
    }
}
