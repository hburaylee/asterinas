// SPDX-License-Identifier: MPL-2.0

//! VFS inode trait implementations for Squashfs.
//!
//! Wires the Squashfs inode into the VFS layer by implementing
//! [`FileOps`], [`Inode`], and [`PageCacheBackend`] traits.
//!
//! Regular file reads go through the page cache. [`SquashFsPageCacheBackend`]
//! fills each 4 KB page on demand by decompressing the containing squashfs
//! block (typically 128 KB) and writing the requested bytes straight into the
//! page frame. Decompressed data and fragment blocks are not cached; each page
//! fault decompresses its containing block afresh.

use core::{ops::Deref, time::Duration};

use device_id::DeviceId;
use io_util::batch::IoBatch;
use ostd::mm::{Segment, VmIo, VmIoFill};
use spin::Once;

use super::super::{
    SquashFs,
    fs::SquashFsIno,
    inode::{BlockSizeInfo, INVALID_FRAG, InodeBody, InodeMeta, SquashFsInodeType},
};
use crate::{
    device,
    fs::{
        file::{AccessMode, InodeMode, InodeType, PerOpenFileOps, StatusFlags},
        utils::DirentVisitor,
        vfs::{
            file_system::FileSystem,
            inode::{
                Extension, FallocMode, FileOps, Inode, Metadata, MknodType, RenameMode,
                SymbolicLink,
            },
        },
    },
    prelude::*,
    process::{Gid, Uid},
    vm::page_cache::{LockedCachePage, PageCache, PageCacheBackend, Vmo},
};

/// VFS-level inode representing a single entry in a Squashfs filesystem.
///
/// Holds the parsed inode body, metadata, and a weak reference to the
/// owning [`SquashFs`] filesystem.
pub(crate) struct SquashFsInode {
    ino: SquashFsIno,
    body: InodeBody,
    meta: InodeMeta,
    fs: Weak<SquashFs>,
    extension: Extension,
    container_dev_id: DeviceId,
    /// The page cache, built lazily on first read of a regular file.
    page_cache: Once<(Arc<SquashFsPageCacheBackend>, PageCache)>,
}

impl SquashFsInode {
    pub(crate) fn new_inode(
        ino: SquashFsIno,
        body: InodeBody,
        meta: InodeMeta,
        fs: Weak<SquashFs>,
        container_dev_id: DeviceId,
    ) -> Arc<dyn Inode> {
        Arc::new(Self {
            ino,
            body,
            meta,
            fs,
            extension: Extension::new(),
            container_dev_id,
            page_cache: Once::new(),
        })
    }

    /// Returns the owning filesystem, or an error if it has been unmounted.
    ///
    /// Named `squash_fs` to distinguish it from the VFS `Inode::fs` method,
    /// which returns the filesystem as a trait object.
    fn squash_fs(&self) -> Result<Arc<SquashFs>> {
        self.fs
            .upgrade()
            .ok_or_else(|| Error::with_message(Errno::EIO, "filesystem is unmounted"))
    }

    fn inode_type(&self) -> InodeType {
        match &self.body {
            InodeBody::Dir { .. } => InodeType::Dir,
            InodeBody::File { .. } => InodeType::File,
            InodeBody::Symlink { .. } => InodeType::SymLink,
            InodeBody::BlockDevice { .. } => InodeType::BlockDevice,
            InodeBody::CharDevice { .. } => InodeType::CharDevice,
            InodeBody::NamedPipe => InodeType::NamedPipe,
            InodeBody::Socket => InodeType::Socket,
        }
    }
}

impl Debug for SquashFsInode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SquashFsInode")
            .field("ino", &self.ino)
            .field("type", &self.inode_type())
            .finish()
    }
}

impl FileOps for SquashFsInode {
    /// `O_DIRECT` is ignored: on-disk data is compressed, so every read must
    /// go through the decompressing page cache. This matches the Linux kernel.
    fn read_at(
        &self,
        offset: usize,
        writer: &mut VmWriter,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        let size = self.body.file_size() as usize;
        if offset >= size {
            return Ok(0);
        }
        let read_len = writer.avail().min(size - offset);
        if read_len == 0 {
            return Ok(0);
        }
        let Some(page_cache) = self.page_cache() else {
            return Ok(0);
        };
        let mut limited_writer = writer.clone_exclusive();
        limited_writer.limit(read_len);
        page_cache
            .read(offset, &mut limited_writer)
            .map_err(|_| Error::with_message(Errno::EIO, "page cache read failed"))?;
        writer.skip(read_len);
        Ok(read_len)
    }

    fn write_at(
        &self,
        _offset: usize,
        _reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn readdir_at(&self, offset: usize, visitor: &mut dyn DirentVisitor) -> Result<usize> {
        let InodeBody::Dir {
            block_start,
            file_size,
            block_offset,
            parent_inode,
        } = &self.body
        else {
            return_errno_with_message!(Errno::ENOTDIR, "not a directory")
        };
        let parent_inode = if *parent_inode == 0 {
            self.ino
        } else {
            *parent_inode
        };

        let mut count = 0;

        if offset == 0 {
            visitor.visit(".", self.ino as u64, InodeType::Dir, 1)?;
            count += 1;
        }

        if offset <= 1 {
            visitor.visit("..", parent_inode as u64, InodeType::Dir, 2)?;
            count += 1;
        }

        let fs = self.squash_fs()?;
        // Real directory entries are visited at VFS offsets 2.., i.e. squashfs
        // entry index `offset - 2` onward. `visit` positions are `index + 3` to
        // leave room for the synthesized "." and ".." at 1 and 2.
        let skip = offset.saturating_sub(2);
        fs.dir_for_each(
            *block_start,
            *block_offset,
            *file_size,
            skip,
            |idx, entry| {
                let child_type = to_vfs_inode_type(entry.inode_type);
                let name = core::str::from_utf8(entry.name()).unwrap_or("");
                visitor.visit(name, entry.inode_num as u64, child_type, idx + 3)?;
                count += 1;
                Ok(true)
            },
        )?;

        Ok(count)
    }
}

impl Inode for SquashFsInode {
    fn size(&self) -> usize {
        self.body.file_size() as usize
    }

    fn resize(&self, _new_size: usize) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn metadata(&self) -> Result<Metadata> {
        let self_dev_id = match self.inode_type() {
            InodeType::BlockDevice | InodeType::CharDevice => {
                let device_number = match &self.body {
                    InodeBody::BlockDevice { device_number }
                    | InodeBody::CharDevice { device_number } => *device_number,
                    _ => unreachable!(),
                };
                DeviceId::from_encoded_u64(device_number as u64)
            }
            _ => None,
        };
        Ok(Metadata {
            ino: self.ino as u64,
            size: self.size(),
            optimal_block_size: self
                .fs
                .upgrade()
                .map_or(4096, |fs| fs.super_block.block_size as usize),
            nr_sectors_allocated: self.size().div_ceil(512),
            last_access_at: Duration::from_secs(self.meta.mtime as u64),
            last_modify_at: Duration::from_secs(self.meta.mtime as u64),
            last_meta_change_at: Duration::from_secs(self.meta.mtime as u64),
            type_: self.inode_type(),
            mode: InodeMode::from_bits_truncate(self.meta.mode),
            nr_hard_links: self.meta.nlink as usize,
            uid: Uid::new(self.meta.uid),
            gid: Gid::new(self.meta.gid),
            container_dev_id: self.container_dev_id,
            self_dev_id,
            birth_at: None,
        })
    }

    fn ino(&self) -> u64 {
        self.ino as u64
    }

    fn type_(&self) -> InodeType {
        self.inode_type()
    }

    fn mode(&self) -> Result<InodeMode> {
        Ok(InodeMode::from_bits_truncate(self.meta.mode))
    }

    fn set_mode(&self, _mode: InodeMode) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn owner(&self) -> Result<Uid> {
        Ok(Uid::new(self.meta.uid))
    }

    fn set_owner(&self, _uid: Uid) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn group(&self) -> Result<Gid> {
        Ok(Gid::new(self.meta.gid))
    }

    fn set_group(&self, _gid: Gid) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn atime(&self) -> Duration {
        Duration::from_secs(self.meta.mtime as u64)
    }

    fn set_atime(&self, _time: Duration) {}

    fn mtime(&self) -> Duration {
        Duration::from_secs(self.meta.mtime as u64)
    }

    fn set_mtime(&self, _time: Duration) {}

    fn ctime(&self) -> Duration {
        Duration::from_secs(self.meta.mtime as u64)
    }

    fn set_ctime(&self, _time: Duration) {}

    fn page_cache(&self) -> Option<Arc<Vmo>> {
        let InodeBody::File {
            blocks_start,
            frag_index,
            block_offset,
            file_size,
            block_sizes,
        } = &self.body
        else {
            return None;
        };
        if *file_size == 0 {
            return None;
        }

        let pair = self
            .page_cache
            .try_call_once(|| {
                let fs = self.squash_fs()?;
                let backend = Arc::new(SquashFsPageCacheBackend {
                    fs: self.fs.clone(),
                    blocks_start: *blocks_start,
                    frag_index: *frag_index,
                    block_offset: *block_offset,
                    block_size: fs.super_block.block_size,
                    block_sizes: block_sizes.clone(),
                    file_size: *file_size as usize,
                });
                let backend_dyn: Arc<dyn PageCacheBackend> = backend.clone();
                let cache =
                    PageCache::new_with_backend(*file_size as usize, Arc::downgrade(&backend_dyn))?;
                Ok::<_, Error>((backend, cache))
            })
            .ok()?;
        Some(pair.1.as_vmo().clone())
    }

    fn open(
        &self,
        _access_mode: AccessMode,
        _status_flags: StatusFlags,
    ) -> Option<Result<Box<dyn PerOpenFileOps>>> {
        match self.inode_type() {
            inode_type @ (InodeType::BlockDevice | InodeType::CharDevice) => {
                let device_id = match &self.body {
                    InodeBody::BlockDevice { device_number }
                    | InodeBody::CharDevice { device_number } => *device_number,
                    _ => return None,
                };
                let device_id = DeviceId::from_encoded_u64(device_id as u64)?;
                let device_type = inode_type
                    .device_type()
                    .expect("BlockDevice and CharDevice always have a device type");
                let dev = device::lookup(device_type, device_id)?;
                Some(dev.open())
            }
            _ => None,
        }
    }

    fn create(&self, _name: &str, _type_: InodeType, _mode: InodeMode) -> Result<Arc<dyn Inode>> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn mknod(&self, _name: &str, _mode: InodeMode, _type_: MknodType) -> Result<Arc<dyn Inode>> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        let InodeBody::Dir {
            block_start,
            file_size,
            block_offset,
            ..
        } = &self.body
        else {
            return_errno_with_message!(Errno::ENOTDIR, "not a directory")
        };

        let fs = self.squash_fs()?;
        let (inode_num, inode_ref) = fs
            .dir_lookup(*block_start, *block_offset, *file_size, name.as_bytes())?
            .ok_or_else(|| Error::with_message(Errno::ENOENT, "entry not found"))?;

        fs.get_or_create_inode(inode_num, inode_ref)
    }

    fn link(&self, _old: &Arc<dyn Inode>, _name: &str) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn unlink(&self, _name: &str, _child: &Arc<dyn Inode>) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn rmdir(&self, _name: &str, _child: &Arc<dyn Inode>) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn rename(
        &self,
        _old_name: &str,
        _old_inode: &Arc<dyn Inode>,
        _new_dir_inode: &Arc<dyn Inode>,
        _new_name: &str,
        _replaced_inode: Option<&Arc<dyn Inode>>,
        _mode: RenameMode,
    ) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn read_link(&self) -> Result<SymbolicLink> {
        match &self.body {
            InodeBody::Symlink { target } => {
                let target = core::str::from_utf8(target)
                    .map_err(|_| Error::with_message(Errno::EIO, "invalid symlink target"))?;
                Ok(SymbolicLink::Plain(target.to_string()))
            }
            _ => return_errno_with_message!(Errno::EINVAL, "not a symlink"),
        }
    }

    fn fallocate(&self, _mode: FallocMode, _offset: usize, _len: usize) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }

    fn fs(&self) -> Arc<dyn FileSystem> {
        // Safe: inodes are only reachable while the filesystem is mounted,
        // which keeps the `Arc<SquashFs>` alive.
        self.squash_fs().unwrap()
    }

    fn extension(&self) -> &Extension {
        &self.extension
    }
}

fn to_vfs_inode_type(inode_type: SquashFsInodeType) -> InodeType {
    match inode_type {
        SquashFsInodeType::BasicDirectory | SquashFsInodeType::ExtendedDirectory => InodeType::Dir,
        SquashFsInodeType::BasicFile | SquashFsInodeType::ExtendedFile => InodeType::File,
        SquashFsInodeType::BasicSymlink | SquashFsInodeType::ExtendedSymlink => InodeType::SymLink,
        SquashFsInodeType::BasicBlockDevice | SquashFsInodeType::ExtendedBlockDevice => {
            InodeType::BlockDevice
        }
        SquashFsInodeType::BasicCharacterDevice | SquashFsInodeType::ExtendedCharDevice => {
            InodeType::CharDevice
        }
        SquashFsInodeType::BasicNamedPipe | SquashFsInodeType::ExtendedNamedPipe => {
            InodeType::NamedPipe
        }
        SquashFsInodeType::BasicSocket | SquashFsInodeType::ExtendedSocket => InodeType::Socket,
    }
}

/// Page cache backend for regular files in Squashfs.
struct SquashFsPageCacheBackend {
    fs: Weak<SquashFs>,
    blocks_start: u64,
    frag_index: u32,
    block_offset: u32,
    block_size: u32,
    block_sizes: Arc<[BlockSizeInfo]>,
    file_size: usize,
}

impl PageCacheBackend for SquashFsPageCacheBackend {
    // TODO: Synchronous — `io_batch` unused. The page cache read path
    // waits per-page anyway; async gains require batched readahead.
    fn read_page_async(
        &self,
        idx: usize,
        locked_page: LockedCachePage,
        _io_batch: &mut IoBatch,
    ) -> Result<()> {
        let offset = self.page_offset(idx)?;
        let fs = self
            .fs
            .upgrade()
            .ok_or_else(|| Error::with_message(Errno::EIO, "filesystem is unmounted"))?;

        let read_len = PAGE_SIZE.min(self.file_size - offset);

        let seg = Segment::from(locked_page.deref().clone());
        let copied = self.fill_page_seg(&fs, offset, read_len, &seg)?;
        if copied != read_len {
            return_errno_with_message!(Errno::EIO, "short read from SquashFS file data");
        }
        // The frames are recycled unzeroed, so the tail past the file's end
        // must be zero-filled explicitly to avoid leaking stale data.
        if read_len < PAGE_SIZE {
            seg.fill_zeros(read_len, PAGE_SIZE - read_len)
                .map_err(|_| Error::with_message(Errno::EIO, "failed to zero page tail"))?;
        }

        locked_page.set_up_to_date();
        Ok(())
    }

    fn write_page_async(
        &self,
        _idx: usize,
        _locked_page: LockedCachePage,
        _io_batch: &mut IoBatch,
    ) -> Result<()> {
        return_errno_with_message!(Errno::EROFS, "SquashFS is read-only")
    }
}

impl SquashFsPageCacheBackend {
    fn page_offset(&self, idx: usize) -> Result<usize> {
        let offset = idx
            .checked_mul(PAGE_SIZE)
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "page index out of bounds"))?;
        if offset >= self.file_size {
            return_errno_with_message!(Errno::EINVAL, "page index out of bounds");
        }
        Ok(offset)
    }

    /// Fills the page frame `seg` with `read_len` bytes of file data starting
    /// at `offset`.
    ///
    /// Returns the number of bytes written, which may be less than `read_len`
    /// if the on-disk data is shorter than the file size claims.
    fn fill_page_seg(
        &self,
        fs: &SquashFs,
        offset: usize,
        read_len: usize,
        seg: &impl VmIo,
    ) -> Result<usize> {
        let block_size = self.block_size as usize;
        let mut seg_pos = 0;
        let mut file_pos = offset;

        while seg_pos < read_len {
            let in_fragment = file_pos / block_size >= self.block_sizes.len();
            if in_fragment {
                // The fragment is always the last data source of a file.
                seg_pos += self.copy_from_fragment(fs, file_pos, seg, seg_pos, read_len)?;
                break;
            }
            let copied = self.copy_from_data_block(fs, file_pos, seg, seg_pos, read_len)?;
            seg_pos += copied;
            file_pos += copied;
        }

        Ok(seg_pos)
    }

    /// Copies file data from the data block containing `file_pos` into `seg`
    /// at byte offset `seg_pos`, writing at most up to `read_len`.
    fn copy_from_data_block(
        &self,
        fs: &SquashFs,
        file_pos: usize,
        seg: &impl VmIo,
        seg_pos: usize,
        read_len: usize,
    ) -> Result<usize> {
        let block_size = self.block_size as usize;
        let block_idx = file_pos / block_size;
        let block = fs.decompress_data_block(
            block_idx,
            self.blocks_start,
            &self.block_sizes,
            self.file_size,
        )?;
        let in_block_off = file_pos - block_idx * block_size;
        let block_avail = block.len().saturating_sub(in_block_off);
        let file_avail = self.file_size.saturating_sub(file_pos);
        let to_copy = (read_len - seg_pos).min(block_avail).min(file_avail);
        if to_copy > 0 {
            let mut reader = block.reader_at(in_block_off, to_copy).to_fallible();
            seg.write(seg_pos, &mut reader)
                .map_err(|_| Error::with_message(Errno::EIO, "failed to write page"))?;
        }
        Ok(to_copy)
    }

    /// Copies file data from the tail fragment block into `seg` at byte
    /// offset `seg_pos`, writing at most up to `read_len`. Returns zero if
    /// the file has no valid fragment.
    fn copy_from_fragment(
        &self,
        fs: &SquashFs,
        file_pos: usize,
        seg: &impl VmIo,
        seg_pos: usize,
        read_len: usize,
    ) -> Result<usize> {
        if self.frag_index == INVALID_FRAG || self.frag_index >= fs.super_block.frag_count {
            return Ok(0);
        }
        let frag_block = fs.fragment_block(self.frag_index)?;
        let bytes_before_frag = self.block_sizes.len() * self.block_size as usize;
        let src_start = self.block_offset as usize + (file_pos - bytes_before_frag);
        let frag_avail = frag_block.len().saturating_sub(src_start);
        let file_avail = self.file_size.saturating_sub(file_pos);
        let to_copy = (read_len - seg_pos).min(frag_avail).min(file_avail);
        if to_copy > 0 {
            let mut reader = frag_block.reader_at(src_start, to_copy).to_fallible();
            seg.write(seg_pos, &mut reader)
                .map_err(|_| Error::with_message(Errno::EIO, "failed to write page"))?;
        }
        Ok(to_copy)
    }
}
