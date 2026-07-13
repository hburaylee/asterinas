// SPDX-License-Identifier: MPL-2.0

use aster_block::BLOCK_SIZE;

use super::super::{SquashFs, super_block::SQUASHFS_MAGIC};
use crate::{
    fs::{
        utils::NAME_MAX,
        vfs::{
            file_system::{FileSystem, FsEventSubscriberStats, FsFlags, SuperBlock},
            inode::Inode,
        },
    },
    prelude::*,
};

impl FileSystem for SquashFs {
    fn name(&self) -> &'static str {
        "squashfs"
    }

    fn sync(&self) -> Result<()> {
        Ok(())
    }

    fn flags(&self) -> FsFlags {
        FsFlags::RDONLY
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        self.root_inode().unwrap()
    }

    fn sb(&self) -> SuperBlock {
        let total_blocks = self.super_block.bytes_used.div_ceil(BLOCK_SIZE as u64);
        SuperBlock {
            magic: SQUASHFS_MAGIC as u64,
            bsize: self.super_block.block_size as usize,
            blocks: total_blocks as usize,
            bfree: 0,
            bavail: 0,
            files: self.super_block.inode_count as usize,
            ffree: 0,
            fsid: 0,
            namelen: NAME_MAX,
            frsize: BLOCK_SIZE,
            flags: 0,
            container_dev_id: self.container_device_id(),
        }
    }

    fn fs_event_subscriber_stats(&self) -> &FsEventSubscriberStats {
        &self.fs_event_subscriber_stats
    }
}
