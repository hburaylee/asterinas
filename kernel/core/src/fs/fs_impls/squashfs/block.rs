// SPDX-License-Identifier: MPL-2.0

//! Decompressed data and fragment blocks held in page frames.
//!
//! Both file data blocks and tail-packing fragment blocks decompress to at most
//! `block_size` bytes (typically 128 KiB, up to 1 MiB). Rather than staging the
//! decompressed output in a heap `Vec` — which for a buffer that large bypasses
//! the slab allocator and falls back to a *zeroed* frame allocation anyway — the
//! bytes are decompressed straight into unzeroed page frames held in a
//! [`Segment`]. Readers then copy from those frames directly into the
//! destination (a page-cache frame) with no intermediate heap buffer.

use aster_block::BlockDevice;
use ostd::mm::{
    FrameAllocOptions, HasSize, Infallible, Segment, VmIo, io::util::HasVmReaderWriter,
};

use super::{SquashFsError, compressor::DecompressContext};
use crate::prelude::*;

/// Reads and decompresses data or fragment blocks.
pub(super) struct BlockReader<'a> {
    device: &'a Arc<dyn BlockDevice>,
    decompress: &'a DecompressContext,
}

impl<'a> BlockReader<'a> {
    pub(super) fn new(device: &'a Arc<dyn BlockDevice>, decompress: &'a DecompressContext) -> Self {
        Self { device, decompress }
    }

    pub(super) fn read_data(
        &self,
        disk_pos: u64,
        on_disk_size: usize,
        compressed: bool,
        capacity: usize,
    ) -> Result<DataBlock, SquashFsError> {
        if on_disk_size == 0 {
            // A zero on-disk size marks a sparse block that reads as all
            // zeros, so the frames must stay zeroed (no `zeroed(false)`).
            let seg = FrameAllocOptions::new()
                .alloc_segment(capacity.div_ceil(PAGE_SIZE))
                .map_err(|_| SquashFsError::IoError)?;
            return Ok(DataBlock::new(seg, capacity));
        }
        self.read_block(disk_pos, on_disk_size, compressed, capacity)
    }

    pub(super) fn read_fragment(
        &self,
        disk_pos: u64,
        on_disk_size: usize,
        compressed: bool,
        capacity: usize,
    ) -> Result<DataBlock, SquashFsError> {
        if on_disk_size == 0 {
            let seg = FrameAllocOptions::new()
                .zeroed(false)
                .alloc_segment(capacity.div_ceil(PAGE_SIZE))
                .map_err(|_| SquashFsError::IoError)?;
            return Ok(DataBlock::new(seg, 0));
        }
        self.read_block(disk_pos, on_disk_size, compressed, capacity)
    }

    fn read_block(
        &self,
        disk_pos: u64,
        on_disk_size: usize,
        compressed: bool,
        capacity: usize,
    ) -> Result<DataBlock, SquashFsError> {
        let seg = FrameAllocOptions::new()
            .zeroed(false)
            .alloc_segment(capacity.div_ceil(PAGE_SIZE))
            .map_err(|_| SquashFsError::IoError)?;

        let len = if compressed {
            let src = FrameAllocOptions::new()
                .zeroed(false)
                .alloc_segment(on_disk_size.div_ceil(PAGE_SIZE))
                .map_err(|_| SquashFsError::IoError)?;
            let mut src_writer = src.writer();
            src_writer.limit(on_disk_size);
            self.device
                .read(disk_pos as usize, &mut src_writer.to_fallible())
                .map_err(|_| SquashFsError::IoError)?;

            let mut src_reader = src.reader();
            src_reader.limit(on_disk_size);

            let mut dst = seg.writer();
            dst.limit(capacity);
            self.decompress
                .decompress_stream(&mut src_reader, &mut dst)?
        } else {
            let mut dst = seg.writer();
            dst.limit(on_disk_size);
            self.device
                .read(disk_pos as usize, &mut dst.to_fallible())
                .map_err(|_| SquashFsError::IoError)?;
            on_disk_size
        };

        Ok(DataBlock::new(seg, len))
    }
}

/// A single decompressed data block backed.
#[derive(Clone)]
pub(super) struct DataBlock {
    seg: Segment<()>,
    len: usize,
}

impl DataBlock {
    fn new(seg: Segment<()>, len: usize) -> Self {
        debug_assert!(len <= seg.size(), "block len exceeds frame capacity");
        Self { seg, len }
    }

    pub(super) fn reader_at(&self, offset: usize, len: usize) -> VmReader<'_, Infallible> {
        let mut reader = self.seg.reader();
        let start = offset.min(self.len);
        let avail = (self.len - start).min(len);
        reader.skip(start).limit(avail);
        reader
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }
}
