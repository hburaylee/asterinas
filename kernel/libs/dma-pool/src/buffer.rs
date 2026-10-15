// SPDX-License-Identifier: MPL-2.0

#[cfg(feature = "kernelet-host")]
use alloc::sync::Arc;
use core::ops::Range;

use ostd::{
    Result,
    mm::{
        Daddr, HasDaddr, HasSize, Infallible, VmReader, VmWriter,
        dma::{DmaDirection, DmaStream},
        io::util::{HasVmReaderWriter, VmReaderWriterResult},
    },
};

use crate::{DmaArena, DmaSegment};

/// A DMA buffer, which is either directly allocated/mapped or comes from a pool.
#[derive(Debug)]
pub enum DmaBuffer<D: DmaDirection> {
    /// A DMA buffer that is directly allocated/mapped.
    Direct(DmaStream<D>),
    /// A shared owning buffer used by Host BIO views.
    #[cfg(feature = "kernelet-host")]
    Shared(Arc<DmaBuffer<D>>),
    /// A DMA buffer that comes from a pool.
    Pooled(DmaSegment<D>),
    /// A large DMA buffer allocated from a shared arena.
    Arena(DmaArena<D>),
}

impl<D: DmaDirection> DmaBuffer<D> {
    /// Clones the owner of a buffer created for shared Host BIO views.
    #[cfg(feature = "kernelet-host")]
    pub fn clone_shared(&self) -> Self {
        match self {
            Self::Shared(owner) => Self::Shared(owner.clone()),
            _ => panic!("BIO view requires a shared owning buffer"),
        }
    }

    /// Synchronizes the streaming DMA mapping data from the device.
    pub fn sync_from_device(&self, byte_range: Range<usize>) -> Result<()> {
        match self {
            Self::Direct(stream) => stream.sync_from_device(byte_range),
            #[cfg(feature = "kernelet-host")]
            Self::Shared(owner) => owner.sync_from_device(byte_range),
            Self::Pooled(segment) => segment.sync_from_device(byte_range),
            Self::Arena(arena) => arena.sync_from_device(byte_range),
        }
    }

    /// Synchronizes the streaming DMA mapping data to the device.
    pub fn sync_to_device(&self, byte_range: Range<usize>) -> Result<()> {
        match self {
            Self::Direct(stream) => stream.sync_to_device(byte_range),
            #[cfg(feature = "kernelet-host")]
            Self::Shared(owner) => owner.sync_to_device(byte_range),
            Self::Pooled(segment) => segment.sync_to_device(byte_range),
            Self::Arena(arena) => arena.sync_to_device(byte_range),
        }
    }
}

impl<D: DmaDirection> HasDaddr for DmaBuffer<D> {
    fn daddr(&self) -> Daddr {
        match self {
            Self::Direct(stream) => stream.daddr(),
            #[cfg(feature = "kernelet-host")]
            Self::Shared(owner) => owner.daddr(),
            Self::Pooled(segment) => segment.daddr(),
            Self::Arena(arena) => arena.daddr(),
        }
    }
}

impl<D: DmaDirection> HasSize for DmaBuffer<D> {
    fn size(&self) -> usize {
        match self {
            Self::Direct(stream) => stream.size(),
            #[cfg(feature = "kernelet-host")]
            Self::Shared(owner) => owner.size(),
            Self::Pooled(segment) => segment.size(),
            Self::Arena(arena) => arena.size(),
        }
    }
}

impl<D: DmaDirection> HasVmReaderWriter for DmaBuffer<D> {
    type Types = VmReaderWriterResult;

    fn reader(&self) -> Result<VmReader<'_, Infallible>> {
        match self {
            Self::Direct(stream) => stream.reader(),
            #[cfg(feature = "kernelet-host")]
            Self::Shared(owner) => owner.reader(),
            Self::Pooled(segment) => segment.reader(),
            Self::Arena(arena) => arena.reader(),
        }
    }

    fn writer(&self) -> Result<VmWriter<'_, Infallible>> {
        match self {
            Self::Direct(stream) => stream.writer(),
            #[cfg(feature = "kernelet-host")]
            Self::Shared(owner) => owner.writer(),
            Self::Pooled(segment) => segment.writer(),
            Self::Arena(arena) => arena.writer(),
        }
    }
}
