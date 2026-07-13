// SPDX-License-Identifier: MPL-2.0

//! Compression and decompression support.
//!
//! Squashfs supports multiple compression algorithms; each data or metadata
//! block can be individually compressed or stored uncompressed.
//! Currently supported: zstd.

use ostd::mm::Infallible;
use ruzstd::{decoding::StreamingDecoder, io::Read as _};

use super::SquashFsError;
use crate::prelude::*;

/// Compression algorithms defined by the Squashfs format.
///
/// Reference:
/// <https://dr-emann.github.io/squashfs/squashfs.html#_the_superblock>
/// <https://elixir.bootlin.com/linux/v7.0/source/fs/squashfs/squashfs_fs.h#L231>
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Compressor {
    Gzip = 1,
    Lzma = 2,
    Lzo = 3,
    Xz = 4,
    Lz4 = 5,
    Zstd = 6,
}

impl TryFrom<u16> for Compressor {
    type Error = SquashFsError;

    fn try_from(v: u16) -> Result<Self, SquashFsError> {
        match v {
            1 => Ok(Self::Gzip),
            2 => Ok(Self::Lzma),
            3 => Ok(Self::Lzo),
            4 => Ok(Self::Xz),
            5 => Ok(Self::Lz4),
            6 => Ok(Self::Zstd),
            _ => Err(SquashFsError::UnsupportedCompression(v)),
        }
    }
}

/// Context for decompressing blocks.
#[derive(Debug, Clone, Copy)]
pub(super) struct DecompressContext {
    compressor: Compressor,
}

impl DecompressContext {
    pub(super) fn new(compressor: Compressor) -> Self {
        Self { compressor }
    }

    /// Decompresses the stream drained from `src` directly into `dst`,
    /// returning the number of bytes written.
    ///
    /// The output is bounded by the writer's available space: a stream longer
    /// than that space is rejected as corrupt.
    pub(super) fn decompress_stream(
        &self,
        src: &mut VmReader<'_, Infallible>,
        dst: &mut VmWriter<'_, Infallible>,
    ) -> Result<usize, SquashFsError> {
        match self.compressor {
            Compressor::Zstd => {
                let mut decoder = StreamingDecoder::new(SegmentReader { src })
                    .map_err(|_| SquashFsError::DecompressError)?;
                let mut scratch = [0u8; 4096];
                let mut written = 0;
                while dst.has_avail() {
                    let want = scratch.len().min(dst.avail());
                    let n = decoder
                        .read(&mut scratch[..want])
                        .map_err(|_| SquashFsError::DecompressError)?;
                    if n == 0 {
                        return Ok(written);
                    }
                    dst.write(&mut VmReader::from(&scratch[..n]));
                    written += n;
                }
                // The writer is full: confirm the stream produced no extra
                // bytes, otherwise the block is larger than expected.
                let mut probe = [0u8; 1];
                let n = decoder
                    .read(&mut probe)
                    .map_err(|_| SquashFsError::DecompressError)?;
                if n != 0 {
                    return Err(SquashFsError::DecompressError);
                }
                Ok(written)
            }
            _ => Err(SquashFsError::UnsupportedCompression(
                self.compressor as u16,
            )),
        }
    }
}

/// Adapts a [`VmReader`] to ruzstd's [`Read`] trait, so a compressed stream
/// held in frames can be decoded without copying it into a contiguous heap
/// buffer.
struct SegmentReader<'a, 'b> {
    src: &'a mut VmReader<'b, Infallible>,
}

impl ruzstd::io::Read for SegmentReader<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> core::result::Result<usize, ruzstd::io::Error> {
        Ok(self.src.read(&mut VmWriter::from(buf)))
    }
}
