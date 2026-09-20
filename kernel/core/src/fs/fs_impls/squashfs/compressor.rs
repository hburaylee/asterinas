// SPDX-License-Identifier: MPL-2.0

//! Compression and decompression support.
//!
//! Squashfs supports multiple compression algorithms; each data or metadata
//! block can be individually compressed or stored uncompressed.
//! Currently supported: zstd.

use ostd::mm::Infallible;
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};

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
                let mut decoder = FrameDecoder::new();
                decoder
                    .init(SegmentReader { src: &mut *src })
                    .map_err(|_| SquashFsError::DecompressError)?;

                let mut written = 0;
                // Decode and drain until the destination is full or the frame ends.
                while !decoder.is_finished() && dst.has_avail() {
                    decoder
                        .decode_blocks(
                            SegmentReader { src: &mut *src },
                            BlockDecodingStrategy::UptoBytes(dst.avail()),
                        )
                        .map_err(|_| SquashFsError::DecompressError)?;
                    written += decoder
                        .collect_to_writer(SegmentWriter { dst: &mut *dst })
                        .map_err(|_| SquashFsError::DecompressError)?;
                }

                if !decoder.is_finished() {
                    // The destination filled before the frame ended. Decode
                    // the rest without writing until one output byte is
                    // pending or the frame actually ends, to detect a block
                    // larger than expected.
                    while decoder.can_collect() == 0 && !decoder.is_finished() {
                        decoder
                            .decode_blocks(
                                SegmentReader { src: &mut *src },
                                BlockDecodingStrategy::UptoBytes(1),
                            )
                            .map_err(|_| SquashFsError::DecompressError)?;
                    }
                    if decoder.can_collect() > 0 {
                        return Err(SquashFsError::DecompressError);
                    }
                    return Ok(written);
                }

                // Frame ended: drain the final retained bytes into the destination.
                written += decoder
                    .collect_to_writer(SegmentWriter { dst: &mut *dst })
                    .map_err(|_| SquashFsError::DecompressError)?;
                Ok(written)
            }
            _ => Err(SquashFsError::UnsupportedCompression(
                self.compressor as u16,
            )),
        }
    }
}

/// Adapts a [`VmReader`] to ruzstd's `Read` trait, so a compressed stream
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

/// Adapts a [`VmWriter`] to ruzstd's `Write` trait, so decoded bytes are
/// written straight into frame-backed memory without an intermediate buffer.
struct SegmentWriter<'a, 'b> {
    dst: &'a mut VmWriter<'b, Infallible>,
}

impl ruzstd::io::Write for SegmentWriter<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> core::result::Result<usize, ruzstd::io::Error> {
        Ok(self.dst.write(&mut VmReader::from(buf)))
    }

    fn flush(&mut self) -> core::result::Result<(), ruzstd::io::Error> {
        Ok(())
    }
}
