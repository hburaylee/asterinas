// SPDX-License-Identifier: MPL-2.0

//! Boot initramfs unpacking and init selection.
//!
//! This module unpacks the boot initramfs into the bootstrap VFS root and selects the initramfs
//! init from the `rdinit` parameter or the default `/init` path.

// Set this module's log prefix for `ostd::log`.
macro_rules! __log_prefix {
    () => {
        "initramfs: "
    };
}

use alloc::{
    borrow::ToOwned,
    io::{self, Cursor, Read},
};

use cpio_decoder::{CpioDecoder, CpioEntry, FileMetadata, FileType};
use device_id::{DeviceId, MajorId, MinorId};
use lending_iterator::LendingIterator;
use miniz_oxide::{
    DataFormat, MZError, MZFlush, MZStatus,
    inflate::stream::{InflateState, inflate},
};
use ostd::boot::boot_info;
use spin::once::Once;

use super::{
    file::{InodeMode, InodeType, mkmod},
    vfs::path::{FsPath, Path, PathResolver, is_dot},
};
use crate::{
    device::tty,
    fs::{
        file::StatusFlags,
        vfs::inode::{Inode, MknodType},
    },
    prelude::*,
};

/// Unpacks the boot initramfs into the bootstrap root filesystem.
///
/// Returns successfully without changing the filesystem when no initramfs was supplied.
pub(crate) fn init_in_first_kthread(path_resolver: &PathResolver) -> Result<()> {
    let Some(initramfs_buf) = boot_info().initramfs else {
        return Ok(());
    };

    match &initramfs_buf[..4] {
        // Gzip magic number: 0x1F 0x8B
        &[0x1F, 0x8B, _, _] => {
            println!("[kernel] unpacking initramfs.cpio.gz to rootfs ...");
            unpack_to_rootfs(
                CpioDecoder::new(
                    GzipReader::new(Cursor::new(initramfs_buf))
                        .map_err(cpio_decoder::error::Error::from)?,
                ),
                path_resolver,
            )?;
        }
        _ => {
            println!("[kernel] unpacking initramfs.cpio to rootfs ...");
            unpack_to_rootfs(CpioDecoder::new(Cursor::new(initramfs_buf)), path_resolver)?;
        }
    };

    ensure_dev_console(path_resolver)?;

    println!("[kernel] initramfs is ready");
    Ok(())
}

/// Unpacks every entry of a CPIO archive into the rootfs.
fn unpack_to_rootfs<R: Read>(
    mut decoder: CpioDecoder<R>,
    path_resolver: &PathResolver,
) -> Result<()> {
    while let Some(entry_result) = decoder.next() {
        let mut entry = entry_result?;
        if let Err(e) = try_append_entry_to_rootfs(&mut entry, path_resolver) {
            warn!("failed to add entry {} to rootfs: {:?}", entry.name(), e);
        }
    }
    Ok(())
}

fn ensure_dev_console(path_resolver: &PathResolver) -> Result<()> {
    // Linux's default built-in initramfs provides /dev and /dev/console so
    // early userspace can open the console even if the external initramfs does
    // not carry this node. Asterinas provides the same default entries after
    // unpacking the supplied initramfs.
    // Reference: <https://elixir.bootlin.com/linux/v6.13/source/usr/default_cpio_list>.
    let dev_path = super::lookup_or_create_dev(path_resolver)?;
    match path_resolver.lookup(&FsPath::try_from("/dev/console")?) {
        Ok(_) => Ok(()),
        Err(error) if error.error() == Errno::ENOENT => {
            dev_path.mknod(
                "console",
                mkmod!(u+rw),
                MknodType::CharDevice(tty::CONSOLE_DEVICE_ID.as_encoded_u64()),
            )?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Finds the init program to run from the initramfs.
///
/// Resolves the path specified by `rdinit`, or `/init` when `rdinit` is not provided, and returns
/// the resolved path together with the original pathname. Returns an error if the pathname is
/// invalid or cannot be resolved.
pub(crate) fn find_init(path_resolver: &PathResolver) -> Result<(Path, &'static str)> {
    const DEFAULT_INITRAMFS_INIT_PATH: &str = "/init";

    let init_path = RDINIT_PATH
        .get()
        .map(String::as_str)
        .unwrap_or(DEFAULT_INITRAMFS_INIT_PATH);
    let path = path_resolver.lookup(&FsPath::try_from(init_path)?)?;
    Ok((path, init_path))
}

fn try_append_entry_to_rootfs<R: Read>(
    entry: &mut CpioEntry<R>,
    path_resolver: &PathResolver,
) -> Result<()> {
    // Make sure the name is a relative path, and is not end with "/".
    let entry_name = entry.name().trim_start_matches('/').trim_end_matches('/');
    if entry_name.is_empty() {
        return_errno_with_message!(Errno::EINVAL, "invalid entry name");
    }
    if is_dot(entry_name) {
        return Ok(());
    }

    // Here we assume that the directory referred by "prefix" must has been created.
    // The basis of this assumption is：
    // The mkinitramfs script uses `find` command to ensure that the entries are
    // sorted that a directory always appears before its child directories and files.
    let (parent, name) = if let Some((prefix, last)) = entry_name.rsplit_once('/') {
        (path_resolver.lookup(&FsPath::try_from(prefix)?)?, last)
    } else {
        (path_resolver.root().clone(), entry_name)
    };

    let metadata = entry.metadata();
    let mode = InodeMode::from_bits_truncate(metadata.permission_mode());
    match metadata.file_type() {
        FileType::File => {
            let path = parent.new_child(name, InodeType::File, mode)?;
            let writer = InodeWriter {
                inner: path.inode().as_ref(),
                offset: 0,
            };
            entry.read_all(writer)?;
        }
        FileType::Dir => {
            let _ = parent.new_child(name, InodeType::Dir, mode)?;
        }
        FileType::Link => {
            // Obtain the owned name here. Otherwise, the later mutable borrow of `entry`
            // will conflict with the immutable borrow of `name` here.
            let child_name = name.to_owned();

            let mut link_data: Vec<u8> = Vec::new();
            entry.read_all(&mut link_data)?;
            let link_content = core::str::from_utf8(&link_data)?;

            parent.new_symlink_child(&child_name, link_content, mode)?;
        }
        FileType::Char => {
            let device_id = try_device_id_from_metadata(metadata)?;
            parent.mknod(name, mode, MknodType::CharDevice(device_id))?;
        }
        FileType::Block => {
            let device_id = try_device_id_from_metadata(metadata)?;
            parent.mknod(name, mode, MknodType::BlockDevice(device_id))?;
        }
        FileType::FiFo => {
            parent.mknod(name, mode, MknodType::NamedPipe)?;
        }
        FileType::Socket => {
            return_errno_with_message!(Errno::EINVAL, "socket files are not supported in initramfs")
        }
    }

    Ok(())
}

/// A streaming gzip decompressor over a [`Read`] source.
struct GzipReader<R> {
    inner: R,
    /// DEFLATE bytes read from `inner` but not yet consumed by `inflate`.
    input: Vec<u8>,
    state: Box<InflateState>,
    done: bool,
}

impl<R: Read> GzipReader<R> {
    /// Creates a decompressor, parsing and skipping the gzip header.
    fn new(mut inner: R) -> io::Result<Self> {
        let mut header = [0u8; 10];
        inner.read_exact(&mut header)?;

        if header[0] != 0x1F || header[1] != 0x8B || header[2] != 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid gzip header",
            ));
        }

        let flg = header[3];
        if flg & FLG_FEXTRA != 0 {
            let mut xlen_buf = [0u8; 2];
            inner.read_exact(&mut xlen_buf)?;
            let xlen = u16::from_le_bytes(xlen_buf) as usize;
            skip_exact(&mut inner, xlen)?;
        }
        if flg & FLG_FNAME != 0 {
            read_until_nul(&mut inner)?;
        }
        if flg & FLG_FCOMMENT != 0 {
            read_until_nul(&mut inner)?;
        }
        if flg & FLG_FHCRC != 0 {
            let mut crc_buf = [0u8; 2];
            inner.read_exact(&mut crc_buf)?;
        }

        Ok(Self {
            inner,
            input: Vec::new(),
            state: InflateState::new_boxed(DataFormat::Raw),
            done: false,
        })
    }
}

impl<R: Read> Read for GzipReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        while !self.done {
            if self.input.is_empty() {
                let mut chunk = [0u8; 4096];
                let n = self.inner.read(&mut chunk)?;
                if n == 0 {
                    break;
                }
                self.input.extend_from_slice(&chunk[..n]);
            }

            let result = inflate(&mut self.state, &self.input, out, MZFlush::None);
            self.input.drain(..result.bytes_consumed);

            match result.status {
                Ok(MZStatus::StreamEnd) => {
                    self.done = true;
                    if result.bytes_written > 0 {
                        return Ok(result.bytes_written);
                    }
                    break;
                }
                Ok(_) => {
                    if result.bytes_written > 0 {
                        return Ok(result.bytes_written);
                    }
                    if result.bytes_consumed == 0 {
                        if self.input.is_empty() {
                            continue;
                        }
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "gzip decompression failed",
                        ));
                    }
                }
                Err(MZError::Buf) => {
                    if result.bytes_written > 0 {
                        return Ok(result.bytes_written);
                    }
                    if self.input.is_empty() {
                        continue;
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "gzip decompression failed",
                    ));
                }
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "gzip decompression failed",
                    ));
                }
            }
        }

        Ok(0)
    }
}

// The gzip header flag bits.
// Reference: <https://datatracker.ietf.org/doc/html/rfc1952>.
const FLG_FHCRC: u8 = 0x02;
const FLG_FEXTRA: u8 = 0x04;
const FLG_FNAME: u8 = 0x08;
const FLG_FCOMMENT: u8 = 0x10;

/// Skips `n` bytes from `reader`.
fn skip_exact<R: Read>(reader: &mut R, mut n: usize) -> io::Result<()> {
    let mut buf = [0u8; 128];
    while n > 0 {
        let chunk = n.min(buf.len());
        reader.read_exact(&mut buf[..chunk])?;
        n -= chunk;
    }
    Ok(())
}

/// Reads from `reader` until a NUL byte, discarding the data.
fn read_until_nul<R: Read>(reader: &mut R) -> io::Result<()> {
    let mut byte = [0u8; 1];
    loop {
        reader.read_exact(&mut byte)?;
        if byte[0] == 0 {
            return Ok(());
        }
    }
}

struct InodeWriter<'a> {
    inner: &'a dyn Inode,
    offset: usize,
}

impl io::Write for InodeWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut reader = VmReader::from(buf).to_fallible();
        let write_len = self
            .inner
            .write_at(self.offset, &mut reader, StatusFlags::empty())
            .map_err(|_| io::ErrorKind::WriteZero)?;
        self.offset += write_len;
        Ok(write_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn try_device_id_from_metadata(metadata: &FileMetadata) -> Result<u64> {
    let major = {
        let dev_maj = u16::try_from(metadata.rdev_maj())?;
        MajorId::try_from(dev_maj).map_err(|msg| Error::with_message(Errno::EINVAL, msg))?
    };
    let minor = MinorId::try_from(metadata.rdev_min())
        .map_err(|msg| Error::with_message(Errno::EINVAL, msg))?;
    Ok(DeviceId::new(major, minor).as_encoded_u64())
}

static RDINIT_PATH: Once<String> = Once::new();
aster_cmdline::define_kv_param!("rdinit", RDINIT_PATH);
