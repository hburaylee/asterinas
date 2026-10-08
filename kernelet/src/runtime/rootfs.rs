// SPDX-License-Identifier: MPL-2.0

//! Immutable content-addressed ext2 images built from OCI root directories.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

use crate::config::Config;

pub fn build(
    config: &mut Config,
    bundle: &Path,
    cache: &Path,
    agent: &Path,
    mke2fs: &Path,
) -> Result<Vec<PathBuf>> {
    let root = bundle
        .join(&config.root.path)
        .canonicalize()
        .context("resolve OCI rootfs")?;
    ensure!(root.is_dir(), "root.path must be a directory");
    let mut images = vec![build_image(&root, cache, Some(agent), mke2fs)?];
    let mut bind_bytes = 0;
    for mount in &mut config.mounts {
        if mount.kind != "bind" && !mount.options.iter().any(|option| option == "bind") {
            continue;
        }
        let source = bundle.join(&mount.source).canonicalize()?;
        if source.is_dir() {
            ensure!(
                mount.options.iter().any(|option| option == "ro"),
                "read-write directory bind is unsupported"
            );
            ensure!(images.len() < 26, "too many block images");
            let image = build_image(&source, cache, None, mke2fs)?;
            mount.source = format!("/dev/vd{}", (b'a' + images.len() as u8) as char);
            mount.kind = "ext2".into();
            mount.options.retain(|option| option != "bind");
            images.push(image);
        } else {
            ensure!(source.is_file(), "bind source must be a file or directory");
            bind_bytes += source.metadata()?.len();
            ensure!(
                bind_bytes <= (crate::protocol::MAX_MESSAGE_BYTES / 8) as u64,
                "bind files exceed agent message limit"
            );
            let metadata = source.metadata()?;
            mount.content_metadata = Some((metadata.mode(), metadata.uid(), metadata.gid()));
            mount.content = Some(fs::read(source)?);
        }
    }
    Ok(images)
}

fn build_image(root: &Path, cache: &Path, agent: Option<&Path>, mke2fs: &Path) -> Result<PathBuf> {
    fs::create_dir_all(cache)?;
    let mut digest = Sha256::new();
    digest.update(b"kernelet-rootfs-v2\0");
    let bytes = hash_tree(root, root, &mut digest)?;
    let root_digest = digest.clone().finalize();
    if let Some(agent) = agent {
        digest.update(b"agent\0");
        hash_file(agent, &mut digest)?;
    }
    let key = format!("{:x}", digest.finalize());
    let image = cache.join(format!("{key}.ext2"));
    if image.is_file() {
        return Ok(image);
    }
    let work = cache.join(format!(".{key}.{}", std::process::id()));
    fs::create_dir(&work)?;
    let result = (|| {
        let staging = work.join("root");
        copy_tree(root, &staging)?;
        let mut copied_digest = Sha256::new();
        copied_digest.update(b"kernelet-rootfs-v2\0");
        hash_tree(&staging, &staging, &mut copied_digest)?;
        ensure!(
            copied_digest.clone().finalize() == root_digest,
            "rootfs changed while building its image"
        );
        if let Some(agent) = agent {
            for directory in ["sbin", "run", "proc", "sys", "dev", "tmp"] {
                let destination = staging.join(directory);
                fs::create_dir_all(&destination)?;
                ensure!(
                    destination
                        .canonicalize()?
                        .starts_with(staging.canonicalize()?),
                    "rootfs directory escapes staging: {directory}"
                );
            }
            let destination = staging.join("sbin/kernelet-agent");
            if fs::symlink_metadata(&destination).is_ok() {
                fs::remove_file(&destination)?;
            }
            fs::copy(agent, &destination)?;
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o755))?;
            copied_digest.update(b"agent\0");
            hash_file(&destination, &mut copied_digest)?;
            ensure!(
                format!("{:x}", copied_digest.finalize()) == key,
                "agent changed while building rootfs"
            );
        }
        let temporary = work.join("root.ext2");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        // Metadata, inode tables, and small-file block rounding need space beyond payload bytes.
        let length = (bytes.saturating_mul(2)
            + agent
                .map(fs::metadata)
                .transpose()?
                .map_or(0, |metadata| metadata.len())
                * 2
            + 64 * 1024 * 1024)
            .next_multiple_of(4096);
        file.set_len(length)?;
        let status = Command::new(mke2fs)
            .args([
                "-q",
                "-t",
                "ext2",
                "-F",
                "-b",
                "4096",
                "-I",
                "256",
                "-O",
                "^resize_inode,^dir_index",
                "-d",
            ])
            .arg(&staging)
            .arg(&temporary)
            .status()
            .context("run bundled mke2fs")?;
        ensure!(status.success(), "mke2fs failed with {status}");
        file.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o444))?;
        fs::rename(&temporary, &image)?;
        File::open(cache)?.sync_all()?;
        Ok(image.clone())
    })();
    let cleanup = fs::remove_dir_all(&work);
    if result.is_ok() {
        cleanup?;
    }
    result
}

fn hash_tree(root: &Path, path: &Path, digest: &mut Sha256) -> Result<u64> {
    hash_tree_inner(root, path, digest, &mut BTreeMap::new())
}

fn hash_tree_inner(
    root: &Path,
    path: &Path,
    digest: &mut Sha256,
    links: &mut BTreeMap<(u64, u64), PathBuf>,
) -> Result<u64> {
    let metadata = fs::symlink_metadata(path)?;
    let relative = path.strip_prefix(root)?.as_os_str().as_bytes();
    digest.update((relative.len() as u64).to_le_bytes());
    digest.update(relative);
    for value in [metadata.mode(), metadata.uid(), metadata.gid()] {
        digest.update(value.to_le_bytes());
    }
    digest.update(metadata.mtime().to_le_bytes());
    digest.update(metadata.mtime_nsec().to_le_bytes());
    let mut attributes: Vec<_> = xattr::list(path)?.collect();
    attributes.sort();
    for name in attributes {
        let value = xattr::get(path, &name)?.context("rootfs xattr changed during hashing")?;
        digest.update((name.as_bytes().len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value);
    }
    digest.update(0u64.to_le_bytes());
    if metadata.is_symlink() {
        let target = fs::read_link(path)?;
        digest.update((target.as_os_str().as_bytes().len() as u64).to_le_bytes());
        digest.update(target.as_os_str().as_bytes());
        return Ok(0);
    }
    if metadata.is_file() {
        let first = links
            .entry((metadata.dev(), metadata.ino()))
            .or_insert_with(|| path.strip_prefix(root).unwrap().to_path_buf());
        digest.update((first.as_os_str().as_bytes().len() as u64).to_le_bytes());
        digest.update(first.as_os_str().as_bytes());
        digest.update(metadata.len().to_le_bytes());
        hash_file(path, digest)?;
        return Ok(metadata.len().max(4096));
    }
    if !metadata.is_dir() {
        ensure!(
            metadata.file_type().is_char_device()
                || metadata.file_type().is_block_device()
                || metadata.file_type().is_fifo(),
            "unsupported rootfs node {}",
            path.display()
        );
        digest.update(metadata.rdev().to_le_bytes());
        return Ok(0);
    }
    let mut entries = fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    let mut size = 4096;
    for entry in entries {
        size += hash_tree_inner(root, &entry.path(), digest, links)?;
    }
    Ok(size)
}

fn hash_file(path: &Path, digest: &mut Sha256) -> Result<()> {
    let mut file = File::open(path)?;
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    copy_tree_inner(source, destination, &mut BTreeMap::new())
}

fn copy_tree_inner(
    source: &Path,
    destination: &Path,
    links: &mut BTreeMap<(u64, u64), PathBuf>,
) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.is_symlink() {
        std::os::unix::fs::symlink(fs::read_link(source)?, destination)?;
    } else if metadata.is_dir() {
        fs::create_dir(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy_tree_inner(&entry.path(), &destination.join(entry.file_name()), links)?;
        }
    } else if metadata.is_file() {
        let key = (metadata.dev(), metadata.ino());
        if let Some(first) = links.get(&key) {
            fs::hard_link(first, destination)?;
        } else {
            fs::copy(source, destination)?;
            links.insert(key, destination.to_path_buf());
        }
    } else {
        use nix::sys::stat::{self, Mode, SFlag};
        stat::mknod(
            destination,
            SFlag::from_bits_truncate(metadata.mode()),
            Mode::from_bits_truncate(metadata.mode()),
            metadata.rdev(),
        )?;
    }
    std::os::unix::fs::lchown(destination, Some(metadata.uid()), Some(metadata.gid()))?;
    if !metadata.is_symlink() {
        fs::set_permissions(destination, fs::Permissions::from_mode(metadata.mode()))?;
    }
    for name in xattr::list(destination)? {
        xattr::remove(destination, &name)?;
    }
    for name in xattr::list(source)? {
        let value = xattr::get(source, &name)?.context("rootfs xattr changed during copy")?;
        xattr::set(destination, &name, &value)?;
    }
    nix::sys::stat::utimensat(
        None,
        destination,
        &nix::sys::time::TimeSpec::new(metadata.atime(), metadata.atime_nsec()),
        &nix::sys::time::TimeSpec::new(metadata.mtime(), metadata.mtime_nsec()),
        nix::sys::stat::UtimensatFlags::NoFollowSymlink,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires the bundled mke2fs executable"]
    fn builds_ext2_and_reuses_immutable_cache() {
        use std::io::{Read, Seek, SeekFrom};
        let tool = std::env::var_os("KERNELET_TEST_MKE2FS").expect("set KERNELET_TEST_MKE2FS");
        let directory =
            std::env::temp_dir().join(format!("kernelet-image-test-{}", std::process::id()));
        let root = directory.join("root");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("payload"), b"immutable root content").unwrap();
        let cache = directory.join("cache");
        let image = build_image(&root, &cache, None, Path::new(&tool)).unwrap();
        let modified = fs::metadata(&image).unwrap().modified().unwrap();
        let mut file = File::open(&image).unwrap();
        file.seek(SeekFrom::Start(1024 + 56)).unwrap();
        let mut magic = [0; 2];
        file.read_exact(&mut magic).unwrap();
        assert_eq!(magic, [0x53, 0xef]);
        assert_eq!(
            build_image(&root, &cache, None, Path::new(&tool)).unwrap(),
            image
        );
        assert_eq!(fs::metadata(&image).unwrap().modified().unwrap(), modified);
        fs::write(root.join("payload"), b"changed root content").unwrap();
        assert_ne!(
            build_image(&root, &cache, None, Path::new(&tool)).unwrap(),
            image
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn staging_preserves_hardlinks_metadata_and_xattrs() {
        let directory =
            std::env::temp_dir().join(format!("kernelet-copy-test-{}", std::process::id()));
        let source = directory.join("source");
        let destination = directory.join("destination");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("one"), b"content").unwrap();
        fs::hard_link(source.join("one"), source.join("two")).unwrap();
        fs::set_permissions(source.join("one"), fs::Permissions::from_mode(0o640)).unwrap();
        xattr::set(source.join("one"), "user.kernelet", b"metadata").unwrap();
        copy_tree(&source, &destination).unwrap();
        assert_eq!(
            fs::metadata(destination.join("one")).unwrap().ino(),
            fs::metadata(destination.join("two")).unwrap().ino()
        );
        assert_eq!(
            xattr::get(destination.join("two"), "user.kernelet").unwrap(),
            Some(b"metadata".to_vec())
        );
        let mut before = Sha256::new();
        hash_tree(&source, &source, &mut before).unwrap();
        let mut after = Sha256::new();
        hash_tree(&destination, &destination, &mut after).unwrap();
        assert_eq!(before.finalize(), after.finalize());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn cache_key_includes_names_and_file_contents() {
        let path = std::env::temp_dir().join(format!("kernelet-hash-test-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::write(path.join("file"), b"first").unwrap();
        let mut first = Sha256::new();
        hash_tree(&path, &path, &mut first).unwrap();
        fs::write(path.join("file"), b"other").unwrap();
        let mut second = Sha256::new();
        hash_tree(&path, &path, &mut second).unwrap();
        assert_ne!(first.finalize(), second.finalize());
        fs::remove_dir_all(path).unwrap();
    }
}
