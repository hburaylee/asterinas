// SPDX-License-Identifier: MPL-2.0

//! Immutable content-addressed ext2 images built from OCI root directories.

use std::{
    collections::BTreeMap,
    ffi::{CString, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Seek},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
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
        let node = SourceNode::open(&source)?;
        let metadata = node.file.metadata()?;
        if metadata.is_dir() {
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
            ensure!(
                metadata.is_file(),
                "bind source must be a file or directory"
            );
            bind_bytes += metadata.len();
            ensure!(
                bind_bytes <= (crate::protocol::MAX_MESSAGE_BYTES / 8) as u64,
                "bind files exceed agent message limit"
            );
            mount.content_metadata = Some((metadata.mode(), metadata.uid(), metadata.gid()));
            let mut content = Vec::new();
            let limit = crate::protocol::MAX_MESSAGE_BYTES / 8;
            File::open(node.fd_path())?
                .take((limit + 1) as u64)
                .read_to_end(&mut content)?;
            ensure!(
                content.len() as u64 == metadata.len(),
                "bind file changed while reading"
            );
            mount.content = Some(content);
        }
    }
    Ok(images)
}

fn build_image(root: &Path, cache: &Path, agent: Option<&Path>, mke2fs: &Path) -> Result<PathBuf> {
    fs::create_dir_all(cache)?;
    let mut digest = Sha256::new();
    digest.update(b"kernelet-rootfs-v2\0");
    let source = SourceNode::open(root)?;
    ensure!(
        source.file.metadata()?.is_dir(),
        "rootfs must be a directory"
    );
    let bytes = hash_tree_inner(&source, Path::new(""), &mut digest, &mut BTreeMap::new())?;
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
    fs::DirBuilder::new().mode(0o700).create(&work)?;
    let result = (|| {
        let staging = work.join("root");
        copy_tree_inner(&source, &staging, &mut BTreeMap::new())?;
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
            let sbin = staging.join("sbin").canonicalize()?;
            ensure!(
                sbin.starts_with(staging.canonicalize()?),
                "agent directory escapes staging"
            );
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(sbin)?;
            let name = c"kernelet-agent";
            // SAFETY: the directory FD and literal C string remain live for both
            // relative operations. The private work parent excludes image UIDs.
            let removed = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
            if removed < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                return Err(std::io::Error::last_os_error().into());
            }
            // SAFETY: the borrowed directory FD and C name remain live; flags
            // require a fresh regular file and reject a substituted symlink.
            let raw = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o755,
                )
            };
            ensure!(
                raw >= 0,
                "create agent relative to staging directory: {}",
                std::io::Error::last_os_error()
            );
            // SAFETY: openat returned a new owned descriptor exactly once here.
            let mut destination = unsafe { File::from_raw_fd(raw) };
            std::io::copy(&mut File::open(agent)?, &mut destination)?;
            destination.set_permissions(fs::Permissions::from_mode(0o755))?;
            destination.rewind()?;
            copied_digest.update(b"agent\0");
            hash_reader(&mut destination, &mut copied_digest)?;
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

// Bind every source component before inspecting it. O_PATH avoids opening a
// device/FIFO while discovering its type. The only followed magic links below
// name our own live descriptors, never a source-provided symlink.
struct SourceNode {
    file: Arc<File>,
    attribute_path: PathBuf,
    _parent: Option<Arc<File>>,
}

impl SourceNode {
    fn open(path: &Path) -> Result<Self> {
        use std::path::Component;
        let mut node = Self {
            file: Arc::new(
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
                    .open(if path.is_absolute() { "/" } else { "." })?,
            ),
            attribute_path: PathBuf::new(),
            _parent: None,
        };
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => node = node.child(name)?,
                _ => anyhow::bail!("source path must not contain parent traversal"),
            }
        }
        Ok(node)
    }

    fn fd_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }

    fn child(&self, name: &std::ffi::OsStr) -> Result<Self> {
        ensure!(
            !name.as_bytes().contains(&b'/') && name != "." && name != ".." && !name.is_empty(),
            "source child must be one normal path component"
        );
        let name_c = CString::new(name.as_bytes())?;
        // Share the directory capability; do not dup/close a new FD per entry.
        let parent = self.file.clone();
        let attribute_path =
            PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(name);
        // SAFETY: parent and the single-component C name remain live. O_NOFOLLOW
        // binds links themselves and never resolves a link supplied by the tree.
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: raw is a newly owned descriptor.
        Ok(Self {
            file: Arc::new(unsafe { File::from_raw_fd(raw) }),
            attribute_path,
            _parent: Some(parent),
        })
    }

    fn read_link(&self) -> Result<PathBuf> {
        let mut bytes = vec![0; 256];
        loop {
            // SAFETY: an empty name reads the symlink bound by this O_PATH FD.
            // Both Linux and the Host readlinkat support this empty-path form.
            let len = unsafe {
                libc::readlinkat(
                    self.file.as_raw_fd(),
                    c"".as_ptr(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            };
            if len < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if (len as usize) < bytes.len() {
                bytes.truncate(len as usize);
                return Ok(PathBuf::from(OsString::from_vec(bytes)));
            }
            ensure!(bytes.len() < 1024 * 1024, "source symlink exceeds bound");
            bytes.resize(bytes.len() * 2, 0);
        }
    }

    fn attributes(&self, symlink: bool) -> Result<Vec<(OsString, Vec<u8>)>> {
        let mut names: Vec<_> = if symlink {
            // l*xattr never follows the final component, even if it is replaced.
            xattr::list(&self.attribute_path)?.collect()
        } else {
            xattr::list_deref(self.fd_path())?.collect()
        };
        names.sort();
        names
            .into_iter()
            .map(|name| {
                let value = if symlink {
                    xattr::get(&self.attribute_path, &name)?
                } else {
                    xattr::get_deref(self.fd_path(), &name)?
                };
                Ok((
                    name,
                    value.context("rootfs xattr changed during traversal")?,
                ))
            })
            .collect()
    }
}

fn hash_tree(root: &Path, path: &Path, digest: &mut Sha256) -> Result<u64> {
    hash_tree_inner(
        &SourceNode::open(path)?,
        path.strip_prefix(root)?,
        digest,
        &mut BTreeMap::new(),
    )
}

fn hash_tree_inner(
    node: &SourceNode,
    relative_path: &Path,
    digest: &mut Sha256,
    links: &mut BTreeMap<(u64, u64), PathBuf>,
) -> Result<u64> {
    let metadata = node.file.metadata()?;
    let relative = relative_path.as_os_str().as_bytes();
    digest.update((relative.len() as u64).to_le_bytes());
    digest.update(relative);
    for value in [metadata.mode(), metadata.uid(), metadata.gid()] {
        digest.update(value.to_le_bytes());
    }
    digest.update(metadata.mtime().to_le_bytes());
    digest.update(metadata.mtime_nsec().to_le_bytes());
    for (name, value) in node.attributes(metadata.is_symlink())? {
        digest.update((name.as_bytes().len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value);
    }
    digest.update(0u64.to_le_bytes());
    if metadata.is_symlink() {
        let target = node.read_link()?;
        digest.update((target.as_os_str().as_bytes().len() as u64).to_le_bytes());
        digest.update(target.as_os_str().as_bytes());
        return Ok(0);
    }
    if metadata.is_file() {
        let first = links
            .entry((metadata.dev(), metadata.ino()))
            .or_insert_with(|| relative_path.to_path_buf());
        digest.update((first.as_os_str().as_bytes().len() as u64).to_le_bytes());
        digest.update(first.as_os_str().as_bytes());
        digest.update(metadata.len().to_le_bytes());
        hash_reader(&mut File::open(node.fd_path())?, digest)?;
        return Ok(metadata.len().max(4096));
    }
    if !metadata.is_dir() {
        ensure!(
            metadata.file_type().is_char_device()
                || metadata.file_type().is_block_device()
                || metadata.file_type().is_fifo(),
            "unsupported rootfs node {}",
            relative_path.display()
        );
        digest.update(metadata.rdev().to_le_bytes());
        return Ok(0);
    }
    let mut entries = fs::read_dir(node.fd_path())?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    let mut size = 4096;
    for entry in entries {
        size += hash_tree_inner(
            &node.child(&entry.file_name())?,
            &relative_path.join(entry.file_name()),
            digest,
            links,
        )?;
    }
    Ok(size)
}

fn hash_file(path: &Path, digest: &mut Sha256) -> Result<()> {
    hash_reader(&mut File::open(path)?, digest)
}

fn hash_reader(file: &mut File, digest: &mut Sha256) -> Result<()> {
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

#[cfg(test)]
fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    copy_tree_inner(
        &SourceNode::open(source)?,
        destination,
        &mut BTreeMap::new(),
    )
}

fn copy_tree_inner(
    source: &SourceNode,
    destination: &Path,
    links: &mut BTreeMap<(u64, u64), PathBuf>,
) -> Result<()> {
    let metadata = source.file.metadata()?;
    if metadata.is_symlink() {
        std::os::unix::fs::symlink(source.read_link()?, destination)?;
    } else if metadata.is_dir() {
        fs::create_dir(destination)?;
        for entry in fs::read_dir(source.fd_path())? {
            let entry = entry?;
            copy_tree_inner(
                &source.child(&entry.file_name())?,
                &destination.join(entry.file_name()),
                links,
            )?;
        }
    } else if metadata.is_file() {
        let key = (metadata.dev(), metadata.ino());
        if let Some(first) = links.get(&key) {
            fs::hard_link(first, destination)?;
        } else {
            let mut input = File::open(source.fd_path())?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)?;
            std::io::copy(&mut input, &mut output)?;
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
    for (name, value) in source.attributes(metadata.is_symlink())? {
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
    #[ignore = "requires mke2fs; validates private staging and no-follow agent injection"]
    fn agent_injection_does_not_follow_an_existing_destination_symlink() {
        let actual = std::env::var_os("KERNELET_TEST_MKE2FS").expect("set KERNELET_TEST_MKE2FS");
        let directory =
            std::env::temp_dir().join(format!("kernelet-agent-injection-{}", std::process::id()));
        let root = directory.join("root");
        fs::create_dir_all(root.join("sbin")).unwrap();
        let outside = directory.join("outside");
        fs::write(&outside, b"must survive").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("sbin/kernelet-agent")).unwrap();
        let agent = directory.join("agent");
        fs::write(&agent, b"replacement agent").unwrap();
        let wrapper = directory.join("mke2fs");
        // The real image builder invokes this guard after copying OCI metadata.
        // It checks the work parent, then delegates to the actual ext2 tool.
        fs::write(&wrapper, b"#!/bin/sh\nstage=\nprevious=\nfor value do\n  if [ \"$previous\" = -d ]; then stage=$value; fi\n  previous=$value\ndone\n[ \"$(stat -c %a \"$(dirname \"$stage\")\")\" = 700 ] || exit 77\nexec \"$KERNELET_TEST_MKE2FS\" \"$@\"\n").unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
        let image = build_image(&root, &directory.join("cache"), Some(&agent), &wrapper).unwrap();
        assert!(image.is_file());
        assert_eq!(fs::read(&outside).unwrap(), b"must survive");
        assert!(fs::metadata(image).unwrap().len() > 0);
        assert!(Path::new(&actual).is_file());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn source_descriptor_survives_path_and_symlink_substitution() {
        let directory =
            std::env::temp_dir().join(format!("kernelet-source-fd-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let source = directory.join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("payload"), b"original").unwrap();
        let root = SourceNode::open(&source).unwrap();
        assert!(root.child(std::ffi::OsStr::new("../outside")).is_err());
        let payload = root.child(std::ffi::OsStr::new("payload")).unwrap();
        fs::rename(&source, directory.join("moved")).unwrap();
        std::os::unix::fs::symlink("/etc", &source).unwrap();
        fs::remove_file(directory.join("moved/payload")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", directory.join("moved/payload")).unwrap();
        let mut data = Vec::new();
        File::open(payload.fd_path())
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
        assert_eq!(data, b"original");
        let link = root.child(std::ffi::OsStr::new("payload")).unwrap();
        assert!(link.file.metadata().unwrap().is_symlink());
        assert_eq!(link.read_link().unwrap(), Path::new("/etc/passwd"));
        assert!(SourceNode::open(&source.join("passwd")).is_err());
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
