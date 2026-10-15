// SPDX-License-Identifier: MPL-2.0

use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use linux_bzimage_builder::{
    BzImageType, PayloadEncoding, encode_kernel, legacy32_rust_target_json, make_bzimage,
};

use crate::{
    arch::Arch,
    bundle::{
        bin::{AsterBin, AsterBinType, AsterBzImageMeta},
        file::BundleFile,
    },
    util::{get_current_crates, new_command_checked_exists},
};

pub fn make_install_bzimage(
    install_dir: impl AsRef<Path>,
    target_dir: impl AsRef<Path>,
    aster_elf: &AsterBin,
    linux_x86_legacy_boot: bool,
    encoding: PayloadEncoding,
) -> AsterBin {
    let target_name = get_current_crates().remove(0).name;
    let image_type = if linux_x86_legacy_boot {
        BzImageType::Legacy32
    } else {
        BzImageType::Efi64
    };
    let setup_bin = {
        let setup_install_dir = target_dir.as_ref();
        let setup_target_dir = &target_dir.as_ref().join("linux-bzimage-setup");
        match image_type {
            BzImageType::Legacy32 => {
                let target_json = legacy32_rust_target_json();
                let gen_target_json_path = target_dir.as_ref().join("x86_64-i386_pm-none.json");
                std::fs::write(&gen_target_json_path, target_json).unwrap();
                let arch = gen_target_json_path.canonicalize().unwrap();
                install_setup_with_arch(
                    setup_install_dir,
                    setup_target_dir,
                    arch.to_str().unwrap(),
                    aster_elf,
                    encoding,
                );
            }
            BzImageType::Efi64 => {
                install_setup_with_arch(
                    setup_install_dir,
                    setup_target_dir,
                    "x86_64-unknown-none",
                    aster_elf,
                    encoding,
                );
            }
        };
        setup_install_dir.join("bin").join("linux-bzimage-setup")
    };
    // Make the `bzImage`-compatible kernel image and place it in the boot directory.
    let install_path = install_dir.as_ref().join(target_name);
    info!("Building bzImage");
    println!("install_path: {:?}", install_path);
    make_bzimage(&install_path, image_type, &setup_bin);

    AsterBin::new(
        &install_path,
        aster_elf.arch(),
        AsterBinType::BzImage(AsterBzImageMeta {
            support_legacy32_boot: linux_x86_legacy_boot,
            support_efi_boot: false,
            support_efi_handover: !linux_x86_legacy_boot,
        }),
        aster_elf.version().clone(),
        aster_elf.stripped(),
    )
}

pub fn make_stripped_boot_elf(
    install_dir: impl AsRef<Path>,
    elf: &AsterBin,
    strip: bool,
) -> AsterBin {
    let result_elf_path = {
        let elf_name = elf
            .path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        install_dir.as_ref().join(elf_name + ".elf")
    };

    // An older boot copy may still share its inode with Cargo's ELF. Remove
    // that directory entry before either copying or stripping into this path.
    match std::fs::remove_file(&result_elf_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("Cannot replace boot ELF: {error}"),
    }
    if strip {
        // We use rust-strip to reduce the kernel image size.
        let status = new_command_checked_exists("rust-strip")
            .arg(elf.path())
            .arg("-o")
            .arg(result_elf_path.as_os_str())
            .status();

        match status {
            Ok(status) => {
                if !status.success() {
                    panic!("Failed to strip kernel ELF");
                }
            }
            Err(err) => match err.kind() {
                std::io::ErrorKind::NotFound => panic!(
                    "`rust-strip` command not found. Please
                    try `cargo install cargo-binutils` and then rerun."
                ),
                _ => panic!("Strip kernel ELF failed, error: {:#?}", err),
            },
        }
    } else {
        // QEMU's ELF header patch must never modify Cargo's original inode.
        std::fs::copy(elf.path(), &result_elf_path).unwrap();
    }

    AsterBin::new(
        &result_elf_path,
        elf.arch(),
        elf.typ().clone(),
        elf.version().clone(),
        strip,
    )
}

pub fn make_elf_for_qemu(elf: AsterBin) -> AsterBin {
    if elf.arch() == Arch::X86_64 {
        // Because QEMU denies a x86_64 multiboot ELF file (GRUB2 accept it, btw),
        // modify `em_machine` to pretend to be an x86 (32-bit) ELF image,
        //
        // https://github.com/qemu/qemu/blob/950c4e6c94b15cd0d8b63891dddd7a8dbf458e6a/hw/i386/multiboot.c#L197
        // Set EM_386 (0x0003) to em_machine.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(elf.path())
            .unwrap();

        let bytes: [u8; 2] = [0x03, 0x00];

        file.seek(SeekFrom::Start(18)).unwrap();
        file.write_all(&bytes).unwrap();
        file.flush().unwrap();
    }

    elf
}

pub fn make_aarch64_image(install_path: impl AsRef<Path>, aster_elf: &AsterBin) -> AsterBin {
    let result_elf_path = {
        let full_elf_name = aster_elf.path().file_name().unwrap().to_str().unwrap();
        let elf_name = full_elf_name
            .strip_suffix(".qemu_elf")
            .unwrap_or(full_elf_name);
        install_path
            .as_ref()
            .join(elf_name.to_string() + ".qemu_bin")
    };

    // QEMU treats ELF kernels as non-Linux [1], where the initrd will not be loaded [2] and the
    // device tree address will not be passed [3]. Therefore, we remove the ELF information and use
    // the Linux AArch64 boot protocol [4] to boot the raw image instead.
    //
    // [1]: https://github.com/qemu/qemu/blob/499039798cdad7d86b787fec0eaf1da4151c0f05/hw/arm/boot.c#L920
    // [2]: https://github.com/qemu/qemu/blob/499039798cdad7d86b787fec0eaf1da4151c0f05/hw/arm/boot.c#L1010
    // [3]: https://github.com/qemu/qemu/blob/499039798cdad7d86b787fec0eaf1da4151c0f05/hw/arm/boot.c#L1091
    // [4]: https://docs.kernel.org/arch/arm64/booting.html
    let status = new_command_checked_exists("rust-objcopy")
        .arg("-O")
        .arg("binary")
        .arg(aster_elf.path())
        .arg(result_elf_path.as_os_str())
        .status();

    match status {
        Ok(status) => {
            if !status.success() {
                panic!("Failed to generate AArch64 Image");
            }
        }
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => panic!(
                "`rust-objcopy` command not found. Please
                    try `cargo install cargo-binutils` and then rerun."
            ),
            _ => panic!("Generate AArch64 Image failed, error: {:#?}", err),
        },
    }

    AsterBin::new(
        &result_elf_path,
        aster_elf.arch(),
        aster_elf.typ().clone(),
        aster_elf.version().clone(),
        aster_elf.stripped(),
    )
}

fn install_setup_with_arch(
    install_dir: impl AsRef<Path>,
    target_dir: impl AsRef<Path>,
    arch: &str,
    aster_elf: &AsterBin,
    encoding: PayloadEncoding,
) {
    if !target_dir.as_ref().exists() {
        std::fs::create_dir_all(&target_dir).unwrap();
    }
    let target_dir = std::fs::canonicalize(target_dir).unwrap();

    let mut cmd = new_command_checked_exists("cargo");
    let rustflags = [
        "-Cdebuginfo=2",
        "-Ccode-model=kernel",
        "-Crelocation-model=pie",
        "-Zplt=yes",
        "-Zrelax-elf-relocations=yes",
        "-Crelro-level=full",
        "-Ctarget-feature=+crt-static",
    ];
    cmd.env("RUSTFLAGS", rustflags.join(" "));
    cmd.env("PAYLOAD_FILE", encode_kernel_to_file(aster_elf, encoding));
    cmd.arg("install").arg("linux-bzimage-setup");
    cmd.arg("--force");
    cmd.arg("--root").arg(install_dir.as_ref());
    if matches!(option_env!("OSDK_LOCAL_DEV"), Some("1")) {
        let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let setup_dir = crate_dir.join("../ostd/libs/linux-bzimage/setup");
        cmd.arg("--path").arg(setup_dir);
    } else {
        cmd.arg("--version").arg(env!("CARGO_PKG_VERSION"));
    }
    cmd.arg("--target").arg(arch);
    // Custom json target requires this cargo flag.
    // See https://doc.rust-lang.org/cargo/reference/unstable.html#target-spec-json
    if arch.ends_with(".json") {
        cmd.arg("-Zjson-target-spec");
    }
    cmd.arg("-Zbuild-std=core,alloc,compiler_builtins");
    cmd.arg("-Zbuild-std-features=compiler-builtins-mem");
    // Specify the build target directory to avoid cargo running
    // into a deadlock reading the workspace files.
    cmd.arg("--target-dir").arg(target_dir.as_os_str());

    let status = cmd.status().unwrap();
    if !status.success() {
        panic!(
            "Failed to build linux x86 setup header:\n\tcommand `{:?}`\n\treturned {}",
            cmd, status
        );
    }
}

fn encode_kernel_to_file(aster_elf: &AsterBin, encoding: PayloadEncoding) -> PathBuf {
    let kernel_path = aster_elf.path();
    let encoded_path = {
        let mut filename = kernel_path.file_name().unwrap().to_os_string();
        filename.push(".compressed");
        kernel_path.with_file_name(filename)
    };

    let mut kernel = Vec::new();
    File::open(kernel_path)
        .unwrap()
        .read_to_end(&mut kernel)
        .unwrap();

    let encoded = encode_kernel(kernel, encoding);
    File::create(&encoded_path)
        .unwrap()
        .write_all(&encoded)
        .unwrap();

    encoded_path
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use super::*;
    use crate::bundle::bin::AsterElfMeta;

    #[test]
    fn repeated_unstripped_qemu_copies_preserve_the_cargo_elf() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("kernel");
        let mut bytes = vec![0; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        let elf = AsterBin::new(
            &path,
            Arch::X86_64,
            AsterBinType::Elf(AsterElfMeta {
                has_linux_header: false,
                has_pvh_header: false,
                has_multiboot_header: true,
                has_multiboot2_header: false,
            }),
            "test".into(),
            false,
        );
        // Also cover replacing a stale hard link produced by the old code.
        std::fs::hard_link(&path, directory.path().join("kernel.qemu_elf")).unwrap();
        for _ in 0..2 {
            let boot = make_stripped_boot_elf(directory.path(), &elf, false);
            assert_ne!(
                path.metadata().unwrap().ino(),
                boot.path().metadata().unwrap().ino()
            );
            let boot = make_elf_for_qemu(boot);
            assert_eq!(
                &std::fs::read(boot.path()).unwrap()[18..20],
                &3u16.to_le_bytes()
            );
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
    }

    #[test]
    fn selected_action_encodings_produce_distinct_linux_payloads() {
        use crate::config::{
            Config,
            scheme::{Action, Build},
        };
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("kernel");
        std::fs::write(&path, b"kernel payload").unwrap();
        let elf = AsterBin::new(
            &path,
            Arch::X86_64,
            AsterBinType::Elf(AsterElfMeta {
                has_linux_header: false,
                has_pvh_header: false,
                has_multiboot_header: false,
                has_multiboot2_header: false,
            }),
            "test".into(),
            false,
        );
        let config = Config {
            work_dir: directory.path().into(),
            target_arch: Arch::X86_64,
            build: Build::default(),
            run: Action {
                build: Build {
                    encoding: PayloadEncoding::Gzip,
                    ..Build::default()
                },
                ..Action::default()
            },
            test: Action {
                build: Build {
                    encoding: PayloadEncoding::Zlib,
                    ..Build::default()
                },
                ..Action::default()
            },
        };
        assert_eq!(config.build.encoding, PayloadEncoding::Raw);
        let gzip = std::fs::read(encode_kernel_to_file(
            &elf,
            config.run.build.encoding.clone(),
        ))
        .unwrap();
        let zlib = std::fs::read(encode_kernel_to_file(
            &elf,
            config.test.build.encoding.clone(),
        ))
        .unwrap();
        assert_eq!(&gzip[..3], &[0x1f, 0x8b, 8]);
        assert_eq!(zlib[0], 0x78);
        assert_ne!(gzip, zlib);
    }
}
