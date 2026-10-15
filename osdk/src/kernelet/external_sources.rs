// SPDX-License-Identifier: MPL-2.0

//! Content identities of the reviewed external unsafe-code exceptions.
//! Registry identities were derived from archives matching Cargo.lock's checksum;
//! the git identity was derived from the clean, pinned smoltcp revision.
//! Cargo's generated `.cargo-ok` marker and git administration are not sources.

use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
pub(super) struct Identity {
    pub package: &'static str,
    pub version: &'static str,
    pub source: &'static str,
    pub archive_sha256: Option<&'static str>,
    pub tree_sha256: &'static str,
}

pub(super) fn verify(
    package: &str,
    version: &str,
    directory: &Path,
) -> io::Result<&'static Identity> {
    let identity = IDENTITIES
        .iter()
        .find(|entry| entry.package == package && entry.version == version)
        .ok_or_else(|| io::Error::other("external unsafe source has no reviewed identity"))?;
    if tree_hash(directory)? != identity.tree_sha256 {
        return Err(io::Error::other(format!(
            "external unsafe source differs from reviewed {} {} ({})",
            package, version, identity.source
        )));
    }
    Ok(identity)
}

fn tree_hash(directory: &Path) -> io::Result<String> {
    fn collect(
        root: &Path,
        directory: &Path,
        files: &mut BTreeMap<String, PathBuf>,
    ) -> io::Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if directory == root
                && (entry.file_name() == ".git" || entry.file_name() == ".cargo-ok")
            {
                continue;
            }
            let kind = entry.file_type()?;
            let path = entry.path();
            if kind.is_dir() {
                collect(root, &path, files)?;
            } else if kind.is_file() {
                let relative = path.strip_prefix(root).expect("walk stays in package root");
                let name = relative
                    .to_str()
                    .ok_or_else(|| io::Error::other("non-UTF-8 external source path"))?;
                files.insert(name.to_string(), path);
            } else {
                return Err(io::Error::other(
                    "external unsafe source contains a symlink or special file",
                ));
            }
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    collect(directory, directory, &mut files)?;
    let mut digest = Sha256::new();
    for (name, path) in files {
        // Keep memory bounded to one file, rather than retaining the package.
        let bytes = fs::read(path)?;
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    Ok(format!("{:x}", digest.finalize()))
}

const IDENTITIES: &[Identity] = &[
    Identity {
        package: "allocator-api2",
        version: "0.2.21",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("683d7910e743518b0e34f1186f92494becacb047c7b6bf616c96772180fef923"),
        tree_sha256: "750592adafb721cc1751b147df8d5271ab73ee67f05a60e2bced065907952f3b",
    },
    Identity {
        package: "byteorder",
        version: "1.5.0",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("1fd0f2584146f6f2ef48085050886acf353beff7305ebd1ae69500e27c67f64b"),
        tree_sha256: "cc0c62272dda8e2faef8c7201a7eb4041738a6ecf5288a9f6315e21c6f0e6202",
    },
    Identity {
        package: "foldhash",
        version: "0.2.0",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("77ce24cb58228fbb8aa041425bb1050850ac19177686ea6e0f41a70416f56fdb"),
        tree_sha256: "a59ed9d92d1d8f20a85fc897c944163499684358eeb89a4348ee4945b63a677d",
    },
    Identity {
        package: "gimli",
        version: "0.28.1",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("4271d37baee1b8c7e4b708028c57d816cf9d2434acb33a549475f78c181f6253"),
        tree_sha256: "dcf2584891d23e643d1354ee1b01082746b71b7addfdb9da1f8b1dfd7f4d10e2",
    },
    Identity {
        package: "gimli",
        version: "0.34.0",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("1033caf0b349c518623b5396bfb2cf0bddf44f0306d543a250e5743297aafd10"),
        tree_sha256: "b1c4ad0df252a5857fbe2e378b837e18dd404e58c1aeb3eaa600955471d8776d",
    },
    Identity {
        package: "inventory",
        version: "0.3.24",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("a4f0c30c76f2f4ccee3fe55a2435f691ca00c0e4bd87abe4f4a851b1d4dac39b"),
        tree_sha256: "dc67d07969010d04bfd363fe5d537982cc6a2babf3697b00dccd57f1a5d6f83a",
    },
    Identity {
        package: "konst_macro_rules",
        version: "0.2.19",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("a4933f3f57a8e9d9da04db23fb153356ecaf00cbd14aee46279c33dc80925c37"),
        tree_sha256: "d60c2c30ca353e0436e885d8473890a08eae5becd5355729cbe4012732f12e32",
    },
    Identity {
        package: "log",
        version: "0.4.34",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("f9f8bd3e56ce4dfc153cf470fffbfa98c7620958b312ca5c3a4b8d5181fd13c6"),
        tree_sha256: "07b0ad8cdcb93e13b31999c2b639728901582b865fe0d0983b033dd9250cd170",
    },
    Identity {
        package: "num-traits",
        version: "0.2.19",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("071dfc062690e90b734c0b2273ce72ad0ffa95f0c74596bc250dcfd960262841"),
        tree_sha256: "37b5b8fe98208ae520055298a7522af3693a892cd681016e4ff886f19779954c",
    },
    Identity {
        package: "once_cell",
        version: "1.21.4",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("9f7c3e4beb33f85d45ae3e3a1792185706c8e16d043238c593331cc7cd313b50"),
        tree_sha256: "ce9f93c7ba2eccff51c82dd85b447ae19c30bd0f57b73f143e5b36f4e2fa7371",
    },
    Identity {
        package: "polonius-the-crab",
        version: "0.2.1",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("c2a69ee997a6282f8462abf1e0d8c38c965e968799e912b3bed8c9e8a28c2f9f"),
        tree_sha256: "4e7205942afe27e9eadba0062b6d2df5154e9e65b3426388ae8ca6e87fe0a4cc",
    },
    Identity {
        package: "ptr_meta",
        version: "0.3.2",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("743da816b98c921cdbe8628ef7381b76f25ecf4da599fc80aca90eae7ef70cc0"),
        tree_sha256: "c1fa4a6a58b44170feb7875daa37b6355ee151f03cc0ce502cc7a4deba4c6652",
    },
    Identity {
        package: "scopeguard",
        version: "1.2.0",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("94143f37725109f92c262ed2cf5e59bce7498c01bcc1502d7b9afe439a4e9f49"),
        tree_sha256: "b5f1cab3a19ee5c176947aa5b173088aa9821eabf6ecfdc319f231f5f4b9d65f",
    },
    Identity {
        package: "serde_core",
        version: "1.0.229",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("67dca2c9c51e58a4791a4b1ed58308b39c64224d349a935ab5039aa360942a48"),
        tree_sha256: "9b14cecef18f596345e0e5475210f9d897ca256cdff4c7f599cc89c8e4577d76",
    },
    Identity {
        package: "smallvec",
        version: "1.16.2",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("f9395f0f0eee849a9b707b2f06bb92a6a422090e2123bb2ef8e87a0e61892a8e"),
        tree_sha256: "7aa97af92b67a0d696d76df89b2d645da482caff1f36f0213f0d02cb20f990bc",
    },
    Identity {
        package: "stable_deref_trait",
        version: "1.2.1",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("6ce2be8dc25455e1f91df71bfa12ad37d7af1092ae736f3a6cd0e37bc7810596"),
        tree_sha256: "9b9d5271bef35b291900bf6686a784b327a178034a222be7442c87e5c2661a01",
    },
    Identity {
        package: "uguid",
        version: "2.2.1",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("0c8352f8c05e47892e7eaf13b34abd76a7f4aeaf817b716e88789381927f199c"),
        tree_sha256: "9c72e3fd2f7941996308e2d64b746a16c3e7b032b284030536262fcaa098a7ba",
    },
    Identity {
        package: "volatile",
        version: "0.4.6",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("442887c63f2c839b346c192d047a7c87e73d0689c9157b00b53dcc27dd5ea793"),
        tree_sha256: "66edd26572e10716671324828b9a17b39b2d863f3e685c665f7318c8c37072e6",
    },
    Identity {
        package: "volatile",
        version: "0.6.1",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("af8ca9a5d4debca0633e697c88269395493cebf2e10db21ca2dbde37c1356452"),
        tree_sha256: "519db1c8c1e55ab89d174017ff18ce57ed98389c9e269e36d0845721c8e8e377",
    },
    Identity {
        package: "zerocopy",
        version: "0.8.59",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("6df92bf3d9227be3d53173901ddbffac2babc27ae50f397776ffd6dc33f800cb"),
        tree_sha256: "42be1934c4f7d58c4c3a44ec772fe9ed6f01ea5ccd4e800e83cec4948cc613ff",
    },
    Identity {
        package: "zero",
        version: "0.1.3",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("2fe21bcc34ca7fe6dd56cc2cb1261ea59d6b93620215aefb5ea6032265527784"),
        tree_sha256: "457d0cb4314691d302b4ade959960329394d7e6b6d77d785e5c49859b9518680",
    },
    Identity {
        package: "powerfmt",
        version: "0.2.0",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("439ee305def115ba05938db6eb1644ff94165c5ab5e9420d1c1bcedbba909391"),
        tree_sha256: "6e469d1aacb02e065bd3d28633f25aed53a4ba18b6d77329e622a2add10a10eb",
    },
    Identity {
        package: "multiboot2-common",
        version: "0.3.0",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("6892f2795001adb0f6e4c124de90b68f9edc4bf52b8d81b14dac45cb361f1cca"),
        tree_sha256: "5c350a1790a4093e8066fd572196cfffc29dc8b6a68fcad750849dd265e681c6",
    },
    Identity {
        package: "hash32",
        version: "0.3.1",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("47d60b12902ba28e2730cd37e95b8c9223af2808df9e902d4df49588d1470606"),
        tree_sha256: "c460c4a7b6902ebc8c542f93083d0dcf5342056e81f493b1f3ffbbd664b3d4d4",
    },
    Identity {
        package: "wyz",
        version: "0.5.1",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("05f360fc0b24296329c78fda852a1e9ae82de9cf7b27dae4b7f62f118f77b9ed"),
        tree_sha256: "af60007b6885546fbf46e8788ca3dd2da62706a66ca89d02cfc2941b2e68d8ab",
    },
    Identity {
        package: "lock_api",
        version: "0.4.14",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("224399e74b87b5f3557511d98dff8b14089b3dadafcab6bb93eab67d3aace965"),
        tree_sha256: "886140900f7baa9250165801764e41bfe41b82d6a9948d9b00f1bd9de9d88fc2",
    },
    Identity {
        package: "acpi",
        version: "5.2.0",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("94476c7ef97af4c4d998b3f422c1b01d5211aad57c80ed200baf148d1f1efab6"),
        tree_sha256: "db6588b1adfd411f4571a5bb51ea0f08520af245273f8301ed9ae92b049b30a7",
    },
    Identity {
        package: "intrusive-collections",
        version: "0.9.7",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("189d0897e4cbe8c75efedf3502c18c887b05046e59d28404d4d8e46cbc4d1e86"),
        tree_sha256: "5260c9c00b267fd64091617d9941cdc3e3e1ec712c99a5c15f98e77714e2c50e",
    },
    Identity {
        package: "raw-cpuid",
        version: "10.7.0",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("6c297679cb867470fa8c9f67dbba74a78d78e3e98d7cf2b08d6d71540f797332"),
        tree_sha256: "be7ad07de20249d3e1fba8fd1bc8f8af5a132892256d984bb2b68da4b94de230",
    },
    Identity {
        package: "deranged",
        version: "0.5.8",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("7cd812cc2bc1d69d4764bd80df88b4317eaef9e773c75226407d9bc0876b211c"),
        tree_sha256: "dc316d3f00f4ccf885175fbf7e5c684b56690ed9075e32d1d97ba5ad8bcb1be2",
    },
    Identity {
        package: "x86_64",
        version: "0.15.5",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("be4ec631e1a81d50e46c35a4a00322bd076c47491b64c2fb10a7ffa89002c697"),
        tree_sha256: "dcb3d5e42c49f449b1a018ab781e4dbf777e762ca43e7a48c67355b982350bfa",
    },
    Identity {
        package: "uefi-raw",
        version: "0.12.0",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("8aff2f4f2b556a36a201d335a1e0a57754967a96857b1f47a52d5a23825cac84"),
        tree_sha256: "986447af2cd288d6947a0afb42fa3914e9ffd45f17c71950c3f85c3e6b1af91c",
    },
    Identity {
        package: "konst",
        version: "0.2.20",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("128133ed7824fcd73d6e7b17957c5eb7bacb885649bd8c69708b2331a10bcefb"),
        tree_sha256: "869eaaf7ad8e5556e40444fa8b9ba0717f988e2ede998cbad49ee0d9f65ab1eb",
    },
    Identity {
        package: "spin",
        version: "0.9.9",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("3763264f6b73151db08c50ff20d7d8a0b8796e021cdea7ceedad07b80155fa0e"),
        tree_sha256: "d9c6f28cfcdb07bea5536a6d50ed0a378862b08eee17811bc6ccd44dd49dd69c",
    },
    Identity {
        package: "xmas-elf",
        version: "0.10.0",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("18245fcbb8b3de8dd198ce7944fdd4096986fd6cd306b0fcfa27df817bd545d6"),
        tree_sha256: "bd049be10a83a3e2d83eaf12addf01d5cb38fbaca450638f06590be8bcd6798a",
    },
    Identity {
        package: "heapless",
        version: "0.8.0",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("0bfb9eb618601c89945a70e254898da93b13be0388091d42117462b265bb3fad"),
        tree_sha256: "a6ec3aca53f2a2d29868a05b490e935576c3ac451dccb6c4c4fd5a85b0a02b32",
    },
    Identity {
        package: "hashbrown",
        version: "0.16.1",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("841d1cc9bed7f9236f321df977030373f4a4163ae1a7dbfe1a51a2c1a51d9100"),
        tree_sha256: "c41a5454db43ea1f92954640229bbb05a6c3c8f72111b4a557b01659ae727bb7",
    },
    Identity {
        package: "bitvec",
        version: "1.1.1",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("ddcec3d12c579d40898fe0a9a358a803c23e9c52ca3c425707f81c9436211837"),
        tree_sha256: "b7236e9c094a029c58e112132f1399c50b10783cb42043b96670573e4612258f",
    },
    Identity {
        package: "ppv-lite86",
        version: "0.2.21",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("85eae3c4ed2f50dcfe72643da4befc30deadb458a9b590d720cde2f2b1e97da9"),
        tree_sha256: "38c2dcf07650dbc4ae9fee825ceace9a7a7293314822f90544b899db478ec2ac",
    },
    Identity {
        package: "time",
        version: "0.3.55",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("cdb87b95ec50ddfa440816d227a17b2ccbdda963a316a727fda0fc4334f7d134"),
        tree_sha256: "6dbaf3e7bc8fa1b43eed9ec28f9e106e3d1e518d224c65e4e46d9550342fbad3",
    },
    Identity {
        package: "multiboot2",
        version: "0.24.1",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("89797c447846ff7c39eebf22b1c6ce1c6d8721d0dced9771fc142d10cc2a4e97"),
        tree_sha256: "28f858d621b09ca5ac9b04b87549ebfd1e519367a4447d76c0014448c9212d07",
    },
    Identity {
        package: "hashbrown",
        version: "0.14.5",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("e5274423e17b7c9fc20b6e7e208532f9b19825d82dfd615708b70edd83df41f1"),
        tree_sha256: "91dd98a7de8031f3c082454d2ff75de8196fe385e143f50f335de87f4635c432",
    },
    Identity {
        package: "x86",
        version: "0.52.0",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("2781db97787217ad2a2845c396a5efe286f87467a5810836db6d74926e94a385"),
        tree_sha256: "f3d6d875b9480882cf703a615192aa036ff2822f2fe0692903e8e1f8c1ba4bb6",
    },
    Identity {
        package: "lru",
        version: "0.16.4",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("7f66e8d5d03f609abc3a39e6f08e4164ebf1447a732906d39eb9b99b7919ef39"),
        tree_sha256: "dc33ef3aa648c15b7e9f836cd9dfcc33247e77c7f0cb171bf93f3dd23996e9d1",
    },
    Identity {
        package: "smoltcp",
        version: "0.11.0",
        source: "git+https://github.com/asterinas/smoltcp?tag=r_2024-11-08_f07e5b5#b10671de8aac3694e16b8f57418aa90f2891af3b",
        archive_sha256: None,
        tree_sha256: "7ccc4f77ce0815a716f4a7cc46ba6cab9e35e8509743c083ce5eb89066cf8f07",
    },
    Identity {
        package: "rand",
        version: "0.9.5",
        source: "registry+https://github.com/rust-lang/crates.io-index",
        archive_sha256: Some("b9ef1d0d795eb7d84685bca4f72f3649f064e6641543d3a8c415898726a57b41"),
        tree_sha256: "968068144303d8e434c9ec563861f3714e9ebb4a18ca1b1781b77e01ebb8422f",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_named_path_dependency_has_no_unsafe_exemption() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("Cargo.toml"),
            "[package]\nname = \"smallvec\"\nversion = \"1.16.2\"\n",
        )
        .unwrap();
        fs::write(
            directory.path().join("lib.rs"),
            "pub unsafe fn unreviewed() {}\n",
        )
        .unwrap();
        assert!(verify("smallvec", "1.16.2", directory.path()).is_err());
    }

    #[test]
    fn generated_marker_is_ignored_but_source_edits_and_symlinks_are_not() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        fs::write(path.join("lib.rs"), b"reviewed source").unwrap();
        let original = tree_hash(path).unwrap();
        fs::write(path.join(".cargo-ok"), b"cargo marker").unwrap();
        assert_eq!(tree_hash(path).unwrap(), original);
        fs::write(path.join("lib.rs"), b"modified source").unwrap();
        assert_ne!(tree_hash(path).unwrap(), original);
        std::os::unix::fs::symlink("lib.rs", path.join("another.rs")).unwrap();
        assert!(tree_hash(path).is_err());
    }
}
