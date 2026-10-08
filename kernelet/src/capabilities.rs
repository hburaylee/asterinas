// SPDX-License-Identifier: MPL-2.0

//! Linux capability sets prepared before forking the container process.

use std::io;

use anyhow::{Result, bail, ensure};

#[derive(Clone, Copy)]
pub(crate) struct Capabilities {
    bounding: u64,
    permitted: u64,
    effective: u64,
    inheritable: u64,
    ambient: u64,
}

impl Capabilities {
    pub(crate) fn parse(value: &serde_json::Value) -> Result<Option<Self>> {
        if value.is_null() {
            return Ok(None);
        }
        let sets = value
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("capabilities must be an object"))?;
        for name in sets.keys() {
            ensure!(
                matches!(
                    name.as_str(),
                    "bounding" | "permitted" | "effective" | "inheritable" | "ambient"
                ),
                "unknown capability set {name}"
            );
        }
        let parse = |name| -> Result<u64> {
            let Some(values) = sets.get(name) else {
                return Ok(0);
            };
            let values = values
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("capability set must be an array"))?;
            let mut bits = 0;
            for value in values {
                bits |= 1u64
                    << capability(
                        value
                            .as_str()
                            .ok_or_else(|| anyhow::anyhow!("capability must be a string"))?,
                    )?;
            }
            Ok(bits)
        };
        let result = Self {
            bounding: parse("bounding")?,
            permitted: parse("permitted")?,
            effective: parse("effective")?,
            inheritable: parse("inheritable")?,
            ambient: parse("ambient")?,
        };
        ensure!(
            result.effective & !result.permitted == 0,
            "effective capabilities exceed permitted capabilities"
        );
        ensure!(
            result.ambient & !(result.permitted & result.inheritable) == 0,
            "ambient capabilities must be permitted and inheritable"
        );
        Ok(Some(result))
    }

    pub(crate) fn before_uid_change(&self) -> io::Result<()> {
        for capability in 0..=40 {
            if self.bounding & (1 << capability) == 0 {
                // SAFETY: PR_CAPBSET_DROP takes an integer capability index only.
                if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        // SAFETY: scalar arguments enable retaining permitted capabilities over setuid.
        if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(crate) fn after_uid_change(&self) -> io::Result<()> {
        #[repr(C)]
        struct Header {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        struct Data {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        let header = Header {
            version: 0x2008_0522,
            pid: 0,
        };
        let data = [
            Data {
                effective: self.effective as u32,
                permitted: self.permitted as u32,
                inheritable: self.inheritable as u32,
            },
            Data {
                effective: (self.effective >> 32) as u32,
                permitted: (self.permitted >> 32) as u32,
                inheritable: (self.inheritable >> 32) as u32,
            },
        ];
        // SAFETY: capset v3 reads one header and exactly two data records.
        if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: PR_CAP_AMBIENT_CLEAR_ALL uses scalar arguments only.
        if unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        for capability in 0..=40 {
            if self.ambient & (1 << capability) != 0 {
                // SAFETY: PR_CAP_AMBIENT_RAISE takes an integer capability index.
                if unsafe {
                    libc::prctl(
                        libc::PR_CAP_AMBIENT,
                        libc::PR_CAP_AMBIENT_RAISE,
                        capability,
                        0,
                        0,
                    )
                } < 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(())
    }
}

fn capability(name: &str) -> Result<u32> {
    const NAMES: &[&str] = &[
        "CHOWN",
        "DAC_OVERRIDE",
        "DAC_READ_SEARCH",
        "FOWNER",
        "FSETID",
        "KILL",
        "SETGID",
        "SETUID",
        "SETPCAP",
        "LINUX_IMMUTABLE",
        "NET_BIND_SERVICE",
        "NET_BROADCAST",
        "NET_ADMIN",
        "NET_RAW",
        "IPC_LOCK",
        "IPC_OWNER",
        "SYS_MODULE",
        "SYS_RAWIO",
        "SYS_CHROOT",
        "SYS_PTRACE",
        "SYS_PACCT",
        "SYS_ADMIN",
        "SYS_BOOT",
        "SYS_NICE",
        "SYS_RESOURCE",
        "SYS_TIME",
        "SYS_TTY_CONFIG",
        "MKNOD",
        "LEASE",
        "AUDIT_WRITE",
        "AUDIT_CONTROL",
        "SETFCAP",
        "MAC_OVERRIDE",
        "MAC_ADMIN",
        "SYSLOG",
        "WAKE_ALARM",
        "BLOCK_SUSPEND",
        "AUDIT_READ",
        "PERFMON",
        "BPF",
        "CHECKPOINT_RESTORE",
    ];
    let Some(name) = name.strip_prefix("CAP_") else {
        bail!("invalid capability {name}");
    };
    NAMES
        .iter()
        .position(|candidate| *candidate == name)
        .map(|index| index as u32)
        .ok_or_else(|| anyhow::anyhow!("unknown capability CAP_{name}"))
}
