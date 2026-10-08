// SPDX-License-Identifier: MPL-2.0

//! OCI configuration supported by the initial userspace runtime.

use std::{collections::BTreeMap, path::PathBuf};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub oci_version: String,
    pub root: Root,
    pub process: Process,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub mounts: Vec<Mount>,
    #[serde(default)]
    pub hooks: BTreeMap<String, Vec<Hook>>,
    #[serde(default)]
    pub linux: serde_json::Value,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
    #[serde(default)]
    pub network: Option<crate::network::NetworkConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Root {
    pub path: PathBuf,
    #[serde(default)]
    pub readonly: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    pub cwd: PathBuf,
    #[serde(default)]
    pub terminal: bool,
    #[serde(default)]
    pub user: User,
    #[serde(default)]
    pub rlimits: Vec<Rlimit>,
    #[serde(default)]
    pub capabilities: serde_json::Value,
    #[serde(default)]
    pub no_new_privileges: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    #[serde(default)]
    pub additional_gids: Vec<u32>,
    #[serde(default)]
    pub umask: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Rlimit {
    #[serde(rename = "type")]
    pub kind: String,
    pub hard: u64,
    pub soft: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Mount {
    pub destination: PathBuf,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub options: Vec<String>,
    /// Filled by the host after reading a bind-mounted file; never cached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Vec<u8>>,
    #[serde(default)]
    pub content_metadata: Option<(u32, u32, u32)>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Hook {
    pub path: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    pub timeout: Option<u64>,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.oci_version.starts_with("1."),
            "unsupported OCI version"
        );
        self.process.validate()?;
        for name in self.hooks.keys() {
            ensure!(
                matches!(
                    name.as_str(),
                    "prestart" | "createRuntime" | "poststart" | "poststop"
                ),
                "unsupported hook {name}"
            );
        }
        for key in ["uidMappings", "gidMappings"] {
            ensure!(
                self.linux
                    .get(key)
                    .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty)),
                "unsupported linux.{key}"
            );
        }
        if let Some(limit) = self
            .linux
            .pointer("/resources/pids/limit")
            .and_then(|value| value.as_i64())
        {
            ensure!(limit < 0, "finite OCI pids limits are unsupported");
        }
        for mount in &self.mounts {
            ensure!(
                mount.destination.is_absolute(),
                "mount destination must be absolute"
            );
            for option in &mount.options {
                ensure!(
                    !matches!(
                        option.as_str(),
                        "rbind"
                            | "shared"
                            | "rshared"
                            | "slave"
                            | "rslave"
                            | "private"
                            | "rprivate"
                            | "unbindable"
                            | "runbindable"
                    ),
                    "unsupported mount option {option}"
                );
            }
            if mount.kind != "bind" && !mount.options.iter().any(|option| option == "bind") {
                ensure!(
                    matches!(
                        mount.kind.as_str(),
                        "proc" | "sysfs" | "tmpfs" | "devpts" | "mqueue" | "ext2"
                    ),
                    "unsupported filesystem {}",
                    mount.kind
                );
            }
        }
        Ok(())
    }
}

impl Process {
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.args.is_empty(), "process.args must not be empty");
        ensure!(self.cwd.is_absolute(), "process.cwd must be absolute");
        for value in self.args.iter().chain(&self.env) {
            ensure!(!value.contains('\0'), "process argument contains NUL");
        }
        for entry in &self.env {
            ensure!(
                entry
                    .split_once('=')
                    .is_some_and(|(key, _)| !key.is_empty()),
                "invalid process environment entry"
            );
        }
        crate::capabilities::Capabilities::parse(&self.capabilities)?;
        ensure!(
            self.user.umask.is_none_or(|mask| mask <= 0o777),
            "invalid process umask"
        );
        for limit in &self.rlimits {
            ensure!(
                limit.soft <= limit.hard,
                "rlimit soft value exceeds hard value"
            );
        }
        Ok(())
    }
}
