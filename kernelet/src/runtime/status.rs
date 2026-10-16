// SPDX-License-Identifier: MPL-2.0

//! Versioned diagnostics from the sandbox STATUS ioctl, independent of OCI state.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::uapi;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum InstanceState {
    Configuring,
    Created,
    Starting,
    Running,
    Dying,
    Exited,
    Destroying,
    Destroyed,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ExitReason {
    None,
    Exited,
    Panicked,
    Killed,
}

/// Addresses use fixed-width hexadecimal strings so JSON consumers retain all bits.
/// Message bytes are preserved exactly when valid UTF-8. The ABI carries at most
/// 256 bytes; `message_truncated` reports loss already incurred in the kernel.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstanceStatus {
    version: u32,
    state: InstanceState,
    reason: ExitReason,
    code: u32,
    uptime_ns: u64,
    cpu_time_ns: Option<u64>,
    #[serde(with = "address")]
    fault_addr: u64,
    #[serde(with = "address")]
    fault_ip: u64,
    message: String,
    message_truncated: bool,
}

impl InstanceStatus {
    pub(super) fn from_raw(raw: uapi::StatusRaw) -> Result<Self> {
        ensure!(raw.reserved0 == 0, "STATUS reserved field is nonzero");
        ensure!(
            raw.flags & !uapi::STATUS_MESSAGE_TRUNCATED == 0,
            "STATUS contains unknown flags {:#x}",
            raw.flags
        );
        let length = usize::try_from(raw.message_len)?;
        ensure!(
            length <= raw.message.len(),
            "STATUS message length exceeds the ABI buffer"
        );
        let state = match raw.state {
            uapi::STATE_CONFIGURING => InstanceState::Configuring,
            uapi::STATE_CREATED => InstanceState::Created,
            uapi::STATE_STARTING => InstanceState::Starting,
            uapi::STATE_RUNNING => InstanceState::Running,
            uapi::STATE_DYING => InstanceState::Dying,
            uapi::STATE_EXITED => InstanceState::Exited,
            uapi::STATE_DESTROYING => InstanceState::Destroying,
            uapi::STATE_DESTROYED => InstanceState::Destroyed,
            other => bail!("STATUS contains unknown instance state {other}"),
        };
        let reason = match raw.reason {
            uapi::STATUS_REASON_NONE => ExitReason::None,
            uapi::STATUS_REASON_EXITED => ExitReason::Exited,
            uapi::STATUS_REASON_PANICKED => ExitReason::Panicked,
            uapi::STATUS_REASON_KILLED => ExitReason::Killed,
            other => bail!("STATUS contains unknown exit reason {other}"),
        };
        let status = Self {
            version: 1,
            state,
            reason,
            code: raw.code,
            uptime_ns: raw.uptime_ns,
            cpu_time_ns: (raw.cpu_time_ns != kernelet_abi::STATS_UNAVAILABLE)
                .then_some(raw.cpu_time_ns),
            fault_addr: raw.fault_addr,
            fault_ip: raw.fault_ip,
            message: std::str::from_utf8(&raw.message[..length])
                .context("STATUS message is not valid UTF-8")?
                .to_owned(),
            message_truncated: raw.flags & uapi::STATUS_MESSAGE_TRUNCATED != 0,
        };
        status.validate()?;
        Ok(status)
    }

    /// Validate the holder reply as well as the ioctl record. No unknown version
    /// or inconsistent record is converted into a successful diagnostic result.
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "unsupported instance status version {}",
            self.version
        );
        ensure!(
            self.message.len() <= 256,
            "instance status message exceeds the ABI buffer"
        );
        if self.reason != ExitReason::None {
            ensure!(
                matches!(self.state, InstanceState::Exited | InstanceState::Destroyed),
                "instance exit reason requires an exited or destroyed state"
            );
        }
        if self.reason != ExitReason::Panicked {
            ensure!(
                self.message.is_empty() && !self.message_truncated,
                "only panic status can carry a message"
            );
        }
        if matches!(self.reason, ExitReason::None | ExitReason::Panicked) {
            ensure!(
                self.code == 0,
                "instance status reason does not carry a code"
            );
        }
        if self.reason != ExitReason::Killed || self.code != uapi::KILL_KERNEL_FAULT {
            ensure!(
                self.fault_addr == 0 && self.fault_ip == 0,
                "only kernel-fault status can carry fault addresses"
            );
        }
        Ok(())
    }
}

mod address {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub(super) fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{value:016x}"))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.len() != 18
            || !value.starts_with("0x")
            || !value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(D::Error::custom(
                "status address requires 0x and 16 hex digits",
            ));
        }
        u64::from_str_radix(&value[2..], 16).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_cpu_time_serializes_as_null() {
        let mut snapshot = raw(uapi::STATE_RUNNING, uapi::STATUS_REASON_NONE);
        snapshot.cpu_time_ns = kernelet_abi::STATS_UNAVAILABLE;
        let status = InstanceStatus::from_raw(snapshot).unwrap();
        assert!(status.cpu_time_ns.is_none());
        assert!(serde_json::to_value(status).unwrap()["cpu_time_ns"].is_null());
    }

    fn raw(state: u32, reason: u32) -> uapi::StatusRaw {
        uapi::StatusRaw {
            state,
            reason,
            code: 0,
            flags: 0,
            uptime_ns: 42,
            cpu_time_ns: 7,
            fault_addr: 0,
            fault_ip: 0,
            message_len: 0,
            reserved0: 0,
            message: [0; 256],
        }
    }

    #[test]
    fn running_exit_panic_and_kernel_fault_preserve_distinct_evidence() {
        let running =
            InstanceStatus::from_raw(raw(uapi::STATE_RUNNING, uapi::STATUS_REASON_NONE)).unwrap();
        assert_eq!(running.state, InstanceState::Running);
        assert_eq!(running.reason, ExitReason::None);
        let mut exit = raw(uapi::STATE_EXITED, uapi::STATUS_REASON_EXITED);
        exit.code = 17;
        assert_eq!(InstanceStatus::from_raw(exit).unwrap().code, 17);
        let message = "panic:\n完整消息\0retained";
        let mut panic = raw(uapi::STATE_EXITED, uapi::STATUS_REASON_PANICKED);
        panic.message_len = message.len() as u32;
        panic.message[..message.len()].copy_from_slice(message.as_bytes());
        let panic = InstanceStatus::from_raw(panic).unwrap();
        assert_eq!(panic.message, message);
        assert!(!panic.message_truncated);
        let mut fault = raw(uapi::STATE_EXITED, uapi::STATUS_REASON_KILLED);
        fault.code = uapi::KILL_KERNEL_FAULT;
        fault.fault_addr = u64::MAX;
        fault.fault_ip = 0xffff_8000_1234_5678;
        let status = InstanceStatus::from_raw(fault).unwrap();
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["version"], 1);
        assert_eq!(json["reason"], "killed");
        assert_eq!(json["fault_addr"], "0xffffffffffffffff");
        assert_eq!(json["fault_ip"], "0xffff800012345678");
        assert_eq!(
            serde_json::from_value::<InstanceStatus>(json).unwrap(),
            status
        );
    }

    #[test]
    fn truncated_message_reports_loss_and_invalid_utf8_is_rejected() {
        let mut panic = raw(uapi::STATE_EXITED, uapi::STATUS_REASON_PANICKED);
        panic.message = [b'x'; 256];
        panic.message_len = 256;
        panic.flags = uapi::STATUS_MESSAGE_TRUNCATED;
        assert!(InstanceStatus::from_raw(panic).unwrap().message_truncated);
        // The truncation flag does not require the kernel to split a UTF-8
        // character just to fill all 256 bytes of its fixed buffer.
        let mut boundary = panic;
        boundary.message_len = 253;
        assert!(
            InstanceStatus::from_raw(boundary)
                .unwrap()
                .message_truncated
        );
        panic.message[255] = 0xe4;
        assert!(
            InstanceStatus::from_raw(panic)
                .unwrap_err()
                .to_string()
                .contains("UTF-8")
        );
    }

    #[test]
    fn malformed_raw_and_holder_records_are_rejected() {
        let running = raw(uapi::STATE_RUNNING, uapi::STATUS_REASON_NONE);
        for broken in [
            uapi::StatusRaw {
                reserved0: 1,
                ..running
            },
            uapi::StatusRaw {
                flags: 2,
                ..running
            },
            uapi::StatusRaw {
                message_len: 257,
                ..running
            },
            uapi::StatusRaw {
                state: 99,
                ..running
            },
            uapi::StatusRaw {
                reason: 99,
                ..running
            },
            uapi::StatusRaw {
                reason: uapi::STATUS_REASON_PANICKED,
                ..running
            },
            uapi::StatusRaw { code: 1, ..running },
        ] {
            assert!(InstanceStatus::from_raw(broken).is_err());
        }
        let status = InstanceStatus::from_raw(running).unwrap();
        let mut json = serde_json::to_value(&status).unwrap();
        json["version"] = 2.into();
        assert!(
            serde_json::from_value::<InstanceStatus>(json)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut json = serde_json::to_value(&status).unwrap();
        json["unknown"] = true.into();
        assert!(serde_json::from_value::<InstanceStatus>(json).is_err());
        for address in [
            serde_json::json!(18446744073709551615u64),
            serde_json::json!("0x1"),
            serde_json::json!("0xfffffffffffffffz"),
        ] {
            let mut json = serde_json::to_value(&status).unwrap();
            json["fault_addr"] = address;
            assert!(serde_json::from_value::<InstanceStatus>(json).is_err());
        }
    }
}
