// SPDX-License-Identifier: MPL-2.0

//! CPU context & state control and CPU local memory.

pub mod context;
pub mod cpuid;
pub mod extension;
#[cfg_attr(feature = "kernelet", path = "kernelet_local.rs")]
pub mod local;
