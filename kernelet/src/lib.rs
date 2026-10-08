// SPDX-License-Identifier: MPL-2.0

//! Userspace control plane for the endovisor and its guest init process.

pub mod agent;
mod capabilities;
pub mod config;
pub mod fd;
pub mod network;
pub mod protocol;
pub mod runtime;
pub mod shim;
pub mod uapi;
