// SPDX-License-Identifier: MPL-2.0

//! Runs kernel images as Host-managed kernelet instances.
//!
//! With `kernelet-host`, `control::KerneletKind` validates and registers an image,
//! and `control::Kernelet` owns an instance's resources and lifecycle.
//! `control::KerneletHooks` connects the instance to the kernel's device
//! model and carrier scheduling. Internal modules manage grants, accounting,
//! page-table roots, and calls between Host and image stacks.
//!
//! With the `kernelet` feature, `entry` initializes the image and calls Host
//! services instead of owning physical hardware. Both halves use [`abi`] for
//! entry tables, services, and shared per-vCPU records.

pub mod abi;
#[cfg(feature = "kernelet-host")]
pub(crate) mod account;
#[cfg(feature = "kernelet-host")]
mod deadline;
#[cfg(any(feature = "kernelet", feature = "kernelet-host", ktest))]
pub(crate) mod dma;

#[cfg(any(feature = "kernelet", feature = "kernelet-host"))]
pub(crate) mod clock;

#[cfg(feature = "kernelet-host")]
pub mod control;

#[cfg(feature = "kernelet")]
pub mod entry;

#[cfg(feature = "kernelet-host")]
pub(crate) mod host_image;

#[cfg(feature = "kernelet-host")]
pub mod guest_memory;
#[cfg(feature = "kernelet-host")]
pub(crate) mod host_grant;
#[cfg(feature = "kernelet")]
pub(crate) mod image_grant;
#[cfg(any(feature = "kernelet", ktest))]
mod initial_grant;
#[cfg(feature = "kernelet-host")]
mod owner;

#[cfg(feature = "kernelet-host")]
pub(crate) mod host_run;

#[cfg(feature = "kernelet-host")]
pub(crate) mod vcpu_slot;

#[cfg(any(kernelet_getpid_profile, kernelet_rq1_diagnostics))]
pub mod getpid_profile;

#[cfg(kernelet_rq1_diagnostics)]
pub mod fpu_profile;

#[cfg(all(kernelet_rq1_diagnostics, feature = "kernelet-host"))]
pub mod tlb_profile;

#[cfg(all(kernelet_rq1, target_arch = "x86_64"))]
pub mod crossing_profile;
