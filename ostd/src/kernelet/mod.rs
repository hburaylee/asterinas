// SPDX-License-Identifier: MPL-2.0

//! Provides the shared image ABI for a kernelet and its Asterinas host.

pub mod abi;
#[cfg(not(feature = "kernelet"))]
pub(crate) mod account;

#[cfg(not(feature = "kernelet"))]
pub(crate) mod clock;

#[cfg(not(feature = "kernelet"))]
pub mod control;

#[cfg(feature = "kernelet")]
pub mod entry;

#[cfg(not(feature = "kernelet"))]
pub(crate) mod host_image;

#[cfg(not(feature = "kernelet"))]
pub mod guest_memory;
#[cfg(not(feature = "kernelet"))]
pub(crate) mod host_grant;
#[cfg(feature = "kernelet")]
pub(crate) mod image_grant;

#[cfg(not(feature = "kernelet"))]
pub(crate) mod host_run;
