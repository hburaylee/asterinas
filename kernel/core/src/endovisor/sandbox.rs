// SPDX-License-Identifier: MPL-2.0

//! One `/dev/kernelet` sandbox descriptor and its staged configuration.
//!
//! The module is organized by concern:
//!
//! - [`config`]: staged configuration, endpoint creation, and attachments;
//! - [`lifecycle`]: start, kill, destroy, and failure reclamation;
//! - [`file`]: the file/ioctl interface, polling, and status conversion;
//! - [`devices`]: host hooks, the virtual device registry, and slot addressing.

mod config;
mod devices;
mod file;
mod lifecycle;

pub(super) use file::create_sandbox;
use kernelet_abi::StatusRaw;
use ostd::{kernelet::control::Kernelet, sync::WaitQueue};

use self::{config::Pending, devices::SandboxHooks};
use super::policy::Admission;
use crate::{
    fs::file::FileCommon,
    prelude::*,
    process::{Uid, signal::Pollee},
};

/// The lifecycle state of one sandbox descriptor.
enum SandboxState {
    Configuring(Pending),
    Starting {
        kill: Option<u32>,
    },
    Running {
        kernelet: Arc<Kernelet>,
        hooks: Arc<SandboxHooks>,
    },
    Exited {
        kernelet: Option<Arc<Kernelet>>,
        hooks: Option<Arc<SandboxHooks>>,
        status: StatusRaw,
        retry_queued: bool,
    },
    Destroying,
    Gone(StatusRaw),
}

/// The capability descriptor returned by `KERNELET_CREATE`.
struct SandboxFile {
    common: FileCommon,
    state: Arc<Mutex<SandboxState>>,
    pollee: Pollee,
    start_waiters: WaitQueue,
    cid: u32,
    owner: Uid,
    admission: SpinLock<Option<Arc<Admission>>>,
}
