// SPDX-License-Identifier: MPL-2.0

//! Network configuration capability and bounded device-to-backend frame queues.

use core::{
    fmt::Display,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use kernelet_abi::NetConfigArgs;
use ostd::kernelet::control::Kernelet;

use super::{super::policy::PrestartEndpointReservation, ENDPOINT_SLOTS, Frame, nat::NatBackend};
use crate::{
    events::IoEvents,
    fs::{
        file::{AccessMode, FileCommon, FileLike, StatusFlags, file_table::FdFlags},
        pseudofs::AnonInodeFs,
    },
    prelude::*,
    process::{
        Uid,
        signal::{PollHandle, Pollable, Pollee},
    },
    util::ioctl::{InData, RawIoctl, dispatch_ioctl, ioc},
};

type Configure = ioc!(KERNELET_NET_CONFIG, 0xc7, 0x12, InData<NetConfigArgs>);

// A TCP listener retains a 256-KiB socket plus one pending 256-KiB
// connection. Leave room for their metadata and the backend's fixed state.
const MAPPING_RESERVATION_BYTES: usize = 640 * 1024;

enum BackendState {
    Unconfigured,
    Prepared(Box<NatBackend>, BackendReservation),
    Running,
}

/// Follows listener buffers from configuration through worker shutdown.
pub(super) struct BackendReservation {
    _user: PrestartEndpointReservation,
    bytes: usize,
    kernelet: Option<Arc<Kernelet>>,
}

impl Drop for BackendReservation {
    fn drop(&mut self) {
        if let Some(kernelet) = &self.kernelet {
            kernelet.uncharge_host_bytes(self.bytes);
        }
    }
}

/// Owns the device queues and transfers its prepared backend to the worker.
pub(in crate::endovisor) struct NetEndpoint {
    owner: Uid,
    input: Mutex<VecDeque<Frame>>,
    output: Mutex<VecDeque<Frame>>,
    backend: Mutex<BackendState>,
    pollee: Pollee,
    control_pollee: Pollee,
    generation: AtomicU64,
    pub(super) revoked: AtomicBool,
    account: Mutex<Option<(Arc<Kernelet>, usize)>>,
}

impl NetEndpoint {
    pub(in crate::endovisor) fn new(owner: Uid) -> Arc<Self> {
        Arc::new(Self {
            owner,
            input: Mutex::new(VecDeque::with_capacity(ENDPOINT_SLOTS)),
            output: Mutex::new(VecDeque::with_capacity(ENDPOINT_SLOTS)),
            backend: Mutex::new(BackendState::Unconfigured),
            pollee: Pollee::new(),
            control_pollee: Pollee::new(),
            generation: AtomicU64::new(0),
            revoked: AtomicBool::new(false),
            account: Mutex::new(None),
        })
    }

    pub(in crate::endovisor) fn file(self: &Arc<Self>) -> Arc<NetEndpointFile> {
        Arc::new(NetEndpointFile {
            common: FileCommon::new(
                AnonInodeFs::new_path(|_| "anon_inode:[kernelet-net]".into()),
                AccessMode::O_RDWR,
                StatusFlags::empty(),
            ),
            endpoint: self.clone(),
        })
    }

    pub(in crate::endovisor) fn reservation_bytes(&self) -> usize {
        let capacity = self.input.lock().capacity() + self.output.lock().capacity();
        capacity * size_of::<Frame>() + size_of::<Self>()
    }

    fn configure(&self, config: NetConfigArgs) -> Result<()> {
        let mut backend = self.backend.lock();
        if self.revoked.load(Ordering::Acquire) {
            return_errno_with_message!(Errno::ENODEV, "the network endpoint is revoked");
        }
        if !matches!(*backend, BackendState::Unconfigured) {
            return_errno_with_message!(Errno::EBUSY, "the network endpoint is configured");
        }
        // Binding occurs in the ioctl caller's context and returns the actual
        // socket error before START can publish a running instance.
        if usize::from(config.num_ports) > kernelet_abi::MAX_NET_PORTS {
            return_errno_with_message!(Errno::EINVAL, "too many network port mappings");
        }
        // Reserve bounded native listener queues before binding ports. This
        // guard follows the sockets into the worker, beyond endpoint revoke.
        let bytes = usize::from(config.num_ports).max(1) * MAPPING_RESERVATION_BYTES;
        let reservation = BackendReservation {
            _user: self.reserve_backend_bytes(bytes)?,
            bytes,
            kernelet: None,
        };
        *backend = BackendState::Prepared(Box::new(NatBackend::new(config)?), reservation);
        Ok(())
    }

    pub(in crate::endovisor) fn bind_account(&self, kernelet: Arc<Kernelet>) -> ostd::Result<()> {
        let mut backend = self.backend.lock();
        if self.revoked.load(Ordering::Acquire) {
            return Err(ostd::Error::InvalidArgs);
        }
        let BackendState::Prepared(_, reservation) = &mut *backend else {
            return Err(ostd::Error::InvalidArgs);
        };
        let bytes = self.reservation_bytes();
        let mut account = self.account.lock();
        if account.is_some() {
            return Err(ostd::Error::InvalidArgs);
        }
        kernelet.charge_host_bytes(bytes)?;
        if let Err(error) = kernelet.charge_host_bytes(reservation.bytes) {
            kernelet.uncharge_host_bytes(bytes);
            return Err(error);
        }
        reservation.kernelet = Some(kernelet.clone());
        *account = Some((kernelet, bytes));
        Ok(())
    }

    pub(in crate::endovisor) fn is_configured(&self) -> bool {
        matches!(*self.backend.lock(), BackendState::Prepared(..))
            && !self.revoked.load(Ordering::Acquire)
    }

    pub(super) fn take_backend(&self) -> Option<(NatBackend, BackendReservation)> {
        let mut backend = self.backend.lock();
        if self.revoked.load(Ordering::Acquire) {
            return None;
        }
        match core::mem::replace(&mut *backend, BackendState::Running) {
            BackendState::Prepared(backend, reservation) => Some((*backend, reservation)),
            _ => None,
        }
    }

    pub(in crate::endovisor) fn revoke(&self) {
        let mut backend = self.backend.lock();
        if self.revoked.swap(true, Ordering::AcqRel) {
            return;
        }
        let prepared = core::mem::replace(&mut *backend, BackendState::Running);
        drop(backend);
        // Running sockets are owned by the worker, which wakes and drops them
        // before disowning its Task. Prepared sockets have no worker yet.
        drop(prepared);
        let input = core::mem::take(&mut *self.input.lock());
        let output = core::mem::take(&mut *self.output.lock());
        drop((input, output));
        if let Some((kernelet, bytes)) = self.account.lock().take() {
            kernelet.uncharge_host_bytes(bytes);
        }
        self.wake_backend();
        self.control_pollee.notify(IoEvents::HUP | IoEvents::ERR);
    }

    pub(super) fn reserve_backend_bytes(
        &self,
        bytes: usize,
    ) -> Result<PrestartEndpointReservation> {
        PrestartEndpointReservation::reserve(self.owner, bytes)
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub(super) fn wake_backend(&self) {
        self.generation.fetch_add(1, Ordering::Release);
        self.pollee.notify(IoEvents::IN);
    }

    pub(super) fn poll_change(&self, old: u64, handle: &mut PollHandle) -> IoEvents {
        // Readiness depends on the worker's captured generation. Do not reuse
        // a readiness value cached for a previous generation.
        self.pollee.invalidate();
        self.pollee.poll_with(IoEvents::IN, Some(handle), || {
            if self.generation() != old || self.revoked.load(Ordering::Acquire) {
                IoEvents::IN
            } else {
                IoEvents::empty()
            }
        })
    }

    pub(super) fn input_available(&self) -> bool {
        !self.input.lock().is_empty()
    }

    pub(super) fn input_has_space(&self) -> bool {
        self.input.lock().len() < ENDPOINT_SLOTS
    }

    pub(super) fn output_has_space(&self) -> bool {
        self.output.lock().len() < ENDPOINT_SLOTS
    }

    pub(super) fn pop_input(&self) -> Option<Frame> {
        self.input.lock().pop_front()
    }

    pub(super) fn pop_output(&self) -> Option<Frame> {
        self.output.lock().pop_front()
    }

    pub(super) fn push_input(&self, frame: Frame) -> bool {
        Self::push(&self.input, &self.revoked, frame)
    }

    pub(super) fn push_output(&self, frame: Frame) -> bool {
        Self::push(&self.output, &self.revoked, frame)
    }

    fn push(queue: &Mutex<VecDeque<Frame>>, revoked: &AtomicBool, frame: Frame) -> bool {
        let mut queue = queue.lock();
        if revoked.load(Ordering::Acquire) || queue.len() == ENDPOINT_SLOTS {
            return false;
        }
        queue.push_back(frame);
        true
    }
}

impl Drop for NetEndpoint {
    fn drop(&mut self) {
        if let Some((kernelet, bytes)) = self.account.lock().take() {
            kernelet.uncharge_host_bytes(bytes);
        }
    }
}

/// Configuration descriptor; packet payloads stay in the Host kernel.
pub(in crate::endovisor) struct NetEndpointFile {
    common: FileCommon,
    endpoint: Arc<NetEndpoint>,
}

impl NetEndpointFile {
    pub(in crate::endovisor) fn endpoint(&self) -> &Arc<NetEndpoint> {
        &self.endpoint
    }
}

impl Pollable for NetEndpointFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.endpoint.control_pollee.poll_with(mask, poller, || {
            if self.endpoint.revoked.load(Ordering::Acquire) {
                IoEvents::HUP | IoEvents::ERR
            } else {
                IoEvents::empty()
            }
        })
    }
}

impl FileLike for NetEndpointFile {
    fn ioctl(&self, raw_ioctl: RawIoctl) -> Result<i32> {
        dispatch_ioctl!(match raw_ioctl {
            cmd @ Configure => {
                self.endpoint.configure(cmd.read()?)?;
            }
            _ => return_errno_with_message!(Errno::ENOTTY, "unknown network endpoint ioctl"),
        });
        Ok(0)
    }

    fn common(&self) -> &FileCommon {
        &self.common
    }

    fn dump_proc_fdinfo(self: Arc<Self>, _fd_flags: FdFlags) -> Box<dyn Display> {
        Box::new("kernelet-net:\tconfiguration\n".to_string())
    }
}
