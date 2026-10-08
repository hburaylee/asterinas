// SPDX-License-Identifier: MPL-2.0

//! Owned file-descriptor interface to the raw endovisor ABI.

use std::{
    fs::{File, OpenOptions},
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
};

use anyhow::Result;
pub use kernelet_abi::*;

pub struct Sandbox {
    file: File,
}

impl Sandbox {
    pub fn create(args: &mut CreateArgs, cmdline: &str) -> Result<Self> {
        let control = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kernelet")?;
        args.cmdline_ptr = cmdline.as_ptr() as u64;
        args.cmdline_len = cmdline.len().try_into()?;
        let fd = call(&control, CREATE, args as *mut _ as usize)?;
        // SAFETY: a successful CREATE returns a new descriptor owned by this call.
        Ok(Self {
            file: unsafe { File::from_raw_fd(fd) },
        })
    }

    pub fn from_file(file: File) -> Self {
        Self { file }
    }
    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn attach(&self, kind: u16, backing: Option<&File>, flags: u32) -> Result<u16> {
        self.attach_with_arg(kind, backing, flags, 0)
    }

    pub fn attach_with_arg(
        &self,
        kind: u16,
        backing: Option<&File>,
        flags: u32,
        arg: u64,
    ) -> Result<u16> {
        let mut args = AttachArgs {
            kind,
            backing_fd: backing.map_or(-1, AsRawFd::as_raw_fd),
            flags,
            arg,
            ..Default::default()
        };
        call(&self.file, ATTACH, &mut args as *mut _ as usize)?;
        Ok(args.out_index)
    }

    pub fn endpoint(&self, kind: u16) -> Result<File> {
        let args = EndpointArgs { kind, reserved0: 0 };
        let fd = call(&self.file, ENDPOINT, &args as *const _ as usize)?;
        // SAFETY: ENDPOINT returns a newly owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub fn listen(&self, port: u32) -> Result<File> {
        let args = VsockArgs { port, flags: 0 };
        let fd = call(&self.file, VSOCK_LISTEN, &args as *const _ as usize)?;
        // SAFETY: VSOCK_LISTEN returns a newly owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub fn start(&self) -> Result<()> {
        call(&self.file, START, 0)?;
        Ok(())
    }
    pub fn kill(&self, reason: u32) -> Result<()> {
        call(&self.file, KILL, reason as usize)?;
        Ok(())
    }
    pub fn destroy(&self) -> Result<()> {
        call(&self.file, DESTROY, 0)?;
        Ok(())
    }
    pub fn stats(&self) -> Result<StatsRaw> {
        let mut stats = StatsRaw::default();
        call(&self.file, STATS, &mut stats as *mut _ as usize)?;
        Ok(stats)
    }

    pub fn status(&self) -> Result<StatusRaw> {
        let mut result = StatusRaw {
            state: 0,
            reason: 0,
            code: 0,
            flags: 0,
            uptime_ns: 0,
            cpu_time_ns: 0,
            fault_addr: 0,
            fault_ip: 0,
            message_len: 0,
            reserved0: 0,
            message: [0; 256],
        };
        call(&self.file, STATUS, &mut result as *mut _ as usize)?;
        Ok(result)
    }
}

fn call(file: &File, request: u64, arg: usize) -> io::Result<i32> {
    // SAFETY: callers supply the exact ABI layout and keep buffers alive through ioctl.
    let result = unsafe { libc::ioctl(file.as_raw_fd(), request as _, arg) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

/// Configures Host-side network forwarding on a network endpoint file.
///
/// The Host validates the configuration and binds mapped ports synchronously,
/// so callers learn about occupied ports before acknowledging creation.
pub fn configure_network(file: &File, args: &NetConfigArgs) -> Result<()> {
    call(file, NET_CONFIG, args as *const _ as usize)?;
    Ok(())
}

pub fn connect_agent(port: u32) -> Result<File> {
    use nix::sys::socket::{self, AddressFamily, SockFlag, SockType, VsockAddr};
    let fd: OwnedFd = socket::socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    socket::connect(fd.as_raw_fd(), &VsockAddr::new(libc::VMADDR_CID_HOST, port))?;
    Ok(File::from(fd))
}

pub fn open_image(path: &Path) -> Result<File> {
    Ok(File::open(path)?)
}
