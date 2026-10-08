// SPDX-License-Identifier: MPL-2.0

//! Relays a guest process and restores the caller's terminal on every return path.

use std::{
    io::{self, Read, Write},
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
        unix::net::UnixStream,
    },
    path::Path,
    time::Instant,
};

use anyhow::{Result, bail, ensure};
use nix::{
    errno::Errno,
    poll::{PollFd, PollFlags, poll},
    sys::{
        socket::{MsgFlags, send},
        termios::{SetArg, Termios, cfmakeraw, tcgetattr, tcsetattr},
    },
};

use super::{CONTROL_TIMEOUT, Control, Reply, begin_request, receive_reply};
use crate::protocol::{self, Message, Stream};

struct RawInput {
    fd: OwnedFd,
    original: Termios,
    active: bool,
}

impl RawInput {
    fn new(fd: BorrowedFd<'_>) -> Result<Option<Self>> {
        let original = match tcgetattr(fd) {
            Ok(settings) => settings,
            Err(Errno::ENOTTY) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let fd = fd.try_clone_to_owned()?;
        let mut raw = original.clone();
        cfmakeraw(&mut raw);
        tcsetattr(&fd, SetArg::TCSANOW, &raw)?;
        Ok(Some(Self {
            fd,
            original,
            active: true,
        }))
    }

    fn restore(&mut self) -> Result<()> {
        if self.active {
            tcsetattr(&self.fd, SetArg::TCSANOW, &self.original)?;
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for RawInput {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!("restore terminal: {error}");
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
struct WindowSize {
    columns: u16,
    rows: u16,
}

fn window_size(fd: BorrowedFd<'_>) -> Result<Option<WindowSize>> {
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ writes one winsize into this valid, writable object.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCGWINSZ, &mut size) } == -1 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(
        (size.ws_col != 0 && size.ws_row != 0).then_some(WindowSize {
            columns: size.ws_col,
            rows: size.ws_row,
        }),
    )
}

pub(super) fn forward(
    directory: &Path,
    connection: UnixStream,
    id: u64,
    terminal: bool,
) -> Result<i32> {
    let mut input = io::stdin();
    let mut raw = if terminal {
        RawInput::new(input.as_fd())?
    } else {
        None
    };
    let result = relay(directory, connection, id, &mut input, raw.is_some());
    if let Some(raw) = &mut raw
        && let Err(error) = raw.restore()
    {
        return match result {
            Ok(_) => Err(error.context("restore terminal")),
            Err(relay_error) => {
                Err(relay_error.context(format!("restore terminal failed: {error}")))
            }
        };
    }
    result
}

fn relay(
    directory: &Path,
    mut connection: UnixStream,
    id: u64,
    input: &mut io::Stdin,
    terminal: bool,
) -> Result<i32> {
    let mut input_open = true;
    let mut data = vec![0; protocol::STREAM_CHUNK_BYTES];
    let mut pending_input = Vec::new();
    let mut sent = 0;
    let mut size = None;
    let mut resize: Option<(UnixStream, WindowSize, Instant)> = None;
    loop {
        if terminal
            && resize.is_none()
            && let Some(next) = window_size(input.as_fd())?.filter(|next| Some(*next) != size)
        {
            let request = begin_request(
                directory,
                &Control::Resize {
                    id,
                    columns: next.columns,
                    rows: next.rows,
                },
            )?;
            resize = Some((request, next, Instant::now()));
        }

        // Keep draining output while a resize is pending: the holder forwards
        // output through a bounded queue before it can receive the resize ACK.
        let mut events = PollFlags::POLLIN;
        if !pending_input.is_empty() {
            events |= PollFlags::POLLOUT;
        }
        let mut fds = vec![PollFd::new(connection.as_fd(), events)];
        let input_index = (input_open && pending_input.is_empty()).then(|| {
            fds.push(PollFd::new(input.as_fd(), PollFlags::POLLIN));
            fds.len() - 1
        });
        let resize_index = resize.as_ref().map(|(request, _, _)| {
            fds.push(PollFd::new(request.as_fd(), PollFlags::POLLIN));
            fds.len() - 1
        });
        match poll(&mut fds, 100u16) {
            Ok(_) => (),
            Err(Errno::EINTR) => continue,
            Err(error) => return Err(error.into()),
        }
        let ready = |index: usize, event: PollFlags| {
            fds[index]
                .revents()
                .unwrap_or_else(PollFlags::empty)
                .intersects(event | PollFlags::POLLHUP | PollFlags::POLLERR | PollFlags::POLLNVAL)
        };
        let output_ready = ready(0, PollFlags::POLLIN);
        let write_ready = ready(0, PollFlags::POLLOUT);
        let input_ready = input_index.is_some_and(|index| ready(index, PollFlags::POLLIN));
        let resize_ready = resize_index.is_some_and(|index| ready(index, PollFlags::POLLIN));
        drop(fds);

        if output_ready {
            match protocol::receive(&mut connection)? {
                Message::Data {
                    id: process_id,
                    stream,
                    data,
                } if process_id == id => match stream {
                    Stream::Stdout => {
                        io::stdout().write_all(&data)?;
                        io::stdout().flush()?;
                    }
                    Stream::Stderr => {
                        io::stderr().write_all(&data)?;
                        io::stderr().flush()?;
                    }
                    Stream::Stdin => bail!("unexpected stdin from sandbox holder"),
                },
                Message::Exited {
                    id: process_id,
                    code,
                } if process_id == id => return Ok(code),
                Message::Error { detail } => bail!("{detail}"),
                _ => (),
            }
        }
        if resize_ready {
            let (mut request, next, _) = resize.take().unwrap();
            ensure!(
                matches!(receive_reply(&mut request)?, Reply::Done),
                "invalid holder resize response"
            );
            size = Some(next);
        }
        if let Some((_, _, started)) = &resize {
            ensure!(
                started.elapsed() < CONTROL_TIMEOUT,
                "terminal resize timed out"
            );
        }
        // A blocked guest reader must not stop output draining. Keep at most
        // one input frame and send only what the socket can accept now.
        if write_ready && !pending_input.is_empty() {
            match send(
                connection.as_raw_fd(),
                &pending_input[sent..],
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
            ) {
                Ok(0) => bail!("sandbox holder closed its input"),
                Ok(length) => {
                    sent += length;
                    if sent == pending_input.len() {
                        pending_input.clear();
                        sent = 0;
                    }
                }
                Err(Errno::EAGAIN | Errno::EINTR) => (),
                Err(error) => return Err(error.into()),
            }
        }
        if input_ready {
            match input.read(&mut data) {
                Ok(0) => {
                    input_open = false;
                    protocol::send(
                        &mut pending_input,
                        &Message::Close {
                            id,
                            stream: Stream::Stdin,
                        },
                    )?;
                }
                Ok(length) => protocol::send(
                    &mut pending_input,
                    &Message::Data {
                        id,
                        stream: Stream::Stdin,
                        data: data[..length].to_vec(),
                    },
                )?,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) => return Err(error.into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use nix::pty::openpty;

    use super::*;

    #[test]
    fn restores_terminal_after_success_and_error() {
        let pty = openpty(None, None).unwrap();
        let original = tcgetattr(&pty.slave).unwrap();
        {
            let mut raw = RawInput::new(pty.slave.as_fd()).unwrap().unwrap();
            assert_ne!(tcgetattr(&pty.slave).unwrap(), original);
            raw.restore().unwrap();
            assert_eq!(tcgetattr(&pty.slave).unwrap(), original);
        }
        let fail = || -> Result<()> {
            let _raw = RawInput::new(pty.slave.as_fd())?.unwrap();
            bail!("forwarding failed");
        };
        assert!(fail().is_err());
        assert_eq!(tcgetattr(&pty.slave).unwrap(), original);
    }

    #[test]
    fn accepts_redirected_input_without_terminal_settings() {
        let (input, _) = UnixStream::pair().unwrap();
        assert!(RawInput::new(input.as_fd()).unwrap().is_none());
    }
}
