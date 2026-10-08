// SPDX-License-Identifier: MPL-2.0

//! Bounded execution of one OCI hook subprocess.

use std::{
    io::{ErrorKind, Write},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, ChildStdin, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use nix::fcntl::{FcntlArg, OFlag, fcntl};

use crate::config::Hook;

/// Wall-clock budget for a hook without an explicit OCI `timeout`.
const DEFAULT_HOOK_TIMEOUT_SECS: u64 = 30;
/// Granularity of exit polling while no stdin bytes are pending.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Runs one hook with its whole lifecycle bounded by a single deadline that
/// starts at spawn: the OCI `timeout` covers stdin delivery too, not just the
/// exit wait. The hook owns its child until the exit status is known, so a
/// failed delivery or a timeout still terminates and reaps the process.
pub(super) fn run_hook(kind: &str, hook: &Hook, state: &impl serde::Serialize) -> Result<()> {
    let mut command = Command::new(&hook.path);
    if let Some(arg0) = hook.args.first() {
        command.arg0(arg0).args(&hook.args[1..]);
    }
    command.env_clear().stdin(Stdio::piped());
    for entry in &hook.env {
        let (key, value) = entry.split_once('=').context("invalid hook environment")?;
        command.env(key, value);
    }
    let timeout = hook.timeout.unwrap_or(DEFAULT_HOOK_TIMEOUT_SECS);
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(timeout))
        .context("hook timeout is too large")?;
    let mut process =
        HookProcess::spawn(kind, command, deadline).context(format!("start {kind} hook"))?;
    let payload = serde_json::to_vec(state)?;
    process.deliver_state(&payload)?;
    process.wait_for_exit()
}

/// A spawned hook whose child stays owned by one value. While armed, dropping
/// the value terminates and reaps the child, covering every error exit
/// including `?` propagation and the timeout; a completed exit disarms it.
struct HookProcess {
    kind: String,
    child: Child,
    stdin: Option<ChildStdin>,
    deadline: Instant,
    armed: bool,
}

impl HookProcess {
    fn spawn(kind: &str, mut command: Command, deadline: Instant) -> Result<Self> {
        let mut child = command.spawn()?;
        let stdin = child.stdin.take();
        let process = Self {
            kind: kind.to_owned(),
            child,
            stdin,
            deadline,
            armed: true,
        };
        // Stdin must not be able to block past the deadline: delivery below
        // interleaves non-blocking writes with deadline-bounded waits.
        if let Some(stdin) = &process.stdin {
            fcntl(stdin.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
                .context("set hook stdin non-blocking")?;
        }
        Ok(process)
    }

    /// Delivers the complete state JSON or reports the actual delivery error.
    fn deliver_state(&mut self, payload: &[u8]) -> Result<()> {
        let mut stdin = self.stdin.take().context("hook stdin unavailable")?;
        let mut sent = 0;
        while sent < payload.len() {
            self.remaining()?;
            match stdin.write(&payload[sent..]) {
                Ok(0) => bail!("{} hook stdin write made no progress", self.kind),
                Ok(count) => sent += count,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    self.wait_writable(&stdin)?;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => {
                    return Err(anyhow::Error::new(error)
                        .context(format!("{} hook stdin delivery", self.kind)));
                }
            }
        }
        drop(stdin);
        Ok(())
    }

    /// Waits for stdin writability without ever blocking past the deadline.
    fn wait_writable(&self, stdin: &ChildStdin) -> Result<()> {
        let remaining = self.remaining()?;
        let mut descriptor = libc::pollfd {
            fd: stdin.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        let timeout = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        // SAFETY: one valid descriptor is passed together with its count.
        let ready = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != ErrorKind::Interrupted {
                return Err(error).context(format!("{} hook stdin poll", self.kind));
            }
        }
        Ok(())
    }

    /// Waits for the hook within the same deadline that bounded its start and
    /// stdin delivery.
    fn wait_for_exit(&mut self) -> Result<()> {
        loop {
            let remaining = self.remaining()?;
            match self.child.try_wait()? {
                Some(status) => {
                    self.armed = false;
                    ensure!(status.success(), "{} hook failed: {status}", self.kind);
                    return Ok(());
                }
                None => {
                    thread::sleep(POLL_INTERVAL.min(remaining));
                }
            }
        }
    }

    fn remaining(&self) -> Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "{} hook timed out", self.kind);
        Ok(remaining)
    }
}

impl Drop for HookProcess {
    fn drop(&mut self) {
        self.stdin.take();
        if self.armed {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use nix::{
        errno::Errno,
        sys::wait::{WaitPidFlag, waitpid},
        unistd::Pid,
    };

    use super::*;
    use crate::runtime::State;

    fn hook(path: &str, args: &[&str], timeout: Option<u64>) -> Hook {
        Hook {
            path: path.into(),
            args: args.iter().map(|argument| argument.to_string()).collect(),
            env: Vec::new(),
            timeout,
        }
    }

    fn large_state() -> State {
        State {
            oci_version: "1.0.2".into(),
            id: "bounded".into(),
            status: "creating".into(),
            pid: 0,
            bundle: std::path::PathBuf::new(),
            annotations: BTreeMap::from([("payload".into(), "x".repeat(3 * 1024 * 1024))]),
        }
    }

    fn spawned_hook(script: &str, budget: Duration) -> HookProcess {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]).stdin(Stdio::piped());
        HookProcess::spawn("prestart", command, Instant::now() + budget).unwrap()
    }

    fn assert_reaped(pid: u32) {
        assert_eq!(
            waitpid(Pid::from_raw(pid as i32), Some(WaitPidFlag::WNOHANG)),
            Err(Errno::ECHILD),
            "the hook child must already have been reaped"
        );
    }

    #[test]
    fn timeout_covers_stdin_delivery_and_reaps_the_hook() {
        let payload = serde_json::to_vec(&large_state()).unwrap();
        let mut process = spawned_hook("exec /bin/sleep 30", Duration::from_millis(100));
        let pid = process.child.id();
        let start = Instant::now();
        let error = process.deliver_state(&payload).unwrap_err();
        assert!(format!("{error:#}").contains("prestart hook timed out"));
        drop(process);
        assert_reaped(pid);
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn closed_stdin_reports_delivery_failure_and_reaps_the_hook() {
        let payload = serde_json::to_vec(&large_state()).unwrap();
        let mut process = spawned_hook("exec 0<&-; exec /bin/sleep 30", Duration::from_secs(5));
        let pid = process.child.id();
        let start = Instant::now();
        let error = process.deliver_state(&payload).unwrap_err();
        assert!(format!("{error:#}").contains("prestart hook stdin delivery"));
        drop(process);
        assert_reaped(pid);
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn consuming_hook_receives_a_complete_large_state() {
        run_hook(
            "prestart",
            &hook("/bin/sh", &["sh", "-c", "cat > /dev/null"], None),
            &large_state(),
        )
        .unwrap();
    }

    #[test]
    fn failing_hook_reports_the_exit_status() {
        let error = run_hook(
            "poststop",
            &hook("/bin/sh", &["sh", "-c", "cat > /dev/null; exit 3"], Some(5)),
            &large_state(),
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("poststop hook failed: exit status: 3"),
            "unexpected error: {error:#}"
        );
    }
}
