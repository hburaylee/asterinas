// SPDX-License-Identifier: MPL-2.0

#[cfg(kernelet_getpid_profile)]
use ostd::kernelet::getpid_profile as profile;

use super::SyscallReturn;
use crate::prelude::*;

pub(super) fn sys_getpid(ctx: &Context) -> Result<SyscallReturn> {
    #[cfg(kernelet_rq1_diagnostics)]
    ctx.thread_local
        .getpid_timeline()
        .borrow_mut()
        .mark(ostd::kernelet::getpid_profile::timeline::Boundary::BodyEnter);
    #[cfg(kernelet_getpid_profile)]
    let _getpid_span = {
        profile::calibrate_empty();
        profile::event(profile::event_id::GETPID);
        profile::span(if cfg!(feature = "kernelet") {
            profile::stage::GUEST_GETPID_BODY
        } else {
            profile::stage::NATIVE_GETPID_BODY
        })
    };
    let pid = ctx.process.pid();
    debug!("pid = {}", pid);
    #[cfg(kernelet_rq1_diagnostics)]
    ctx.thread_local
        .getpid_timeline()
        .borrow_mut()
        .mark(ostd::kernelet::getpid_profile::timeline::Boundary::BodyLeave);
    Ok(SyscallReturn::Return(pid as _))
}
