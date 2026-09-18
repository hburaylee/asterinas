// SPDX-License-Identifier: MPL-2.0

//! Restartable sequences (rseq) system call.

use core::mem::offset_of;

use ostd::{arch::cpu::context::UserContext, cpu::CpuId, mm::VmIo, user::UserContextApi};

use super::SyscallReturn;
use crate::{
    prelude::*,
    process::posix_thread::{Rseq, ThreadLocal},
    vm::vmar::is_userspace_vaddr,
};

/// The original size of `struct rseq` (including trailing padding).
const RSEQ_AREA_SIZE: u32 = 32;

/// Flag requesting unregistration.
const RSEQ_FLAG_UNREGISTER: u32 = 1 << 0;

/// Value stored in `cpu_id` while no rseq area is active.
const RSEQ_CPU_ID_UNINITIALIZED: u32 = u32::MAX;

/// User-space layout of the original 32-byte `struct rseq` ABI.
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RseqArea {
    pub cpu_id_start: u32,
    pub cpu_id: u32,
    pub rseq_cs: u64,
    pub flags: u32,
    pub node_id: u32,
    pub mm_cid: u32,
}

/// User-space layout of the `struct rseq_cs` critical-section descriptor.
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default, Pod)]
pub(crate) struct RseqCs {
    pub version: u32,
    pub flags: u32,
    pub start_ip: u64,
    pub post_commit_offset: u64,
    pub abort_ip: u64,
}

pub(super) fn sys_rseq(
    rseq_ptr: Vaddr,
    rseq_len: u32,
    flags: u32,
    sig: u32,
    ctx: &Context,
) -> Result<SyscallReturn> {
    if flags & RSEQ_FLAG_UNREGISTER != 0 {
        if flags != RSEQ_FLAG_UNREGISTER {
            return_errno_with_message!(Errno::EINVAL, "unsupported rseq flags");
        }

        let Some(rseq) = ctx.thread_local.rseq().get() else {
            return_errno_with_message!(Errno::EINVAL, "rseq is not registered");
        };
        if rseq.user_ptr != rseq_ptr || rseq.len != rseq_len {
            return_errno_with_message!(
                Errno::EINVAL,
                "rseq area does not match the registered one"
            );
        }
        if rseq.sig != sig {
            return_errno_with_message!(Errno::EPERM, "rseq signature does not match");
        }

        write_rseq_ids(
            ctx,
            rseq_ptr,
            RSEQ_CPU_ID_UNINITIALIZED,
            RSEQ_CPU_ID_UNINITIALIZED,
        )?;
        ctx.user_space()
            .write_val(rseq_ptr + offset_of!(RseqArea, rseq_cs), &0u64)?;
        ctx.thread_local.rseq().set(None);
        return Ok(SyscallReturn::Return(0));
    }

    if flags != 0 {
        return_errno_with_message!(Errno::EINVAL, "unsupported rseq flags");
    }

    if let Some(rseq) = ctx.thread_local.rseq().get() {
        if rseq.user_ptr != rseq_ptr || rseq.len != rseq_len {
            return_errno_with_message!(
                Errno::EINVAL,
                "rseq is already registered with a different area"
            );
        }
        if rseq.sig != sig {
            return_errno_with_message!(Errno::EPERM, "rseq signature does not match");
        }
        return_errno_with_message!(Errno::EBUSY, "rseq is already registered");
    }

    if rseq_len != RSEQ_AREA_SIZE || !rseq_ptr.is_multiple_of(32) {
        return_errno_with_message!(Errno::EINVAL, "invalid rseq area");
    }
    if !is_userspace_vaddr(rseq_ptr) || !is_userspace_vaddr(rseq_ptr + RSEQ_AREA_SIZE as usize - 1)
    {
        return_errno_with_message!(Errno::EFAULT, "invalid rseq area address");
    }

    let cpu_id: u32 = CpuId::current_racy().into();
    write_rseq_ids(ctx, rseq_ptr, cpu_id, cpu_id)?;
    ctx.user_space()
        .write_val(rseq_ptr + offset_of!(RseqArea, rseq_cs), &0u64)?;
    ctx.user_space()
        .write_val(rseq_ptr + offset_of!(RseqArea, flags), &0u32)?;
    ctx.user_space()
        .write_val(rseq_ptr + offset_of!(RseqArea, node_id), &0u32)?;
    ctx.user_space()
        .write_val(rseq_ptr + offset_of!(RseqArea, mm_cid), &0u32)?;

    ctx.thread_local.rseq().set(Some(Rseq {
        user_ptr: rseq_ptr,
        len: rseq_len,
        sig,
        last_cpu_id: cpu_id,
        needs_ip_fixup: false,
    }));
    Ok(SyscallReturn::Return(0))
}

/// Updates the CPU IDs in the thread's rseq area when the thread has been
/// rescheduled onto a different CPU.
pub(crate) fn rseq_update_cpu_id(ctx: &Context) {
    let Some(rseq) = ctx.thread_local.rseq().get() else {
        return;
    };

    let cpu_id: u32 = CpuId::current_racy().into();
    if rseq.last_cpu_id == cpu_id {
        return;
    }

    let result = (|| -> Result<()> {
        let user_space = ctx.user_space();
        user_space.write_val(rseq.user_ptr + offset_of!(RseqArea, cpu_id_start), &cpu_id)?;
        user_space.write_val(rseq.user_ptr + offset_of!(RseqArea, cpu_id), &cpu_id)?;
        Ok(())
    })();
    if result.is_err() {
        return;
    }

    ctx.thread_local.rseq().set(Some(Rseq {
        last_cpu_id: cpu_id,
        ..rseq
    }));
}

/// Marks a thread as potentially interrupted inside an rseq critical section
/// because it is being scheduled away.
pub(crate) fn rseq_mark_preempted(thread_local: &ThreadLocal) {
    let Some(rseq) = thread_local.rseq().get() else {
        return;
    };
    thread_local.rseq().set(Some(Rseq {
        needs_ip_fixup: true,
        ..rseq
    }));
}

/// Aborts a critical section if the thread was scheduled away while inside it.
pub(crate) fn rseq_ip_fixup_if_preempted(ctx: &Context, user_ctx: &mut UserContext) {
    let Some(rseq) = ctx.thread_local.rseq().get() else {
        return;
    };
    if !rseq.needs_ip_fixup {
        return;
    }
    ctx.thread_local.rseq().set(Some(Rseq {
        needs_ip_fixup: false,
        ..rseq
    }));
    rseq_ip_fixup(ctx, user_ctx);
}

/// Aborts a critical section if the saved user instruction pointer falls
/// inside it, restarting execution at the abort handler.
pub(crate) fn rseq_ip_fixup(ctx: &Context, user_ctx: &mut UserContext) {
    let Some(rseq) = ctx.thread_local.rseq().get() else {
        return;
    };

    let Ok(csaddr) = ctx
        .user_space()
        .read_val::<u64>(rseq.user_ptr + offset_of!(RseqArea, rseq_cs))
    else {
        return;
    };
    if csaddr == 0 || !is_userspace_vaddr(csaddr as usize) {
        return;
    }

    let Ok(cs) = ctx.user_space().read_val::<RseqCs>(csaddr as usize) else {
        return;
    };
    // Only the original ABI version and no flags are supported.
    if cs.version != 0 || cs.flags != 0 {
        return;
    }

    let ip = user_ctx.instruction_pointer() as u64;
    let Some(end_ip) = cs.start_ip.checked_add(cs.post_commit_offset) else {
        return;
    };
    if !is_userspace_vaddr(cs.start_ip as usize) || !is_userspace_vaddr(end_ip as usize) {
        return;
    }

    // Outside the critical section: clear the stale descriptor pointer.
    if ip < cs.start_ip || ip >= end_ip {
        let _ = ctx
            .user_space()
            .write_val(rseq.user_ptr + offset_of!(RseqArea, rseq_cs), &0u64);
        return;
    }

    // The four bytes before the abort handler must contain the signature.
    if cs.abort_ip < 4 || !is_userspace_vaddr(cs.abort_ip as usize) {
        return;
    }
    let Ok(sig) = ctx.user_space().read_val::<u32>((cs.abort_ip - 4) as usize) else {
        return;
    };
    if sig != rseq.sig {
        return;
    }

    let _ = ctx
        .user_space()
        .write_val(rseq.user_ptr + offset_of!(RseqArea, rseq_cs), &0u64);
    user_ctx.set_instruction_pointer(cs.abort_ip as usize);
}

fn write_rseq_ids(ctx: &Context, rseq_ptr: Vaddr, cpu_id_start: u32, cpu_id: u32) -> Result<()> {
    let user_space = ctx.user_space();
    user_space.write_val(rseq_ptr + offset_of!(RseqArea, cpu_id_start), &cpu_id_start)?;
    user_space.write_val(rseq_ptr + offset_of!(RseqArea, cpu_id), &cpu_id)?;
    Ok(())
}
