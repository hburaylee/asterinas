// SPDX-License-Identifier: MPL-2.0

//! Restartable sequences (rseq) system call.

use core::mem::offset_of;

use ostd::{cpu::CpuId, mm::VmIo};

use super::SyscallReturn;
use crate::{prelude::*, process::posix_thread::Rseq, vm::vmar::is_userspace_vaddr};

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

fn write_rseq_ids(
    ctx: &Context,
    rseq_ptr: Vaddr,
    cpu_id_start: u32,
    cpu_id: u32,
) -> Result<()> {
    let user_space = ctx.user_space();
    user_space.write_val(rseq_ptr + offset_of!(RseqArea, cpu_id_start), &cpu_id_start)?;
    user_space.write_val(rseq_ptr + offset_of!(RseqArea, cpu_id), &cpu_id)?;
    Ok(())
}