// SPDX-License-Identifier: MPL-2.0

//! Adapts OSTD's private x86 user register file to the kernelet service ABI.

use super::{GeneralRegs, RawUserContext};
use crate::kernelet::abi::KletUserContext;

fn to_wire(raw: &RawUserContext) -> KletUserContext {
    let regs = &raw.general;
    KletUserContext {
        rax: regs.rax as u64,
        rbx: regs.rbx as u64,
        rcx: regs.rcx as u64,
        rdx: regs.rdx as u64,
        rsi: regs.rsi as u64,
        rdi: regs.rdi as u64,
        rbp: regs.rbp as u64,
        rsp: regs.rsp as u64,
        r8: regs.r8 as u64,
        r9: regs.r9 as u64,
        r10: regs.r10 as u64,
        r11: regs.r11 as u64,
        r12: regs.r12 as u64,
        r13: regs.r13 as u64,
        r14: regs.r14 as u64,
        r15: regs.r15 as u64,
        rip: regs.rip as u64,
        rflags: regs.rflags as u64,
        fsbase: 0,
        gsbase: 0,
        trap_num: 0,
        error_code: 0,
        fault_addr: 0,
    }
}

fn from_wire(wire: &KletUserContext) -> RawUserContext {
    RawUserContext {
        general: GeneralRegs {
            rax: wire.rax as usize,
            rbx: wire.rbx as usize,
            rcx: wire.rcx as usize,
            rdx: wire.rdx as usize,
            rsi: wire.rsi as usize,
            rdi: wire.rdi as usize,
            rbp: wire.rbp as usize,
            rsp: wire.rsp as usize,
            r8: wire.r8 as usize,
            r9: wire.r9 as usize,
            r10: wire.r10 as usize,
            r11: wire.r11 as usize,
            r12: wire.r12 as usize,
            r13: wire.r13 as usize,
            r14: wire.r14 as usize,
            r15: wire.r15 as usize,
            rip: wire.rip as usize,
            rflags: wire.rflags as usize,
        },
        trap_num: wire.trap_num as usize,
        error_code: wire.error_code as usize,
    }
}

fn update_wire(wire: &mut KletUserContext, raw: &RawUserContext) {
    let fsbase = wire.fsbase;
    let gsbase = wire.gsbase;
    let fault_addr = wire.fault_addr;
    *wire = to_wire(raw);
    wire.fsbase = fsbase;
    wire.gsbase = gsbase;
    wire.fault_addr = fault_addr;
    wire.trap_num = raw.trap_num as u64;
    wire.error_code = raw.error_code as u64;
}

#[cfg(feature = "kernelet")]
pub(super) fn run_image_user(
    raw: &mut RawUserContext,
    guard: crate::irq::DisabledLocalIrqGuard,
) -> bool {
    use crate::kernelet::abi::{USER_RETURN_EXCEPTION, USER_RETURN_PENDING, USER_RETURN_SYSCALL};

    let mut wire = to_wire(raw);
    wire.fsbase = super::KERNELET_USER_FS_BASE.load() as u64;
    wire.gsbase = super::KERNELET_USER_GS_BASE.load() as u64;
    // The image resumes with virtual IRQs masked. `execute` reenables them
    // after interpreting the service result, as it does for native entry.
    let result = (crate::kernelet::entry::services().user_run)(&mut wire);
    assert!(
        matches!(
            result,
            USER_RETURN_SYSCALL | USER_RETURN_EXCEPTION | USER_RETURN_PENDING
        ),
        "invalid user_run result: {result}"
    );
    core::mem::forget(guard);
    *raw = from_wire(&wire);
    super::KERNELET_USER_FS_BASE.store(wire.fsbase as usize);
    super::KERNELET_USER_GS_BASE.store(wire.gsbase as usize);
    super::KERNELET_USER_FAULT_ADDR.store(wire.fault_addr as usize);
    result == USER_RETURN_PENDING
}

#[cfg(not(feature = "kernelet"))]
pub(crate) fn run_host_user(
    wire: &mut KletUserContext,
) -> (i64, Option<crate::arch::trap::TrapFrame>) {
    use super::{FsBase, GsBase, UserContext};
    use crate::{
        kernelet::abi::{USER_RETURN_EXCEPTION, USER_RETURN_PENDING, USER_RETURN_SYSCALL},
        user::UserContextApiInternal,
    };

    let guard = crate::irq::disable_local();
    let mut old_fs = FsBase::default();
    let mut old_gs = GsBase::default();
    old_fs.save();
    old_gs.save(&guard);
    FsBase::new(wire.fsbase as usize).load();
    GsBase::new(wire.gsbase as usize).load(&guard);

    let mut raw = from_wire(wire);
    raw.run(guard);
    let fault_addr = if raw.trap_num == 14 {
        x86_64::registers::control::Cr2::read_raw()
    } else {
        0
    };
    let guard = crate::irq::disable_local();
    let mut user_fs = FsBase::default();
    let mut user_gs = GsBase::default();
    user_fs.save();
    user_gs.save(&guard);
    old_fs.load();
    old_gs.load(&guard);
    update_wire(wire, &raw);
    wire.fsbase = user_fs.addr() as u64;
    wire.gsbase = user_gs.addr() as u64;
    wire.fault_addr = fault_addr;

    if raw.trap_num == 0x100 {
        (USER_RETURN_SYSCALL, None)
    } else if raw.trap_num <= 31 {
        (USER_RETURN_EXCEPTION, None)
    } else {
        let context = UserContext {
            user_context: raw,
            exception: None,
        };
        (USER_RETURN_PENDING, Some(context.as_trap_frame()))
    }
}
