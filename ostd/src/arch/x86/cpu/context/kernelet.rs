// SPDX-License-Identifier: MPL-2.0

//! Borrows the common user register file across the service boundary.

use super::RawUserContext;
#[cfg(kernelet_getpid_profile)]
use crate::kernelet::getpid_profile as profile;

#[cfg(feature = "kernelet")]
pub(super) fn run_image_user(
    raw: &mut RawUserContext,
    _guard: &crate::irq::DisabledLocalIrqGuard,
) -> i32 {
    use crate::kernelet::abi::{USER_RETURN_EXCEPTION, USER_RETURN_PENDING, USER_RETURN_SYSCALL};

    // The Host borrows this task-stack object synchronously and retains no
    // pointer. Its native entry assembly writes the returned registers here.
    #[cfg(kernelet_getpid_profile)]
    let result = {
        let pre_span = profile::span(profile::stage::GUEST_USER_PRE);
        let user_run = crate::kernelet::entry::services().user_run;
        let _ = profile::end(pre_span);
        user_run(raw)
    };
    #[cfg(not(kernelet_getpid_profile))]
    let result = (crate::kernelet::entry::services().user_run)(raw);
    #[cfg(kernelet_getpid_profile)]
    let _post_span = profile::span(profile::stage::GUEST_USER_POST);
    assert_ne!(
        result,
        -(crate::kernelet::abi::INVALID as i32),
        "user context must reside on the current task's kernel stack and contain valid user addresses"
    );
    assert!(
        matches!(
            result,
            USER_RETURN_SYSCALL | USER_RETURN_EXCEPTION | USER_RETURN_PENDING
        ),
        "invalid user_run result: {result}"
    );
    result
}

#[cfg(feature = "kernelet-host")]
#[cfg_attr(not(kernelet_getpid_profile), inline(always))]
pub(crate) fn run_host_user(raw: &mut RawUserContext) -> i32 {
    use crate::kernelet::abi::{USER_RETURN_PENDING, USER_RETURN_SYSCALL};

    #[cfg(kernelet_getpid_profile)]
    let raw_span = profile::span(profile::stage::HOST_RAW_RUN);
    raw.fault_addr = raw.run(crate::irq::disable_local());
    #[cfg(kernelet_getpid_profile)]
    let _ = profile::end(raw_span);

    if raw.trap_num == 0x100 {
        USER_RETURN_SYSCALL
    } else if raw.trap_num >= crate::arch::irq::IRQ_NUM_MIN as usize {
        USER_RETURN_PENDING
    } else {
        classify_host_user_return(raw)
    }
}

#[cfg(feature = "kernelet-host")]
#[cold]
#[inline(never)]
fn classify_host_user_return(raw: &mut RawUserContext) -> i32 {
    use crate::kernelet::abi::{USER_RETURN_EXCEPTION, USER_RETURN_PENDING};

    if let Some(exception) =
        super::CpuException::from_raw(raw.trap_num, raw.error_code, raw.fault_addr)
    {
        if exception.type_().is_fault_or_trap() {
            USER_RETURN_EXCEPTION
        } else {
            // Machine events belong to the Host. Its existing policy is
            // fatal for unsupported NMIs, machine checks and aborts; never
            // turn those into a tenant exception or silently consume them.
            crate::arch::trap::handle_user_machine_exception(&mut raw.as_trap_frame());
            USER_RETURN_PENDING
        }
    } else {
        USER_RETURN_PENDING
    }
}

#[cfg(all(ktest, feature = "kernelet-host"))]
mod test {
    use super::{
        super::{FsBase, GsBase},
        *,
    };
    use crate::{
        arch::irq::HwIrqLine,
        cpu::PrivilegeLevel,
        irq::call_irq_callback_functions,
        kernelet::abi::{USER_RETURN_EXCEPTION, USER_RETURN_PENDING, USER_RETURN_SYSCALL},
        mm::{
            CachePolicy, FrameAllocOptions, PAGE_SIZE, PageFlags, PageProperty, VmSpace,
            io::util::HasVmReaderWriter,
        },
        prelude::*,
        task::disable_preempt,
    };

    const USER_CODE: usize = 0x400000;

    fn segment_bases() -> (usize, usize) {
        let guard = crate::irq::disable_local();
        let mut fsbase = FsBase::default();
        let mut gsbase = GsBase::default();
        fsbase.save();
        gsbase.save(&guard);
        (fsbase.addr(), gsbase.addr())
    }

    struct RestoreSegmentBases {
        fs: FsBase,
        gs: GsBase,
    }

    impl RestoreSegmentBases {
        fn load_user(fs: usize, gs: usize) -> Self {
            let guard = crate::irq::disable_local();
            let mut saved = Self {
                fs: FsBase::default(),
                gs: GsBase::default(),
            };
            saved.fs.save();
            saved.gs.save(&guard);
            FsBase::new(fs).load();
            GsBase::new(gs).load(&guard);
            saved
        }
    }

    impl Drop for RestoreSegmentBases {
        fn drop(&mut self) {
            let guard = crate::irq::disable_local();
            self.fs.load();
            self.gs.load(&guard);
        }
    }

    struct UserSpace {
        _space: Arc<VmSpace>,
    }

    impl UserSpace {
        fn new(code: &[u8]) -> Self {
            let space = Arc::new(VmSpace::new());
            let frame = FrameAllocOptions::new().alloc_frame().unwrap();
            frame.writer().write(&mut code.into());
            let guard = disable_preempt();
            space
                .cursor_mut(&guard, &(USER_CODE..USER_CODE + PAGE_SIZE))
                .unwrap()
                .map(
                    frame.into(),
                    PageProperty::new_user(PageFlags::RWX, CachePolicy::Writeback),
                );
            space.activate();
            Self { _space: space }
        }

        fn context(&self) -> RawUserContext {
            RawUserContext {
                general: super::super::GeneralRegs {
                    rip: USER_CODE,
                    rsp: USER_CODE + PAGE_SIZE,
                    r12: 0x123456789abcdef0,
                    ..Default::default()
                },
                rflags: 2 | (1 << 9),
                ..Default::default()
            }
        }
    }

    impl Drop for UserSpace {
        fn drop(&mut self) {
            VmSpace::deactivate();
        }
    }

    fn enter_until_event(context: &mut RawUserContext) -> i32 {
        loop {
            let reason = run_host_user(context);
            if reason == USER_RETURN_PENDING {
                let frame = context.as_trap_frame();
                call_irq_callback_functions(
                    &frame,
                    &HwIrqLine::new(frame.trap_num as u8),
                    PrivilegeLevel::User,
                );
            }
            crate::arch::irq::enable_local();
            if reason != USER_RETURN_PENDING {
                return reason;
            }
        }
    }

    #[ktest]
    fn shared_context_survives_syscall_and_exception_entry() {
        let _preempt = disable_preempt();
        // mov eax, 0x13572468; syscall; ud2.
        let space = UserSpace::new(&[0xb8, 0x68, 0x24, 0x57, 0x13, 0x0f, 0x05, 0x0f, 0x0b]);
        let mut context = space.context();
        context.rflags |= 1; // Carry must survive both entry and return.
        assert_eq!(enter_until_event(&mut context), USER_RETURN_SYSCALL);
        assert_eq!(context.rflags & (1 | 2 | (1 << 9)), 1 | 2 | (1 << 9));
        assert_eq!(context.general.rax, 0x13572468);
        assert_eq!(context.general.r12, 0x123456789abcdef0);
        assert_eq!(context.general.rip, USER_CODE + 7);
        assert_eq!(context.trap_num, 0x100);
        assert_eq!(context.fault_addr, 0);

        assert_eq!(enter_until_event(&mut context), USER_RETURN_EXCEPTION);
        assert_eq!(context.general.rip, USER_CODE + 7);
        assert_eq!(context.general.r12, 0x123456789abcdef0);
        assert_eq!(context.trap_num, 6);
        assert_eq!(context.error_code, 0);
        assert_eq!(context.rflags & (1 | 2 | (1 << 9)), 1 | 2 | (1 << 9));
    }

    #[ktest]
    fn native_user_return_leaves_shared_fault_metadata_untouched() {
        let _preempt = disable_preempt();
        let enter = |context: &mut RawUserContext| loop {
            let fault_addr = context.run(crate::irq::disable_local());
            let pending = context.trap_num >= crate::arch::irq::IRQ_NUM_MIN as usize
                && context.trap_num != 0x100;
            if pending {
                let frame = context.as_trap_frame();
                call_irq_callback_functions(
                    &frame,
                    &HwIrqLine::new(frame.trap_num as u8),
                    PrivilegeLevel::User,
                );
            }
            crate::arch::irq::enable_local();
            if !pending {
                break fault_addr;
            }
        };
        const SENTINEL: usize = 0xfeedcafe;
        let fault_addr = 0x12345000usize;
        let mut code = alloc::vec![0x48, 0xa1];
        code.extend_from_slice(&fault_addr.to_le_bytes());
        {
            let space = UserSpace::new(&code);
            let mut context = space.context();
            context.fault_addr = SENTINEL;
            assert_eq!(enter(&mut context), fault_addr);
            assert_eq!(context.trap_num, 14);
            assert_eq!(context.fault_addr, SENTINEL);
        }
        {
            let space = UserSpace::new(&[0x0f, 0x05]);
            let mut context = space.context();
            context.fault_addr = SENTINEL;
            assert_eq!(enter(&mut context), 0);
            assert_eq!(context.trap_num, 0x100);
            assert_eq!(context.fault_addr, SENTINEL);
        }
    }

    #[ktest]
    fn shared_context_captures_user_page_fault_address() {
        let _preempt = disable_preempt();
        let fault_addr = 0x12345000usize;
        // movabs rax, [fault_addr].
        let mut code = alloc::vec![0x48, 0xa1];
        code.extend_from_slice(&fault_addr.to_le_bytes());
        let space = UserSpace::new(&code);
        let mut context = space.context();
        assert_eq!(enter_until_event(&mut context), USER_RETURN_EXCEPTION);
        assert_eq!(context.trap_num, 14);
        assert_eq!(context.fault_addr, fault_addr);
        assert_eq!(context.general.rip, USER_CODE);
        assert_eq!(context.general.r12, 0x123456789abcdef0);
        assert_eq!(context.error_code & 7, 4);
    }

    #[ktest]
    fn shared_context_uses_loaded_segment_bases() {
        let _preempt = disable_preempt();
        let fs_value = 0x123456789abcdef0u64;
        let gs_value = 0xfedcba9876543210u64;
        // mov rax, fs:[0]; mov rbx, gs:[0]; syscall; ud2.
        let mut code = alloc::vec![
            0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x65, 0x48, 0x8b, 0x1c, 0x25, 0, 0, 0, 0,
            0x0f, 0x05, 0x0f, 0x0b,
        ];
        code.resize(0x100, 0);
        code.extend_from_slice(&fs_value.to_le_bytes());
        code.extend_from_slice(&gs_value.to_le_bytes());
        let space = UserSpace::new(&code);
        let mut context = space.context();
        let host_bases = segment_bases();
        let user_bases = (USER_CODE + 0x100, USER_CODE + 0x108);
        let restore = RestoreSegmentBases::load_user(user_bases.0, user_bases.1);

        assert_eq!(enter_until_event(&mut context), USER_RETURN_SYSCALL);
        assert_eq!(context.general.rax, fs_value as usize);
        assert_eq!(context.general.rbx, gs_value as usize);
        assert_eq!(segment_bases(), user_bases);

        assert_eq!(enter_until_event(&mut context), USER_RETURN_EXCEPTION);
        assert_eq!(context.trap_num, 6);
        assert_eq!(segment_bases(), user_bases);
        drop(restore);
        assert_eq!(segment_bases(), host_bases);
    }

    #[ktest]
    fn user_written_segment_bases_remain_live_after_syscall() {
        let _preempt = disable_preempt();
        let user_bases = (USER_CODE + 0x200, USER_CODE + 0x208);
        // movabs rax, fs; wrfsbase rax; movabs rax, gs; wrgsbase rax;
        // syscall; ud2.
        let mut code = alloc::vec![0x48, 0xb8];
        code.extend_from_slice(&user_bases.0.to_le_bytes());
        code.extend_from_slice(&[0xf3, 0x48, 0x0f, 0xae, 0xd0, 0x48, 0xb8]);
        code.extend_from_slice(&user_bases.1.to_le_bytes());
        code.extend_from_slice(&[0xf3, 0x48, 0x0f, 0xae, 0xd8, 0x0f, 0x05, 0x0f, 0x0b]);
        let space = UserSpace::new(&code);
        let mut context = space.context();
        let host_bases = segment_bases();
        let restore = RestoreSegmentBases::load_user(0, 0);

        assert_eq!(enter_until_event(&mut context), USER_RETURN_SYSCALL);
        assert_eq!(segment_bases(), user_bases);
        assert_eq!(enter_until_event(&mut context), USER_RETURN_EXCEPTION);
        assert_eq!(context.trap_num, 6);
        assert_eq!(segment_bases(), user_bases);
        drop(restore);
        assert_eq!(segment_bases(), host_bases);
    }
}
