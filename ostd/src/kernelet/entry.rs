// SPDX-License-Identifier: MPL-2.0

//! The fixed entry into a separately linked kernelet image.

use core::{
    arch::asm,
    fmt::{self, Write},
    sync::atomic::{AtomicPtr, Ordering},
};

use super::abi::{
    BootArgs, ClockPage, CopyFaultRecord, DeviceEntry, EntryTable, STOP_PANIC, ServiceTable,
    VIRQ_LINES, VIRQ_TICK, VcpuRecord, copy_fault_records_offset, vcpu_shared_bytes,
};
use crate::mm::PAGE_SIZE;

const ENTRY_TABLE_OFFSET: usize = 0x1000;

unsafe extern "C" {
    static __kernelet_image_base: u8;
}

// Entry publishes the Host-pinned pointers before any boot-page accessor or
// Host service runs.
#[unsafe(no_mangle)]
static KERNELET_SERVICES: AtomicPtr<ServiceTable> = AtomicPtr::new(core::ptr::null_mut());
#[unsafe(no_mangle)]
pub(crate) static KERNELET_BOOT_ARGS: AtomicPtr<BootArgs> = AtomicPtr::new(core::ptr::null_mut());

/// Starts virtual CPU zero on its boot stack.
///
/// The Host validates the entry target and both argument mappings before the
/// call. The boot page remains mapped for the instance lifetime.
///
/// # Safety
///
/// OSDK's validated Host must call this once on vCPU zero's initialized boot
/// stack. `boot` must back the complete immutable boot mapping and every
/// referenced shared page for the instance lifetime; `services` must be the
/// matching Host table. The current carrier and CPU-local replica must agree.
// SAFETY: OSDK links this symbol into the kernelet image only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _kernelet_entry(services: &'static ServiceTable, boot: &BootArgs) -> ! {
    KERNELET_SERVICES.store(core::ptr::from_ref(services).cast_mut(), Ordering::Release);
    KERNELET_BOOT_ARGS.store(core::ptr::from_ref(boot).cast_mut(), Ordering::Release);

    if services.size != size_of::<ServiceTable>() as u64 {
        loop {
            core::hint::spin_loop();
        }
    }
    let entry_table_ptr = core::ptr::addr_of!(__kernelet_image_base)
        .wrapping_add(ENTRY_TABLE_OFFSET)
        .cast::<EntryTable>();
    // SAFETY: OSDK places the table at this fixed, aligned offset and the
    // Host validates its size and mapping before entering the image.
    let entry_table = unsafe { &*entry_table_ptr };
    let record_pages = vcpu_shared_bytes(boot.num_vcpus as usize).div_ceil(PAGE_SIZE);
    let run_bytes = u64::from(boot.max_meta_sections)
        * (super::abi::META_SECTION_BYTES / super::abi::GRAIN_SIZE) as u64
        * size_of::<super::abi::RunDesc>() as u64;
    let run_end =
        u64::from(boot.grant_table) + run_bytes.div_ceil(PAGE_SIZE as u64) * PAGE_SIZE as u64;
    let reverse_bytes = u64::from(boot.max_meta_sections) * size_of::<u32>() as u64;
    let bitmap_offset = u64::from(boot.meta_block_sections)
        + reverse_bytes.div_ceil(PAGE_SIZE as u64) * PAGE_SIZE as u64;
    let bitmap_end = bitmap_offset + u64::from(boot.max_meta_sections) * size_of::<u64>() as u64;
    if boot.size != size_of::<BootArgs>() as u32
        || entry_table.size != size_of::<EntryTable>() as u64
        || boot.source_hash != entry_table.source_hash
        || (boot.num_vcpus == 0 || boot.num_vcpus as usize > super::abi::MAX_VCPUS)
        || boot.vcpu_records != PAGE_SIZE as u32
        || boot.clock_page != ((1 + record_pages) * PAGE_SIZE) as u32
        || boot.info_page != boot.clock_page + PAGE_SIZE as u32
        || boot.max_meta_sections == 0
        || boot.grant_table != boot.info_page + PAGE_SIZE as u32
        || u64::from(boot.meta_section_index) < run_end
        || !boot.meta_section_index.is_multiple_of(PAGE_SIZE as u32)
        || boot.meta_block_sections <= boot.meta_section_index
        || !boot.meta_block_sections.is_multiple_of(PAGE_SIZE as u32)
        || u64::from(boot.meta_grain_bitmap) != bitmap_offset
        || bitmap_end > u64::from(u32::MAX)
        || (boot.cmdline_offset as usize) < size_of::<BootArgs>()
        || (boot.cmdline_offset as usize)
            .checked_add(boot.cmdline_len as usize)
            .is_none_or(|end| end > PAGE_SIZE)
        || (boot.devices_offset as usize)
            < (boot.cmdline_offset as usize + boot.cmdline_len as usize)
        || !(boot.devices_offset as usize).is_multiple_of(align_of::<DeviceEntry>())
        || (boot.devices_offset as usize)
            .checked_add(boot.num_devices as usize * size_of::<DeviceEntry>())
            .is_none_or(|end| end > PAGE_SIZE)
        || boot.reserved != 0
    {
        const MESSAGE: &[u8] = b"invalid kernelet boot ABI";
        (services.stop)(STOP_PANIC, 0, MESSAGE.as_ptr(), MESSAGE.len() as u32);
    }

    let boot = boot_args();
    let cmdline_start =
        (boot as *const BootArgs as *const u8).wrapping_add(boot.cmdline_offset as usize);
    // SAFETY: The validated range lies in the Host-pinned, read-only boot page.
    let cmdline_bytes: &'static [u8] =
        unsafe { core::slice::from_raw_parts(cmdline_start, boot.cmdline_len as usize) };
    let cmdline = match core::str::from_utf8(cmdline_bytes) {
        Ok(cmdline) => cmdline,
        Err(_) => {
            const MESSAGE: &[u8] = b"invalid kernelet command line";
            (services.stop)(STOP_PANIC, 0, MESSAGE.as_ptr(), MESSAGE.len() as u32)
        }
    };
    let early_cmdline = crate::boot::parse_early_cmdline_from(cmdline);
    crate::log::init(&early_cmdline);
    crate::console::init_kernelet_logging();
    crate::arch::init_kernelet_cpu_features();
    crate::cpu::init_kernelet_bsp();
    let regions = crate::kernelet::image_grant::init_initial_grant();
    crate::sync::init();
    crate::boot::init_kernelet(cmdline, regions);
    crate::task::adopt_boot_task();
    crate::arch::irq::enable_local();
    crate::invoke_ffi_init_funcs();
    crate::boot::smp::boot_all_aps();
    crate::IN_BOOTSTRAP_CONTEXT.store(false, Ordering::Release);

    unsafe extern "Rust" {
        fn __ostd_main() -> !;
    }
    // SAFETY: The kernel proper linked into this image defines `__ostd_main`.
    unsafe { __ostd_main() }
}

/// Returns the immutable boot page installed at image entry.
pub fn boot_args() -> &'static BootArgs {
    let ptr = KERNELET_BOOT_ARGS.load(Ordering::Acquire);
    assert!(!ptr.is_null(), "boot arguments used before image entry");
    // SAFETY: The Host maps and pins the read-only boot page until the image
    // stops, and the pointer is published before the kernel proper starts.
    unsafe { &*ptr }
}

/// Reads the Host's one-field monotonic clock snapshot.
pub fn clock_now_ns() -> u64 {
    let boot = boot_args();
    let ptr = (boot as *const BootArgs as *const u8)
        .wrapping_add(boot.clock_page as usize)
        .cast::<ClockPage>();
    // SAFETY: Entry validation checked the page offset and the Host maps and
    // pins the clock frame read-only for the lifetime of every carrier.
    let page = unsafe { &*ptr };
    page.monotonic_ns.load(Ordering::Relaxed)
}

/// Reads realtime nanoseconds since the Unix epoch from the virtual clock.
pub fn realtime_now_ns() -> u64 {
    let boot = boot_args();
    boot.realtime_base_ns
        .saturating_add(clock_now_ns().saturating_sub(boot.monotonic_base_ns))
}

/// Returns the immutable virtual-device descriptions in the boot page.
pub fn devices() -> &'static [DeviceEntry] {
    let boot = boot_args();
    let ptr = (boot as *const BootArgs as *const u8)
        .wrapping_add(boot.devices_offset as usize)
        .cast::<DeviceEntry>();
    // SAFETY: Entry validation checked the aligned range, and the Host pins
    // the read-only boot page for the instance lifetime.
    unsafe { core::slice::from_raw_parts(ptr, boot.num_devices as usize) }
}

/// Returns the shared cooperation record for the current virtual CPU.
pub(crate) fn vcpu_record() -> &'static VcpuRecord {
    let record: *const VcpuRecord;
    // SAFETY: The complete lookup is nonredirectable and the Host pins the
    // validated records for the image lifetime. This accessor stays inside
    // OSTD: exposing writable cooperation fields would invalidate IRQ guards.
    unsafe {
        crate::arch::cpu::local::record_asm!("mov {record}, {record_base}";
            record = out(reg) record,
            options(nostack, readonly),
        );
        &*record
    }
}

pub(crate) fn record_for_vcpu(vcpu: usize) -> &'static VcpuRecord {
    let boot = boot_args();
    assert!(vcpu < boot.num_vcpus as usize);
    let ptr = (boot as *const BootArgs as *const u8)
        .wrapping_add(boot.vcpu_records as usize + vcpu * size_of::<VcpuRecord>())
        .cast::<VcpuRecord>();
    // SAFETY: The Host pins the complete validated record array until all carriers detach.
    unsafe { &*ptr }
}

/// Returns the recoverable user-copy state for this virtual CPU.
pub(crate) fn copy_fault_record() -> &'static CopyFaultRecord {
    let boot = boot_args();
    let vcpu = vcpu_record().vcpu as usize;
    let offset = boot.vcpu_records as usize
        + copy_fault_records_offset(boot.num_vcpus as usize)
        + vcpu * size_of::<CopyFaultRecord>();
    let ptr = (boot as *const BootArgs as *const u8)
        .wrapping_add(offset)
        .cast::<CopyFaultRecord>();
    // SAFETY: The Host pins and maps both arrays for the instance lifetime.
    unsafe { &*ptr }
}

/// Publishes one nested internal preemption guard to the virtual CPU record.
pub(crate) fn enter_preempt_guard() {
    let record = vcpu_record();
    debug_assert_ne!(record.irq_off.load(Ordering::Relaxed), 0);
    // The caller masks virtual IRQs across both count updates. This vCPU is
    // the only writer; native carrier preemption cannot introduce another one.
    let next = record
        .guards
        .load(Ordering::Relaxed)
        .checked_add(1)
        .expect("kernelet preemption guard count overflow");
    record.guards.store(next, Ordering::Release);
}

/// Releases one internal preemption guard after the image's own count drops.
pub(crate) fn leave_preempt_guard() {
    let record = vcpu_record();
    debug_assert_ne!(record.irq_off.load(Ordering::Relaxed), 0);
    // As on entry, virtual IRQ masking excludes another image-side writer.
    let next = record
        .guards
        .load(Ordering::Relaxed)
        .checked_sub(1)
        .expect("kernelet preemption guard count underflow");
    record.guards.store(next, Ordering::Release);
}

/// Whether a virtual interrupt was deferred by the current Task.
pub(crate) enum PendingDelivery {
    Handled,
    DeferredByCurrentTask,
}

/// Delivers level-triggered virtual-device lines at a safe image boundary.
pub(crate) fn deliver_pending() -> PendingDelivery {
    use crate::{
        arch::{irq::HwIrqLine, trap::TrapFrame},
        cpu::PrivilegeLevel,
        irq::{InterruptLevel, call_irq_callback_functions},
    };

    if super::image_grant::is_dying() {
        // The Host publishes stop before this notice. The service gate takes
        // the fixed exit path without admitting another callback or schedule.
        (services().vcpu_yield)();
        return PendingDelivery::Handled;
    }
    let record = vcpu_record();
    if record.pending.load(Ordering::Acquire) == 0 {
        return PendingDelivery::Handled;
    }
    // Claim this pending batch with virtual IRQs masked. Host physical IRQs
    // may still arrive while callbacks run; their virtual events stay queued
    // until this upcall returns to task context.
    let was_off = record.irq_off.swap(1, Ordering::AcqRel);
    // An upcall's scheduler check, or a scheduler decision before its context
    // switch, may disable and re-enable virtual IRQs. Leave the pending batch
    // for the next safe boundary on this Task. A newly scheduled Task can
    // receive it without reentering the suspended Task's scheduler call.
    if crate::task::virq_delivery_deferred() {
        record.irq_off.store(was_off, Ordering::Release);
        return PendingDelivery::DeferredByCurrentTask;
    }
    // Upcalls enter only from task context. Pending events arriving during
    // a handler remain queued until its task-context continuation resumes.
    let level = InterruptLevel::current();
    if !level.is_task_context() {
        record.irq_off.store(was_off, Ordering::Release);
        return PendingDelivery::Handled;
    }
    // Retain the interrupted Task's identity without an extra Arc count.
    // Advance its progress before the epilogue is allowed to switch Tasks.
    let batch_task = crate::task::Task::current();
    let pending = record.pending.swap(0, Ordering::AcqRel);
    #[cfg(kernelet_getpid_profile)]
    if pending != 0 {
        super::getpid_profile::event(super::getpid_profile::event_id::VIRTUAL_IRQ);
    }
    if pending & super::abi::VIRQ_KICK != 0 {
        super::image_grant::rescan_grants();
        crate::smp::do_virtual_inter_processor_call();
        crate::task::scheduler::check_preempt_after_virtual_kick();
    }
    // Replay the tick snapshot before device callbacks. A shared callback
    // limit would let continuously raised device lines starve the timer.
    // New ticks and lines remain queued for the next upcall.
    if pending & VIRQ_TICK != 0 {
        if let Some(task) = batch_task.as_ref() {
            task.flush_sampled_ticks();
        }
        let user = record.tick_user.swap(0, Ordering::AcqRel);
        for _ in 0..user {
            crate::irq::call_virtual_timer_callback_functions(
                &TrapFrame::default(),
                PrivilegeLevel::User,
            );
        }
        let kernel = record.tick_kernel.swap(0, Ordering::AcqRel);
        for _ in 0..kernel {
            crate::irq::call_virtual_timer_callback_functions(
                &TrapFrame::default(),
                PrivilegeLevel::Kernel,
            );
        }
        let l2 = record.tick_l2.swap(0, Ordering::AcqRel);
        for _ in 0..l2 {
            crate::irq::call_virtual_l2_timer_callback_functions(&TrapFrame::default());
        }
    }
    if pending & VIRQ_LINES != 0 {
        for (word, lines) in record.pending_lines.iter().enumerate() {
            let mut lines = lines.swap(0, Ordering::AcqRel);
            while lines != 0 {
                let bit = lines.trailing_zeros() as usize;
                lines &= lines - 1;
                let line = word * 64 + bit;
                if line >= 32 {
                    call_irq_callback_functions(
                        &TrapFrame::default(),
                        &HwIrqLine::new(line as u8),
                        PrivilegeLevel::Kernel,
                    );
                }
            }
        }
    }
    if pending != 0 {
        if let Some(task) = batch_task {
            task.complete_virq_batch();
        }
    }
    finish_virtual_interrupt();
    PendingDelivery::Handled
}

fn finish_virtual_interrupt() {
    // Capture the level before re-enabling virtual IRQs; the scheduler and RCU
    // checks below belong to the context in which this upcall completed.
    let task_context = crate::irq::InterruptLevel::current().is_task_context();
    debug_assert!(!crate::task::virq_delivery_deferred());
    let _virq_deferral = crate::task::VirtualIrqDeferral::new();
    vcpu_record().irq_off.store(0, Ordering::Release);
    // The current Task's deferral mark prevents a guard inside reschedule from
    // replaying a remaining batch on this stack. A Task switch preserves the
    // mark on the suspended Task, while the next Task can receive the notice.
    // L1 callbacks leave their scheduling request for the outer L0 epilogue.
    if task_context && crate::task::Task::current().is_some() {
        // Bootstrap must reach its explicit first scheduling point. An IRQ
        // must not abandon CPU initialization before its idle Task is queued.
        crate::task::scheduler::might_preempt();
    }
    // A busy vCPU can finish many upcalls without switching internal Tasks.
    // Report a quiescent point after the handler and any preemption, once no
    // read-side section can still span the completed interrupt.
    if task_context
        && vcpu_record().guards.load(Ordering::Acquire) == 0
        && crate::arch::irq::is_local_enabled()
        // The one-shot boot Task cannot run callbacks that sleep or yield.
        // The first ordinary Task will report quiescence and dispatch them.
        && !crate::task::in_boot_task()
    {
        // SAFETY: The virtual IRQ has completed in ordinary Task context,
        // with no guard or RCU reader carried across this boundary.
        unsafe { crate::sync::finish_grace_period() };
    }
}

/// Returns the Host service table installed at image entry.
pub(crate) fn services() -> &'static ServiceTable {
    let ptr = KERNELET_SERVICES.load(Ordering::Acquire);
    assert!(!ptr.is_null(), "kernelet services used before image entry");
    // SAFETY: `_kernelet_entry` stores a Host-owned static table that remains
    // mapped for the image lifetime before any kernel-proper entry is called.
    unsafe { &*ptr }
}

/// Reports a kernel oops, retaining the Host's service result.
///
/// The Host accepts at most 1024 bytes of the message.
pub fn report_oops(message: &str) -> i64 {
    let mut len = message.len().min(1024);
    while !message.is_char_boundary(len) {
        len -= 1;
    }
    (services().oops)(message.as_ptr(), len as u32)
}

/// Returns the safe virtual-CPU kick service for boundary measurements.
///
/// The Host validates the target virtual CPU before publishing a kick.
pub fn vcpu_kick_service() -> extern "C" fn(u32) -> i64 {
    services().vcpu_kick
}

/// Returns the successful diagnostic service through its normal Host gate.
#[cfg(kernelet_rq1)]
pub fn rq1_echo_service() -> extern "C" fn(u64) -> i64 {
    services().rq1_echo
}

/// Reports an unrecoverable image panic to the Host without allocating.
pub fn stop_panic(message: fmt::Arguments<'_>) -> ! {
    // Larger than the status field so the Host can report truncation.
    const PANIC_RECORD_BYTES: usize = 1024;

    struct BoundedMessage {
        bytes: [u8; PANIC_RECORD_BYTES],
        len: usize,
    }

    impl Write for BoundedMessage {
        fn write_str(&mut self, text: &str) -> fmt::Result {
            let mut len = text.len().min(self.bytes.len() - self.len);
            while !text.is_char_boundary(len) {
                len -= 1;
            }
            self.bytes[self.len..self.len + len].copy_from_slice(&text.as_bytes()[..len]);
            self.len += len;
            Ok(())
        }
    }

    let mut record = BoundedMessage {
        bytes: [0; PANIC_RECORD_BYTES],
        len: 0,
    };
    let _ = record.write_fmt(message);
    (services().stop)(STOP_PANIC, 0, record.bytes.as_ptr(), record.len as u32)
}

/// Starts a secondary virtual CPU with the same boot protocol.
///
/// # Safety
///
/// The Host must enter this once on the dedicated carrier's initialized boot
/// stack and CPU-local replica, after vCPU zero publishes the shared boot state.
// SAFETY: OSDK links this fixed symbol into the entry table.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vcpu_entry() -> ! {
    let vcpu = vcpu_record().vcpu;
    // SAFETY: This dedicated carrier enters its initialized replica only once.
    unsafe { crate::cpu::init_on_ap(vcpu) };
    crate::arch::init_kernelet_cpu_features();
    crate::boot::smp::kernelet_ap_entry()
}

// Both returning stubs enter with IF clear and RSP pointing at the two retired
// trap words: the original RIP and RSP. The remaining five words still hold
// the first IRET frame. Save flags before changing them, then save all GPRs.
// The original IF was set, which the Host's redirect gate requires.
macro_rules! returning_stub {
    ($name:ident, $dispatch:ident) => {
        // SAFETY: Only the checked Host trap-return hook enters these symbols.
        // The linker publishes their complete executable range to the Host.
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        #[unsafe(link_section = ".text.kernelet_stubs")]
        #[doc = concat!("The fixed trap-return target `", stringify!($name), "`.")]
        ///
        /// # Safety
        ///
        /// Only the validated Host trap-return gate may enter this symbol,
        /// with physical IRQs masked and the documented saved trap frame.
        pub unsafe extern "C" fn $name() -> ! {
            core::arch::naked_asm!(
                "endbr64",
                "pushfq",
                "push rax",
                "push rbx",
                "push rcx",
                "push rdx",
                "push rsi",
                "push rdi",
                "push rbp",
                "push r8",
                "push r9",
                "push r10",
                "push r11",
                "push r12",
                "push r13",
                "push r14",
                "push r15",
                "mov rbx, rsp",
                "and rsp, -16",
                "cld",
                "sti",
                "call {dispatch}",
                "cli",
                "mov rsp, rbx",
                // Read every source before writing the overlapping IRET frame.
                // Fifteen saved GPRs and saved RFLAGS precede the hand-off.
                "mov rax, [rsp + 128]",
                "mov rcx, [rsp + 152]",
                // PUSHFQ clears RF in its saved image. The first IRET's saved
                // RFLAGS word retains it, along with all the other flags.
                "mov rdx, [rsp + 160]",
                "or rdx, 512",
                "mov rsi, [rsp + 136]",
                "mov rdi, [rsp + 176]",
                "mov [rsp + 128], rax",
                "mov [rsp + 136], rcx",
                "mov [rsp + 144], rdx",
                "mov [rsp + 152], rsi",
                "mov [rsp + 160], rdi",
                "pop r15",
                "pop r14",
                "pop r13",
                "pop r12",
                "pop r11",
                "pop r10",
                "pop r9",
                "pop r8",
                "pop rbp",
                "pop rdi",
                "pop rsi",
                "pop rdx",
                "pop rcx",
                "pop rbx",
                "pop rax",
                "add rsp, 8",
                "iretq",
                dispatch = sym $dispatch,
            )
        }
    };
}

returning_stub!(virq_entry, virq_dispatch);
returning_stub!(yield_entry, yield_dispatch);

extern "C" fn yield_dispatch() {
    (services().vcpu_yield)();
}

/// Terminates a carrier without touching its possibly exhausted Task stack.
///
/// # Safety
///
/// Only the checked Host trap-return gate may enter with the documented
/// saved frame and the matching pinned Host service table.
// SAFETY: Only a checked Host redirect enters this symbol. The Host's fixed
// stop prologue installs its protected stack before invoking Rust code.
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.kernelet_stubs")]
pub unsafe extern "C" fn exit_entry() -> ! {
    core::arch::naked_asm!(
        "endbr64",
        "xor edi, edi",
        "xor esi, esi",
        "xor edx, edx",
        "xor ecx, ecx",
        "mov rax, [rip + {services}]",
        "jmp qword ptr [rax + {stop_offset}]",
        services = sym KERNELET_SERVICES,
        stop_offset = const core::mem::offset_of!(ServiceTable, stop),
    )
}

extern "C" fn virq_dispatch() {
    if matches!(deliver_pending(), PendingDelivery::DeferredByCurrentTask) {
        // A redirected upcall can interrupt the scheduler check in this Task's
        // epilogue. Return to it without recursively checking the scheduler.
        vcpu_record().irq_off.store(0, Ordering::Release);
        return;
    }
    // The fixed entry must release its virtual IRQ mask even if no bit remains.
    if vcpu_record().irq_off.load(Ordering::Acquire) != 0 {
        finish_virtual_interrupt();
    }
}

crate::cpu_local_cell! {
    static LAST_SPIN_TICK: u64 = u64::MAX;
}

/// A lock slow path may yield its fixed carrier at most once per Host tick.
pub(crate) fn on_spin() {
    let tick = crate::arch::read_tsc() / (boot_args().tsc_freq_hz / crate::timer::TIMER_FREQ);
    if LAST_SPIN_TICK.load() != tick {
        LAST_SPIN_TICK.store(tick);
        (services().vcpu_on_spin)();
    }
}
