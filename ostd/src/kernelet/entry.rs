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
static KERNELET_BOOT_ARGS: AtomicPtr<BootArgs> = AtomicPtr::new(core::ptr::null_mut());

/// Starts virtual CPU zero on its boot stack.
///
/// The Host validates the entry target and both argument mappings before the
/// call. The boot page remains mapped for the instance lifetime.
// SAFETY: OSDK links this symbol into the kernelet image only.
#[unsafe(no_mangle)]
pub extern "C" fn _kernelet_entry(services: &'static ServiceTable, boot: &BootArgs) -> ! {
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
    if boot.size != size_of::<BootArgs>() as u32
        || entry_table.size != size_of::<EntryTable>() as u64
        || boot.source_hash != entry_table.source_hash
        || (boot.num_vcpus == 0 || boot.num_vcpus as usize > super::abi::MAX_VCPUS)
        || boot.vcpu_records != PAGE_SIZE as u32
        || boot.clock_page != ((1 + record_pages) * PAGE_SIZE) as u32
        || boot.info_page != boot.clock_page + PAGE_SIZE as u32
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

    crate::console::init_kernelet_logging();
    crate::arch::init_kernelet_cpu_features();
    crate::cpu::init_kernelet_bsp();
    let regions = crate::kernelet::image_grant::init_initial_grant();
    crate::sync::init();
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
    crate::boot::init_kernelet(cmdline, regions);
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
pub fn vcpu_record() -> &'static VcpuRecord {
    let boot = boot_args();
    let host_cpu: u32;
    // SAFETY: Host publishes its immutable CPU-slot offset and keeps GS native
    // across all image execution. Each carrier is pinned to its assigned CPU.
    unsafe {
        asm!("mov {id:e}, gs:[{offset}]", id = out(reg) host_cpu, offset = in(reg) boot.cpu_slot_gs_offset as usize, options(nostack, readonly, preserves_flags))
    };
    let vcpu = boot.vcpu_host_cpu[..boot.num_vcpus as usize]
        .iter()
        .position(|cpu| *cpu as u32 == host_cpu)
        .expect("carrier CPU absent from boot map");
    record_for_vcpu(vcpu)
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
    let previous = record.guards.fetch_add(1, Ordering::Relaxed);
    assert_ne!(
        previous,
        u32::MAX,
        "kernelet preemption guard count overflow"
    );
}

/// Releases one internal preemption guard after the image's own count drops.
pub(crate) fn leave_preempt_guard() {
    let previous = vcpu_record().guards.fetch_sub(1, Ordering::Relaxed);
    assert_ne!(previous, 0, "kernelet preemption guard count underflow");
}

/// Masks physical IRQs only for the shared/native preemption handshake.
/// Internal critical sections continue to use virtual IRQ masking.
fn with_physical_irqs_masked<R>(f: impl FnOnce() -> R) -> R {
    let flags: usize;
    // SAFETY: The image runs at CPL 0 on its pinned carrier. Saving IF and
    // masking physical IRQs prevents a Host trap from observing half a mirror.
    unsafe { asm!("pushfq", "pop {}", "cli", out(reg) flags) };
    let result = f();
    if flags & (1 << 9) != 0 {
        // SAFETY: Restore exactly the physical IRQ state saved above.
        unsafe { asm!("sti", options(nostack)) };
    }
    result
}

/// Establishes the outer Host guard before publishing virtual IRQ masking.
pub(crate) fn disable_virtual_irqs() {
    with_physical_irqs_masked(|| {
        let record = vcpu_record();
        if record.mirrored.load(Ordering::Relaxed) == 0 {
            let offset = boot_args().host_preempt_gs_offset as usize;
            // SAFETY: The Host publishes its native u32 preemption cell's GS
            // offset. The pinned carrier owns this CPU with physical IRQs off.
            unsafe { asm!("add dword ptr gs:[{}], 1", in(reg) offset, options(nostack)) };
            record.mirrored.store(1, Ordering::Relaxed);
        }
        record.irq_off.store(1, Ordering::Release);
    });
}

/// Releases the outer guard after pending IRQ delivery and hands a pending
/// native reschedule to the protected Host-stack yield service.
pub(crate) fn release_host_preemption() {
    let should_yield = with_physical_irqs_masked(|| {
        let record = vcpu_record();
        if record.guards.load(Ordering::Relaxed) != 0
            || record.irq_off.load(Ordering::Relaxed) != 0
            || record.mirrored.swap(0, Ordering::Relaxed) == 0
        {
            return false;
        }
        let offset = boot_args().host_preempt_gs_offset as usize;
        let word: u32;
        // SAFETY: This vCPU owns exactly one native guard. Physical IRQs are
        // masked, so the decrement and pending-reschedule test cannot race a
        // Host trap. The Host repairs the count at service and exit boundaries.
        unsafe {
            asm!(
                "sub dword ptr gs:[{offset}], 1",
                "mov {word:e}, gs:[{offset}]",
                offset = in(reg) offset,
                word = out(reg) word,
                options(nostack),
            )
        };
        word == 0
    });
    if should_yield {
        (services().vcpu_yield)();
    }
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
    // Claim this pending batch with virtual IRQs masked. A callback may enable
    // virtual IRQs and admit one nested device interrupt, but not a third level.
    let was_off = record.irq_off.swap(1, Ordering::AcqRel);
    // An upcall's scheduler check, or a scheduler decision before its context
    // switch, may disable and re-enable virtual IRQs. Leave the pending batch
    // for the next safe boundary on this Task. A newly scheduled Task can
    // receive it without reentering the suspended Task's scheduler call.
    if crate::task::virq_delivery_deferred() {
        record.irq_off.store(was_off, Ordering::Release);
        return PendingDelivery::DeferredByCurrentTask;
    }
    // A device callback may re-enable virtual IRQs at L1. It can then nest a
    // second device callback, but OSTD has no third interrupt level.
    let level = InterruptLevel::current();
    if level == InterruptLevel::L2
        || (!level.is_task_context() && record.pending.load(Ordering::Acquire) & !VIRQ_TICK == 0)
    {
        // An L1 delivery consisting only of ticks must wait for L0, where
        // the saved L1-user/L1-kernel/L2 classes can be replayed faithfully.
        record.irq_off.store(was_off, Ordering::Release);
        return PendingDelivery::Handled;
    }
    let pending = record.pending.swap(0, Ordering::AcqRel);
    if pending & super::abi::VIRQ_KICK != 0 {
        crate::task::scheduler::mark_need_preempt_on_current_cpu();
        super::image_grant::rescan_grants();
        crate::smp::do_virtual_inter_processor_call();
    }
    let mut remaining = 64;
    if pending & VIRQ_LINES != 0 {
        for (word, lines) in record.pending_lines.iter().enumerate() {
            let mut lines = lines.swap(0, Ordering::AcqRel);
            while lines != 0 && remaining != 0 {
                let bit = lines.trailing_zeros() as usize;
                lines &= lines - 1;
                let line = word * 64 + bit;
                if line >= 32 {
                    call_irq_callback_functions(
                        &TrapFrame::default(),
                        &HwIrqLine::new(line as u8),
                        PrivilegeLevel::Kernel,
                    );
                    remaining -= 1;
                }
            }
            if lines != 0 {
                record.pending_lines[word].fetch_or(lines, Ordering::Release);
            }
            if remaining == 0 {
                record.pending.fetch_or(VIRQ_LINES, Ordering::Release);
                break;
            }
        }
    }
    if pending & VIRQ_TICK != 0 && !level.is_task_context() {
        // The counters describe the interrupted level, not the level at which
        // this delivery happens. Replay them from L0 so L1 and L2 callbacks
        // keep their original accounting class.
        record.pending.fetch_or(VIRQ_TICK, Ordering::Release);
    } else if pending & VIRQ_TICK != 0 {
        let user = record.tick_user.swap(0, Ordering::AcqRel);
        let user_count = user.min(remaining);
        for _ in 0..user_count {
            crate::irq::with_virtual_interrupt_level(
                || crate::timer::call_timer_callback_functions(&TrapFrame::default()),
                PrivilegeLevel::User,
            );
        }
        remaining -= user_count;
        if user > user_count {
            record
                .tick_user
                .fetch_add(user - user_count, Ordering::Release);
            record.pending.fetch_or(VIRQ_TICK, Ordering::Release);
        }

        let kernel = record.tick_kernel.swap(0, Ordering::AcqRel);
        let kernel_count = kernel.min(remaining);
        for _ in 0..kernel_count {
            crate::irq::with_virtual_interrupt_level(
                || crate::timer::call_timer_callback_functions(&TrapFrame::default()),
                PrivilegeLevel::Kernel,
            );
        }
        remaining -= kernel_count;
        if kernel > kernel_count {
            record
                .tick_kernel
                .fetch_add(kernel - kernel_count, Ordering::Release);
            record.pending.fetch_or(VIRQ_TICK, Ordering::Release);
        }

        let l2 = record.tick_l2.swap(0, Ordering::AcqRel);
        let l2_count = l2.min(remaining);
        for _ in 0..l2_count {
            crate::irq::with_virtual_l2_level(|| {
                crate::timer::call_timer_callback_functions(&TrapFrame::default())
            });
        }
        if l2 > l2_count {
            record.tick_l2.fetch_add(l2 - l2_count, Ordering::Release);
            record.pending.fetch_or(VIRQ_TICK, Ordering::Release);
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
    {
        // SAFETY: The virtual IRQ has completed in ordinary Task context,
        // with no guard or RCU reader carried across this boundary.
        unsafe { crate::sync::finish_grace_period() };
    }
}

/// Returns the Host service table installed at image entry.
pub fn services() -> &'static ServiceTable {
    let ptr = KERNELET_SERVICES.load(Ordering::Acquire);
    assert!(!ptr.is_null(), "kernelet services used before image entry");
    // SAFETY: `_kernelet_entry` stores a Host-owned static table that remains
    // mapped for the image lifetime before any kernel-proper entry is called.
    unsafe { &*ptr }
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
// SAFETY: OSDK links this fixed symbol into the entry table.
#[unsafe(no_mangle)]
pub extern "C" fn vcpu_entry() -> ! {
    let vcpu = vcpu_record().vcpu;
    // SAFETY: This dedicated carrier enters its initialized replica only once.
    unsafe { crate::cpu::init_on_ap(vcpu) };
    crate::arch::init_kernelet_cpu_features();
    crate::boot::smp::kernelet_ap_entry()
}

/// The fixed virtual-interrupt redirection target.
///
/// The Host places a pointer to two retired trap slots in RAX: the original
/// RIP immediately before the pointer and the original RAX at the pointer.
/// It returns with physical IRQs masked. This prologue restores RAX before
/// enabling physical IRQs,
/// then preserves the complete interrupted register image for the callback.
// SAFETY: OSDK links this fixed symbol into the validated entry table. Only
// the Host's checked interrupt-return redirection enters it.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub extern "C" fn virq_entry() -> ! {
    core::arch::naked_asm!(
        "endbr64",
        "push qword ptr [rax - 8]",
        "mov rax, [rax]",
        "sti",
        "nop",
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
        "call {dispatch}",
        "mov rsp, rbx",
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
        "popfq",
        "ret",
        dispatch = sym virq_dispatch,
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
