// SPDX-License-Identifier: MPL-2.0

//! Tenant vCPU services: boot, kick, yield, spin throttling, idle parking,
//! and the synchronous tenant-user gate.
//!
//! These services may block or yield while the image stays stopped in the
//! crossing; the carrier keeps its pinned Task and protected Host stack
//! across that scheduling.

use core::sync::atomic::Ordering;

use super::{IDLE, RETURNING, SERVICE, STOP_REQUESTED, USER, current_carrier_state};
use crate::{
    kernelet::{
        abi::{
            BootArgs, INVALID, KletUserContext, STATE, USER_RETURN_PENDING, VIRQ_KICK, VIRQ_TICK,
            VcpuRecord,
        },
        account, clock,
    },
    task::Task,
};

const MIN_IDLE_NS: u64 = 50_000;

// SAFETY: Both services are entered through authenticated Host-stack stubs.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_vcpu_boot_impl(vcpu: u32) -> i64 {
    // SAFETY: The service stub keeps this Task on its pinned CPU with IRQs masked.
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    let result = state.control.boot_vcpu(vcpu).map(|_| 0).unwrap_or(-INVALID);
    state.set_phase(RETURNING);
    result
}

#[unsafe(no_mangle)]
extern "C" fn kernelet_host_vcpu_kick_impl(vcpu: u32) -> i64 {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    let result = if let Some(carrier) = state.control.carriers.get(vcpu as usize) {
        // SAFETY: The carrier retains the Host-built boot page while services run.
        let boot = unsafe { &*(state.boot_args as *const BootArgs) };
        // SAFETY: `vcpu` was checked against the fixed carrier array, and the
        // boot page indexes the pinned shared record array for that carrier.
        let record = unsafe {
            &*((state.boot_args
                + boot.vcpu_records as usize
                + vcpu as usize * size_of::<VcpuRecord>()) as *const VcpuRecord)
        };
        record.pending.fetch_or(VIRQ_KICK, Ordering::Release);
        carrier.wait.wake_all();
        crate::smp::inter_processor_call(&carrier.cpu.into(), || {});
        0
    } else {
        -INVALID
    };
    state.set_phase(RETURNING);
    result
}
// SAFETY: The fixed service stub has switched to the native Host stack and
// authenticated this carrier before scheduling it.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_vcpu_yield_impl() -> i64 {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    state.enter_schedulable_service();
    // A virtual guard may still be held. The carrier yields on its protected
    // Host stack, where only native guards govern Host scheduling.
    // The service stub already installed the protected Host root. The shared
    // return stub selects the image's active root only after Host work ends.
    crate::arch::irq::enable_local();
    Task::yield_now();
    crate::arch::irq::disable_local();
    state.set_phase(RETURNING);
    0
}

// SAFETY: The service adapter has installed the protected Host stack and root.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_vcpu_on_spin_impl() {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return;
    };
    let Some(_admission) = state.admit_service() else {
        return;
    };
    state.enter_schedulable_service();
    let tick = crate::timer::Jiffies::elapsed().as_u64();
    if state.last_spin.replace(tick) != tick {
        crate::arch::irq::enable_local();
        Task::yield_now();
        crate::arch::irq::disable_local();
    }
    state.set_phase(RETURNING);
}

// SAFETY: The assembly stub has authenticated the crossing and switched to
// the carrier's native stack. The carrier stays pinned during this wait.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_vcpu_idle_impl(deadline_ns: u64) -> i64 {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    state.enter_schedulable_service();
    // SAFETY: The owning image instance pins this shared record until the
    // carrier has returned from `enter`.
    let record = unsafe { &*(state.vcpu_record as *const VcpuRecord) };
    // The idle caller may have masked virtual IRQs before entering RCU's
    // quiescent state. The return stub defers a pending upcall until virtual
    // IRQs are enabled.
    if record.irq_off.load(Ordering::Acquire) > 1 || record.guards.load(Ordering::Acquire) != 0 {
        state.set_phase(RETURNING);
        return -STATE;
    }
    // The service stub keeps the Host root active while this Task waits.
    state.set_phase(IDLE);
    state.parked.set(true);
    crate::arch::irq::enable_local();
    let guest_now_ns = clock::now_ns();
    let host_now_ns = crate::task::accounting::now_ns();
    let tick_ns = 1_000_000_000 / crate::timer::TIMER_FREQ;
    let guest_deadline_ns = if deadline_ns == 0 {
        guest_now_ns.saturating_add(tick_ns)
    } else {
        deadline_ns
    };
    // Guest deadlines are relative to the Host-boot clock page; the Host's
    // deadline queue uses its own TSC-derived epoch. Convert only the remaining
    // interval, and bound the minimum sleep against short-deadline storms.
    let host_deadline_ns = if guest_deadline_ns == u64::MAX {
        u64::MAX
    } else {
        host_now_ns.saturating_add(
            guest_deadline_ns
                .saturating_sub(guest_now_ns)
                .max(MIN_IDLE_NS),
        )
    };
    let alarm = (host_deadline_ns != u64::MAX)
        .then(|| account::Deadline::new(host_deadline_ns, &state.idle_wait));
    state.idle_wait.wait_until(|| {
        (record.pending.load(Ordering::Acquire) != 0
            || state.run_state.load(Ordering::Acquire) & STOP_REQUESTED != 0
            || crate::task::accounting::now_ns() >= host_deadline_ns)
            .then_some(())
    });
    drop(alarm);
    // A deadline may expire between physical ticks. Publish a fresh clock
    // sample before vOSTD tests the absolute deadline on service return.
    clock::publish();
    crate::arch::irq::disable_local();
    state.parked.set(false);
    state.set_phase(SERVICE);
    state.set_phase(RETURNING);
    0
}

// SAFETY: The service stub switches to this carrier's native stack before
// calling. It leaves the image context on the current allocated image stack.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_user_run_impl(ptr: *mut KletUserContext) -> i64 {
    use crate::{
        arch::irq::HwIrqLine, cpu::PrivilegeLevel, irq::call_irq_callback_functions,
        mm::MAX_USERSPACE_VADDR,
    };

    const ALLOWED_USER_RFLAGS: u64 = (1 << 0)
        | (1 << 2)
        | (1 << 4)
        | (1 << 6)
        | (1 << 7)
        | (1 << 8)
        | (1 << 9)
        | (1 << 11)
        | (1 << 16)
        | (1 << 21);

    // SAFETY: The service stub enters with IRQs masked on the fixed carrier;
    // later scheduling resumes the same Task before this state is reused.
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    // The synchronous user gate uses the already registered tenant root.
    // Native callbacks and quota waits leave it only when needed.
    state.suspend_mirror();
    let start = ptr as usize;
    let Some(end) = start.checked_add(size_of::<KletUserContext>()) else {
        state.set_phase(RETURNING);
        return -INVALID;
    };
    if !start.is_multiple_of(align_of::<KletUserContext>())
        || !state
            .execution
            .stacks
            .lock()
            .contains_current_range(start, end, state.image_rsp)
        || state.active_root.get() == 0
    {
        state.set_phase(RETURNING);
        return -INVALID;
    }
    // SAFETY: The full, aligned object lies in the live current image stack.
    // It is borrowed only during this synchronous service crossing.
    let mut context = unsafe { ptr.read() };
    if [context.rip, context.rsp, context.fsbase, context.gsbase]
        .iter()
        .any(|addr| *addr >= MAX_USERSPACE_VADDR as u64)
    {
        state.set_phase(RETURNING);
        return -INVALID;
    }
    // Install only the architectural user flags accepted by this gate.
    context.rflags = (context.rflags & ALLOWED_USER_RFLAGS) | 2 | (1 << 9);
    context.trap_num = 0;
    context.error_code = 0;
    context.fault_addr = 0;
    // SAFETY: The authenticated carrier pins this shared record until exit.
    let record = unsafe { &*(state.vcpu_record as *const VcpuRecord) };
    if record.irq_off.load(Ordering::Acquire) == 0 || record.guards.load(Ordering::Acquire) != 0 {
        state.set_phase(RETURNING);
        return -STATE;
    }
    // `user_run` may block or be natively preempted while the image remains
    // stopped in this service.
    state.wait_for_budget(SERVICE);
    let (result, interrupt) = if record.pending.load(Ordering::Acquire) != 0
        || state
            .run_state
            .compare_exchange(SERVICE, USER, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        (USER_RETURN_PENDING, None)
    } else {
        // The selected registered tenant root must be active while ring 3
        // executes; the Host half of
        // that root is the validated copy of the native kernel mappings.
        if state.prepare_active_root() {
            // SAFETY: Registration validated the root and copied Host mappings;
            // the active-root set pins it until the Host root is restored.
            if crate::arch::mm::current_page_table_paddr() != state.active_root.get() {
                unsafe { crate::arch::mm::activate_page_table(state.active_root.get()) };
            }
            crate::arch::cpu::context::run_host_user(&mut context)
        } else {
            (USER_RETURN_PENDING, None)
        }
    };
    state.set_phase(SERVICE);
    if let Some(frame) = interrupt {
        // A native IRQ callback may schedule. Leave the active set only
        // after installing the Host root, before enabling that work.
        state.install_host_root();
        if crate::arch::is_timer_irq(frame.trap_num) {
            record.tick_user.fetch_add(1, Ordering::Relaxed);
            record.pending.fetch_or(VIRQ_TICK, Ordering::Release);
        }
        call_irq_callback_functions(
            &frame,
            &HwIrqLine::new(frame.trap_num as u8),
            PrivilegeLevel::User,
        );
    }
    // SAFETY: The current image stack remains pinned while this Host frame
    // executes; no Host code retains the context pointer after this write.
    unsafe { ptr.write(context) };
    state.set_phase(RETURNING);
    result
}
