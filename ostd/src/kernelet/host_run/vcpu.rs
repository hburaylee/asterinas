// SPDX-License-Identifier: MPL-2.0

//! Tenant vCPU services: boot, kick, yield, spin throttling, idle parking,
//! and the synchronous tenant-user gate.
//!
//! These services may block or yield while the image stays stopped in the
//! crossing; the carrier keeps its pinned Task and current shared Task stack
//! across that scheduling.

use core::{sync::atomic::Ordering, time::Duration};

use super::{IDLE, RETURNING, SERVICE, USER, current_carrier_state};
#[cfg(kernelet_getpid_profile)]
use crate::kernelet::getpid_profile as profile;
use crate::{
    cpu::PinCurrentCpu,
    kernelet::{
        abi::{
            BootArgs, INVALID, KSTACK_USABLE_BYTES, KletUserContext, STATE, USER_RETURN_PENDING,
            VIRQ_KICK, VIRQ_TICK, VcpuRecord,
        },
        clock,
        deadline::Deadline,
    },
    task::{Task, scheduler},
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
        let irq_guard = crate::irq::disable_local();
        if carrier.cpu == irq_guard.current_cpu() {
            // Native inter_processor_call executes a self call synchronously.
            // Send a real physical IPI instead: IRQs stay masked until the
            // common STI; RET returns to the Guest continuation. The IPI
            // handler's trap return remains the only virtual IRQ delivery.
            crate::arch::irq::send_self_ipi(&irq_guard)
                .expect("failed to send a self virtual-CPU kick");
        } else {
            crate::smp::IPI_SENDER
                .get()
                .unwrap()
                .notify_remote_cpu(carrier.cpu);
        }
        0
    } else {
        -INVALID
    };
    state.set_phase(RETURNING);
    result
}
// SAFETY: The fixed service stub authenticated this carrier and validated
// its current shared Task stack before scheduling it.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_vcpu_yield_impl() -> i64 {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    state.enter_schedulable_service();
    // A virtual guard may still be held. Only native guards govern Host
    // scheduling. enter_schedulable_service installed the Host root; the shared
    // return stub selects the image's active root only after Host work ends.
    crate::arch::irq::enable_local();
    Task::yield_now();
    crate::arch::irq::disable_local();
    state.set_phase(RETURNING);
    state.sample_stop();
    0
}

// SAFETY: The service adapter authenticated this carrier and its shared stack.
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

// SAFETY: The assembly stub authenticated this crossing and its shared Task
// stack. The native carrier stays pinned during this wait.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_vcpu_idle_impl(deadline_ns: u64) -> i64 {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
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
    if record.pending.load(Ordering::Acquire) != 0 {
        // The caller already has work. Keep its active root and avoid creating
        // a timer for a wait that cannot sleep.
        state.sample_stop();
        state.set_phase(RETURNING);
        return 0;
    }
    state.enter_schedulable_service();
    // The service stub keeps the Host root active while this Task waits.
    state.set_phase(IDLE);
    state.parked.set(true);
    crate::arch::irq::enable_local();
    let guest_now_ns = clock::now_ns();
    let tick_ns = 1_000_000_000 / crate::timer::TIMER_FREQ;
    let guest_deadline_ns = if deadline_ns == 0 {
        guest_now_ns.saturating_add(tick_ns)
    } else {
        deadline_ns
    };
    // Pass a relative duration to the Host's existing monotonic timers. The
    // image and Host timer need not share an epoch. Keep the minimum sleep
    // against short-deadline storms; indefinite waits allocate no timer.
    let alarm = (guest_deadline_ns != u64::MAX).then(|| {
        Deadline::after(
            Duration::from_nanos(
                guest_deadline_ns
                    .saturating_sub(guest_now_ns)
                    .max(MIN_IDLE_NS),
            ),
            &state.idle_wait,
        )
    });
    state.idle_wait.wait_until(|| {
        (record.pending.load(Ordering::Acquire) != 0
            || state.sample_stop()
            || alarm.as_ref().is_some_and(Deadline::is_expired))
        .then_some(())
    });
    drop(alarm);
    crate::arch::irq::disable_local();
    state.parked.set(false);
    state.set_phase(SERVICE);
    state.sample_stop();
    state.set_phase(RETURNING);
    0
}

const ALLOWED_USER_RFLAGS: u64 = (1 << 0)
    | (1 << 2)
    | (1 << 4)
    | (1 << 6)
    | (1 << 7)
    | (1 << 8)
    | (1 << 9)
    | (1 << 10)
    | (1 << 11)
    | (1 << 16)
    | (1 << 21);

fn user_registers_valid(rip: usize, rsp: usize) -> bool {
    rip < crate::mm::MAX_USERSPACE_VADDR && matches!((rsp as i64) >> 47, 0 | -1)
}

fn user_flags(flags: usize) -> usize {
    (flags & ALLOWED_USER_RFLAGS as usize) | 2 | (1 << 9)
}

// SAFETY: The service stub validates the current Host-owned image stack and
// its reserve before calling. The borrowed context stays above these frames.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_user_run_impl(ptr: *mut KletUserContext) -> i32 {
    #[cfg(kernelet_getpid_profile)]
    let _user_span = profile::span(profile::stage::HOST_USER_RUN);
    use crate::{arch::irq::HwIrqLine, cpu::PrivilegeLevel, irq::call_irq_callback_functions};

    #[cfg(kernelet_getpid_profile)]
    let admit_span = profile::span(profile::stage::HOST_ADMIT);
    // SAFETY: The service stub enters with IRQs masked on the fixed carrier;
    // later scheduling resumes the same Task before this state is reused.
    let Some(state) = (unsafe { current_carrier_state() }) else {
        #[cfg(kernelet_getpid_profile)]
        profile::event(profile::event_id::SERVICE_REJECTED);
        return -(STATE as i32);
    };
    let Some(_admission) = state.admit_service() else {
        #[cfg(kernelet_getpid_profile)]
        profile::event(profile::event_id::SERVICE_REJECTED);
        return -(STATE as i32);
    };
    #[cfg(kernelet_getpid_profile)]
    {
        let _ = profile::end(admit_span);
        profile::event(profile::event_id::SERVICE_USER_RUN);
    }
    #[cfg(kernelet_getpid_profile)]
    let validate_span = profile::span(profile::stage::HOST_VALIDATE);
    // The synchronous user gate uses the already registered tenant root.
    // Native callbacks leave it only when needed.
    let start = ptr as usize;
    let Some(end) = start.checked_add(size_of::<KletUserContext>()) else {
        state.set_phase(RETURNING);
        return -(INVALID as i32);
    };
    if !start.is_multiple_of(align_of::<KletUserContext>())
        || start < state.image_rsp.saturating_add(size_of::<usize>())
        || end
            > (state.image_rsp & !(super::resources::STACK_STRIDE - 1))
                + super::resources::STACK_BYTES
                + KSTACK_USABLE_BYTES
        || state.active_root.get() == 0
    {
        state.set_phase(RETURNING);
        return -(INVALID as i32);
    }
    // SAFETY: The aligned object is entirely in the current live image stack,
    // above the suspended crossing frame. The image cannot unmap this Host
    // stack, and its Task cannot run again until this synchronous borrow ends.
    // Host code and entry assembly retain no reference after this call.
    let context = unsafe { &mut *ptr };
    // RSP is a saved register, not a pointer dereferenced by this gate.
    // High-half canonical values are legal until user code accesses the stack.
    if !user_registers_valid(context.general.rip, context.general.rsp) {
        state.set_phase(RETURNING);
        return -(INVALID as i32);
    }
    // Install only the architectural user flags accepted by this gate.
    context.rflags = user_flags(context.rflags);
    context.trap_num = 0;
    context.error_code = 0;
    context.fault_addr = 0;
    // SAFETY: The authenticated carrier pins this shared record until exit.
    let record = unsafe { &*(state.vcpu_record as *const VcpuRecord) };
    if record.irq_off.load(Ordering::Acquire) == 0 || record.guards.load(Ordering::Acquire) != 0 {
        state.set_phase(RETURNING);
        return -(STATE as i32);
    }
    // A physical IRQ may natively preempt this carrier while the image
    // remains stopped in the synchronous user gate.
    #[cfg(kernelet_getpid_profile)]
    let _ = profile::end(validate_span);
    let result = if state.sample_stop() || state.run_state.load(Ordering::Acquire) != SERVICE {
        USER_RETURN_PENDING
    } else {
        // This carrier is the only phase writer, with physical IRQs masked.
        // A remote stop is published independently and checked again below.
        state.set_phase(USER);
        // The selected registered tenant root must be active while ring 3
        // executes; the Host half of
        // that root is the validated copy of the native kernel mappings.
        #[cfg(kernelet_getpid_profile)]
        let root_span = profile::span(profile::stage::HOST_ROOT_USER);
        if state.prepare_active_root() && !state.sample_stop() {
            #[cfg(kernelet_getpid_profile)]
            let _ = profile::end(root_span);
            // SAFETY: Registration validated the root and copied Host mappings;
            // the active-root set pins it until the Host root is restored.
            if crate::arch::mm::current_page_table_paddr() != state.active_root.get() {
                unsafe { crate::arch::mm::activate_page_table(state.active_root.get()) };
                #[cfg(kernelet_getpid_profile)]
                profile::event(profile::event_id::CR3_WRITE);
            }
            crate::arch::cpu::context::run_host_user(context)
        } else {
            #[cfg(kernelet_getpid_profile)]
            let _ = profile::end(root_span);
            USER_RETURN_PENDING
        }
    };
    state.set_phase(SERVICE);
    // A virtual event detected before entry leaves `trap_num` zero. Only a
    // physical interrupt needs a frame for the native IRQ callbacks.
    if result == USER_RETURN_PENDING && context.trap_num > 31 {
        #[cfg(kernelet_getpid_profile)]
        profile::event(profile::event_id::PHYSICAL_IRQ);
        let frame = context.as_trap_frame();
        // The validated root contains the native kernel mappings. Keep it
        // active for the IRQ; an actual native switch saves the carrier and
        // leaves this active set through pause_carrier_context.
        if crate::arch::is_timer_irq(frame.trap_num) {
            if record.task_ticks.record(true) {
                record.tick_user.fetch_add(1, Ordering::Relaxed);
                record.pending.fetch_or(VIRQ_TICK, Ordering::Release);
            } else {
                state.stop_tick_overflow();
            }
        }
        // Sampling failure stops the image, but the physical IRQ still needs
        // its Host callbacks and acknowledgement before service termination.
        #[cfg(kernelet_getpid_profile)]
        let irq_span = profile::span(profile::stage::HOST_IRQ);
        call_irq_callback_functions(
            &frame,
            &HwIrqLine::new(frame.trap_num as u8),
            PrivilegeLevel::User,
        );
        #[cfg(kernelet_getpid_profile)]
        let _ = profile::end(irq_span);
        // Consume the Host tick's reschedule request at depth one. Virtual
        // guards govern the image scheduler, so no native mirror delays this.
        crate::arch::irq::enable_local();
        scheduler::might_preempt();
        crate::arch::irq::disable_local();
        // All Native IRQ callbacks have returned to L0. Park the carrier at
        // this Host tick continuation even though user_run masks Guest IRQs.
        state.sample_stop();
    }
    state.set_phase(RETURNING);
    result
}

#[cfg(ktest)]
#[crate::prelude::ktest]
fn user_gate_retains_direction_flag_and_canonical_stack_register() {
    assert_eq!(user_flags(1 << 10) & (1 << 10), 1 << 10);
    assert_eq!(user_flags(usize::MAX) & (3 << 12), 0);
    assert_eq!(user_flags(0) & ((1 << 9) | 2), (1 << 9) | 2);
    assert!(user_registers_valid(0x1000, usize::MAX));
    assert!(user_registers_valid(
        0x1000,
        crate::mm::MAX_USERSPACE_VADDR - 1
    ));
    assert!(user_registers_valid(0x1000, crate::mm::MAX_USERSPACE_VADDR));
    assert!(!user_registers_valid(0x1000, 1usize << 47));
    assert!(!user_registers_valid(
        crate::mm::MAX_USERSPACE_VADDR,
        0x1000
    ));
}
