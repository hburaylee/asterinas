// SPDX-License-Identifier: MPL-2.0

//! Host-private state for one carrier crossing a kernelet image boundary.
//!
//! Ordinary physical traps and service calls use the current shared Task
//! stack. Only double fault enters a permanent CPU-local IST stack.
//!
//! This module owns the authoritative carrier state and the single
//! enter/return/stop transaction, including trap containment and virtual
//! interrupt redirection. Child modules own the shared execution resources
//! ([`resources`]) and the service implementation bodies
//! ([`vcpu`], [`roots`], [`mem`], [`hooks`]).

use alloc::{string::ToString, sync::Arc};
use core::{
    arch::global_asm,
    cell::{Cell, RefCell},
    mem::offset_of,
    ops::Range,
    sync::atomic::{AtomicU32, Ordering},
};

use super::{
    abi::{
        BootArgs, CopyFaultRecord, INVALID, KSTACK_USABLE_BYTES, KletUserContext, MAX_OOPS_BYTES,
        MmioResult, STATE, ServiceTable, VIRQ_TICK, VcpuRecord, copy_fault_records_offset,
    },
    control::{ExitReason, KerneletHooks, KillReason, RunControl},
    guest_memory::GuestMemory,
    host_grant::Grant,
};
use crate::{
    arch::cpu::context::FpuContext,
    irq,
    sync::WaitQueue,
    task::{Task, scheduler},
};

mod hook_stack;
mod hooks;
mod mem;
mod record;
mod resources;
mod roots;
#[cfg(kernelet_rq1)]
mod rq1;
mod tls;
mod vcpu;

pub(crate) use record::recover_host_copy_fault;
pub(crate) use resources::ExecutionResources;

// The carrier alone writes its phase while physical IRQs are masked. The
// instance's separate active word carries the remotely published sticky stop
// bit, so phase publication needs only Release stores.
// host_run.S receives phase operands through global_asm! below. Keep its
// fixed entry transactions and OSDK byte audits synchronized.
pub(crate) const PREPARED: u32 = 0;
const IMAGE: u32 = 1;
pub(crate) const STARTING: u32 = 8;
const ENTERING: u32 = 2;
pub(crate) const SERVICE: u32 = 3;
pub(crate) const RETURNING: u32 = 4;
pub(crate) const STOP_REQUESTED: u32 = 1 << 31;
pub(crate) const LEAVING: u32 = 5;
pub(crate) const DETACHED: u32 = 11;
const USER: u32 = 6;
const IDLE: u32 = 9;
const THROTTLED: u32 = 10;

const _: () = {
    assert!(
        (PREPARED
            | IMAGE
            | STARTING
            | ENTERING
            | SERVICE
            | RETURNING
            | LEAVING
            | DETACHED
            | USER
            | IDLE
            | THROTTLED)
            & STOP_REQUESTED
            == 0
    );
};

const UPCALL_STACK_RESERVE: usize = 64 * 1024;

global_asm!(
    include_str!("host_run.S"),
    phase_starting = const STARTING,
    phase_image = const IMAGE,
    phase_entering = const ENTERING,
    phase_returning = const RETURNING,
    stop_requested = const STOP_REQUESTED,
    stop_state = const offset_of!(CarrierState, stop_state),
    stack_pool_start = const offset_of!(CarrierState, stack_pool_start),
    stack_pool_end = const offset_of!(CarrierState, stack_pool_end),
    stack_pool_live = const offset_of!(CarrierState, stack_pool_live),
    stack_stride = const resources::STACK_STRIDE,
    stack_bytes = const resources::STACK_BYTES,
    stack_reserve = const UPCALL_STACK_RESERVE,
    rq1_bench = const cfg!(kernelet_rq1) as usize,
    options(att_syntax)
);

#[repr(C)]
struct CarrierState<'a> {
    host_rsp: usize,
    image_rsp: usize,
    image_start: usize,
    image_end: usize,
    run_state: &'a AtomicU32,
    carrier_task: usize,
    // The permanent kernel root, never a borrowed outgoing Task's user root.
    host_root: usize,
    active_root: Cell<usize>,
    stack_pool_start: usize,
    stack_pool_end: usize,
    stack_pool_live: usize,
    execution: &'a ExecutionResources,
    vcpu: u16,
    vcpu_record: usize,
    copy_fault_record: usize,
    boot_args: usize,
    fpu_stage: RefCell<FpuContext>,
    guest_memory: GuestMemory,
    idle_wait: Arc<WaitQueue>,
    hooks: Arc<dyn KerneletHooks>,
    ex_table: Range<usize>,
    deferred_ticks: Cell<u32>,
    text: Range<usize>,
    virq_entry: usize,
    yield_entry: usize,
    exit_entry: usize,
    stub_range: Range<usize>,
    control: &'a RunControl,
    grant: &'a Grant,
    hook_active: Cell<bool>,
    paused_at: Cell<u64>,
    parked: Cell<bool>,
    throttled: Cell<bool>,
    last_spin: Cell<u64>,
    // Preserve hardware FPU state across every carrier switch, including
    // image-side FPU restores that do not cross a Host service.
    fpu_paused: Cell<bool>,
    vm_space: Arc<crate::mm::VmSpace>,
    tls: Cell<tls::TlsState>,
    // The instance owns this word until all carriers have detached. Remote
    // stop changes this word without writing the current carrier's phase.
    stop_state: &'a AtomicU32,
    // Keep new Rust-only state after every assembly-visible field.
    cpu_access_range: Range<usize>,
}

const _: () = {
    assert!(offset_of!(CarrierState, host_rsp) == 0);
    assert!(offset_of!(CarrierState, image_rsp) == 8);
    assert!(offset_of!(CarrierState, run_state) == 32);
    assert!(offset_of!(CarrierState, carrier_task) == 40);
    assert!(offset_of!(CarrierState, host_root) == 48);
    assert!(offset_of!(CarrierState, active_root) == 56);
    assert!(offset_of!(CarrierState, stack_pool_start) == 64);
    assert!(offset_of!(CarrierState, stack_pool_end) == 72);
    assert!(offset_of!(CarrierState, stack_pool_live) == 80);
    assert!(offset_of!(CarrierState, stop_state) == 344);
};

crate::cpu_local_cell! {
    #[unsafe(no_mangle)]
    static KERNELET_HOST_STATE_PTR: usize = 0;
}

#[cfg(kernelet_getpid_profile)]
use super::getpid_profile as profile;

/// Reinstalls a native Task's protected carrier pointer after a Host switch.
/// The Task owns this address until it clears the slot at fixed exit.
///
/// # Safety
/// A nonzero address must name the current Task's pinned carrier. Physical
/// IRQs must be masked while the CPU-local pointer and counters are updated.
pub(crate) unsafe fn restore_carrier_context(address: usize) {
    KERNELET_HOST_STATE_PTR.store(address);
    if address == 0 {
        super::vcpu_slot::restore(None);
        return;
    }
    // SAFETY: The native Task owns this pinned carrier context until fixed exit.
    let state = unsafe { &*(address as *const CarrierState) };
    #[cfg(kernelet_rq1_diagnostics)]
    super::fpu_profile::carrier_event(super::fpu_profile::CarrierEvent::Resume);
    #[cfg(kernelet_getpid_profile)]
    let _resume_span = profile::span(profile::stage::HOST_CARRIER_RESUME);
    super::vcpu_slot::restore(Some(state.control.cpu_slot(state.vcpu)));
    #[cfg(kernelet_getpid_profile)]
    let tls_span = profile::span(profile::stage::HOST_FS_GS_ENTER);
    state.tls.get().restore();
    #[cfg(kernelet_getpid_profile)]
    let _ = profile::end(tls_span);
    if state.fpu_paused.replace(false) {
        state.fpu_stage.borrow().load();
        #[cfg(kernelet_rq1_diagnostics)]
        super::fpu_profile::carrier_event(super::fpu_profile::CarrierEvent::LoadCompleted);
    }
    // The kernel's post-schedule handler restores the carrier's VMAR after
    // this protected pointer and its hardware state have been installed.
    if state.sample_stop() {
        state.vm_space.set_root_restore(false);
    }
    let paused_at = state.paused_at.replace(0);
    if paused_at == 0 {
        return;
    }
    let elapsed = crate::arch::read_tsc().saturating_sub(paused_at);
    // SAFETY: Every mapped cooperation record outlives the corresponding Task context.
    let record = unsafe { &*(state.vcpu_record as *const VcpuRecord) };
    record.nonrunning_tsc.fetch_add(elapsed, Ordering::Release);
    let ns = (elapsed as u128 * 1_000_000_000 / crate::arch::tsc_freq() as u128) as u64;
    if state.parked.get() {
        record.parked_ns.fetch_add(ns, Ordering::Release);
    } else if !state.throttled.get() {
        record.stolen_ns.fetch_add(ns, Ordering::Release);
    }
}

/// Starts the outgoing carrier's off-CPU interval.
///
/// # Safety
/// A nonzero address must name the outgoing Task's pinned carrier context;
/// physical IRQs must remain masked through the context switch.
pub(crate) unsafe fn pause_carrier_context(address: usize) {
    if address != 0 {
        #[cfg(kernelet_getpid_profile)]
        let _pause_span = profile::span(profile::stage::HOST_CARRIER_PAUSE);
        // SAFETY: Called only for the outgoing Task while IRQs are masked.
        let state = unsafe { &*(address as *const CarrierState) };
        #[cfg(kernelet_rq1_diagnostics)]
        super::fpu_profile::carrier_event(super::fpu_profile::CarrierEvent::Pause);
        #[cfg(kernelet_getpid_profile)]
        let tls_span = profile::span(profile::stage::HOST_FS_GS_LEAVE);
        state.tls.set(tls::TlsState::capture());
        #[cfg(kernelet_getpid_profile)]
        let _ = profile::end(tls_span);
        state.fpu_stage.borrow_mut().save();
        #[cfg(kernelet_rq1_diagnostics)]
        super::fpu_profile::carrier_event(super::fpu_profile::CarrierEvent::SaveCompleted);
        state.fpu_paused.set(true);
        state.install_host_root();
        // A native IRQ may suspend an image Task stack directly. Restore its
        // tenant root before returning to image text or tenant user mode.
        state.vm_space.set_root_restore(
            matches!(state.run_state.load(Ordering::Acquire), IMAGE | USER) && !state.sample_stop(),
        );
        state.paused_at.set(crate::arch::read_tsc());
        // A real native context switch restarts the cooperative grace period.
        state.deferred_ticks.set(0);
    }
    super::vcpu_slot::restore(None);
}

unsafe extern "C" {
    fn kernelet_host_enter(
        entry: usize,
        image_stack_top: usize,
        services: &'static ServiceTable,
        boot: *const BootArgs,
    ) -> u32;
}

// The service table is entered through indirect calls from the image. Every
// naked wrapper starts with ENDBR64 before its direct jump to the Host stub.
#[unsafe(naked)]
extern "C" fn grains_request(_: u32, _: u32) -> i64 {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_grains_request");
}
#[unsafe(naked)]
extern "C" fn pt_root_register(_: u64) -> i64 {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_pt_root_register");
}
#[unsafe(naked)]
extern "C" fn pt_root_unregister(_: u64) -> i64 {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_pt_root_unregister");
}
#[unsafe(naked)]
extern "C" fn pt_activate(_: u64) -> i64 {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_pt_activate");
}
#[unsafe(naked)]
extern "C" fn tlb_shootdown(_: u64, _: u64, _: u64) -> i64 {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_tlb_shootdown");
}
#[unsafe(naked)]
extern "C" fn vcpu_boot(_: u32) -> i64 {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_vcpu_boot");
}
#[unsafe(naked)]
extern "C" fn vcpu_idle(_: u64) -> i64 {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_vcpu_idle");
}
#[unsafe(naked)]
extern "C" fn vcpu_kick(_: u32) -> i64 {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_vcpu_kick");
}
#[unsafe(naked)]
extern "C" fn vcpu_yield() {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_vcpu_yield");
}
#[unsafe(naked)]
extern "C" fn vcpu_on_spin() {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_vcpu_on_spin");
}
#[unsafe(naked)]
extern "C" fn user_run(_: *mut KletUserContext) -> i32 {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_user_run");
}
#[unsafe(naked)]
extern "C" fn mmio_read(_: u32, _: u32, _: u32) -> MmioResult {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_mmio_read");
}

#[unsafe(naked)]
extern "C" fn mmio_write(_: u32, _: u32, _: u32, _: u64) -> i64 {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_mmio_write");
}
#[unsafe(naked)]
extern "C" fn oops(_: *const u8, _: u32) -> i64 {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_oops");
}

#[unsafe(naked)]
extern "C" fn log_write(_: u32, _: *const u8, _: u32, _: *const u8, _: u32) -> i64 {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_log_write");
}

#[unsafe(naked)]
extern "C" fn kstack_alloc() -> u64 {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_kstack_alloc");
}

#[unsafe(naked)]
extern "C" fn kstack_free(_: u64) -> i64 {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_kstack_free");
}

#[unsafe(naked)]
extern "C" fn stop(_: u32, _: u32, _: *const u8, _: u32) -> ! {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_stop");
}

#[cfg(kernelet_rq1)]
#[unsafe(naked)]
extern "C" fn rq1_echo(_: u64) -> i64 {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_rq1_echo");
}

#[unsafe(export_name = "__ostd_kernelet_service_table")]
static SERVICES: ServiceTable = ServiceTable {
    size: size_of::<ServiceTable>() as u64,
    grains_request,
    pt_root_register,
    pt_root_unregister,
    pt_activate,
    tlb_shootdown,
    kstack_alloc,
    kstack_free,
    vcpu_boot,
    vcpu_idle,
    vcpu_kick,
    vcpu_yield,
    vcpu_on_spin,
    user_run,
    mmio_read,
    mmio_write,
    log_write,
    oops,
    stop,
    #[cfg(kernelet_rq1)]
    rq1_echo,
};

/// Enters an image through an already validated entry address.
///
/// # Safety
///
/// `entry` must point into a live, validated RX image mapping. The caller
/// must retain that mapping and `boot`'s read-only page until this function
/// returns through `stop`.
pub(crate) unsafe fn enter(
    entry: usize,
    image: Range<usize>,
    text: Range<usize>,
    virq_entry: usize,
    yield_entry: usize,
    exit_entry: usize,
    stub_range: Range<usize>,
    cpu_access_range: Range<usize>,
    ex_table: Range<usize>,
    boot: *const BootArgs,
    vcpu_record: *const VcpuRecord,
    guest_memory: GuestMemory,
    idle_wait: Arc<WaitQueue>,
    hooks: Arc<dyn KerneletHooks>,
    control: &RunControl,
    grant: &Grant,
    execution: &ExecutionResources,
    vcpu: u16,
) -> crate::Result<u32> {
    let boot_stack = execution.stacks.lock().slots[vcpu as usize].base() as u64;
    let (stack_pool_start, stack_pool_end, stack_pool_live) = execution.stack_pool_layout();
    // The Host-built boot page indexes two pinned arrays: all vCPU records
    // first, followed by all recoverable copy-fault records.
    // SAFETY: `enter` receives the live, Host-built boot page retained by
    // the caller until all fixed carriers detach.
    let boot_args = unsafe { &*boot };
    debug_assert!((vcpu as usize) < boot_args.num_vcpus as usize);
    let copy_fault_offset = boot_args.vcpu_records as usize
        + copy_fault_records_offset(boot_args.num_vcpus as usize)
        + vcpu as usize * size_of::<CopyFaultRecord>();
    let copy_fault_record = (boot as *const u8).wrapping_add(copy_fault_offset);
    let fpu_stage = FpuContext::new();
    control.account.attach_carrier()?;
    assert!(crate::arch::irq::is_local_enabled());
    let irq_guard = irq::disable_local();
    // SAFETY: The caller passes the live, writable record mapped by the
    // instance; this publish happens before the first image instruction.
    unsafe {
        (*vcpu_record)
            .stack_limit
            .store(boot_stack, Ordering::Release);
        (*vcpu_record).irq_off.store(1, Ordering::Release);
    }
    let current = Task::current().expect("a kernelet carrier must be a native Task");
    let host_root = crate::mm::VmSpace::kernel_root_paddr();
    let mut state = CarrierState {
        host_rsp: 0,
        image_rsp: 0,
        image_start: image.start,
        image_end: image.end,
        ex_table,
        run_state: &control.carriers[vcpu as usize].run_state,
        carrier_task: &*current as *const Task as usize,
        host_root,
        active_root: Cell::new(0),
        execution,
        vcpu,
        vcpu_record: vcpu_record as usize,
        copy_fault_record: copy_fault_record as usize,
        boot_args: boot as usize,
        fpu_stage: RefCell::new(fpu_stage),
        fpu_paused: Cell::new(false),
        guest_memory,
        idle_wait,
        hooks,
        deferred_ticks: Cell::new(0),
        text,
        virq_entry,
        yield_entry,
        exit_entry,
        stub_range,
        cpu_access_range,
        control,
        grant,
        hook_active: Cell::new(false),
        paused_at: Cell::new(0),
        parked: Cell::new(false),
        throttled: Cell::new(false),
        last_spin: Cell::new(u64::MAX),
        vm_space: execution.carrier_vm_space(vcpu)?,
        tls: Cell::new(tls::TlsState::capture()),
        stop_state: control.stop_state(),
        stack_pool_start,
        stack_pool_end,
        stack_pool_live,
    };
    assert_eq!(KERNELET_HOST_STATE_PTR.load(), 0);
    // Guest XSAVE/XRSTOR use hardware directly, without an activation service.
    // Install neutral state before publishing this carrier: even the initial
    // budget wait can switch it out and save the now-live hardware state.
    // The borrow ends before a scheduler hook can borrow the staging context.
    state.fpu_stage.borrow().load();
    // SAFETY: The carrier is pinned on this current Task until fixed exit.
    unsafe { current.set_carrier_context(&mut state as *mut CarrierState as usize) };
    state.wait_for_budget(STARTING);

    // SAFETY: The caller supplies a live image entry, this function owns the
    // guarded image stack, and the carrier state is pinned. The assembly
    // entry enables physical IRQs after changing stacks and disables them on
    // the fixed exit continuation.
    core::mem::forget(irq_guard);
    let code = unsafe {
        kernelet_host_enter(
            entry,
            boot_stack as usize + KSTACK_USABLE_BYTES,
            &SERVICES,
            boot,
        )
    };

    // The assembly has restored the Host root with IRQs masked. In particular,
    // a stop racing the final trap commit may have left a conservative CPU bit
    // in the root's active set; remove it before releasing this carrier.
    state.clear_active_root();
    // A stop may make service entry or the final image-return commit fail.
    // Fixed exits restore the protected Host stack before publishing
    // LEAVING here, once the Host root and stack have been restored and before
    // the native carrier can detach.
    state.set_phase(LEAVING);
    // SAFETY: Fixed exit owns this Task and has masked physical IRQs.
    unsafe { current.set_carrier_context(0) };
    crate::arch::irq::enable_local();
    control.account.detach();
    Ok(code)
}

impl CarrierState<'_> {
    /// Retains a physical sample with its interrupted stack, independently of
    /// the Guest's current-Task publication during a context switch.
    fn sample_stack_tick(&self, rsp: usize, user: bool) -> bool {
        let result = self.execution.stacks.lock().record_tick(rsp, user);
        let reason = match result {
            Ok(()) => return true,
            Err(resources::TickSampleError::InvalidStack) => KillReason::StackReserve,
            // Opaque Host-policy code "TICK": stop rather than wrap or drop.
            Err(resources::TickSampleError::Overflow) => KillReason::HostPolicy(0x5449_434b),
        };
        self.control.stop(ExitReason::Killed(reason));
        false
    }

    fn copy_fault_record(&self) -> &CopyFaultRecord {
        // SAFETY: The Host pins both shared arrays for this instance. Entry
        // calculates this address from its validated boot page and vCPU index.
        unsafe { &*(self.copy_fault_record as *const CopyFaultRecord) }
    }
    /// Removes this physical CPU after the protected Host root is installed.
    /// The desired image root remains recorded across a Host deschedule.
    fn leave_active_root(&self) {
        crate::mm::VmSpace::deactivate();
        self.vm_space.set_root_restore(false);
    }

    /// Reserves this CPU for the desired root before the fixed CR3 write.
    ///
    /// Both the active-set insertion and generation observation are serialized
    /// with shootdown. IRQs remain masked until assembly installs the root;
    /// a concurrent shootdown must then target this CPU and await its IPI.
    fn prepare_active_root(&self) -> bool {
        if self.sample_stop() {
            return false;
        }
        let root = self.active_root.get();
        if root == 0 {
            return true;
        }
        let irq_guard = irq::disable_local();
        if !self.vm_space.prepare_registered_root(root, &irq_guard) {
            self.control
                .stop(ExitReason::Killed(KillReason::EntryFailed));
            self.sample_stop();
            return false;
        }
        true
    }

    /// Leaves the registered root before a native wait or root replacement.
    /// Both roots share the validated Host kernel half, including this stack.
    fn install_host_root(&self) {
        debug_assert!(!crate::arch::irq::is_local_enabled());
        self.leave_active_root();
    }

    fn admit_service(&self) -> Option<()> {
        debug_assert!(!crate::arch::irq::is_local_enabled());
        if self.sample_stop() || self.run_state.load(Ordering::Acquire) != ENTERING {
            return None;
        }
        // enter_vcpu retains the image/grant and execution resources through
        // fixed exit. Its native Task and active reservation prevent Exited
        // and reclamation until all service frames have returned. Only
        // operations outside this carrier need a separate operation guard.
        self.set_phase(SERVICE);
        Some(())
    }

    /// Releases the desired root after fixed exit or stop. Call only after
    /// the Host root has been installed, with physical IRQs masked.
    fn clear_active_root(&self) {
        let _guard = irq::disable_local();
        self.leave_active_root();
        self.vm_space.set_registered_root(None);
        self.active_root.set(0);
        self.control.carriers[self.vcpu as usize]
            .active_root
            .store(0, Ordering::Release);
    }

    /// Observes the instance's sticky mark without modifying the carrier phase.
    fn sample_stop(&self) -> bool {
        self.stop_state.load(Ordering::Acquire) & STOP_REQUESTED != 0
    }

    /// Host hook unwind completes on this CPU's private hook stack.
    fn call_hook<R>(&self, hook: impl FnOnce() -> R) -> Option<R> {
        let guard = crate::task::disable_preempt();
        self.hook_active.set(true);
        // SAFETY: The guard pins and excludes another task on this CPU's
        // hook stack. The catch runs there, so no unwind crosses the switch.
        let result = unsafe { hook_stack::call(&guard, || crate::panic::catch_unwind(hook)) };
        self.hook_active.set(false);
        drop(guard);
        match result {
            Ok(value) => Some(value),
            Err(_) => {
                self.control
                    .stop(ExitReason::Killed(KillReason::HostHookPanicked));
                None
            }
        }
    }

    /// Services that can wait or yield execute with native Host guard ownership.
    fn enter_schedulable_service(&self) {
        self.install_host_root();
        self.set_phase(SERVICE);
    }

    /// Publishes a phase from its sole writer with physical IRQs masked.
    /// Remote stop has its own word and cannot be overwritten by this store.
    fn set_phase(&self, phase: u32) {
        debug_assert!(!crate::arch::irq::is_local_enabled());
        if phase == SERVICE && self.run_state.load(Ordering::Acquire) == ENTERING {
            self.control
                .account
                .service_calls
                .fetch_add(1, Ordering::Relaxed);
        }
        self.run_state.store(phase, Ordering::Release);
    }

    /// Parks an authenticated carrier in Native Task context with no Host
    /// guard held. Physical IRQs are masked on entry and return. A synchronous
    /// service frame may remain live on the pinned shared Task stack; Guest
    /// guards do not prevent the Host from parking the entire carrier.
    /// `STARTING` has no image continuation yet; every other caller temporarily
    /// publishes the depth-one `THROTTLED` phase.
    fn wait_for_budget(&self, resume_phase: u32) {
        if self.sample_stop() {
            return;
        }
        #[cfg(kernelet_getpid_profile)]
        profile::event(profile::event_id::BUDGET_CHECK);
        #[cfg(kernelet_getpid_profile)]
        let account_span = profile::span(profile::stage::HOST_ACCOUNT);
        scheduler::runtime_ticks();
        #[cfg(kernelet_getpid_profile)]
        let _ = profile::end(account_span);
        if !self.control.account.exhausted() {
            return;
        }
        #[cfg(kernelet_getpid_profile)]
        profile::event(profile::event_id::THROTTLE);
        self.install_host_root();
        if resume_phase != STARTING {
            self.set_phase(THROTTLED);
        }
        self.throttled.set(true);
        crate::arch::irq::enable_local();
        self.control.account.wait_for_budget(|| self.sample_stop());
        crate::arch::irq::disable_local();
        self.throttled.set(false);
        if resume_phase != STARTING {
            self.set_phase(resume_phase);
        }
    }
}

/// Records the quota decision made by the physical Host tick.
///
/// The timer has already charged the current Task. Parking waits until a
/// user IRQ continuation or the fixed yield continuation can sleep.
pub(crate) fn on_host_tick() {
    // SAFETY: The timer callback runs with physical IRQs masked on this CPU.
    if let Some(state) = unsafe { current_carrier_state() } {
        let _ = state.control.account.exhausted();
    }
}

/// # Safety
///
/// The caller must run on the current carrier's pinned physical CPU.
unsafe fn current_carrier_state<'a>() -> Option<&'a CarrierState<'a>> {
    let state_ptr = KERNELET_HOST_STATE_PTR.load() as *const CarrierState;
    if state_ptr.is_null() {
        return None;
    }
    // SAFETY: The pointer is installed by `enter` before image entry and only
    // removed after the fixed exit continuation returns on the same pinned CPU.
    let state = unsafe { &*state_ptr };
    let current = Task::current()?;
    if state.carrier_task != &*current as *const Task as usize {
        return None;
    }
    #[cfg(kernelet_getpid_profile)]
    let _identity_span = {
        profile::event(profile::event_id::IDENTITY_LOOKUP);
        profile::span(profile::stage::HOST_IDENTITY)
    };
    let identity = super::vcpu_slot::current();
    if identity.vcpu != state.vcpu {
        return None;
    }
    // The current Task pins state.control. Authenticate its borrowed address
    // against the Host registry without acquiring a lock or cloning an Arc.
    RunControl::lookup_cpu_slot(identity, state.control)?;
    Some(state)
}

/// Identifies the bounded Host-hook unwind scope to the kernel panic handler.
pub(crate) fn in_host_hook() -> bool {
    // SAFETY: Disabling IRQs pins the current CPU while validating the carrier.
    let _irq = irq::disable_local();
    unsafe { current_carrier_state() }.is_some_and(|state| state.hook_active.get())
}

/// Finds the validated fixup for a copy fault in the current image.
///
/// The ELF registration audit checked every self-relative entry, including
/// its ordering and both targets' membership in executable image text.
pub(crate) fn image_copy_recovery(instruction: usize) -> Option<usize> {
    // SAFETY: The carrier pins the image and its immutable table until exit.
    let state = unsafe { current_carrier_state()? };
    if state.run_state.load(Ordering::Acquire) != IMAGE || !state.text.contains(&instruction) {
        return None;
    }
    let table = &state.ex_table;
    let mut low = 0;
    let mut high = (table.end - table.start) / 16;
    while low < high {
        let mid = low + (high - low) / 2;
        let entry = table.start + mid * 16;
        // SAFETY: The read-only table is mapped and its complete bounds were
        // validated when the image kind was registered.
        let offset = unsafe { (entry as *const i64).read() };
        let fault = entry.wrapping_add_signed(offset as isize);
        match fault.cmp(&instruction) {
            core::cmp::Ordering::Less => low = mid + 1,
            core::cmp::Ordering::Greater => high = mid,
            core::cmp::Ordering::Equal => {
                // SAFETY: Registration checked the second field as well.
                let recovery_field = entry + 8;
                let offset = unsafe { (recovery_field as *const i64).read() };
                return Some(recovery_field.wrapping_add_signed(offset as isize));
            }
        }
    }
    None
}

fn containable_image_exception(vector: usize) -> bool {
    vector < 32 && !matches!(vector, 2 | 18)
}

/// Contains an image exception on the native trap path at service depth zero.
/// A validated user-copy fault publishes its hardware details before the fixup.
pub(crate) fn contain_image_exception(frame: &mut crate::arch::trap::TrapFrame) -> bool {
    if !containable_image_exception(frame.trap_num) {
        return false;
    }
    // SAFETY: The native trap retains this current carrier with IRQs masked.
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return false;
    };
    if !state.text.contains(&frame.rip) || state.run_state.load(Ordering::Acquire) != IMAGE {
        return false;
    }
    if frame.trap_num == 8 {
        // Double fault may have interrupted an exhausted stack while it held
        // Guest locks. Detection must neither inspect that stack nor take locks.
        state
            .control
            .stop(ExitReason::Killed(KillReason::StackOverflow));
        redirect_fatal_image_exception(state, frame);
        return true;
    }
    if frame.trap_num == 14
        && x86_64::registers::control::Cr2::read_raw() < crate::mm::MAX_USERSPACE_VADDR as u64
    {
        if let Some(recovery) = image_copy_recovery(frame.rip) {
            // The trap epilogue checks this again after the handler returns.
            // Do not resume at a fixup after stop has already been published.
            if state.sample_stop() {
                return true;
            }
            // Only this carrier publishes its recoverable copy-fault slot.
            let copy_fault = state.copy_fault_record();
            copy_fault.addr.store(
                x86_64::registers::control::Cr2::read_raw(),
                Ordering::Relaxed,
            );
            copy_fault
                .error
                .store(frame.error_code as u64, Ordering::Relaxed);
            copy_fault.pending.store(1, Ordering::Release);
            frame.rip = recovery;
            return true;
        }
    }
    let addr = if frame.trap_num == 14 {
        x86_64::registers::control::Cr2::read_raw()
    } else {
        0
    };
    let in_pool_guard = (state.stack_pool_start..state.stack_pool_end).contains(&(addr as usize))
        && (addr as usize - state.stack_pool_start) % resources::STACK_STRIDE
            < resources::STACK_BYTES;
    let reason = if frame.trap_num == 14 && in_pool_guard {
        KillReason::StackOverflow
    } else {
        KillReason::KernelFault {
            addr,
            ip: frame.rip as u64,
        }
    };
    state.control.stop(ExitReason::Killed(reason));
    redirect_fatal_image_exception(state, frame);
    true
}

/// A synchronous fatal exception discards the failed continuation, including
/// exceptions inside a redirect stub. Never IRET through its untrusted RSP or
/// selectors before the fixed exit installs the protected Host stack/root.
fn redirect_fatal_image_exception(state: &CarrierState, frame: &mut crate::arch::trap::TrapFrame) {
    frame.rip = state.exit_entry;
    frame.rsp = state.host_rsp;
    frame.cs = crate::arch::trap::KERNEL_CS_VALUE;
    frame.ss = crate::arch::trap::KERNEL_SS_VALUE;
    frame.rflags = 2;
}

/// Runs at native kernel trap return, after Host callback levels unwind.
/// Ordinary traps retain the shared Task stack and the currently active root.
pub(crate) fn finish_image_trap(frame: &mut crate::arch::trap::TrapFrame) {
    if frame.cs & 3 != 0 || !irq::InterruptLevel::current().is_task_context() {
        return;
    }
    // SAFETY: Physical IRQs are masked by the native trap path. The current
    // carrier and its immutable image entry table are pinned until fixed exit.
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return;
    };
    if state.run_state.load(Ordering::Acquire) != IMAGE
        || !state.text.contains(&frame.rip)
        || state.stub_range.contains(&frame.rip)
    {
        return;
    }
    let cpu_access = state.cpu_access_range.contains(&frame.rip);
    // An ordinary CPU-local sequence must finish on this internal Task even
    // after stop or quota exhaustion. Unlike fixed entry stubs, it still owes
    // the interrupted Task and virtual timer their physical tick samples.
    if !cpu_access && state.sample_stop() {
        frame.rip = state.exit_entry;
        frame.rflags &= !(1 << 9);
        return;
    }
    if frame.trap_num < 32 || frame.rflags & (1 << 9) == 0 {
        return;
    }
    // SAFETY: The authenticated carrier pins its cooperation record.
    let record = unsafe { &*(state.vcpu_record as *const VcpuRecord) };
    let is_timer = crate::arch::is_timer_irq(frame.trap_num);
    if is_timer {
        match sample_tick_before_redirect(record, frame.rsp, cpu_access, |rsp| {
            state.sample_stack_tick(rsp, false)
        }) {
            Ok(false) => return,
            Ok(true) => (),
            Err(()) => {
                redirect_fatal_image_exception(state, frame);
                return;
            }
        }
    } else if cpu_access {
        return;
    }
    let critical =
        record.guards.load(Ordering::Acquire) != 0 || record.irq_off.load(Ordering::Acquire) != 0;
    let at_bound = if critical && is_timer {
        let ticks = state.deferred_ticks.get().saturating_add(1);
        state.deferred_ticks.set(ticks);
        ticks >= 2
    } else {
        false
    };
    if at_bound || state.control.account.is_throttled() {
        let redirected = redirect_image_return(state, record, frame, state.yield_entry);
        #[cfg(kernelet_rq1_diagnostics)]
        if redirected {
            state
                .control
                .account
                .forced_yields
                .fetch_add(1, Ordering::Relaxed);
        }
        #[cfg(not(kernelet_rq1_diagnostics))]
        let _ = redirected;
        state.deferred_ticks.set(0);
    } else if !critical
        && has_deliverable_virtual_interrupt(record)
        && state.copy_fault_record().pending.load(Ordering::Acquire) == 0
    {
        state.deferred_ticks.set(0);
        let _ = redirect_image_return(state, record, frame, state.virq_entry);
    }
}

/// Records a physical timer before deciding whether this instruction can be
/// redirected. The stack sampler authenticates the interrupted Task's slot.
fn sample_tick_before_redirect(
    record: &VcpuRecord,
    rsp: usize,
    cpu_access: bool,
    sample_stack: impl FnOnce(usize) -> bool,
) -> Result<bool, ()> {
    let counter = if record.irq_level.load(Ordering::Acquire) != 0 {
        &record.tick_l2
    } else {
        if !sample_stack(rsp) {
            return Err(());
        }
        &record.tick_kernel
    };
    counter.fetch_add(1, Ordering::Relaxed);
    record.pending.fetch_or(VIRQ_TICK, Ordering::Release);
    Ok(!cpu_access)
}

/// Uses the two retired trap words below the live IRET frame as a handoff.
/// The image stub saves registers before rebuilding its final IRET frame.
fn redirect_image_return(
    state: &CarrierState,
    record: &VcpuRecord,
    frame: &mut crate::arch::trap::TrapFrame,
    entry: usize,
) -> bool {
    let Some(reserve_start) = frame.rsp.checked_sub(UPCALL_STACK_RESERVE) else {
        state
            .control
            .stop(ExitReason::Killed(KillReason::StackReserve));
        redirect_fatal_image_exception(state, frame);
        return false;
    };
    if !state
        .execution
        .stacks
        .lock()
        .contains_current_range(reserve_start, frame.rsp, frame.rsp)
    {
        state
            .control
            .stop(ExitReason::Killed(KillReason::StackReserve));
        redirect_fatal_image_exception(state, frame);
        return false;
    }
    // &trap_num == align_down(interrupted RSP, 16) - 56. Only trap_num and
    // error_code are retired before the first IRET; writing beyond them would
    // corrupt that IRET's still-live RIP/CS/RFLAGS/RSP/SS.
    frame.trap_num = frame.rip;
    frame.error_code = frame.rsp;
    frame.rsp = core::ptr::addr_of!(frame.trap_num) as usize;
    frame.rip = entry;
    frame.rflags &= !(1 << 9);
    if entry == state.virq_entry {
        record.irq_off.store(1, Ordering::Release);
    }
    true
}

fn has_deliverable_virtual_interrupt(record: &VcpuRecord) -> bool {
    let pending = record.pending.load(Ordering::Acquire);
    pending != 0 && record.irq_level.load(Ordering::Acquire) == 0
}

// SAFETY: The rejecting assembly stub has installed the native stack/root
// before this function runs; it never dereferences the rejected RSP.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_stack_invalid_impl() {
    if let Some(state) = unsafe { current_carrier_state() } {
        state
            .control
            .stop(ExitReason::Killed(KillReason::StackReserve));
    }
}

/// Completes a service after every Rust service frame and guard has unwound.
/// Virtual interrupts are delivered only by the native trap-return hook.
// SAFETY: The fixed service stubs call with physical IRQs masked. Entry has
// authenticated the pinned carrier, and native switches restore its pointer.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_prepare_service_return_impl() {
    #[cfg(kernelet_getpid_profile)]
    let _return_span = profile::span(profile::stage::HOST_RETURN_PREPARE);
    let ptr = KERNELET_HOST_STATE_PTR.load() as *const CarrierState;
    if ptr.is_null() {
        return;
    }
    // SAFETY: This is the same Host-private carrier authenticated on entry;
    // a synchronous service continuation cannot migrate to another Task.
    let state = unsafe { &*ptr };
    if state.sample_stop() {
        return;
    }
    if state.run_state.load(Ordering::Acquire) == RETURNING {
        let _ = state.prepare_active_root();
    }
}

// SAFETY: A failed final commit calls with IRQs masked on the validated shared
// Task stack. The fixed exit restores the protected Host stack afterward.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_cancel_service_return_impl() {
    if let Some(state) = unsafe { current_carrier_state() } {
        state.set_phase(LEAVING);
    }
}

// SAFETY: Only the assembly stop stub calls this on the native Host stack.
// The assembly continuation restores the carrier's saved registers and stack.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_stop_impl(kind: u32, code: u32, msg: *const u8, len: u32) -> u32 {
    // SAFETY: The assembly stub entered from the current carrier and retains
    // its state until the fixed exit continuation.
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return (-STATE) as u32;
    };
    let Some(_admission) = state.admit_service() else {
        return (-STATE) as u32;
    };
    state.leave_active_root();
    state.set_phase(LEAVING);
    // Copy once into Host storage before publishing the stop.
    let mut buffer = [0; MAX_OOPS_BYTES as usize];
    // SAFETY: The carrier pins the Image; mapped source bytes are supplied
    // under the synchronous shared-byte borrow of the stop ABI.
    let message = unsafe { record::read(state, msg, len, &mut buffer) }
        .ok()
        .and_then(|bytes| core::str::from_utf8(bytes).ok());
    let reason = match kind {
        super::abi::STOP_EXIT => ExitReason::Exited(code),
        super::abi::STOP_PANIC => {
            ExitReason::Panicked(message.unwrap_or("invalid panic record").to_string())
        }
        super::abi::STOP_STACK_OVERFLOW => ExitReason::Killed(KillReason::StackOverflow),
        _ => ExitReason::Killed(KillReason::HostPolicy(kind)),
    };
    state.control.stop(reason);
    // The stop assembly stub already installed the native root. Keep the
    // desired root until fixed-exit cleanup clears its shared registration.
    if let Some(message) = message {
        crate::info!("kernelet stopped: kind={kind}, code={code}, {message}");
    } else {
        crate::info!("kernelet stopped: kind={kind}, code={code}");
    }
    code
}

#[cfg(ktest)]
#[crate::prelude::ktest]
fn machine_events_do_not_enter_tenant_fault_containment() {
    assert!(!containable_image_exception(2));
    assert!(!containable_image_exception(18));
    assert!(!containable_image_exception(32));
    assert!(containable_image_exception(8));
    assert!(containable_image_exception(14));
}

#[cfg(ktest)]
#[crate::prelude::ktest]
fn cpu_local_access_defers_redirect_without_losing_physical_ticks() {
    use super::abi::StackTickRecord;

    let record = VcpuRecord::default();
    let stack_ticks = StackTickRecord::default();
    let rsp = 0x1000;
    let may_redirect = sample_tick_before_redirect(&record, rsp, true, |observed| {
        assert_eq!(observed, rsp);
        stack_ticks.record(false)
    })
    .unwrap();
    assert!(!may_redirect);
    assert_eq!(record.tick_kernel.load(Ordering::Acquire), 1);
    assert_eq!(record.pending.load(Ordering::Acquire), VIRQ_TICK);
    assert_eq!(stack_ticks.take(), (0, 1));

    // A nested virtual IRQ keeps its L2 classification without attributing
    // its tick to the interrupted Task, including in a protected CPU access.
    record.irq_level.store(1, Ordering::Release);
    assert!(
        !sample_tick_before_redirect(&record, rsp, true, |_| {
            panic!("L2 must not sample the Task stack")
        })
        .unwrap()
    );
    assert_eq!(record.tick_l2.load(Ordering::Acquire), 1);
    record.irq_level.store(0, Ordering::Release);
    assert!(
        sample_tick_before_redirect(&record, rsp, false, |_| stack_ticks.record(false)).unwrap()
    );
    assert_eq!(record.tick_kernel.load(Ordering::Acquire), 2);
    assert_eq!(stack_ticks.take(), (0, 1));
}
