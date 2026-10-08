// SPDX-License-Identifier: MPL-2.0

//! Host-private state for one carrier crossing a kernelet image boundary.
//!
//! Physical interrupts from image code switch to the carrier's protected Host
//! stack before entering compiled Host handlers.
//!
//! This module owns the authoritative carrier state and the single
//! enter/return/stop transaction, including trap containment and virtual
//! interrupt redirection. Child modules own the shared execution resources
//! ([`resources`]), the FPU crossing policy ([`fpu`]), and the service
//! implementation bodies ([`vcpu`], [`roots`], [`mem`], [`hooks`]).

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
        BootArgs, CopyFaultRecord, INVALID, KletUserContext, MAX_OOPS_BYTES, MmioResult, STATE,
        ServiceTable, VIRQ_TICK, VcpuRecord, copy_fault_records_offset,
    },
    control::{ExitReason, KerneletHooks, KerneletState, KillReason, OperationGuard, RunControl},
    guest_memory::GuestMemory,
    host_grant::Grant,
};
use crate::{
    arch::cpu::context::FpuContext,
    cpu::PinCurrentCpu,
    irq,
    sync::WaitQueue,
    task::{Task, scheduler},
};

mod fpu;
mod hooks;
mod mem;
mod resources;
mod roots;
mod vcpu;

pub(crate) use resources::ExecutionResources;

pub(crate) const PREPARED: u32 = 0;
const IMAGE: u32 = 1;
pub(crate) const STARTING: u32 = 8;
const ENTERING: u32 = 2;
const SERVICE: u32 = 3;
pub(crate) const RETURNING: u32 = 4;
pub(crate) const STOP_REQUESTED: u32 = 1 << 31;
pub(crate) const LEAVING: u32 = 5;
pub(crate) const DETACHED: u32 = 11;
const USER: u32 = 6;
const IDLE: u32 = 9;
const THROTTLED: u32 = 10;
const UPCALL_STACK_RESERVE: usize = 64 * 1024;

global_asm!(
    include_str!("host_run.S"),
    phase_starting = const STARTING,
    phase_image = const IMAGE,
    phase_entering = const ENTERING,
    phase_returning = const RETURNING,
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
    host_root: Cell<usize>,
    active_root: Cell<usize>,
    host_idtr: x86_64::structures::DescriptorTablePointer,
    image_idtr: x86_64::structures::DescriptorTablePointer,
    execution: &'a ExecutionResources,
    vcpu: u16,
    vcpu_record: usize,
    copy_fault_record: usize,
    boot_args: usize,
    fpu_stage: RefCell<FpuContext>,
    fpu_restore: fpu::FpuRestorePolicy,
    guest_memory: GuestMemory,
    idle_wait: Arc<WaitQueue>,
    hooks: Arc<dyn KerneletHooks>,
    ex_table: Range<usize>,
    deferred_ticks: Cell<u32>,
    text: Range<usize>,
    virq_entry: usize,
    control: &'a RunControl,
    grant: &'a Grant,
    hook_active: Cell<bool>,
    paused_at: Cell<u64>,
    parked: Cell<bool>,
    throttled: Cell<bool>,
    last_spin: Cell<u64>,
    service_redirected: Cell<bool>,
    landing_start: usize,
    landing_end: usize,
    // A forced-yield IRET borrows this carrier's pinned IST frame. The first
    // IRET enters the fixed stub with safe flags; the second restores these
    // original flags and RIP together with the frame's unmodified GPRs/RSP.
    yield_rip: Cell<usize>,
    yield_rflags: Cell<usize>,
    yield_pending: Cell<bool>,
    trap_active: Cell<bool>,
    // Host-private native guard baseline; shared fields never authorize subtraction.
    host_preempt_base: Cell<u32>,
    mirror_suspended: Cell<bool>,
    // True from active-set reservation until the hardware root is left.
    root_installed: Cell<bool>,
    // Once a guest user context has been loaded, preserve its hardware state
    // across native carrier switches, including switches inside a service.
    fpu_active: Cell<bool>,
    fpu_paused: Cell<bool>,
}

const _: () = {
    assert!(offset_of!(CarrierState, host_rsp) == 0);
    assert!(offset_of!(CarrierState, image_rsp) == 8);
    assert!(offset_of!(CarrierState, run_state) == 32);
    assert!(offset_of!(CarrierState, carrier_task) == 40);
    assert!(offset_of!(CarrierState, host_root) == 48);
    assert!(offset_of!(CarrierState, active_root) == 56);
    assert!(offset_of!(CarrierState, host_idtr) == 64);
    assert!(offset_of!(CarrierState, image_idtr) == 74);
    assert!(offset_of!(CarrierState, landing_start) == 304);
    assert!(offset_of!(CarrierState, landing_end) == 312);
};

crate::cpu_local_cell! {
    #[unsafe(no_mangle)]
    static KERNELET_HOST_STATE_PTR: usize = 0;
}

/// Reinstalls a native Task's protected carrier pointer after a Host switch.
/// The Task owns this address until it clears the slot at fixed exit.
///
/// # Safety
/// A nonzero address must name the current Task's pinned carrier. Physical
/// IRQs must be masked while the CPU-local pointer and counters are updated.
pub(crate) unsafe fn restore_carrier_context(address: usize) {
    KERNELET_HOST_STATE_PTR.store(address);
    if address == 0 {
        // SAFETY: The native IDT does not reference the reserved image slots.
        unsafe { crate::arch::trap::set_carrier_stacks([0; 5]) };
        return;
    }
    // SAFETY: The native Task owns this pinned carrier context until fixed exit.
    let state = unsafe { &*(address as *const CarrierState) };
    if state.fpu_paused.replace(false) {
        state.fpu_stage.borrow().load();
    }
    // SAFETY: The fixed carrier owns these mapped landing stacks until detach.
    unsafe {
        crate::arch::trap::set_carrier_stacks(state.execution.landings[state.vcpu as usize].tops())
    };
    // A native IRQ can preempt the Host user-entry prefix while USER is
    // published. Its continuation must regain the tenant root before it can
    // enter ring 3. SERVICE/trap continuations resume under the Host root.
    state
        .host_root
        .set(crate::arch::mm::current_page_table_paddr());
    if state.run_state.load(Ordering::Acquire) & !STOP_REQUESTED == USER
        && state.prepare_active_root()
    {
        // SAFETY: IRQs are masked and the active-set reservation pins this
        // registered root through user entry or a subsequent Host handoff.
        unsafe { crate::arch::mm::activate_page_table(state.active_root.get()) };
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
        // SAFETY: Called only for the outgoing Task while IRQs are masked.
        let state = unsafe { &*(address as *const CarrierState) };
        if state.fpu_active.get() {
            state.fpu_stage.borrow_mut().save();
            state.fpu_paused.set(true);
        }
        state.install_host_root();
        state.paused_at.set(crate::arch::read_tsc());
        // A real native context switch restarts the cooperative grace period.
        state.deferred_ticks.set(0);
    }
}

unsafe extern "C" {
    fn kernelet_host_enter(
        entry: usize,
        image_stack_top: usize,
        services: &'static ServiceTable,
        boot: *const BootArgs,
    ) -> u32;
    fn kernelet_host_forced_yield();
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
extern "C" fn user_run(_: *mut KletUserContext) -> i64 {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_user_run");
}
#[unsafe(naked)]
extern "C" fn fpu_save(_: *mut u8, _: u32) -> i64 {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_fpu_save");
}
#[unsafe(naked)]
extern "C" fn fpu_load(_: *const u8, _: u32) -> i64 {
    core::arch::naked_asm!("endbr64", "jmp kernelet_service_fpu_load");
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
    fpu_save,
    fpu_load,
    mmio_read,
    mmio_write,
    log_write,
    oops,
    stop,
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
    let landing_range = execution.landings[vcpu as usize].area.range();
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
    let mut fpu_stage = FpuContext::new();
    let fpu_restore = fpu::FpuRestorePolicy::from_host(&mut fpu_stage);
    control.account.attach(false)?;
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
    let host_root = crate::arch::mm::current_page_table_paddr();
    let (host_idtr, image_idtr) = crate::arch::trap::carrier_idtrs();
    let mut state = CarrierState {
        host_rsp: 0,
        image_rsp: 0,
        image_start: image.start,
        image_end: image.end,
        ex_table,
        run_state: &control.carriers[vcpu as usize].run_state,
        carrier_task: &*current as *const Task as usize,
        host_root: Cell::new(host_root),
        active_root: Cell::new(0),
        host_idtr,
        image_idtr,
        execution,
        vcpu,
        vcpu_record: vcpu_record as usize,
        copy_fault_record: copy_fault_record as usize,
        boot_args: boot as usize,
        fpu_stage: RefCell::new(fpu_stage),
        fpu_restore,
        fpu_active: Cell::new(false),
        fpu_paused: Cell::new(false),
        guest_memory,
        idle_wait,
        hooks,
        deferred_ticks: Cell::new(0),
        text,
        virq_entry,
        control,
        grant,
        hook_active: Cell::new(false),
        paused_at: Cell::new(0),
        parked: Cell::new(false),
        throttled: Cell::new(false),
        last_spin: Cell::new(u64::MAX),
        service_redirected: Cell::new(false),
        landing_start: landing_range.start,
        landing_end: landing_range.end,
        yield_rip: Cell::new(0),
        yield_rflags: Cell::new(0),
        yield_pending: Cell::new(false),
        trap_active: Cell::new(false),
        host_preempt_base: Cell::new(crate::task::carrier_preempt::guard_count()),
        mirror_suspended: Cell::new(true),
        root_installed: Cell::new(false),
    };
    assert_eq!(KERNELET_HOST_STATE_PTR.load(), 0);
    // SAFETY: The carrier is pinned on this current Task until fixed exit.
    unsafe { current.set_carrier_context(&mut state as *mut CarrierState as usize) };
    state.wait_for_budget(STARTING);
    state.resume_mirror();

    // SAFETY: The caller supplies a live image entry, this function owns the
    // guarded image stack, and the carrier state is pinned. The assembly
    // entry enables physical IRQs after changing stacks and disables them on
    // the fixed exit continuation.
    core::mem::forget(irq_guard);
    let code = unsafe {
        kernelet_host_enter(
            entry,
            boot_stack as usize + resources::STACK_BYTES,
            &SERVICES,
            boot,
        )
    };

    // The assembly has restored the Host root with IRQs masked. In particular,
    // a stop racing the final trap commit may have left a conservative CPU bit
    // in the root's active set; remove it before releasing this carrier.
    state.suspend_mirror();
    state.clear_active_root();
    // A stop may make service entry or the final image-return commit fail.
    // Fixed exits cannot call Rust on the image stack or IST, so publish
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
    fn copy_fault_record(&self) -> &CopyFaultRecord {
        // SAFETY: The Host pins both shared arrays for this instance. Entry
        // calculates this address from its validated boot page and vCPU index.
        unsafe { &*(self.copy_fault_record as *const CopyFaultRecord) }
    }
    /// Removes this physical CPU after the protected Host root is installed.
    /// The desired image root remains recorded across a Host deschedule.
    fn leave_active_root(&self) {
        if !self.root_installed.replace(false) {
            return;
        }
        let root = self.active_root.get();
        if root == 0 {
            return;
        }
        let guard = irq::disable_local();
        let cpu = guard.current_cpu();
        let mut roots = self.execution.roots.lock();
        if let Ok(index) = roots.binary_search_by_key(&(root as u64), |entry| entry.paddr) {
            roots[index].active.remove(cpu);
        }
    }

    /// Reserves this CPU for the desired root before the fixed CR3 write.
    ///
    /// Both the active-set insertion and generation observation are serialized
    /// with shootdown. IRQs remain masked until assembly installs the root;
    /// a concurrent shootdown must then target this CPU and await its IPI.
    fn prepare_active_root(&self) -> bool {
        if self.root_installed.get() {
            return true;
        }
        let root = self.active_root.get();
        if root == 0 {
            return true;
        }
        let guard = irq::disable_local();
        let cpu = guard.current_cpu();
        let mut roots = self.execution.roots.lock();
        let Ok(index) = roots.binary_search_by_key(&(root as u64), |entry| entry.paddr) else {
            drop(roots);
            self.control
                .stop(ExitReason::Killed(KillReason::EntryFailed));
            return false;
        };
        let registration = &mut roots[index];
        let seen = &mut registration.seen_generation[u32::from(cpu) as usize];
        if *seen != registration.generation {
            // The CPU used this root before an inactive-period invalidation.
            // The mandatory CR3 write on resume also flushes non-global TLBs.
            crate::arch::mm::tlb_flush_all_excluding_global();
            *seen = registration.generation;
        }
        registration.active.add(cpu);
        self.root_installed.set(true);
        true
    }

    /// Leaves the registered root before a native wait or root replacement.
    /// Both roots share the validated Host kernel half, including this stack.
    fn install_host_root(&self) {
        debug_assert!(!crate::arch::irq::is_local_enabled());
        if self.root_installed.get() {
            // SAFETY: The saved native root and Host stack remain live while
            // this carrier runs. IRQ masking excludes a partial root handoff.
            if crate::arch::mm::current_page_table_paddr() != self.host_root.get() {
                unsafe { crate::arch::mm::activate_page_table(self.host_root.get()) };
            }
            self.leave_active_root();
        }
        self.host_root
            .set(crate::arch::mm::current_page_table_paddr());
    }

    fn admit_service(&self) -> Option<OperationGuard<'_>> {
        if self.run_state.load(Ordering::Acquire) != ENTERING {
            return None;
        }
        let admission = self
            .control
            .admit_operation(&[KerneletState::Running])
            .ok()?;
        self.set_phase(SERVICE);
        Some(admission)
    }

    /// Releases the desired root after fixed exit or stop. Call only after
    /// the Host root has been installed, with physical IRQs masked.
    fn clear_active_root(&self) {
        let guard = irq::disable_local();
        let cpu = guard.current_cpu();
        let mut roots = self.execution.roots.lock();
        if let Ok(index) =
            roots.binary_search_by_key(&(self.active_root.get() as u64), |entry| entry.paddr)
        {
            roots[index].active.remove(cpu);
        }
        self.active_root.set(0);
        self.root_installed.set(false);
        self.control.carriers[self.vcpu as usize]
            .active_root
            .store(0, Ordering::Release);
    }

    /// Host hook unwind completes on the native stack before requesting stop.
    fn call_hook<R>(&self, hook: impl FnOnce() -> R) -> Option<R> {
        self.hook_active.set(true);
        let result = crate::panic::catch_unwind(hook);
        self.hook_active.set(false);
        match result {
            Ok(value) => Some(value),
            Err(_) => {
                self.control
                    .stop(ExitReason::Killed(KillReason::HostHookPanicked));
                None
            }
        }
    }

    /// Removes image-owned guard state before a native wait or fixed exit.
    /// This is called with physical IRQs masked and no temporary Host guard.
    fn suspend_mirror(&self) {
        debug_assert!(!crate::arch::irq::is_local_enabled());
        // SAFETY: The carrier pins the shared record through fixed exit.
        let record = unsafe { &*(self.vcpu_record as *const VcpuRecord) };
        record.mirrored.store(0, Ordering::Relaxed);
        crate::task::carrier_preempt::restore_guards(self.host_preempt_base.get());
        self.mirror_suspended.set(true);
    }

    /// Reestablishes the mirror immediately before the final image commit.
    fn resume_mirror(&self) {
        debug_assert!(!crate::arch::irq::is_local_enabled());
        if self.mirror_suspended.replace(false) {
            self.host_preempt_base
                .set(crate::task::carrier_preempt::guard_count());
        }
        // SAFETY: The carrier pins the shared record through fixed exit.
        let record = unsafe { &*(self.vcpu_record as *const VcpuRecord) };
        let critical = record.guards.load(Ordering::Acquire) != 0
            || record.irq_off.load(Ordering::Acquire) != 0;
        crate::task::carrier_preempt::restore_guards(
            self.host_preempt_base.get() + u32::from(critical),
        );
        record
            .mirrored
            .store(u32::from(critical), Ordering::Release);
    }

    /// Services that can wait or yield execute with native Host guard ownership.
    fn enter_schedulable_service(&self) {
        self.install_host_root();
        self.suspend_mirror();
        self.set_phase(SERVICE);
    }

    /// Changes only the phase; a concurrent stop request is never overwritten.
    fn set_phase(&self, phase: u32) {
        if phase == SERVICE
            && self.run_state.load(Ordering::Acquire) == ENTERING
            && !self.yield_pending.get()
            && !self.trap_active.get()
        {
            self.control
                .account
                .service_calls
                .fetch_add(1, Ordering::Relaxed);
        }
        let _ = self
            .run_state
            .try_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                Some((old & STOP_REQUESTED) | phase)
            });
    }

    /// Throttling runs only after the Rust service frame has unwound, or at a
    /// Host-stack entry point. `STARTING` has no image continuation yet; every
    /// other caller temporarily publishes the depth-one `THROTTLED` phase.
    fn wait_for_budget(&self, resume_phase: u32) {
        // Native scheduling may have changed CR3. The current root owns the
        // CPU's page-table reference; a previously captured root may retire.
        if !self.root_installed.get() {
            self.host_root
                .set(crate::arch::mm::current_page_table_paddr());
        }
        scheduler::runtime_ticks();
        if !self.control.account.exhausted() {
            return;
        }
        self.install_host_root();
        if resume_phase != STARTING {
            self.set_phase(THROTTLED);
        }
        self.throttled.set(true);
        crate::arch::irq::enable_local();
        self.control
            .account
            .wait_for_budget(|| self.run_state.load(Ordering::Acquire) & STOP_REQUESTED != 0);
        crate::arch::irq::disable_local();
        self.throttled.set(false);
        self.host_root
            .set(crate::arch::mm::current_page_table_paddr());
        if resume_phase != STARTING {
            self.set_phase(resume_phase);
        }
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
    if (state.run_state.load(Ordering::Acquire) & !STOP_REQUESTED) != SERVICE
        || !state.trap_active.get()
        || !(state.image_start..state.image_end).contains(&instruction)
    {
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

/// Contains a depth-zero image exception after its trap switched to Host state.
/// A validated user-copy fault publishes its hardware details before the fixup.
pub(crate) fn contain_image_exception(frame: &mut crate::arch::trap::TrapFrame) -> bool {
    if frame.trap_num >= 32 {
        return false;
    }
    // SAFETY: The trap adapter retains the pinned current carrier.
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return false;
    };
    if !state.text.contains(&frame.rip) {
        return false;
    }
    if frame.trap_num == 14 {
        if let Some(recovery) = image_copy_recovery(frame.rip) {
            // The trap epilogue checks this again after the handler returns.
            // Do not resume at a fixup after stop has already been published.
            if state.run_state.load(Ordering::Acquire) & STOP_REQUESTED != 0 {
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
    let reason = if frame.trap_num == 14
        && state.execution.stacks.lock().slots.iter().any(|slot| {
            slot.area.range().contains(&(addr as usize)) && !slot.contains(addr as usize)
        }) {
        KillReason::StackOverflow
    } else {
        KillReason::KernelFault {
            addr,
            ip: frame.rip as u64,
        }
    };
    state.control.stop(ExitReason::Killed(reason));
    true
}

/// The trap assembly has installed the Host root before calling its handler.
pub(crate) fn begin_image_trap() {
    // SAFETY: The trap adapter runs on the authenticated, pinned carrier.
    if let Some(state) = unsafe { current_carrier_state() } {
        // The assembly published IMAGE -> ENTERING before switching the
        // protected root and stack. This is a physical trap, not a Guest
        // service-table call, so it does not increment service_calls.
        state.trap_active.set(true);
        state.leave_active_root();
        state.set_phase(SERVICE);
    }
}

/// Prepares the root before the trap assembly's final IMAGE commit.
/// A stop racing that commit is cleaned up by `enter` after fixed exit.
pub(crate) fn end_image_trap() {
    // Leave IRQs masked until trap.S has committed IMAGE and written CR3.
    // Restoring IF here would permit a native preemption to migrate the
    // carrier after we recorded this physical CPU in the active set.
    crate::arch::irq::disable_local();
    // SAFETY: The native trap adapter retains this carrier across Host work.
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return;
    };
    state
        .host_root
        .set(crate::arch::mm::current_page_table_paddr());
    state.trap_active.set(false);
    state.set_phase(RETURNING);
    if state.run_state.load(Ordering::Acquire) == RETURNING && !state.yield_pending.get() {
        let _ = state.prepare_active_root();
        state.resume_mirror();
    }
}

/// Accounts for a physical image IRQ and selects a safe interrupt return.
///
/// The trap adapter holds the Host root and Host stack until this returns.
pub(crate) fn finish_image_trap(frame: &mut crate::arch::trap::TrapFrame) {
    if frame.trap_num < 32 || frame.rflags & (1 << 9) == 0 {
        return;
    }
    // SAFETY: The assembly adapter authenticated the current carrier before
    // calling the trap handler and keeps its state pinned across scheduling.
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return;
    };
    if (state.run_state.load(Ordering::Acquire) & !STOP_REQUESTED) != SERVICE
        || !state.trap_active.get()
    {
        return;
    }
    if state.run_state.load(Ordering::Acquire) & STOP_REQUESTED != 0 {
        return;
    }
    // SAFETY: The authenticated carrier pins this shared record until exit.
    let record = unsafe { &*(state.vcpu_record as *const VcpuRecord) };
    let is_timer = crate::arch::is_timer_irq(frame.trap_num);
    if is_timer {
        let counter = if record.irq_level.load(Ordering::Acquire) == 2 {
            &record.tick_l2
        } else {
            &record.tick_kernel
        };
        counter.fetch_add(1, Ordering::Relaxed);
        record.pending.fetch_or(VIRQ_TICK, Ordering::Release);
    }
    let is_critical =
        record.guards.load(Ordering::Acquire) != 0 || record.irq_off.load(Ordering::Acquire) != 0;
    let forced_yield = if is_critical && is_timer {
        let ticks = state.deferred_ticks.get().saturating_add(1);
        state.deferred_ticks.set(ticks);
        ticks >= 2
    } else {
        if !is_critical {
            state.deferred_ticks.set(0);
        }
        false
    };
    // Tick accounting charges every carrier to the same aggregate budget.
    // This sampling closes the current Task's interval before consulting the
    // Host-private quota, even when the virtual guard suppresses preemption.
    scheduler::runtime_ticks();
    if (forced_yield || state.control.account.exhausted()) && redirect_forced_yield(state, frame) {
        state.deferred_ticks.set(0);
        return;
    }
    if !is_critical {
        state.deferred_ticks.set(0);
        crate::arch::irq::enable_local();
        scheduler::might_preempt();
        crate::arch::irq::disable_local();
    }
    redirect_virtual_interrupt(state, record, frame);
}

/// Borrows the pinned landing frame as a complete continuation. The image
/// stack is authenticated but is not touched by the redirect stub before it
/// switches to the protected Host stack. The saved RFLAGS are restored only
/// for the second IRET; the first IRET masks IF/TF for the transition.
fn redirect_forced_yield(state: &CarrierState, frame: &mut crate::arch::trap::TrapFrame) -> bool {
    if !state.text.contains(&frame.rip)
        || state.run_state.load(Ordering::Acquire) != SERVICE
        || !state.trap_active.get()
        || state.yield_pending.get()
    {
        return false;
    }
    // The fixed yield stub switches to the Host stack before touching memory.
    // Authenticate the interrupted stack pointer, but do not require upcall
    // headroom here: a valid deep stack must still give up the CPU.
    let valid_stack = frame.rsp.checked_sub(1).is_some_and(|last_byte| {
        state
            .execution
            .stacks
            .lock()
            .contains_current_range(last_byte, frame.rsp, last_byte)
    });
    if !valid_stack {
        state
            .control
            .stop(ExitReason::Killed(KillReason::StackReserve));
        return false;
    }
    state.yield_rip.set(frame.rip);
    state.yield_rflags.set(frame.rflags);
    state.yield_pending.set(true);
    frame.rip = kernelet_host_forced_yield as *const () as usize;
    frame.rflags = 2;
    true
}

/// Commits the fixed image upcall only after validating the saved continuation.
fn redirect_virtual_interrupt(
    state: &CarrierState,
    record: &VcpuRecord,
    frame: &mut crate::arch::trap::TrapFrame,
) {
    if !has_deliverable_virtual_interrupt(record)
        || record.irq_off.load(Ordering::Acquire) != 0
        // A fixup has returned to the image, but the copy has not yet read
        // the Host's fault details. An upcall here could run another copy.
        || state.copy_fault_record().pending.load(Ordering::Acquire) != 0
        || !state.text.contains(&frame.rip)
    {
        return;
    }
    let Some(reserve_start) = frame.rsp.checked_sub(UPCALL_STACK_RESERVE) else {
        state
            .control
            .stop(ExitReason::Killed(KillReason::StackReserve));
        return;
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
        return;
    }
    // Trap number and error code are skipped by the assembly return. Their
    // exact address, unlike an offset from the interrupted RSP, also accounts
    // for any alignment padding in the hardware interrupt frame.
    let rip = frame.rip;
    frame.trap_num = rip;
    frame.error_code = frame.rax;
    frame.rax = core::ptr::addr_of!(frame.error_code) as usize;
    frame.rip = state.virq_entry;
    frame.rflags &= !(1 << 9);
    record.irq_off.store(1, Ordering::Release);
}

fn has_deliverable_virtual_interrupt(record: &VcpuRecord) -> bool {
    let pending = record.pending.load(Ordering::Acquire);
    let level = record.irq_level.load(Ordering::Acquire);
    pending != 0 && level < 2 && (level == 0 || pending & !VIRQ_TICK != 0)
}

/// Completes a service while still on the native Host stack and root.
///
/// The assembly return uses the nonzero result as its image upcall target.
/// It stores the original return RIP and service RAX in two retired slots
/// below the checked image RSP, exactly as `virq_entry` expects from the trap
/// redirect. The pending bit belongs to vOSTD and remains set until handled.
// SAFETY: Only the fixed service stubs call this with physical IRQs masked,
// after every Rust service frame and its Host guards have returned.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_prepare_service_return_impl() -> usize {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return 0;
    };
    debug_assert!(!crate::arch::irq::is_local_enabled());
    if !state.root_installed.get() {
        state
            .host_root
            .set(crate::arch::mm::current_page_table_paddr());
    }
    state.service_redirected.set(false);
    // No Rust service frame remains. Quota parking can now publish THROTTLED
    // with neither an image stack nor a Host service object active.
    if state.run_state.load(Ordering::Acquire) == RETURNING {
        state.suspend_mirror();
        state.wait_for_budget(RETURNING);
    }
    if state.run_state.load(Ordering::Acquire) != RETURNING {
        return 0;
    }
    // SAFETY: The authenticated carrier retains this shared record.
    let record = unsafe { &*(state.vcpu_record as *const VcpuRecord) };
    let mut redirect = false;
    if state.run_state.load(Ordering::Acquire) == RETURNING
        && has_deliverable_virtual_interrupt(record)
        && record.irq_off.load(Ordering::Acquire) == 0
        && state.copy_fault_record().pending.load(Ordering::Acquire) == 0
    {
        let image_rsp = state.image_rsp;
        if let Some(post_call_rsp) = image_rsp.checked_add(size_of::<usize>())
            && let Some(reserve_start) = post_call_rsp.checked_sub(UPCALL_STACK_RESERVE)
            && state.execution.stacks.lock().contains_current_range(
                reserve_start,
                post_call_rsp,
                image_rsp,
            )
        {
            // SAFETY: The private stack pool validated the entire mapped
            // range. The saved stack pointer need not be aligned here.
            let return_ip = unsafe { (image_rsp as *const usize).read_unaligned() };
            redirect = state.text.contains(&return_ip);
        }
    }
    if redirect {
        record.irq_off.store(1, Ordering::Release);
        state.service_redirected.set(true);
    }
    if state.run_state.load(Ordering::Acquire) == RETURNING {
        let _ = state.prepare_active_root();
    }
    if state.run_state.load(Ordering::Acquire) == RETURNING {
        state.resume_mirror();
    }
    if redirect { state.virq_entry } else { 0 }
}

/// Undoes a prepared upcall if the final no-stop image commit loses a race.
// SAFETY: Only the fixed service stubs call this on the protected Host stack
// after a failed RETURNING -> IMAGE compare-and-exchange with IRQs masked.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_cancel_service_return_impl() {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return;
    };
    // SAFETY: The authenticated carrier retains this shared record.
    let record = unsafe { &*(state.vcpu_record as *const VcpuRecord) };
    if state.service_redirected.replace(false) {
        record.irq_off.store(0, Ordering::Release);
    }
    state.set_phase(LEAVING);
}

// SAFETY: The trap or fixed-yield return calls this only on the protected
// Host stack/root after a failed final no-stop image commit. It never adjusts
// service-upcall state, which may belong to a prior completed service.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_cancel_trap_return_impl() {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return;
    };
    state.set_phase(LEAVING);
}

// SAFETY: The fixed yield stub has switched to the native Host stack under
// the Host root. The complete interrupted image frame remains pinned on this
// carrier's private IST landing stack until its final IRET or fixed exit.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_forced_yield_impl() {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return;
    };
    if state.run_state.load(Ordering::Acquire) != ENTERING || !state.yield_pending.get() {
        return;
    }
    state.enter_schedulable_service();
    crate::arch::irq::enable_local();
    Task::yield_now();
    crate::arch::irq::disable_local();
    state.set_phase(RETURNING);
}

// SAFETY: Only the fixed yield return calls this after its Rust service frame
// has unwound, with physical IRQs masked on the protected Host stack/root.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_prepare_yield_return_impl() {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return;
    };
    if state.run_state.load(Ordering::Acquire) != RETURNING || !state.yield_pending.get() {
        return;
    }
    state.wait_for_budget(RETURNING);
    if state.run_state.load(Ordering::Acquire) != RETURNING {
        return;
    }
    let frame_start = state.image_rsp;
    if frame_start < state.landing_start
        || frame_start
            .checked_add(size_of::<crate::arch::trap::TrapFrame>())
            .is_none_or(|end| end > state.landing_end)
    {
        state
            .control
            .stop(ExitReason::Killed(KillReason::EntryFailed));
        return;
    }
    // SAFETY: The trap adapter retained this private landing frame and no
    // other handler can use its per-carrier IST while the native IDT is live.
    let frame = unsafe { &mut *(frame_start as *mut crate::arch::trap::TrapFrame) };
    frame.rip = state.yield_rip.get();
    frame.rflags = state.yield_rflags.get();
    state.yield_pending.set(false);
    let _ = state.prepare_active_root();
    state.resume_mirror();
}

/// # Safety
///
/// The current carrier must retain the mapped image through lifetime `'a`.
unsafe fn image_bytes<'a>(ptr: *const u8, len: u32, limit: u32) -> Result<&'a [u8], i64> {
    if len > limit {
        return Err(-INVALID);
    }
    if len == 0 {
        return Ok(&[]);
    }
    let state_ptr = KERNELET_HOST_STATE_PTR.load() as *const CarrierState;
    if state_ptr.is_null() {
        return Err(-STATE);
    }
    // SAFETY: The carrier installs its state before entry and interrupts are
    // disabled, so no other thread can remove the pointer during a crossing.
    let state = unsafe { &*state_ptr };
    let start = ptr as usize;
    let Some(end) = start.checked_add(len as usize) else {
        return Err(-INVALID);
    };
    let in_image = start >= state.image_start && end <= state.image_end;
    let in_stack = state.execution.stacks.lock().contains_range(start, end);
    let in_grant = start
        .checked_sub(crate::mm::kspace::LINEAR_MAPPING_BASE_VADDR)
        .is_some_and(|paddr| state.guest_memory.contains(paddr as u64, len as usize));
    if !in_image && !in_stack && !in_grant {
        return Err(-INVALID);
    }
    // SAFETY: The range lies in the pinned image, stack pool or owned linear
    // grant. Grants are append-only until every carrier has detached.
    Ok(unsafe { core::slice::from_raw_parts(ptr, len as usize) })
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
    // Copy the bounded panic text before abandoning the image continuation.
    // SAFETY: This carrier still pins the image and its current stack.
    let message = unsafe { image_bytes(msg, len, MAX_OOPS_BYTES) }
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
    // SAFETY: The carrier retains the image until the fixed exit continuation.
    if let Ok(message) = unsafe { image_bytes(msg, len, MAX_OOPS_BYTES) }
        && let Ok(message) = core::str::from_utf8(message)
    {
        crate::info!("kernelet stopped: kind={kind}, code={code}, {message}");
    } else {
        crate::info!("kernelet stopped: kind={kind}, code={code}");
    }
    code
}
