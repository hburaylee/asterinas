// SPDX-License-Identifier: MPL-2.0

//! Host control of a kernelet image.

use alloc::{
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    time::Duration,
};

pub use super::account::CpuBudget;
use super::{
    abi::{BootArgs, DeviceEntry, META_SECTION_BYTES, MmioResult, VIRQ_LINES, VcpuRecord},
    account::Account,
    guest_memory::GuestMemory,
    host_grant::Grant,
    host_image::{ImageInstance, RegisteredImage},
    host_run,
};
use crate::{
    Error,
    cpu::{CpuId, CpuSet, PinCurrentCpu},
    sync::{LocalIrqDisabled, Mutex, SpinLock, WaitQueue},
    task::Task,
};

mod config;

use self::config::{boot_args, host_source_hash, validate_config};

/// Nonblocking Host-side operations supplied by the kernelet's endovisor.
///
/// These methods run on the carrier's native Host stack. An MMIO write may be
/// made while the image holds a spin lock, so implementations must finish in
/// bounded time and hand any blocking I/O to an adopted device thread.
pub trait KerneletHooks: Send + Sync {
    /// Builds one pinned native carrier without placing it on the run queue.
    /// The closure must retain only a weak reference to `kernelet`: OSTD owns
    /// the dormant Task until it has detached or construction is rolled back.
    fn create_vcpu_thread(
        &self,
        kernelet: &Arc<Kernelet>,
        vcpu: u16,
        host_cpu: CpuId,
        nice: i8,
    ) -> crate::Result<Arc<Task>>;

    /// Samples the Host realtime clock as a duration since the Unix epoch.
    /// Called only during instance construction to anchor its virtual RTC.
    fn realtime_now(&self) -> Duration;

    /// Reads one register from a virtual device.
    fn mmio_read(&self, device: u16, offset: u32, width: u32) -> MmioResult;

    /// Writes one register in a virtual device.
    fn mmio_write(&self, device: u16, offset: u32, width: u32, value: u64) -> i64;

    /// Accepts a bounded kernel log or early-console record; false means dropped.
    fn log(&self, level: u32, module: &str, text: &str) -> bool;

    /// Records a bounded caught-panic notification after its budget charge.
    fn on_oops(&self, _message: &str) {}

    /// Offers additional grains when the configured live ceiling is exhausted.
    /// OSTD clamps this answer to the bounded request and metadata capacity.
    fn on_grant_exhausted(&self, _requested: u32) -> u32 {
        0
    }

    /// Settles a preceding positive memory authorization after growth unlocks.
    /// `committed` is the ceiling increase, including authorized but unallocated grains.
    fn on_grant_settled(&self, _reserved: u32, _committed: u32) {}

    /// Updates the fair scheduling weight of every prepared carrier Thread.
    fn set_vcpu_nice(&self, nice: i8) -> crate::Result<()>;
}

/// Whether the calling Host thread is inside a caught kernelet request hook.
///
/// The Host panic handler uses this to permit unwinding to the service wrapper
/// even when ordinary kernel oopses are configured to halt the machine.
pub fn in_host_hook() -> bool {
    host_run::in_host_hook()
}

/// Resident sizes obtained from the validated image load segments.
#[derive(Clone, Copy, Debug)]
pub struct ImageInfo {
    /// Shared executable text bytes.
    pub text_bytes: usize,
    /// Writable template bytes copied for each instance.
    pub template_bytes: usize,
    /// CPU-local template bytes replicated for each virtual CPU.
    pub cpu_local_bytes: usize,
}

/// Resource policy fixed when an instance is created.
#[derive(Clone, Copy, Debug)]
pub struct KerneletPolicy {
    /// Number of caught panics permitted before forced termination.
    pub oops_budget: u32,
    /// Maximum log bytes delivered to hooks in each one-second window.
    pub log_bytes_per_sec: u32,
    /// Whether to ask the Host hook for additional memory at the live ceiling.
    pub ask_before_oom: bool,
}

impl Default for KerneletPolicy {
    fn default() -> Self {
        Self {
            oops_budget: 0,
            log_bytes_per_sec: 65536,
            ask_before_oom: false,
        }
    }
}

/// A validated image kind whose read-only frames may be shared by instances.
pub struct KerneletKind {
    image: RegisteredImage,
}

impl KerneletKind {
    /// Registers an OSDK-built image after checking its common source hash.
    pub fn register(elf: &[u8]) -> crate::Result<Self> {
        if cfg!(panic = "abort") {
            return Err(Error::InvalidArgs);
        }
        let image = RegisteredImage::register(elf, host_source_hash()?)?;
        Ok(Self { image })
    }

    /// Returns resident sizes from this kind's validated ELF metadata.
    pub fn image_info(&self) -> ImageInfo {
        self.image.image_info()
    }

    /// Creates an instance and every dormant carrier without scheduling one.
    pub fn create(
        &self,
        config: &KerneletConfig<'_>,
        hooks: &dyn KerneletHooks,
    ) -> crate::Result<Arc<Kernelet>> {
        validate_config(config)?;
        let image = &self.image;
        // The caller supplies a bound on distinct metadata sections. Only the
        // Host knows the physical address range, so cap that bound here before
        // reserving metadata and publishing the immutable boot page.
        let physical_sections = crate::mm::frame::max_paddr().div_ceil(META_SECTION_BYTES);
        let max_meta_sections = config
            .max_meta_sections
            .min(u32::try_from(physical_sections).unwrap_or(u32::MAX));
        let grant = Grant::new(config.initial_grains, config.max_grains, max_meta_sections)?;
        let mut boot = boot_args(image, config)?;
        // Initialize the clock page before sampling either clock. The image
        // extends this immutable realtime snapshot using Host monotonic time.
        super::clock::frame()?;
        boot.monotonic_base_ns = super::clock::now_ns();
        boot.realtime_base_ns = hooks
            .realtime_now()
            .as_nanos()
            .try_into()
            .map_err(|_| Error::Overflow)?;
        boot.max_meta_sections = max_meta_sections;
        let instance = image.instantiate(&boot, config.cmdline, config.devices, &grant)?;
        crate::info!(
            "kernelet image mapped at {:#x}, entry {:#x}",
            instance.base_vaddr(),
            instance.entry_address()
        );
        let mut control = RunControl::new(
            grant.dying_address(),
            Account::new(grant.drain_queue(), config.budget, config.policy),
            config.cpus.iter().collect(),
            config.max_tasks as usize,
        )?;
        let boot_stack_bytes = Arc::get_mut(control.execution.get_mut().as_mut().unwrap())
            .unwrap()
            .prepare()?;
        let control = Arc::new(control);
        grant.bind_lifecycle(control.lifecycle.clone());
        control
            .account
            .stacks
            .store(config.cpus.count() as u32, Ordering::Relaxed);
        control
            .account
            .grains
            .store(config.initial_grains, Ordering::Relaxed);
        control
            .account
            .ceiling
            .store(config.max_grains, Ordering::Relaxed);
        control.account.overhead.store(
            instance.private_bytes() + boot_stack_bytes,
            Ordering::Relaxed,
        );
        control
            .account
            .grant_overhead
            .store(grant.overhead_bytes(), Ordering::Relaxed);
        let memory = grant.guest_memory();
        let kernelet = Arc::new(Kernelet {
            memory,
            resources: SpinLock::new(Some(Arc::new(InstanceResources { instance, grant }))),
            device_lines: config
                .devices
                .iter()
                .map(|device| (device.irq, device.vcpu))
                .collect(),
            control,
        });
        let mut carriers = Vec::with_capacity(kernelet.num_vcpus() as usize);
        for vcpu in 0..kernelet.num_vcpus() {
            carriers.push(hooks.create_vcpu_thread(
                &kernelet,
                vcpu,
                kernelet.vcpu_host_cpu(vcpu).unwrap(),
                config.budget.nice,
            )?);
        }
        *kernelet.control.tasks.lock() = carriers;
        Ok(kernelet)
    }
}

/// Parameters published in an instance's immutable boot page.
pub struct KerneletConfig<'a> {
    /// Kernel command line composed by the endovisor.
    pub cmdline: &'a str,
    /// Initial number of 2 MiB grains.
    pub initial_grains: u32,
    /// Initial live grant ceiling, in 2 MiB grains.
    pub max_grains: u32,
    /// Lifetime bound on distinct physical 128 MiB metadata sections.
    pub max_meta_sections: u32,
    /// Host fair weight and aggregate vCPU quota.
    pub budget: CpuBudget,
    /// Immutable panic, logging and memory-exhaustion policy.
    pub policy: KerneletPolicy,
    /// Maximum number of internal Task stacks.
    pub max_tasks: u32,
    /// Pseudo-physical virtual-device register files.
    pub devices: &'a [DeviceEntry],
    /// Fixed Host CPUs, in ascending virtual-CPU index order.
    pub cpus: CpuSet,
}

/// Lifecycle of a Host-controlled instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KerneletState {
    /// Resources exist and no carrier has been entered.
    Created,
    /// A carrier may execute the image or a Host service.
    Running,
    /// Stop is sticky; existing Host service frames may still be draining.
    Dying,
    /// Every carrier has detached and the reaper published status.
    Exited,
    /// One destroy caller has exclusive reclamation rights.
    Destroying,
    /// All instance resources have been reclaimed.
    Destroyed,
}

/// Why the Host requested termination.
#[derive(Clone, Debug)]
pub enum KillReason {
    /// The runtime explicitly requested termination.
    Requested,
    /// The configured caught-panic allowance was exhausted.
    OopsBudget,
    /// An image entry could not retain the required landing reserve.
    StackReserve,
    /// An internal Task exhausted its guarded stack.
    StackOverflow,
    /// A Host request hook unwound on the carrier stack.
    HostHookPanicked,
    /// A prepared carrier could not establish its image execution context.
    EntryFailed,
    /// A depth-zero image exception had no validated recovery entry.
    KernelFault {
        /// Faulting address, or zero for exceptions without an address.
        addr: u64,
        /// Saved image instruction pointer.
        ip: u64,
    },
    /// An endovisor policy identified by its opaque reason code.
    HostPolicy(u32),
}

/// Once-published outcome of image execution.
#[derive(Clone, Debug)]
pub enum ExitReason {
    /// The image requested shutdown with this code.
    Exited(u32),
    /// The image reported an unrecovered panic.
    Panicked(String),
    /// Execution was terminated by Host policy or fault containment.
    Killed(KillReason),
}

/// Exit information retained after all instance resources are reclaimed.
#[derive(Clone, Debug)]
pub struct ExitStatus {
    /// The first accepted stop reason.
    pub reason: ExitReason,
    /// Elapsed Host time from construction through carrier detachment.
    pub uptime: Duration,
    /// CPU time charged to carriers and adopted Host workers.
    pub cpu_time: Duration,
}

/// Resources released by one successful destroy.
#[derive(Clone, Copy, Debug)]
pub struct ReclaimReport {
    /// Number of 2 MiB grant grains returned to the Host.
    pub grains_released: u32,
    /// Number of pooled boot and internal Task stack ranges released.
    pub kstack_ranges_released: u32,
    /// Number of inactive registered roots discarded with the grant.
    pub roots_forgotten: u32,
}

/// A destroy can be retried after remaining device memory views are dropped.
#[derive(Clone, Copy, Debug)]
pub enum DestroyError {
    /// Reclamation is not legal in the observed lifecycle state.
    NotExited(KerneletState),
    /// Device memory views still retain grant frames; no resource was freed.
    Zombie {
        /// Outstanding device memory handles.
        pins: usize,
        /// Adopted Host Tasks that have not yet disowned this account.
        adopted: u32,
    },
}

/// Refusal of a bounded Host grant operation.
#[derive(Clone, Copy, Debug)]
pub enum GrantError {
    /// Growth is not admitted in this lifecycle state.
    State(KerneletState),
    /// One crossing or the lifetime ceiling would be exceeded.
    Limit,
    /// The candidate touches too many physical metadata sections.
    MetadataCapacity,
    /// No suitably aligned physical memory is currently available.
    NoMemory,
}

/// Refusal of a Host scheduling-policy update.
#[derive(Clone, Copy, Debug)]
pub enum BudgetError {
    /// No running carrier accepts policy changes in this state.
    State(KerneletState),
    /// Nice lies outside -20..=19.
    InvalidNice,
    /// Quota is zero or its period does not exceed one Host tick.
    InvalidQuota,
    /// The endovisor could not apply the validated fair scheduling weight.
    Rejected,
}

/// Host-observed counters for one instance, retained through destruction.
#[derive(Clone, Debug)]
pub struct KerneletStats {
    /// Published grant grains.
    pub grains_granted: u32,
    /// Current grain ceiling, including successful Host grants.
    pub max_grains: u32,
    /// Explicit live device-buffer charges.
    pub host_bytes_charged: usize,
    /// Currently allocated boot and internal Task stacks.
    pub stacks_allocated: u32,
    /// Carrier and adopted-worker CPU time.
    pub cpu_time: Duration,
    /// Device completion CPU time explicitly attributed by the endovisor.
    pub completion_cpu_time: Duration,
    /// Receive-copy CPU time explicitly attributed by the endovisor.
    pub ingress_copy_cpu_time: Duration,
    /// Admitted service crossings.
    pub service_calls: u64,
    /// Validated MMIO service requests.
    pub mmio_accesses: u64,
    /// Accepted Host device IRQ publications.
    pub irqs_raised: u64,
    /// Log payload bytes delivered to the endovisor.
    pub log_bytes: u64,
    /// Log records refused by the configured rate limit.
    pub log_records_dropped: u64,
    /// Reported caught panics.
    pub oopses: u32,
    /// Private resident data, metadata, shared protocol, and stack frames.
    pub host_overhead_bytes: usize,
    /// Carrier time spent waiting for CPU quota replenishment.
    pub throttled: Duration,
}

pub(crate) struct CarrierControl {
    pub(crate) run_state: AtomicU32,
    pub(crate) active_root: AtomicU64,
    pub(crate) cpu: CpuId,
    requested: AtomicBool,
    entered: AtomicBool,
    pub(crate) wait: Arc<WaitQueue>,
}

/// A single writer publishes a stop record before the Dying transition.
/// Losers never wait on an interrupted initializer.
pub(crate) struct RunControl {
    pub(crate) account: Arc<Account>,
    hooks: SpinLock<Option<Arc<dyn KerneletHooks>>, LocalIrqDisabled>,
    budget_change: Mutex<()>,
    lifecycle: Arc<AtomicU8>,
    claimed: AtomicBool,
    reason: UnsafeCell<MaybeUninit<ExitReason>>,
    pub(crate) carriers: Vec<CarrierControl>,
    /// Built at creation, queued only by `start` or `vcpu_boot`.
    tasks: SpinLock<Vec<Arc<Task>>, LocalIrqDisabled>,
    /// Reaper-owned weak references, retained until every native Task drops.
    retired_tasks: SpinLock<Option<Vec<Weak<Task>>>, LocalIrqDisabled>,
    /// Wakes the reaper if a native Task still held its stack at the last scan.
    reap_retry: SpinLock<Option<super::account::Deadline>, LocalIrqDisabled>,
    active: AtomicU32,
    /// Serializes operation admission with the Destroying transition. Never
    /// hold this lock while entering a subsystem or calling a hook. Resource
    /// Arc acquisition uses the order admission -> resources, before work.
    admission: SpinLock<(), LocalIrqDisabled>,
    /// Service and control operations that must drain before reclamation.
    admitted: AtomicUsize,
    pub(crate) execution: SpinLock<Option<Arc<host_run::ExecutionResources>>, LocalIrqDisabled>,
    dying_address: usize,
    ready_for_reap: AtomicBool,
    detached: AtomicBool,
    detached_at: AtomicU64,
    started_at: Duration,
    status: SpinLock<Option<ExitStatus>, LocalIrqDisabled>,
    exited: Arc<WaitQueue>,
}

// SAFETY: Only the successful claimed CAS writes reason; the release Dying
// transition publishes it. Readers first acquire lifecycle. No writer ever
// modifies it afterward, including across Exited and Destroyed.
unsafe impl Sync for RunControl {}

impl RunControl {
    fn new(
        dying_address: usize,
        account: Arc<Account>,
        cpus: Vec<CpuId>,
        max_tasks: usize,
    ) -> crate::Result<Self> {
        let vcpus = cpus.len();
        let execution = host_run::ExecutionResources::new(max_tasks, vcpus)?;
        Ok(Self {
            account,
            hooks: SpinLock::new(None),
            budget_change: Mutex::new(()),
            lifecycle: Arc::new(AtomicU8::new(KerneletState::Created as u8)),
            claimed: AtomicBool::new(false),
            reason: UnsafeCell::new(MaybeUninit::uninit()),
            carriers: cpus
                .into_iter()
                .enumerate()
                .map(|(index, cpu)| CarrierControl {
                    run_state: AtomicU32::new(host_run::PREPARED),
                    active_root: AtomicU64::new(0),
                    cpu,
                    requested: AtomicBool::new(index == 0),
                    entered: AtomicBool::new(false),
                    wait: Arc::new(WaitQueue::new()),
                })
                .collect(),
            tasks: SpinLock::new(Vec::new()),
            retired_tasks: SpinLock::new(None),
            reap_retry: SpinLock::new(None),
            active: AtomicU32::new(0),
            admission: SpinLock::new(()),
            admitted: AtomicUsize::new(0),
            execution: SpinLock::new(Some(Arc::new(execution))),
            dying_address,
            ready_for_reap: AtomicBool::new(false),
            detached: AtomicBool::new(false),
            detached_at: AtomicU64::new(0),
            started_at: crate::timer::Jiffies::elapsed().as_duration(),
            status: SpinLock::new(None),
            exited: Arc::new(WaitQueue::new()),
        })
    }

    fn state(&self) -> KerneletState {
        match self.lifecycle.load(Ordering::Acquire) {
            state if state == KerneletState::Created as u8 => KerneletState::Created,
            state if state == KerneletState::Running as u8 => KerneletState::Running,
            state if state == KerneletState::Dying as u8 => KerneletState::Dying,
            state if state == KerneletState::Exited as u8 => KerneletState::Exited,
            state if state == KerneletState::Destroying as u8 => KerneletState::Destroying,
            state if state == KerneletState::Destroyed as u8 => KerneletState::Destroyed,
            _ => unreachable!(),
        }
    }

    pub(crate) fn admit_operation(
        &self,
        allowed: &[KerneletState],
    ) -> Result<OperationGuard<'_>, KerneletState> {
        let _admission = self.admission.lock();
        let state = self.state();
        if !allowed.contains(&state) {
            return Err(state);
        }
        self.admitted.fetch_add(1, Ordering::AcqRel);
        Ok(OperationGuard { control: self })
    }

    fn release_operation(&self) {
        let previous = self.admitted.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous != 0);
        // Destroy registers its waiter before checking the count. If it
        // closes admission after this check, it observes zero without waiting.
        if previous == 1 && self.state() == KerneletState::Destroying {
            self.account.drained.wake_all();
        }
    }

    pub(crate) fn stop(&self, reason: ExitReason) {
        if self
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        // SAFETY: The claim gives this call exclusive initialization rights.
        unsafe { (*self.reason.get()).write(reason) };
        let active = self
            .active
            .fetch_or(host_run::STOP_REQUESTED, Ordering::AcqRel);
        for carrier in &self.carriers {
            carrier
                .run_state
                .fetch_or(host_run::STOP_REQUESTED, Ordering::Release);
            carrier.wait.wake_all();
        }
        self.account.cancel_wait();
        if self.dying_address != 0 {
            // SAFETY: Construction takes this pointer from the pinned info
            // frame. The first stop precedes Exited and all reclamation; later
            // stop callers lose the claim and never dereference the pointer.
            unsafe { &*(self.dying_address as *const AtomicU32) }.store(1, Ordering::Release);
        }
        let previous = self.lifecycle.compare_exchange(
            KerneletState::Created as u8,
            KerneletState::Dying as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        if previous.is_err() {
            let _ = self.lifecycle.compare_exchange(
                KerneletState::Running as u8,
                KerneletState::Dying as u8,
                Ordering::Release,
                Ordering::Acquire,
            );
        }
        if active & !host_run::STOP_REQUESTED == 0 {
            self.signal_reaper();
        } else {
            // A last detach can race publication of Dying; wake again after
            // that release so an early reaper scan cannot miss the exit.
            self.exited.wake_all();
        }
    }

    pub(crate) fn boot_vcpu(&self, vcpu: u32) -> crate::Result<()> {
        let carrier = self.carriers.get(vcpu as usize).ok_or(Error::InvalidArgs)?;
        if vcpu == 0 || self.state() != KerneletState::Running {
            return Err(Error::InvalidArgs);
        }
        let task = self
            .tasks
            .lock()
            .get(vcpu as usize)
            .cloned()
            .ok_or(Error::InvalidArgs)?;
        self.active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                (old & host_run::STOP_REQUESTED == 0).then_some(old + 1)
            })
            .map_err(|_| Error::AccessDenied)?;
        if carrier.requested.swap(true, Ordering::AcqRel) {
            self.detach_carrier();
            return Err(Error::InvalidArgs);
        }
        // A concurrent stop sees this carrier in `active` before it can be
        // queued. The Task must run once to release that reservation, even if
        // the stop bit was set between the reservation and this enqueue. The
        // caller is inside a carrier service; defer a scheduler switch until
        // that service returns.
        let _preempt = crate::task::disable_preempt();
        task.run();
        Ok(())
    }

    fn detach_carrier(&self) {
        if self.active.fetch_sub(1, Ordering::AcqRel) == (host_run::STOP_REQUESTED | 1) {
            self.signal_reaper();
        }
    }

    /// A native carrier may still be returning from its closure. Only the
    /// reaper may retire its Task and publish full detachment.
    fn signal_reaper(&self) {
        self.ready_for_reap.store(true, Ordering::Release);
        self.exited.wake_all();
    }

    fn try_detach(&self) -> bool {
        if !self.ready_for_reap.load(Ordering::Acquire) {
            return false;
        }
        if self.retired_tasks.lock().is_none() {
            let tasks = core::mem::take(&mut *self.tasks.lock());
            let weak = tasks.iter().map(Arc::downgrade).collect();
            *self.retired_tasks.lock() = Some(weak);
            // Queued Tasks still retain themselves in the scheduler. Dormant
            // Tasks have no execution context to finish and drop here.
            drop(tasks);
        }
        if self
            .retired_tasks
            .lock()
            .as_ref()
            .unwrap()
            .iter()
            .any(|task| task.upgrade().is_some())
        {
            let retry_at = crate::task::accounting::now_ns().saturating_add(1_000_000);
            *self.reap_retry.lock() = Some(super::account::Deadline::new(retry_at, &self.exited));
            return false;
        }
        self.reap_retry.lock().take();
        for carrier in &self.carriers {
            let phase = carrier.run_state.load(Ordering::Acquire) & !host_run::STOP_REQUESTED;
            assert!(matches!(
                phase,
                host_run::PREPARED | host_run::STARTING | host_run::LEAVING
            ));
            carrier.run_state.store(
                host_run::STOP_REQUESTED | host_run::DETACHED,
                Ordering::Release,
            );
        }
        let hooks = self.hooks.lock().take();
        drop(hooks);
        self.detached_at
            .store(crate::timer::Jiffies::elapsed().as_u64(), Ordering::Relaxed);
        self.detached.store(true, Ordering::Release);
        self.exited.wake_all();
        true
    }
}

impl Drop for RunControl {
    fn drop(&mut self) {
        if self.claimed.load(Ordering::Acquire) {
            // SAFETY: The last owning reference cannot disappear while the
            // winning stop caller is still initializing the record.
            unsafe { (*self.reason.get()).assume_init_drop() };
        }
    }
}

struct InstanceResources {
    instance: ImageInstance,
    grant: Grant,
}

/// An operation owns its admission through early returns and unwinds.
/// The guard retains no lock; nested service/control admissions are legal.
pub(crate) struct OperationGuard<'a> {
    control: &'a RunControl,
}

impl Drop for OperationGuard<'_> {
    fn drop(&mut self) {
        self.control.release_operation();
    }
}

/// One admitted control operation. All exits release its resources before
/// notifying the reaper, including early errors and hook unwinds.
struct ResourceLease {
    resources: Option<Arc<InstanceResources>>,
    control: Arc<RunControl>,
}
impl core::ops::Deref for ResourceLease {
    type Target = InstanceResources;
    fn deref(&self) -> &Self::Target {
        self.resources.as_ref().unwrap()
    }
}
impl Drop for ResourceLease {
    fn drop(&mut self) {
        // Release the resource reference before publishing the last admission.
        // The counter lives in RunControl, so a concurrent destroy cannot see
        // zero while a preempted lease destructor still retains its grant.
        drop(self.resources.take());
        self.control.release_operation();
    }
}

/// One instantiated kernelet with Host-owned grant and image mappings.
pub struct Kernelet {
    memory: GuestMemory,
    resources: SpinLock<Option<Arc<InstanceResources>>, LocalIrqDisabled>,
    device_lines: Vec<(u8, u16)>,
    control: Arc<RunControl>,
}

impl Kernelet {
    /// Returns the current lifecycle state.
    pub fn state(&self) -> KerneletState {
        self.control.state()
    }

    /// Returns a revocable device capability. Cloning it pins no frames;
    /// each checked access pins its range only for the duration of that call.
    /// Capabilities retained after destroy reject further memory accesses.
    pub fn guest_memory(&self) -> GuestMemory {
        self.memory.clone()
    }

    fn admit(&self, allow_created: bool) -> Result<ResourceLease, KerneletState> {
        let _admission = self.control.admission.lock();
        let state = self.state();
        if state != KerneletState::Running && !(allow_created && state == KerneletState::Created) {
            return Err(state);
        }
        let resources = self.resources.lock().as_ref().unwrap().clone();
        // Reserving under the admission lock keeps the destroy flip and lease
        // creation mutually exclusive: destroy counts this reservation before
        // it starts waiting, and refuses everything admitted after the flip.
        self.control.admitted.fetch_add(1, Ordering::AcqRel);
        Ok(ResourceLease {
            resources: Some(resources),
            control: self.control.clone(),
        })
    }

    /// Applies a validated fair weight and vCPU quota as one serialized update.
    pub fn set_budget(&self, budget: CpuBudget) -> Result<(), BudgetError> {
        if !(-20..=19).contains(&budget.nice) {
            return Err(BudgetError::InvalidNice);
        }
        budget.validate().map_err(|_| BudgetError::InvalidQuota)?;
        let _resources = self.admit(false).map_err(BudgetError::State)?;
        let _update = self.control.budget_change.lock();
        let hooks = self
            .control
            .hooks
            .lock()
            .clone()
            .ok_or(BudgetError::Rejected)?;
        hooks
            .set_vcpu_nice(budget.nice)
            .map_err(|_| BudgetError::Rejected)?;
        self.control.account.set_budget(budget);
        Ok(())
    }

    /// Takes an atomic counter snapshot without waiting for any device or carrier.
    pub fn stats(&self) -> KerneletStats {
        let account = &self.control.account;
        KerneletStats {
            grains_granted: account.grains.load(Ordering::Acquire),
            max_grains: account.ceiling.load(Ordering::Acquire),
            host_bytes_charged: account.host_bytes.load(Ordering::Acquire),
            stacks_allocated: account.stacks.load(Ordering::Acquire),
            cpu_time: account.cpu_time(),
            completion_cpu_time: Duration::from_nanos(
                account.completion_ns.load(Ordering::Acquire),
            ),
            ingress_copy_cpu_time: Duration::from_nanos(account.ingress_ns.load(Ordering::Acquire)),
            service_calls: account.service_calls.load(Ordering::Relaxed),
            mmio_accesses: account.mmio_accesses.load(Ordering::Relaxed),
            irqs_raised: account.irqs_raised.load(Ordering::Relaxed),
            log_bytes: account.log_bytes.load(Ordering::Relaxed),
            log_records_dropped: account.logs_dropped.load(Ordering::Relaxed),
            oopses: account.oopses.load(Ordering::Relaxed),
            host_overhead_bytes: account.overhead.load(Ordering::Acquire)
                + account.grant_overhead.load(Ordering::Acquire),
            throttled: Duration::from_nanos(account.throttled_ns.load(Ordering::Acquire)),
        }
    }

    /// Attributes a bounded physical-device completion to this instance.
    pub fn charge_completion_time(&self, elapsed: Duration) {
        self.control.account.completion_ns.fetch_add(
            elapsed.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }

    /// Attributes an incoming data-copy operation to its recipient.
    pub fn charge_ingress_time(&self, elapsed: Duration) {
        self.control.account.ingress_ns.fetch_add(
            elapsed.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }

    /// Adds 1–16 grains and raises the live ceiling by the published amount.
    pub fn grant(&self, grains: u32) -> Result<u32, GrantError> {
        if grains == 0 || grains > super::abi::MAX_GRAINS_PER_REQUEST {
            return Err(GrantError::Limit);
        }
        let resources = self.admit(true).map_err(GrantError::State)?;
        let result = resources
            .grant
            .grow(grains, 0, true)
            .map_err(|error| match error {
                Error::Overflow => GrantError::MetadataCapacity,
                Error::NoMemory => GrantError::NoMemory,
                _ => GrantError::Limit,
            });
        if result.is_ok() {
            self.control
                .account
                .grant_overhead
                .fetch_max(resources.grant.overhead_bytes(), Ordering::Relaxed);
            self.control
                .account
                .grains
                .fetch_max(resources.grant.grains(), Ordering::Release);
            self.control
                .account
                .ceiling
                .fetch_max(resources.grant.ceiling(), Ordering::Release);

            let record = resources.instance.vcpu_record_address() as *const VcpuRecord;
            // SAFETY: The admitted operation retains all instance mappings.
            unsafe { &*record }
                .pending
                .fetch_or(super::abi::VIRQ_KICK, Ordering::Release);
            self.control.carriers[0].wait.wake_all();
        }
        result
    }

    /// Charges a Host worker until disown or Task exit, without making it a vCPU.
    pub fn adopt_current_task(&self) -> crate::Result<()> {
        {
            let _resources = self.resources.lock();
            if !matches!(
                self.state(),
                KerneletState::Created | KerneletState::Running
            ) {
                return Err(Error::AccessDenied);
            }
            self.control
                .account
                .adopted
                .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| Error::Overflow)?;
        }
        // The reservation prevents destroy while attaching. A rejected attach
        // drops its TaskCharge and refunds this reference outside admission.
        self.control.account.attach(true)
    }

    /// Ends this Task's adoption and wakes pending destroy retries.
    pub fn disown_current_task(&self) {
        self.control.account.detach();
    }

    /// Accounts bounded Host buffers admitted by an endovisor device queue.
    pub fn charge_host_bytes(&self, bytes: usize) -> crate::Result<()> {
        let _admission = self
            .control
            .admit_operation(&[KerneletState::Created, KerneletState::Running])
            .map_err(|_| Error::AccessDenied)?;
        self.control
            .account
            .host_bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(bytes)
            })
            .map_err(|_| Error::Overflow)?;
        Ok(())
    }

    /// Releases a previous explicit Host-memory charge.
    pub fn uncharge_host_bytes(&self, bytes: usize) {
        let result = self.control.account.host_bytes.try_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |value| value.checked_sub(bytes),
        );
        debug_assert!(result.is_ok(), "unbalanced kernelet Host-memory charge");
        self.control.account.drained.wake_all();
    }

    /// Publishes a device line and wakes an idle carrier.
    pub fn raise_irq(&self, line: u8) -> crate::Result<()> {
        let vcpu = self
            .device_lines
            .iter()
            .find(|(irq, _)| *irq == line)
            .map(|(_, vcpu)| *vcpu as usize)
            .ok_or(Error::InvalidArgs)?;
        let resources = self.admit(false).map_err(|_| Error::InvalidArgs)?;
        let record = (resources.instance.vcpu_record_address() + vcpu * size_of::<VcpuRecord>())
            as *const VcpuRecord;
        // SAFETY: The admitted resource lease pins the record through publication.
        let record = unsafe { &*record };
        record.pending_lines[(line / 64) as usize].fetch_or(1u64 << (line % 64), Ordering::Release);
        record.pending.fetch_or(VIRQ_LINES, Ordering::Release);
        self.control
            .account
            .irqs_raised
            .fetch_add(1, Ordering::Relaxed);
        self.control.carriers[vcpu].wait.wake_all();
        // Its physical trap return makes a running image observe the line;
        // waking the queue alone only reaches a parked carrier.
        crate::smp::inter_processor_call(&self.control.carriers[vcpu].cpu.into(), || {});
        Ok(())
    }

    /// Requests termination without waiting for the carrier or its Host I/O.
    pub fn kill(&self, reason: KillReason) -> crate::Result<()> {
        let _admission = self
            .control
            .admit_operation(&[
                KerneletState::Created,
                KerneletState::Running,
                KerneletState::Dying,
            ])
            .map_err(|_| Error::InvalidArgs)?;
        self.control.stop(ExitReason::Killed(reason));
        // The callback itself retains no instance pointer. Its physical trap
        // return observes the sticky stop bit, even inside a virtual guard.
        for carrier in &self.control.carriers {
            crate::smp::inter_processor_call(&carrier.cpu.into(), || {});
        }
        Ok(())
    }

    /// Publishes exit after carrier detachment, from the Host reaper task.
    pub fn reap(&self) -> Option<ExitStatus> {
        if self.state() != KerneletState::Dying {
            return self.exit_status();
        }
        if !self.control.try_detach() {
            return None;
        }
        let mut status = self.control.status.lock();
        if status.is_none() {
            // SAFETY: Acquiring Dying observes the initialized immutable record.
            let reason = unsafe { (*self.control.reason.get()).assume_init_ref() }.clone();
            *status = Some(ExitStatus {
                reason,
                cpu_time: self.control.account.cpu_time(),
                uptime: crate::timer::Jiffies::new(
                    self.control.detached_at.load(Ordering::Acquire),
                )
                .as_duration()
                .saturating_sub(self.control.started_at),
            });
            self.control
                .lifecycle
                .store(KerneletState::Exited as u8, Ordering::Release);
        }
        let result = status.clone();
        drop(status);
        self.control.exited.wake_all();
        result
    }

    /// Notifies carrier detachment and once-published exit without retaining
    /// instance mappings. Register a waker before checking `reap` or status.
    pub fn exit_wait_queue(&self) -> Arc<WaitQueue> {
        self.control.exited.clone()
    }

    /// Observes the retained exit status without waiting.
    pub fn exit_status(&self) -> Option<ExitStatus> {
        self.control.status.lock().clone()
    }

    /// Waits until the Host reaper publishes exit.
    pub fn wait_exited(&self) -> ExitStatus {
        self.control.exited.wait_until(|| self.exit_status())
    }

    /// Waits for a once-published exit status, bounded by a Host deadline.
    pub fn wait_exited_timeout(&self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = crate::task::accounting::now_ns()
            .saturating_add(timeout.as_nanos().min(u64::MAX as u128) as u64);
        let _alarm = super::account::Deadline::new(deadline, &self.control.exited);
        self.control.exited.wait_until(|| {
            self.exit_status()
                .map(Some)
                .or_else(|| (crate::task::accounting::now_ns() >= deadline).then_some(None))
        })
    }

    /// Returns the device-pin release event used by the Host retry task.
    ///
    /// Enqueue the retry task's waker before calling `destroy` to avoid losing
    /// a final-pin notification between observing Zombie and starting a wait.
    /// The queue does not retain the instance or any of its grant frames.
    pub fn reclaim_wait_queue(&self) -> Option<Arc<WaitQueue>> {
        self.resources
            .lock()
            .as_ref()
            .map(|r| r.grant.drain_queue())
    }

    /// Releases mappings only after the carrier, every admitted control
    /// operation and all device views have drained.
    ///
    /// The caller runs in task context with physical interrupts enabled and
    /// must not itself hold a resource lease of this instance. Destroy first
    /// closes lease admission by flipping to `Destroying`, then waits without
    /// any spinlock held for the leases admitted before the flip. They live
    /// only inside bounded control calls (`grant`, `set_budget`) that never
    /// wait on destroy or the reaper, and each drop wakes the grant drain
    /// queue. Only then are guest pins closed; remaining pins or adopted
    /// references restore `Exited` and are reported as a retriable `Zombie`
    /// without releasing anything.
    pub fn destroy(&self) -> Result<ReclaimReport, DestroyError> {
        let (held, drained) = {
            // Holding the admission lock across the flip serializes the
            // transition with lease creation: a lease admitted before this
            // critical section has already incremented `admitted`, and one
            // admitted after it observes `Destroying` and is refused.
            let _admission = self.control.admission.lock();
            if self
                .control
                .lifecycle
                .compare_exchange(
                    KerneletState::Exited as u8,
                    KerneletState::Destroying as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return Err(DestroyError::NotExited(self.state()));
            }
            let held = self.resources.lock().as_ref().unwrap().clone();
            let drained = held.grant.drain_queue();
            (held, drained)
        };
        drained.wait_until(|| (self.control.admitted.load(Ordering::Acquire) == 0).then_some(()));
        let pins = held.grant.close();
        let adopted = self.control.account.adopted.load(Ordering::Acquire);
        if pins != 0 || adopted != 0 {
            self.control
                .lifecycle
                .store(KerneletState::Exited as u8, Ordering::Release);
            return Err(DestroyError::Zombie { pins, adopted });
        }
        let resources_to_drop = self.resources.lock().take().unwrap();
        assert!(self.control.detached.load(Ordering::Acquire));
        assert!(self.control.tasks.lock().is_empty());
        assert!(self.control.carriers.iter().all(|carrier| {
            carrier.run_state.load(Ordering::Acquire) & !host_run::STOP_REQUESTED
                == host_run::DETACHED
        }));
        assert!(
            self.control
                .retired_tasks
                .lock()
                .as_ref()
                .is_some_and(|tasks| tasks.iter().all(|task| task.upgrade().is_none()))
        );
        self.control.retired_tasks.lock().take();
        let retired = self.control.execution.lock().take();
        let (stacks, roots) = retired.as_ref().map(|r| r.counts()).unwrap_or((0, 0));
        let report = ReclaimReport {
            grains_released: resources_to_drop.grant.grains(),
            kstack_ranges_released: stacks,
            roots_forgotten: roots,
        };
        // Mappings synchronously invalidate every CPU before freeing frames
        // or reservations. No control/subsystem lock spans the shootdown.
        drop(retired);
        drop((resources_to_drop, held));
        self.control.account.grains.store(0, Ordering::Release);
        self.control.account.overhead.store(0, Ordering::Release);
        self.control
            .account
            .grant_overhead
            .store(0, Ordering::Release);
        self.control.account.stacks.store(0, Ordering::Release);
        self.control
            .lifecycle
            .store(KerneletState::Destroyed as u8, Ordering::Release);
        Ok(report)
    }

    /// Number of fixed carrier Threads required by this instance.
    pub fn num_vcpus(&self) -> u16 {
        self.control.carriers.len() as u16
    }

    /// Host CPU for virtual CPU `vcpu`, in the configured set's ascending order.
    pub fn vcpu_host_cpu(&self, vcpu: u16) -> Option<CpuId> {
        self.control
            .carriers
            .get(vcpu as usize)
            .map(|carrier| carrier.cpu)
    }

    /// Publishes Running and queues only the prepared bootstrap carrier.
    /// A racing stop retains the queued Task in `active` until it detaches.
    pub fn start(&self, hooks: Arc<dyn KerneletHooks>) -> crate::Result<()> {
        let _admission = self
            .control
            .admit_operation(&[KerneletState::Created])
            .map_err(|_| Error::AccessDenied)?;
        let task = self
            .control
            .tasks
            .lock()
            .first()
            .cloned()
            .ok_or(Error::InvalidArgs)?;
        self.control
            .active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                (old == 0).then_some(1)
            })
            .map_err(|_| Error::AccessDenied)?;
        *self.control.hooks.lock() = Some(hooks);
        if self
            .control
            .lifecycle
            .compare_exchange(
                KerneletState::Created as u8,
                KerneletState::Running as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.control.detach_carrier();
            return Err(Error::AccessDenied);
        }
        // Stop may win immediately after the transition. The reservation
        // above prevents the reaper from publishing Exited before this Task
        // has run and observed the stop bit.
        task.run();
        Ok(())
    }

    /// Enters one prepared carrier exactly once after its native Task is queued.
    /// The calling native Task must remain pinned to `vcpu_host_cpu(vcpu)`.
    pub fn run_vcpu(&self, vcpu: u16) -> crate::Result<u32> {
        let carrier = self
            .control
            .carriers
            .get(vcpu as usize)
            .ok_or(Error::InvalidArgs)?;
        if !carrier.requested.load(Ordering::Acquire)
            || carrier.entered.swap(true, Ordering::AcqRel)
        {
            return Err(Error::InvalidArgs);
        }
        let result = self.enter_vcpu(vcpu, carrier);
        self.control.stop(match &result {
            Ok(code) => ExitReason::Exited(*code),
            Err(_) => ExitReason::Killed(KillReason::EntryFailed),
        });
        self.control.detach_carrier();
        result
    }

    fn enter_vcpu(&self, vcpu: u16, carrier: &CarrierControl) -> crate::Result<u32> {
        let irq = crate::irq::disable_local();
        if irq.current_cpu() != carrier.cpu {
            return Err(Error::InvalidArgs);
        }
        drop(irq);
        if self.state() != KerneletState::Running
            || carrier.run_state.load(Ordering::Acquire) & host_run::STOP_REQUESTED != 0
        {
            return Err(Error::AccessDenied);
        }
        carrier
            .run_state
            .compare_exchange(
                host_run::PREPARED,
                host_run::STARTING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| Error::AccessDenied)?;
        let hooks = self
            .control
            .hooks
            .lock()
            .clone()
            .ok_or(Error::AccessDenied)?;
        let resources = self.resources.lock().as_ref().unwrap().clone();
        let execution = self.control.execution.lock().as_ref().unwrap().clone();
        let instance = &resources.instance;
        // SAFETY: Registration checked both entry targets; admission retains every mapping.
        let result = unsafe {
            host_run::enter(
                if vcpu == 0 {
                    instance.entry_address()
                } else {
                    instance.vcpu_entry_address()
                },
                instance.range(),
                instance.text_range(),
                instance.virq_entry_address(),
                instance.ex_table_range(),
                instance.boot_args_address() as *const BootArgs,
                (instance.vcpu_record_address() + vcpu as usize * size_of::<VcpuRecord>())
                    as *const VcpuRecord,
                resources.grant.guest_memory(),
                carrier.wait.clone(),
                hooks,
                &self.control,
                &resources.grant,
                &execution,
                vcpu,
            )
        };
        result
    }
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::{mm::PAGE_SIZE, prelude::*};

    #[unsafe(no_mangle)]
    static KERNELET_TEST_ROOT: AtomicU64 = AtomicU64::new(0);
    static STOPPED_IMAGE_IRQ_CALLS: AtomicUsize = AtomicUsize::new(0);
    const STOPPED_IMAGE_IRQ: u8 = 240;

    #[repr(C)]
    struct TrapProbeBoot {
        args: BootArgs,
        record: VcpuRecord,
        fault: super::super::abi::CopyFaultRecord,
        stack_base: usize,
        run_state: usize,
    }

    core::arch::global_asm!(
        ".text",
        ".global kernelet_test_invalid_rsp",
        "kernelet_test_invalid_rsp:",
        "xor rsp, rsp",
        "ud2",
        ".global kernelet_test_invalid_rsp_end",
        "kernelet_test_invalid_rsp_end:",
        ".global kernelet_test_stack_guard",
        "kernelet_test_stack_guard:",
        "mov rsp, [rsi + {probe_stack}]",
        "push rax",
        "ud2",
        ".global kernelet_test_stack_guard_end",
        "kernelet_test_stack_guard_end:",
        ".global kernelet_test_bounded_service",
        "kernelet_test_bounded_service:",
        "mov r12, rdi",
        "mov rdi, [rip + KERNELET_TEST_ROOT]",
        "call [r12 + {activate}]",
        "test rax, rax",
        "jnz 2f",
        "mov r13, cr3",
        "xor edi, edi",
        "xor esi, esi",
        "mov edx, 4",
        "call [r12 + {mmio}]",
        "test rax, rax",
        "jnz 2f",
        "mov rax, cr3",
        "cmp rax, r13",
        "jne 2f",
        // An invalid request still completes the admitted return protocol.
        "xor edi, edi",
        "xor esi, esi",
        "xor edx, edx",
        "call [r12 + {mmio}]",
        "cmp rax, -{invalid}",
        "jne 2f",
        "mov edi, {stop_exit}",
        "mov esi, 42",
        "xor edx, edx",
        "xor ecx, ecx",
        "call [r12 + {stop}]",
        "2: ud2",
        ".global kernelet_test_bounded_service_end",
        "kernelet_test_bounded_service_end:",
        ".global kernelet_test_stopped_irq",
        "kernelet_test_stopped_irq:",
        "cli",
        // Inject the stop publication immediately before the real trap prefix.
        "mov rax, [rsi + {probe_state}]",
        "lock or dword ptr [rax], {stop_requested}",
        "int {stopped_irq}",
        "ud2",
        ".global kernelet_test_stopped_irq_end",
        "kernelet_test_stopped_irq_end:",
        activate = const core::mem::offset_of!(super::super::abi::ServiceTable, pt_activate),
        mmio = const core::mem::offset_of!(super::super::abi::ServiceTable, mmio_read),
        stop = const core::mem::offset_of!(super::super::abi::ServiceTable, stop),
        stop_exit = const super::super::abi::STOP_EXIT,
        invalid = const super::super::abi::INVALID,
        stop_requested = const host_run::STOP_REQUESTED,
        stopped_irq = const STOPPED_IMAGE_IRQ,
        probe_stack = const core::mem::offset_of!(TrapProbeBoot, stack_base),
        probe_state = const core::mem::offset_of!(TrapProbeBoot, run_state),
    );
    unsafe extern "C" {
        fn kernelet_test_invalid_rsp();
        fn kernelet_test_invalid_rsp_end();
        fn kernelet_test_stack_guard();
        fn kernelet_test_stack_guard_end();
        fn kernelet_test_bounded_service();
        fn kernelet_test_bounded_service_end();
        fn kernelet_test_stopped_irq();
        fn kernelet_test_stopped_irq_end();
        fn kernelet_test_large_frame_end();
    }

    #[inline(never)]
    #[expect(clippy::large_stack_arrays, reason = "exercise compiler stack probes")]
    extern "C" fn compiled_large_stack_frame(
        _: &super::super::abi::ServiceTable,
        _: &BootArgs,
    ) -> ! {
        // This exceeds the guarded 256 KiB boot stack. The compiler's ordinary
        // stack probes must fault before initialization can skip its guard.
        let mut frame = [0u8; 512 * 1024];
        core::hint::black_box(&mut frame);
        // SAFETY: This non-inlined fixture defines its end marker exactly once.
        // The directive emits no instruction and changes no machine state.
        unsafe {
            core::arch::asm!(
                ".global kernelet_test_large_frame_end",
                ".set kernelet_test_large_frame_end, 2f",
                "2:",
                options(nostack, preserves_flags),
            );
        }
        loop {
            core::hint::spin_loop();
        }
    }

    struct FaultHooks;
    impl KerneletHooks for FaultHooks {
        fn realtime_now(&self) -> Duration {
            panic!("fault fixture never samples realtime")
        }

        fn create_vcpu_thread(
            &self,
            _: &Arc<Kernelet>,
            _: u16,
            _: CpuId,
            _: i8,
        ) -> crate::Result<Arc<Task>> {
            panic!("fault fixture never builds a carrier")
        }
        fn mmio_read(&self, _: u16, _: u32, _: u32) -> MmioResult {
            panic!("fault fixture never accesses MMIO")
        }
        fn mmio_write(&self, _: u16, _: u32, _: u32, _: u64) -> i64 {
            panic!("fault fixture never accesses MMIO")
        }
        fn log(&self, _: u32, _: &str, _: &str) -> bool {
            panic!("fault fixture never logs")
        }
        fn set_vcpu_nice(&self, _: i8) -> crate::Result<()> {
            panic!("fault fixture never changes budget")
        }
    }

    fn run_entry_fixture(entry: usize, end: usize, stop_before_entry: bool) -> ExitReason {
        let grant = Grant::new(1, 1, 1).unwrap();
        let cpu = crate::irq::disable_local().current_cpu();
        let control = RunControl::new(
            grant.dying_address(),
            Account::new(
                grant.drain_queue(),
                CpuBudget::default(),
                KerneletPolicy::default(),
            ),
            alloc::vec![cpu],
            1,
        )
        .unwrap();
        let mut execution = host_run::ExecutionResources::new(1, 1).unwrap();
        execution.prepare().unwrap();
        // SAFETY: BootArgs contains only integers and integer arrays. Populate
        // the fields read by enter(), with actual live record/fault storage.
        let mut args: BootArgs = unsafe { core::mem::zeroed() };
        args.size = size_of::<BootArgs>() as u32;
        args.num_vcpus = 1;
        args.vcpu_records = core::mem::offset_of!(TrapProbeBoot, record) as u32;
        let probe = TrapProbeBoot {
            args,
            record: VcpuRecord::default(),
            fault: super::super::abi::CopyFaultRecord::default(),
            stack_base: execution.boot_stack_base(),
            run_state: core::ptr::addr_of!(control.carriers[0].run_state) as usize,
        };
        assert_eq!(
            core::mem::offset_of!(TrapProbeBoot, fault),
            probe.args.vcpu_records as usize + super::super::abi::copy_fault_records_offset(1)
        );
        control.active.store(1, Ordering::Release);
        control
            .lifecycle
            .store(KerneletState::Running as u8, Ordering::Release);
        control.carriers[0]
            .run_state
            .store(host_run::STARTING, Ordering::Release);
        if stop_before_entry {
            control.stop(ExitReason::Killed(KillReason::Requested));
        }
        // SAFETY: The static assembly fixture is RX and its exact instruction
        // range is supplied below. The complete boot arguments, record/fault
        // storage, stacks and grant stay live until the fixed exit returns.
        let result = unsafe {
            host_run::enter(
                entry,
                entry..end,
                entry..end,
                entry,
                0..0,
                &probe.args,
                &probe.record,
                grant.guest_memory(),
                Arc::new(WaitQueue::new()),
                Arc::new(FaultHooks),
                &control,
                &grant,
                &execution,
                0,
            )
        };
        assert!(result.is_ok());
        if entry == kernelet_test_stopped_irq as *const () as usize {
            // The assembly fixture injects only the stop bit. Complete the
            // lifecycle publication after the fixed exit restored Host state.
            control.stop(ExitReason::Killed(KillReason::Requested));
        }
        assert_eq!(
            control.carriers[0].run_state.load(Ordering::Acquire) & !host_run::STOP_REQUESTED,
            host_run::LEAVING
        );
        control.detach_carrier();
        assert!(!control.detached.load(Ordering::Acquire));
        assert!(control.try_detach());
        assert!(control.detached.load(Ordering::Acquire));
        // SAFETY: The acquire Dying observation follows the once-published reason.
        assert_eq!(control.state(), KerneletState::Dying);
        unsafe { (*control.reason.get()).assume_init_ref() }.clone()
    }

    #[ktest]
    fn invalid_image_rsp_fault_lands_on_host_ist() {
        let reason = run_entry_fixture(
            kernelet_test_invalid_rsp as *const () as usize,
            kernelet_test_invalid_rsp_end as *const () as usize,
            false,
        );
        assert!(matches!(
            reason,
            ExitReason::Killed(KillReason::KernelFault { .. })
        ));
    }

    #[ktest]
    fn image_stack_guard_fault_is_contained() {
        let reason = run_entry_fixture(
            kernelet_test_stack_guard as *const () as usize,
            kernelet_test_stack_guard_end as *const () as usize,
            false,
        );
        assert!(matches!(
            reason,
            ExitReason::Killed(KillReason::StackOverflow)
        ));
    }

    #[ktest]
    fn compiled_large_stack_frame_fault_is_contained() {
        let reason = run_entry_fixture(
            compiled_large_stack_frame as *const () as usize,
            kernelet_test_large_frame_end as *const () as usize,
            false,
        );
        assert!(matches!(
            reason,
            ExitReason::Killed(KillReason::StackOverflow)
        ));
    }

    #[ktest]
    fn stopped_image_irq_runs_host_callback_before_exit() {
        let mut irq = crate::irq::IrqLine::alloc_specific(STOPPED_IMAGE_IRQ).unwrap();
        STOPPED_IMAGE_IRQ_CALLS.store(0, Ordering::Release);
        irq.on_active(|_| {
            STOPPED_IMAGE_IRQ_CALLS.fetch_add(1, Ordering::Relaxed);
        });
        let reason = run_entry_fixture(
            kernelet_test_stopped_irq as *const () as usize,
            kernelet_test_stopped_irq_end as *const () as usize,
            false,
        );
        assert!(matches!(reason, ExitReason::Killed(KillReason::Requested)));
        assert_eq!(STOPPED_IMAGE_IRQ_CALLS.load(Ordering::Acquire), 1);
    }

    #[ktest]
    fn stopped_initial_entry_publishes_leaving() {
        let reason = run_entry_fixture(
            kernelet_test_invalid_rsp as *const () as usize,
            kernelet_test_invalid_rsp_end as *const () as usize,
            true,
        );
        assert!(matches!(reason, ExitReason::Killed(KillReason::Requested)));
    }

    #[ktest]
    fn kill_before_start_prevents_image_entry() {
        let control = RunControl::new(
            0,
            Account::new(
                Arc::new(WaitQueue::new()),
                CpuBudget::default(),
                KerneletPolicy::default(),
            ),
            alloc::vec![CpuId::bsp()],
            4,
        )
        .unwrap();
        control.stop(ExitReason::Killed(KillReason::Requested));
        assert_eq!(control.state(), KerneletState::Dying);
        assert!(!control.detached.load(Ordering::Acquire));
        assert!(control.try_detach());
        assert!(control.detached.load(Ordering::Acquire));
        assert!(
            control
                .lifecycle
                .compare_exchange(
                    KerneletState::Created as u8,
                    KerneletState::Running as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        );
        assert!(
            control.carriers[0]
                .run_state
                .compare_exchange(
                    host_run::PREPARED,
                    host_run::STARTING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        );
    }

    #[ktest]
    fn kill_during_service_prevents_image_return() {
        let control = RunControl::new(
            0,
            Account::new(
                Arc::new(WaitQueue::new()),
                CpuBudget::default(),
                KerneletPolicy::default(),
            ),
            alloc::vec![CpuId::bsp()],
            4,
        )
        .unwrap();
        control.active.store(1, Ordering::Release);
        control
            .lifecycle
            .store(KerneletState::Running as u8, Ordering::Release);
        control.carriers[0]
            .run_state
            .store(host_run::RETURNING, Ordering::Release);
        control.stop(ExitReason::Killed(KillReason::Requested));
        assert!(!control.detached.load(Ordering::Acquire));
        assert!(
            control.carriers[0]
                .run_state
                .compare_exchange(host_run::RETURNING, 1, Ordering::AcqRel, Ordering::Acquire,)
                .is_err()
        );
    }

    #[ktest]
    fn repeated_stop_preserves_first_reason() {
        let control = RunControl::new(
            0,
            Account::new(
                Arc::new(WaitQueue::new()),
                CpuBudget::default(),
                KerneletPolicy::default(),
            ),
            alloc::vec![CpuId::bsp()],
            4,
        )
        .unwrap();
        control.stop(ExitReason::Exited(42));
        control.stop(ExitReason::Killed(KillReason::Requested));
        assert_eq!(control.state(), KerneletState::Dying);
        // SAFETY: Acquiring Dying observes the once-initialized reason.
        let reason = unsafe { (*control.reason.get()).assume_init_ref() };
        assert!(matches!(reason, ExitReason::Exited(42)));
    }

    #[ktest]
    fn detach_waits_for_native_task_release() {
        let control = RunControl::new(
            0,
            Account::new(
                Arc::new(WaitQueue::new()),
                CpuBudget::default(),
                KerneletPolicy::default(),
            ),
            alloc::vec![CpuId::bsp()],
            1,
        )
        .unwrap();
        let task = Arc::new(crate::task::TaskOptions::new(|| {}).build().unwrap());
        control.tasks.lock().push(task.clone());
        control.stop(ExitReason::Killed(KillReason::Requested));
        assert!(!control.try_detach());
        assert!(!control.detached.load(Ordering::Acquire));
        drop(task);
        assert!(control.try_detach());
        assert_eq!(
            control.carriers[0].run_state.load(Ordering::Acquire),
            host_run::STOP_REQUESTED | host_run::DETACHED
        );
    }

    // ---- Destroy admission drain ----

    /// Builds an instance in the `Created` state with one grant grain, no
    /// carriers and no hooks. Tests drive the lifecycle to `Exited` through
    /// the same stop/detach/reap path the reaper uses.
    fn created_fixture(initial_grains: u32) -> Arc<Kernelet> {
        let image =
            RegisteredImage::register(&super::super::host_image::fixture_image(), [0; 32]).unwrap();
        let grant = Grant::new(initial_grains, initial_grains, 1).unwrap();
        let cpu = crate::irq::disable_local().current_cpu();
        let control = RunControl::new(
            grant.dying_address(),
            Account::new(
                grant.drain_queue(),
                CpuBudget::default(),
                KerneletPolicy::default(),
            ),
            alloc::vec![cpu],
            1,
        )
        .unwrap();
        let mut cpus = CpuSet::new_empty();
        cpus.add(cpu);
        let config = KerneletConfig {
            cmdline: "",
            initial_grains,
            max_grains: initial_grains,
            max_meta_sections: 1,
            budget: CpuBudget::default(),
            policy: KerneletPolicy::default(),
            max_tasks: 1,
            devices: &[],
            cpus,
        };
        let boot = boot_args(&image, &config).unwrap();
        let instance = image.instantiate(&boot, "", &[], &grant).unwrap();
        grant.bind_lifecycle(control.lifecycle.clone());
        Arc::new(Kernelet {
            memory: grant.guest_memory(),
            resources: SpinLock::new(Some(Arc::new(InstanceResources { instance, grant }))),
            device_lines: Vec::new(),
            control: Arc::new(control),
        })
    }

    fn drive_to_exited(kernelet: &Kernelet) {
        kernelet.control.active.store(1, Ordering::Release);
        kernelet
            .control
            .stop(ExitReason::Killed(KillReason::Requested));
        kernelet.control.detach_carrier();
        assert!(kernelet.reap().is_some());
        assert_eq!(kernelet.state(), KerneletState::Exited);
    }

    struct RootProbeHooks {
        kernelet: Arc<Kernelet>,
        root: usize,
        execution: Arc<host_run::ExecutionResources>,
        calls: AtomicUsize,
        panic_in_hook: bool,
    }

    impl KerneletHooks for RootProbeHooks {
        fn realtime_now(&self) -> Duration {
            panic!("root probe never samples realtime")
        }

        fn create_vcpu_thread(
            &self,
            _: &Arc<Kernelet>,
            _: u16,
            _: CpuId,
            _: i8,
        ) -> Result<Arc<Task>> {
            Err(Error::InvalidArgs)
        }
        fn mmio_read(&self, _: u16, _: u32, _: u32) -> MmioResult {
            assert_eq!(crate::arch::mm::current_page_table_paddr(), self.root);
            assert!(
                self.execution.test_root_is_active(
                    self.root as u64,
                    crate::irq::disable_local().current_cpu(),
                )
            );
            assert_eq!(self.kernelet.control.admitted.load(Ordering::Acquire), 1);
            self.kernelet.charge_host_bytes(8).unwrap();
            self.kernelet.uncharge_host_bytes(8);
            assert_eq!(self.kernelet.control.admitted.load(Ordering::Acquire), 1);
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.panic_in_hook {
                let _nested = self
                    .kernelet
                    .control
                    .admit_operation(&[KerneletState::Running])
                    .unwrap();
                assert_eq!(self.kernelet.control.admitted.load(Ordering::Acquire), 2);
                panic!("injected admitted Host-hook failure");
            }
            MmioResult {
                status: 0,
                value: 17,
            }
        }
        fn mmio_write(&self, _: u16, _: u32, _: u32, _: u64) -> i64 {
            -1
        }
        fn log(&self, _: u32, _: &str, _: &str) -> bool {
            false
        }
        fn set_vcpu_nice(&self, _: i8) -> Result<()> {
            Ok(())
        }
    }

    #[ktest]
    fn bounded_service_preserves_root_and_drains_admission() {
        run_root_probe(false);
    }

    #[ktest]
    fn hook_unwind_drains_nested_and_service_admission() {
        run_root_probe(true);
    }

    fn run_root_probe(panic_in_hook: bool) {
        use crate::mm::{FrameAllocOptions, VmIo};
        let kernelet = created_fixture(1);
        let resources = kernelet.resources.lock().as_ref().unwrap().clone();
        let native_root = crate::arch::mm::current_page_table_paddr();
        let root = FrameAllocOptions::new().alloc_frame().unwrap();
        // SAFETY: The current root is live and linearly mapped. The fixture
        // retains both this copy and every shared kernel mapping through exit.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                crate::mm::kspace::paddr_to_vaddr(native_root) as *const u8,
                PAGE_SIZE,
            )
        };
        root.write_bytes(0, bytes).unwrap();
        KERNELET_TEST_ROOT.store(root.paddr() as u64, Ordering::Release);
        let mut execution = host_run::ExecutionResources::new(1, 1).unwrap();
        execution.prepare().unwrap();
        execution.register_test_root(root.paddr() as u64);
        let execution = Arc::new(execution);
        let hooks = Arc::new(RootProbeHooks {
            kernelet: kernelet.clone(),
            root: root.paddr(),
            execution: execution.clone(),
            calls: AtomicUsize::new(0),
            panic_in_hook,
        });
        kernelet.control.active.store(1, Ordering::Release);
        kernelet
            .control
            .lifecycle
            .store(KerneletState::Running as u8, Ordering::Release);
        kernelet.control.carriers[0]
            .run_state
            .store(host_run::STARTING, Ordering::Release);
        let entry = kernelet_test_bounded_service as *const () as usize;
        let end = kernelet_test_bounded_service_end as *const () as usize;
        // SAFETY: The RX assembly fixture, real boot/record mappings and
        // private stacks are live. The copied root has identical mappings;
        // this test exercises activation/crossing, not registration validation.
        let result = unsafe {
            host_run::enter(
                entry,
                entry..end,
                entry..end,
                entry,
                0..0,
                resources.instance.boot_args_address() as *const BootArgs,
                resources.instance.vcpu_record_address() as *const VcpuRecord,
                resources.grant.guest_memory(),
                Arc::new(WaitQueue::new()),
                hooks.clone(),
                &kernelet.control,
                &resources.grant,
                &execution,
                0,
            )
        }
        .unwrap();
        assert_eq!(result, if panic_in_hook { (-5i32) as u32 } else { 42 });
        assert_eq!(hooks.calls.load(Ordering::Acquire), 1);
        assert_eq!(kernelet.control.admitted.load(Ordering::Acquire), 0);
        assert_eq!(crate::arch::mm::current_page_table_paddr(), native_root);
        kernelet.control.detach_carrier();
        let status = kernelet.reap().unwrap();
        if panic_in_hook {
            assert!(matches!(
                status.reason,
                ExitReason::Killed(KillReason::HostHookPanicked)
            ));
        } else {
            assert!(matches!(status.reason, ExitReason::Exited(42)));
        }
        drop((execution, hooks, resources, root));
        kernelet.destroy().unwrap();
    }

    #[ktest]
    fn destroy_refuses_before_exit() {
        let kernelet = created_fixture(1);
        assert!(matches!(
            kernelet.destroy(),
            Err(DestroyError::NotExited(KerneletState::Created))
        ));
        assert_eq!(kernelet.state(), KerneletState::Created);
    }

    #[ktest]
    fn destroy_waits_for_last_admitted_lease_and_closes_admission() {
        let kernelet = created_fixture(1);
        let lease = kernelet.admit(true).unwrap();
        drive_to_exited(&kernelet);

        let released = Arc::new(AtomicBool::new(false));
        let worker_kernelet = kernelet.clone();
        let worker_released = released.clone();
        crate::task::TaskOptions::new(move || {
            while worker_kernelet.state() != KerneletState::Destroying {
                Task::yield_now();
            }
            assert!(worker_kernelet.admit(true).is_err());
            assert!(
                worker_kernelet
                    .control
                    .admit_operation(&[KerneletState::Running])
                    .is_err()
            );
            let mut called = false;
            assert!(
                worker_kernelet
                    .guest_memory()
                    .with_range(0, 0, |_, _| {
                        called = true;
                    })
                    .is_err()
            );
            assert!(
                !called,
                "Destroying must close pins before operation drain finishes"
            );
            worker_released.store(true, Ordering::Release);
            drop(lease);
        })
        .data(())
        .spawn()
        .unwrap();

        let report = kernelet.destroy().unwrap();
        // The reclaim could not complete before the lease retired itself.
        assert!(released.load(Ordering::Acquire));
        assert_eq!(report.grains_released, 1);
        assert_eq!(kernelet.state(), KerneletState::Destroyed);
        // Destroying closed admission for every later control operation.
        assert!(kernelet.admit(true).is_err());
        assert!(matches!(
            kernelet.destroy(),
            Err(DestroyError::NotExited(KerneletState::Destroyed))
        ));
    }

    #[ktest]
    fn destroy_reports_adopted_tasks_and_allows_retry() {
        let kernelet = created_fixture(1);
        kernelet.adopt_current_task().unwrap();
        drive_to_exited(&kernelet);

        assert!(matches!(
            kernelet.destroy(),
            Err(DestroyError::Zombie {
                pins: 0,
                adopted: 1
            })
        ));
        assert_eq!(kernelet.state(), KerneletState::Exited);
        kernelet.disown_current_task();
        let report = kernelet.destroy().unwrap();
        assert_eq!(report.grains_released, 1);
        assert_eq!(kernelet.state(), KerneletState::Destroyed);
    }
}
