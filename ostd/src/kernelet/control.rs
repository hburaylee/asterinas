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

use super::{
    abi::{BootArgs, CpuSlot, DeviceEntry, META_SECTION_BYTES, MmioResult, VIRQ_LINES, VcpuRecord},
    account::Account,
    deadline::Deadline,
    guest_memory::GuestMemory,
    host_grant::Grant,
    host_image::{ImageInstance, RegisteredImage},
    host_run,
};
pub use super::{
    account::CpuBudget,
    deadline::{HostTimer, register_host_timer},
};
use crate::{
    Error,
    cpu::{CpuId, CpuSet, PinCurrentCpu},
    sync::{LocalIrqDisabled, Mutex, SpinLock, WaitQueue},
    task::Task,
};

mod config;
pub(super) mod identity;
mod reaper;

pub use reaper::{ReclaimCallbacks, enqueue_reclaim, init_reaper, watch_exit};

use self::config::{boot_args, host_source_hash, validate_config};

const REAPER_RETRY_NS: u64 = Duration::from_millis(1).as_nanos() as u64;

/// Hard bound on per-instance Task/root metadata and guarded stack slots.
pub const MAX_TASKS: u32 = 4096;

/// Conservative Host reservation for the configured execution high-water mark.
///
/// Includes retained image stacks, native carriers, slot/root/VM metadata and
/// four page-table pages per slot. A UID admission owner reserves these bytes
/// before constructing execution resources and refunds them after destroy.
pub fn execution_reservation_bytes(max_tasks: u32, vcpus: u16) -> crate::Result<usize> {
    host_run::ExecutionResources::reservation_bytes(max_tasks, vcpus as usize)
}

static REAPER_PENDING: AtomicBool = AtomicBool::new(false);

/// Takes the coalesced stop notice for the Host reaper.
///
/// A Host timer callback calls this only after the reaper has published its
/// waker. Detection only publishes this atomic flag; waking and scheduling
/// stay outside exception context.
pub fn take_reaper_notification() -> bool {
    REAPER_PENDING.swap(false, Ordering::Acquire)
}

/// Host-side operations supplied by the kernelet's endovisor.
///
/// Request hooks run on a private 64 KiB stack of the current physical CPU,
/// with native preemption disabled. Ordinary services enter on the shared
/// Image Task stack; `call_hook` performs the private stack switch. An MMIO write may be
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

    /// Reports the first death on the reaper after carrier stop dispatch.
    /// This callback must return in bounded time without blocking.
    fn on_dying(&self, _kernelet: &Kernelet, _reason: &ExitReason) {}

    /// Reports exit on the reaper after every carrier Task has retired.
    /// This callback may sleep or call `destroy`; no control lock is held.
    fn on_exited(&self, _kernelet: &Kernelet, _status: &ExitStatus) {}

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

include!(concat!(env!("OUT_DIR"), "/kernelet_image.rs"));

impl KerneletKind {
    /// Registers the image selected by OSDK at this Host's build time.
    ///
    /// No caller-provided executable bytes enter through this safe interface.
    pub fn register_embedded() -> crate::Result<Option<Self>> {
        EMBEDDED_IMAGE
            .map(|image| {
                // SAFETY: The Host build embeds only OSDK's audited image from
                // the same source/toolchain; runtime callers cannot replace it.
                unsafe { Self::register(image) }
            })
            .transpose()
    }

    /// Registers an OSDK-built image after checking its common source hash.
    ///
    /// # Safety
    ///
    /// The executable must satisfy the trusted OSTD/vOSTD memory, entry and
    /// instruction contracts and have passed the matching OSDK audit. Layout
    /// and a caller-provided source hash alone do not establish these facts.
    pub unsafe fn register(elf: &[u8]) -> crate::Result<Self> {
        if cfg!(panic = "abort") {
            return Err(Error::InvalidArgs);
        }
        let image = RegisteredImage::register(elf, host_source_hash()?)?;
        Ok(Self { image })
    }

    /// Builds OSTD's fixed loader fixture with an inert UD2 entry for tests.
    #[cfg(ktest)]
    pub fn register_dormant_fixture() -> crate::Result<Self> {
        let mut bytes = super::host_image::fixture_image();
        // This fixture's entry is UD2 and it never returns into caller data.
        let source = host_source_hash()?;
        bytes[0x1000 + 40..0x1000 + 72].copy_from_slice(&source);
        let entry = 0x1000 + size_of::<super::abi::EntryTable>();
        bytes[entry..entry + 8].copy_from_slice(&[0x0f, 0x0b, 0x0f, 0x0b, 0x0f, 0x0b, 0x0f, 0x0b]);
        let image = RegisteredImage::register(&bytes, source)?;
        Ok(Self { image })
    }

    /// Returns resident sizes from this kind's validated ELF metadata.
    pub fn image_info(&self) -> ImageInfo {
        self.image.image_info()
    }

    /// Reserves all Host storage before instance allocation or publication.
    ///
    /// `lifetime_grains` is the admission owner's maximum total authorization,
    /// including future growth. Metadata is charged for that high-water mark;
    /// the Guest grant bytes themselves are charged by the admission owner.
    pub fn instance_reservation_bytes(
        &self,
        config: &KerneletConfig<'_>,
        lifetime_grains: u32,
    ) -> crate::Result<usize> {
        validate_config(config)?;
        if config.max_grains == 0 || config.max_grains > lifetime_grains {
            return Err(Error::InvalidArgs);
        }
        let sections = config.max_meta_sections.min(
            u32::try_from(crate::mm::frame::max_paddr().div_ceil(META_SECTION_BYTES))
                .map_err(|_| Error::Overflow)?,
        );
        if sections == 0
            || sections > lifetime_grains
            || config.max_grains as u64
                > sections as u64 * (META_SECTION_BYTES / super::abi::GRAIN_SIZE) as u64
        {
            return Err(Error::InvalidArgs);
        }
        let vcpus = config.cpus.count();
        let execution = execution_reservation_bytes(config.max_tasks, vcpus as u16)?;
        let grant = Grant::reservation_bytes(sections, lifetime_grains)?;
        let image = self.image.reservation_bytes(vcpus)?;
        let workers = config
            .devices
            .len()
            .checked_mul(
                crate::task::native_stack_reservation_bytes()
                    + size_of::<Task>()
                    + 8 * crate::mm::PAGE_SIZE,
            )
            .ok_or(Error::Overflow)?;
        // Control/identity/accounting/queues and Arc headers are bounded by
        // the Task/device limits; retain a conservative page per such owner.
        // The vCPU page includes its cache-line-isolated counters and at most
        // one live Host deadline registration; cancellation removes that node.
        let owners = (config.max_tasks as usize)
            .checked_add(config.devices.len())
            .and_then(|n| n.checked_add(vcpus + 8))
            .and_then(|n| n.checked_mul(crate::mm::PAGE_SIZE))
            .ok_or(Error::Overflow)?;
        // Hook stacks are prepared once for every physical CPU. The first
        // instance can trigger that global allocation, so reserve its bound.
        let hook_stacks = crate::cpu::num_cpus()
            .checked_mul(64 * 1024 + 4 * crate::mm::PAGE_SIZE)
            .ok_or(Error::Overflow)?;
        [execution, grant, image, workers, owners, hook_stacks]
            .into_iter()
            .try_fold(0usize, |sum, bytes| {
                sum.checked_add(bytes).ok_or(Error::Overflow)
            })
    }

    /// Creates an instance and every dormant carrier without scheduling one.
    pub fn create(
        &self,
        config: &KerneletConfig<'_>,
        hooks: Arc<dyn KerneletHooks>,
    ) -> crate::Result<Arc<Kernelet>> {
        reaper::require_initialized()?;
        validate_config(config)?;
        let image = &self.image;
        // The caller supplies a bound on distinct metadata sections. Only the
        // Host knows the physical address range, so cap that bound here before
        // reserving metadata and publishing the immutable boot page.
        let physical_sections = crate::mm::frame::max_paddr().div_ceil(META_SECTION_BYTES);
        let max_meta_sections = config
            .max_meta_sections
            .min(u32::try_from(physical_sections).unwrap_or(u32::MAX));
        let cpus: Vec<_> = config.cpus.iter().collect();
        let execution = host_run::ExecutionResources::new(config.max_tasks as usize, cpus.len())?;
        // Locals drop in reverse declaration order. On construction failure,
        // grant mappings, owners and frames must retire before the identity.
        let mut control;
        let identity = identity::Registration::new()?;
        let grant = Grant::new(
            identity.owner(),
            config.initial_grains,
            config.max_grains,
            max_meta_sections,
        )?;
        control = RunControl::new(
            identity,
            grant.dying_address(),
            Account::new(grant.drain_queue(), config.policy),
            cpus,
            execution,
        );
        grant.bind_identity(control.identity.clone());
        let mut boot = boot_args(image, config, control.cpu_slot(0))?;
        // Both sides use the immutable TSC calibration in this boot page to
        // extend the realtime snapshot in the same Host-boot clock domain.
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
        let boot_stack_bytes = Arc::get_mut(
            Arc::get_mut(&mut control)
                .unwrap()
                .execution
                .get_mut()
                .as_mut()
                .unwrap(),
        )
        .unwrap()
        .prepare()?;
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
        *kernelet.control.hooks.lock() = Some(hooks);
        reaper::track(&kernelet);
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
    /// Host fair weight; hard CPU quota requests are rejected.
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
    /// CPU time, currently `STATS_UNAVAILABLE` nanoseconds in Host builds.
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

/// Failure to validate or apply a Host scheduling policy.
#[derive(Clone, Copy, Debug)]
pub enum BudgetError {
    /// No running carrier accepts policy changes in this state.
    State(KerneletState),
    /// Nice lies outside -20..=19.
    InvalidNice,
    /// This Host build supports weights but no aggregate CPU bandwidth limit.
    UnsupportedQuota,
    /// The endovisor could not apply the validated fair scheduling weight.
    Rejected,
}

/// Value returned for an observation not collected by this build.
///
/// Duration observations use `Duration::from_nanos(STATS_UNAVAILABLE)`.
/// Aggregate CPU time is currently unavailable in Host builds.
/// Memory and log-limit accounting remain available in every Host build.
pub const STATS_UNAVAILABLE: u64 = u64::MAX;

/// Host-observed counters for one instance, retained through destruction.
///
/// Service, MMIO and IRQ counts are collected in every build.
/// Completion/ingress attribution and yield counts require
/// `kernelet_rq1_diagnostics`; otherwise they contain [`STATS_UNAVAILABLE`].
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
    /// Carrier and adopted-worker CPU time, or `STATS_UNAVAILABLE` nanoseconds.
    pub cpu_time: Duration,
    /// Device completion CPU time explicitly attributed by the endovisor.
    pub completion_cpu_time: Duration,
    /// Receive-copy CPU time explicitly attributed by the endovisor.
    pub ingress_copy_cpu_time: Duration,
    /// Admitted service crossings.
    pub service_calls: u64,
    /// Trap-return yields requested at the cooperation bound.
    pub forced_yields: u64,
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
    /// Reserved throttle duration; currently zero because quotas are unsupported.
    pub throttled: Duration,
}

// Observation only. Each carrier writes its own cache line; readers aggregate
// without stopping carriers. Admission, resource limits and lifetime counters
// remain in Account and keep their existing synchronization.
#[repr(align(64))]
#[derive(Default)]
pub(crate) struct CarrierCounters {
    pub(crate) service_calls: AtomicU64,
    pub(crate) mmio_accesses: AtomicU64,
    pub(crate) irqs_raised: AtomicU64,
}

pub(crate) struct CarrierControl {
    pub(crate) counters: CarrierCounters,
    // Written only by this carrier with physical IRQs masked, until its Task
    // has disappeared and the reaper publishes DETACHED.
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
    #[cfg(all(kernelet_rq1_diagnostics, not(feature = "kernelet")))]
    pub(crate) tlb_profile: super::tlb_profile::TlbProfile,
    #[cfg(all(kernelet_rq1_crossing_diag, target_arch = "x86_64"))]
    pub(crate) crossing_profile: super::crossing_profile::CrossingProfile,
    pub(crate) account: Arc<Account>,
    hooks: SpinLock<Option<Arc<dyn KerneletHooks>>, LocalIrqDisabled>,
    budget_change: Mutex<()>,
    lifecycle: Arc<AtomicU8>,
    claimed: AtomicBool,
    /// Distinguishes started instances from Created teardown, which has no hooks.
    started: AtomicBool,
    reason: UnsafeCell<MaybeUninit<ExitReason>>,
    pub(crate) carriers: Vec<CarrierControl>,
    /// Built at creation, queued only by `start` or `vcpu_boot`.
    tasks: SpinLock<Vec<Arc<Task>>, LocalIrqDisabled>,
    /// Reaper-owned weak references, retained until every native Task drops.
    retired_tasks: SpinLock<Option<Vec<Weak<Task>>>, LocalIrqDisabled>,
    /// Wakes the reaper if a native Task still held its stack at the last scan.
    reap_retry: SpinLock<Option<Deadline>, LocalIrqDisabled>,
    /// Serializes task-context reaping; true after carrier stop dispatch.
    reaping: Mutex<bool>,
    active: AtomicU32,
    /// Serializes operation admission and dormant-carrier state transitions. Never
    /// hold this lock while entering a subsystem or calling a hook. Resource
    /// Arc acquisition uses the order admission -> resources, before work.
    admission: SpinLock<(), LocalIrqDisabled>,
    /// External control operations that must drain before reclamation.
    admitted: AtomicUsize,
    pub(crate) execution: SpinLock<Option<Arc<host_run::ExecutionResources>>, LocalIrqDisabled>,
    dying_address: usize,
    ready_for_reap: AtomicBool,
    detached: AtomicBool,
    /// First stop publication time; detachment retains its separate timestamp.
    marked_at: AtomicU64,
    detached_at: AtomicU64,
    started_at: Duration,
    status: SpinLock<Option<ExitStatus>, LocalIrqDisabled>,
    exited: Arc<WaitQueue>,
    // Drop every control-owned resource before releasing this reservation.
    identity: Arc<identity::Registration>,
}

// SAFETY: Only the successful claimed CAS writes reason; the release Dying
// transition publishes it. Readers first acquire lifecycle. No writer ever
// modifies it afterward, including across Exited and Destroyed.
unsafe impl Sync for RunControl {}

impl RunControl {
    fn new(
        identity: identity::Registration,
        dying_address: usize,
        account: Arc<Account>,
        cpus: Vec<CpuId>,
        execution: host_run::ExecutionResources,
    ) -> Arc<Self> {
        #[cfg(ktest)]
        super::deadline::test::init();
        let control = Arc::new(Self {
            identity: Arc::new(identity),
            #[cfg(all(kernelet_rq1_diagnostics, not(feature = "kernelet")))]
            tlb_profile: super::tlb_profile::TlbProfile::new(),
            #[cfg(all(kernelet_rq1_crossing_diag, target_arch = "x86_64"))]
            crossing_profile: super::crossing_profile::CrossingProfile::new(),
            account,
            hooks: SpinLock::new(None),
            budget_change: Mutex::new(()),
            lifecycle: Arc::new(AtomicU8::new(KerneletState::Created as u8)),
            claimed: AtomicBool::new(false),
            started: AtomicBool::new(false),
            reason: UnsafeCell::new(MaybeUninit::uninit()),
            carriers: cpus
                .into_iter()
                .enumerate()
                .map(|(index, cpu)| CarrierControl {
                    counters: CarrierCounters::default(),
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
            reaping: Mutex::new(false),
            active: AtomicU32::new(0),
            admission: SpinLock::new(()),
            admitted: AtomicUsize::new(0),
            execution: SpinLock::new(Some(Arc::new(execution))),
            dying_address,
            ready_for_reap: AtomicBool::new(false),
            detached: AtomicBool::new(false),
            marked_at: AtomicU64::new(0),
            detached_at: AtomicU64::new(0),
            started_at: crate::timer::Jiffies::elapsed().as_duration(),
            status: SpinLock::new(None),
            exited: Arc::new(WaitQueue::new()),
        });
        control.identity.publish(&control);
        control
    }

    pub(crate) fn cpu_slot(&self, vcpu: u16) -> CpuSlot {
        self.identity.cpu_slot(vcpu)
    }

    pub(crate) fn lookup_cpu_slot(identity: CpuSlot, owner: &Self) -> Option<&Self> {
        identity::lookup(identity, owner)
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

    pub(crate) fn stop_requested(&self) -> bool {
        self.active.load(Ordering::Acquire) & host_run::STOP_REQUESTED != 0
    }

    pub(crate) fn stop_state(&self) -> &AtomicU32 {
        &self.active
    }

    /// Records the first stop and notifies the Host reaper. This may run on
    /// an exception path; carrier wakeups and IPIs belong to task context.
    pub(crate) fn stop(&self, reason: ExitReason) {
        let Some(active) = self.mark_dying(reason) else {
            return;
        };
        if active & !host_run::STOP_REQUESTED == 0 {
            self.signal_reaper();
        } else {
            // A last detach can race publication of Dying; notify again after
            // that release so an early reaper scan cannot miss the exit.
            REAPER_PENDING.store(true, Ordering::Release);
        }
    }

    /// Publishes the first reason and returns the preceding carrier reservation.
    fn mark_dying(&self, reason: ExitReason) -> Option<u32> {
        if self
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return None;
        }
        // SAFETY: The claim gives this call exclusive initialization rights.
        unsafe { (*self.reason.get()).write(reason) };
        self.marked_at
            .store(crate::timer::Jiffies::elapsed().as_u64(), Ordering::Relaxed);
        let active = self
            .active
            .fetch_or(host_run::STOP_REQUESTED, Ordering::AcqRel);
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
        Some(active)
    }

    /// Runs once under `reaping`, before native Tasks can be retired. Each
    /// wait checks the sticky instance stop bit after waking, so a carrier
    /// entering idle sleep concurrently cannot miss termination.
    fn stop_carriers(&self) {
        for carrier in &self.carriers {
            carrier.wait.wake_all();
            // No instance pointer crosses the IPI queue. A running image
            // observes the instance stop bit at the physical trap boundary.
            crate::smp::inter_processor_call(&carrier.cpu.into(), || {});
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
        REAPER_PENDING.store(true, Ordering::Release);
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
            *self.reap_retry.lock() = Some(Deadline::after(
                Duration::from_nanos(REAPER_RETRY_NS),
                &self.exited,
            ));
            return false;
        }
        self.reap_retry.lock().take();
        for carrier in &self.carriers {
            let phase = carrier.run_state.load(Ordering::Acquire);
            assert!(matches!(
                phase,
                host_run::PREPARED | host_run::STARTING | host_run::LEAVING
            ));
            carrier
                .run_state
                .store(host_run::DETACHED, Ordering::Release);
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
        // Also covers failed construction before a Kernelet can be destroyed.
        // Withdraw the address before any of this owner's fields are dropped.
        self.identity.unpublish(self);
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

/// A Host buffer charge that retains accounting without retaining an instance.
pub struct HostByteCharge {
    counter: Arc<AtomicUsize>,
    bytes: usize,
}

impl HostByteCharge {
    /// Splits a charge without changing the total accounted bytes.
    pub fn split_off(&mut self, bytes: usize) -> Option<Self> {
        if bytes == 0 || bytes > self.bytes {
            return None;
        }
        self.bytes -= bytes;
        Some(Self {
            counter: self.counter.clone(),
            bytes,
        })
    }
}

impl Drop for HostByteCharge {
    fn drop(&mut self) {
        let result = self
            .counter
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_sub(self.bytes)
            });
        debug_assert!(result.is_ok(), "unbalanced kernelet Host-memory charge");
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
    /// Arms a bounded echo-body capture through this instance capability.
    ///
    /// The nonce labels evidence; it does not select or authenticate an instance.
    /// Slot zero supplies only the instance identity at arm time. Each record
    /// obtains its actual vCPU from the authenticated carrier. The returned
    /// handle retains diagnostic memory only and survives instance destruction.
    #[cfg(all(kernelet_rq1_crossing_diag, target_arch = "x86_64"))]
    pub fn rq1_crossing_capture(
        &self,
        nonce: u64,
    ) -> Result<super::crossing_profile::CaptureHandle, super::crossing_profile::CaptureError> {
        if nonce == 0 {
            return Err(super::crossing_profile::CaptureError::Invalid);
        }
        if self.state() != KerneletState::Running {
            return Err(super::crossing_profile::CaptureError::Unavailable);
        }
        self.control
            .crossing_profile
            .arm(self.control.cpu_slot(0), nonce)
    }

    /// Arms a bounded Host TLB capture without retaining tenant resources.
    ///
    /// The instance must be running when requested. The returned handle closes
    /// admission on `finish()` and remains readable after instance destruction.
    #[cfg(all(kernelet_rq1_diagnostics, not(feature = "kernelet")))]
    pub fn rq1_tlb_capture(
        &self,
    ) -> Result<super::tlb_profile::CaptureHandle, super::tlb_profile::CaptureError> {
        if self.state() != KerneletState::Running {
            return Err(super::tlb_profile::CaptureError::Unavailable);
        }
        self.control.tlb_profile.arm(self.control.cpu_slot(0))
    }

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

    /// Applies a validated fair weight as one serialized update.
    pub fn set_budget(&self, budget: CpuBudget) -> Result<(), BudgetError> {
        budget.validate()?;
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
            cpu_time: Duration::from_nanos(STATS_UNAVAILABLE),
            #[cfg(kernelet_rq1_diagnostics)]
            completion_cpu_time: Duration::from_nanos(
                account.completion_ns.load(Ordering::Acquire),
            ),
            #[cfg(not(kernelet_rq1_diagnostics))]
            completion_cpu_time: Duration::from_nanos(STATS_UNAVAILABLE),
            #[cfg(kernelet_rq1_diagnostics)]
            ingress_copy_cpu_time: Duration::from_nanos(account.ingress_ns.load(Ordering::Acquire)),
            #[cfg(not(kernelet_rq1_diagnostics))]
            ingress_copy_cpu_time: Duration::from_nanos(STATS_UNAVAILABLE),
            service_calls: self
                .control
                .carriers
                .iter()
                .map(|carrier| carrier.counters.service_calls.load(Ordering::Relaxed))
                .fold(0u64, u64::wrapping_add),
            #[cfg(kernelet_rq1_diagnostics)]
            forced_yields: account.forced_yields.load(Ordering::Relaxed),
            #[cfg(not(kernelet_rq1_diagnostics))]
            forced_yields: STATS_UNAVAILABLE,
            mmio_accesses: self
                .control
                .carriers
                .iter()
                .map(|carrier| carrier.counters.mmio_accesses.load(Ordering::Relaxed))
                .fold(0u64, u64::wrapping_add),
            irqs_raised: self
                .control
                .carriers
                .iter()
                .map(|carrier| carrier.counters.irqs_raised.load(Ordering::Relaxed))
                .fold(0u64, u64::wrapping_add),
            log_bytes: account.log_bytes.load(Ordering::Relaxed),
            log_records_dropped: account.logs_dropped.load(Ordering::Relaxed),
            oopses: account.oopses.load(Ordering::Relaxed),
            host_overhead_bytes: account.overhead.load(Ordering::Acquire)
                + account.grant_overhead.load(Ordering::Acquire),
            throttled: Duration::ZERO,
        }
    }

    /// Attributes a bounded physical-device completion to this instance.
    #[cfg(kernelet_rq1_diagnostics)]
    pub fn charge_completion_time(&self, elapsed: Duration) {
        self.control.account.completion_ns.fetch_add(
            elapsed.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }

    /// Attributes an incoming data-copy operation to its recipient.
    #[cfg(kernelet_rq1_diagnostics)]
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
        let result =
            resources
                .grant
                .grow_and_raise_ceiling(grains, 0)
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

    /// Retains a Host worker until disown or Task exit, without making it a vCPU.
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
        // drops its AdoptedTask and refunds this reference outside admission.
        self.control.account.attach_adopted()
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

    /// Reserves Host buffers with an owner that can outlive instance teardown.
    pub fn reserve_host_bytes(&self, bytes: usize) -> crate::Result<HostByteCharge> {
        self.charge_host_bytes(bytes)?;
        Ok(HostByteCharge {
            counter: self.control.account.host_bytes.clone(),
            bytes,
        })
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
        self.control.carriers[vcpu]
            .counters
            .irqs_raised
            .fetch_add(1, Ordering::Relaxed);
        self.control.carriers[vcpu].wait.wake_all();
        // A remote physical trap return makes a running image observe the line;
        // waking the queue alone only reaches a parked carrier.
        crate::smp::IPI_SENDER
            .get()
            .unwrap()
            .notify_remote_cpu(self.control.carriers[vcpu].cpu);
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
        if self.state() == KerneletState::Created {
            // Serialize with the reaper before publishing Dying, and with
            // start before it can borrow or reserve a dormant carrier.
            let mut stop_dispatched = self.control.reaping.lock();
            let transition = self.control.admission.lock();
            let was_created = self.state() == KerneletState::Created;
            let finish_created = if was_created {
                match self.control.mark_dying(ExitReason::Killed(reason)) {
                    Some(active) if active & !host_run::STOP_REQUESTED == 0 => {
                        self.control.ready_for_reap.store(true, Ordering::Release);
                        true
                    }
                    Some(_) => {
                        REAPER_PENDING.store(true, Ordering::Release);
                        false
                    }
                    None => false,
                }
            } else {
                self.control.stop(ExitReason::Killed(reason));
                false
            };
            drop(transition);
            if finish_created {
                *stop_dispatched = true;
                if self.control.try_detach() {
                    self.publish_exit();
                } else {
                    REAPER_PENDING.store(true, Ordering::Release);
                }
            }
            // An unexpected retained native Task still needs the ordinary
            // reaper retirement path; never publish detachment while its
            // Weak reference can be upgraded.
        } else {
            self.control.stop(ExitReason::Killed(reason));
        }
        Ok(())
    }

    /// Notifies the reaper and returns an already published exit status.
    /// Instance creation registers automatic progress; callers need not poll this.
    pub fn reap(&self) -> Option<ExitStatus> {
        reaper::notify();
        self.exit_status()
    }

    // Only the reaper drives these phases for registered instances. Splitting
    // them lets on_dying cancel Host backends before waiting for detachment.
    fn begin_reap(&self) -> bool {
        let mut stop_dispatched = self.control.reaping.lock();
        if self.state() != KerneletState::Dying {
            return false;
        }
        if !*stop_dispatched {
            self.control.stop_carriers();
            *stop_dispatched = true;
        }
        true
    }

    fn finish_reap(&self) -> Option<ExitStatus> {
        let _reaping = self.control.reaping.lock();
        if self.state() != KerneletState::Dying {
            return self.exit_status();
        }
        if !self.control.try_detach() {
            return None;
        }
        Some(self.publish_exit())
    }

    fn stop_reason(&self) -> ExitReason {
        // SAFETY: Every caller observes Dying with acquire ordering before
        // this read. The first stop initialized the reason and never changes it.
        unsafe { (*self.control.reason.get()).assume_init_ref() }.clone()
    }

    #[cfg(ktest)]
    fn reap_for_test(&self) -> Option<ExitStatus> {
        if self.begin_reap() {
            self.finish_reap()
        } else {
            self.exit_status()
        }
    }

    fn publish_exit(&self) -> ExitStatus {
        let mut status = self.control.status.lock();
        if status.is_none() {
            let reason = self.stop_reason();
            *status = Some(ExitStatus {
                reason,
                cpu_time: Duration::from_nanos(STATS_UNAVAILABLE),
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
        let result = status.as_ref().unwrap().clone();
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
        let alarm = Deadline::after(timeout, &self.control.exited);
        self.control.exited.wait_until(|| {
            self.exit_status()
                .map(Some)
                .or_else(|| alarm.is_expired().then_some(None))
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
        assert!(
            self.control
                .carriers
                .iter()
                .all(|carrier| { carrier.run_state.load(Ordering::Acquire) == host_run::DETACHED })
        );
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
        // No carrier Task or admitted operation can use this identity after
        // mappings and execution resources have drained. Existing handles may
        // retain the control, but its registry slot can now serve a new owner.
        self.control.identity.retire();
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

    /// Returns the address space held by the corresponding native carrier.
    pub fn carrier_vm_space(&self, vcpu: u16) -> crate::Result<Arc<crate::mm::VmSpace>> {
        self.control
            .execution
            .lock()
            .as_ref()
            .ok_or(Error::AccessDenied)?
            .carrier_vm_space(vcpu)
    }

    /// Publishes Running and queues only the prepared bootstrap carrier.
    /// A racing stop retains the queued Task in `active` until it detaches.
    pub fn start(self: &Arc<Self>) -> crate::Result<()> {
        let _admission = self
            .control
            .admit_operation(&[KerneletState::Created])
            .map_err(|_| Error::AccessDenied)?;
        // Close construction-time byte access before the Guest allocator can
        // run. An existing scoped pin makes start retryable, never blocking.
        self.memory.restrict_to_dma()?;
        let transition = self.control.admission.lock();
        if self.state() != KerneletState::Created {
            return Err(Error::AccessDenied);
        }
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
        reaper::retain_started(self.clone());
        self.control.started.store(true, Ordering::Release);
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
        drop(transition);
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
        if self.state() != KerneletState::Running
            || self.control.stop_requested()
            || carrier.run_state.load(Ordering::Acquire) != host_run::PREPARED
        {
            return Err(Error::AccessDenied);
        }
        // entered.swap above permits only this Task to start the carrier.
        // A concurrent remote stop changes the separate active word; the
        // fixed entry checks it again before executing any image instruction.
        carrier
            .run_state
            .store(host_run::STARTING, Ordering::Release);
        drop(irq);
        let hooks = self
            .control
            .hooks
            .lock()
            .clone()
            .ok_or(Error::AccessDenied)?;
        let resources = self.resources.lock().as_ref().unwrap().clone();
        let execution = self.control.execution.lock().as_ref().unwrap().clone();
        let instance = &resources.instance;
        // SAFETY: Registration checked every entry target. The resource Arcs
        // above retain all mappings until fixed exit; the active reservation
        // and native Task retirement prevent destroy until this call returns.
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
                instance.yield_entry_address(),
                instance.exit_entry_address(),
                instance.stub_range(),
                instance.cpu_access_range(),
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
    static KERNELET_TEST_ROOTS: [AtomicU64; 7] = [const { AtomicU64::new(0) }; 7];
    #[unsafe(no_mangle)]
    static KERNELET_TEST_SERVICE_RETURNED: AtomicBool = AtomicBool::new(false);
    static STOPPED_IMAGE_IRQ_CALLS: AtomicUsize = AtomicUsize::new(0);
    const STOPPED_IMAGE_IRQ: u8 = 240;

    #[repr(C)]
    struct TrapProbeBoot {
        args: BootArgs,
        record: VcpuRecord,
        fault: super::super::abi::CopyFaultRecord,
        stack_base: usize,
        stop_state: usize,
        host_root: usize,
    }

    core::arch::global_asm!(
        ".text",
        ".global kernelet_test_exit",
        "kernelet_test_exit:",
        "endbr64",
        "mov eax, -5",
        "jmp kernelet_host_exit",
        ".global kernelet_test_exit_end",
        "kernelet_test_exit_end:",
        ".global kernelet_test_initial_root",
        "kernelet_test_initial_root:",
        "cli",
        // Check before the first service can repair the root on its own.
        "mov rax, cr3",
        "cmp rax, [rsi + {probe_host_root}]",
        "jne 2f",
        "sub rsp, 8",
        "mov r12, rdi",
        "mov edi, {stop_exit}",
        "mov esi, 42",
        "xor edx, edx",
        "xor ecx, ecx",
        "call [r12 + {stop}]",
        "2: ud2",
        ".global kernelet_test_initial_root_end",
        "kernelet_test_initial_root_end:",
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
        "sub rsp, 8",
        "mov r12, rdi",
        "lea r15, [rip + KERNELET_TEST_ROOTS]",
        "xor r14d, r14d",
        // A, B, A, same A, invalid, Host root, then A again. Every successful
        // service return must expose the committed hardware root to the hook.
        "4:",
        "mov rdi, [r15 + r14 * 8]",
        "call [r12 + {activate}]",
        "cmp r14d, 4",
        "jne 5f",
        "cmp rax, -{invalid}",
        "jne 2f",
        "jmp 6f",
        "5:",
        "test rax, rax",
        "jnz 2f",
        "6:",
        "mov r13, cr3",
        "mov edi, r14d",
        "xor esi, esi",
        "mov edx, 4",
        "call [r12 + {mmio}]",
        "test rax, rax",
        "jnz 2f",
        "mov rax, cr3",
        "cmp rax, r13",
        "jne 2f",
        // Root zero accepts only a full local invalidation. Neither rejection
        // nor success may replace the carrier's selected root.
        "xor edi, edi",
        "xor esi, esi",
        "mov edx, 4096",
        "call [r12 + {shootdown}]",
        "cmp rax, -{invalid}",
        "jne 2f",
        "xor edi, edi",
        "mov esi, 1",
        "mov rdx, -1",
        "call [r12 + {shootdown}]",
        "cmp rax, -{invalid}",
        "jne 2f",
        "xor edi, edi",
        "xor esi, esi",
        "mov rdx, -1",
        "call [r12 + {shootdown}]",
        "test rax, rax",
        "jnz 2f",
        "mov rax, cr3",
        "cmp rax, r13",
        "jne 2f",
        "inc r14d",
        "cmp r14d, 7",
        "jb 4b",
        "mov byte ptr [rip + KERNELET_TEST_SERVICE_RETURNED], 1",
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
        ".global kernelet_test_idle_service",
        "kernelet_test_idle_service:",
        "cli",
        "sub rsp, 8",
        "mov r12, rdi",
        "mov eax, dword ptr [rsi + {vcpu_records}]",
        "mov dword ptr [rsi + rax + {pending}], 0",
        "mov rdi, -1",
        "call [r12 + {idle}]",
        "mov byte ptr [rip + KERNELET_TEST_SERVICE_RETURNED], 1",
        "ud2",
        ".global kernelet_test_idle_service_end",
        "kernelet_test_idle_service_end:",
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
        shootdown = const core::mem::offset_of!(super::super::abi::ServiceTable, tlb_shootdown),
        mmio = const core::mem::offset_of!(super::super::abi::ServiceTable, mmio_read),
        idle = const core::mem::offset_of!(super::super::abi::ServiceTable, vcpu_idle),
        vcpu_records = const core::mem::offset_of!(BootArgs, vcpu_records),
        pending = const core::mem::offset_of!(VcpuRecord, pending),
        stop = const core::mem::offset_of!(super::super::abi::ServiceTable, stop),
        stop_exit = const super::super::abi::STOP_EXIT,
        invalid = const super::super::abi::INVALID,
        stop_requested = const host_run::STOP_REQUESTED,
        stopped_irq = const STOPPED_IMAGE_IRQ,
        probe_stack = const core::mem::offset_of!(TrapProbeBoot, stack_base),
        probe_state = const core::mem::offset_of!(TrapProbeBoot, stop_state),
        probe_host_root = const core::mem::offset_of!(TrapProbeBoot, host_root),
    );
    unsafe extern "C" {
        fn kernelet_test_exit();
        fn kernelet_test_exit_end();
        fn kernelet_test_initial_root();
        fn kernelet_test_initial_root_end();
        fn kernelet_test_invalid_rsp();
        fn kernelet_test_invalid_rsp_end();
        fn kernelet_test_stack_guard();
        fn kernelet_test_stack_guard_end();
        fn kernelet_test_bounded_service();
        fn kernelet_test_bounded_service_end();
        fn kernelet_test_idle_service();
        fn kernelet_test_idle_service_end();
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
        // Match create's grant-before-identity cleanup on a fixture unwind.
        let control;
        let resources = host_run::ExecutionResources::new(1, 1).unwrap();
        let identity = identity::Registration::new().unwrap();
        let grant = Grant::new(identity.owner(), 1, 1, 1).unwrap();
        let cpu = crate::irq::disable_local().current_cpu();
        control = RunControl::new(
            identity,
            grant.dying_address(),
            Account::new(grant.drain_queue(), KerneletPolicy::default()),
            alloc::vec![cpu],
            resources,
        );
        let mut execution = host_run::ExecutionResources::new(1, 1).unwrap();
        execution.prepare().unwrap();
        // SAFETY: BootArgs contains only integers and integer arrays. Populate
        // the fields read by enter(), with actual live record/fault storage.
        let mut args: BootArgs = unsafe { core::mem::zeroed() };
        args.size = size_of::<BootArgs>() as u32;
        let slot = control.cpu_slot(0);
        args.kernelet = slot.kernelet;
        args.generation = slot.generation;
        args.cpu_slot_gs_offset = super::super::vcpu_slot::gs_offset();
        args.num_vcpus = 1;
        args.vcpu_records = core::mem::offset_of!(TrapProbeBoot, record) as u32;
        let probe = TrapProbeBoot {
            args,
            record: VcpuRecord::default(),
            fault: super::super::abi::CopyFaultRecord::default(),
            stack_base: execution.boot_stack_base(),
            stop_state: core::ptr::addr_of!(control.active) as usize,
            host_root: crate::mm::VmSpace::kernel_root_paddr(),
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
        // These entry/fault fixtures do not block. Retain this CPU so each
        // starts with a live ordinary Host space, including early stop.
        let temporary_space = Arc::new(crate::mm::VmSpace::new());
        let preempt = crate::task::disable_preempt();
        temporary_space.activate();
        assert_ne!(
            crate::arch::mm::current_page_table_paddr(),
            crate::mm::VmSpace::kernel_root_paddr()
        );
        assert_eq!(Arc::strong_count(&temporary_space), 2);
        // SAFETY: The static assembly fixture is RX and its exact instruction
        // range is supplied below. The complete boot arguments, record/fault
        // storage, stacks and grant stay live until the fixed exit returns.
        let result = unsafe {
            host_run::enter(
                entry,
                entry..end,
                entry..end,
                entry,
                entry,
                kernelet_test_exit as *const () as usize,
                (kernelet_test_exit as *const () as usize)
                    ..(kernelet_test_exit_end as *const () as usize),
                0..0,
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
        assert!(
            host_run::test_carrier_context_is_clear(),
            "fixed exit retained a carrier identity"
        );
        // Normal, fault and stopped fixed exits must release the previous
        // native identity. Reactivating that same object must install its root.
        assert_eq!(
            crate::arch::mm::current_page_table_paddr(),
            crate::mm::VmSpace::kernel_root_paddr()
        );
        assert_eq!(Arc::strong_count(&temporary_space), 1);
        temporary_space.activate();
        assert_ne!(
            crate::arch::mm::current_page_table_paddr(),
            crate::mm::VmSpace::kernel_root_paddr()
        );
        assert_eq!(Arc::strong_count(&temporary_space), 2);
        crate::mm::VmSpace::deactivate();
        assert_eq!(Arc::strong_count(&temporary_space), 1);
        drop(preempt);
        if entry == kernelet_test_stopped_irq as *const () as usize {
            // The assembly fixture injects only the active word's stop bit. Complete the
            // lifecycle publication after the fixed exit restored Host state.
            control.stop(ExitReason::Killed(KillReason::Requested));
        }
        assert_eq!(
            control.carriers[0].run_state.load(Ordering::Acquire),
            host_run::LEAVING
        );
        control.detach_carrier();
        assert!(!control.detached.load(Ordering::Acquire));
        control.stop_carriers();
        assert!(control.try_detach());
        assert!(control.detached.load(Ordering::Acquire));
        // SAFETY: The acquire Dying observation follows the once-published reason.
        assert_eq!(control.state(), KerneletState::Dying);
        unsafe { (*control.reason.get()).assume_init_ref() }.clone()
    }

    #[ktest]
    fn invalid_image_rsp_is_contained_by_double_fault_stack() {
        let reason = run_entry_fixture(
            kernelet_test_invalid_rsp as *const () as usize,
            kernelet_test_invalid_rsp_end as *const () as usize,
            false,
        );
        assert!(matches!(
            reason,
            ExitReason::Killed(KillReason::StackOverflow)
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
        irq.on_active(|frame| {
            STOPPED_IMAGE_IRQ_CALLS.fetch_add(1, Ordering::Relaxed);
            // This real carrier already has a stop request, but its IRQ
            // callback is still L1. Only the outer trap return may redirect it.
            let mut during_irq = *frame;
            host_run::finish_image_trap(&mut during_irq);
            assert_eq!(during_irq.rip, frame.rip);
            assert_eq!(during_irq.rsp, frame.rsp);
            assert_eq!(during_irq.rflags, frame.rflags);
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
    fn initial_entry_leaves_the_previous_native_root() {
        let reason = run_entry_fixture(
            kernelet_test_initial_root as *const () as usize,
            kernelet_test_initial_root_end as *const () as usize,
            false,
        );
        assert!(matches!(reason, ExitReason::Exited(42)));
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
            identity::Registration::new().unwrap(),
            0,
            Account::new(Arc::new(WaitQueue::new()), KerneletPolicy::default()),
            alloc::vec![CpuId::bsp()],
            host_run::ExecutionResources::new(4, 1).unwrap(),
        );
        control.stop(ExitReason::Killed(KillReason::Requested));
        assert_eq!(control.state(), KerneletState::Dying);
        assert!(!control.detached.load(Ordering::Acquire));
        control.stop_carriers();
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
        assert!(control.stop_requested());
        assert_eq!(
            control.carriers[0].run_state.load(Ordering::Acquire),
            host_run::DETACHED
        );
    }

    #[ktest]
    fn kill_during_service_prevents_image_return() {
        run_root_probe(false, true);
    }

    #[ktest]
    fn repeated_stop_preserves_first_reason() {
        let control = RunControl::new(
            identity::Registration::new().unwrap(),
            0,
            Account::new(Arc::new(WaitQueue::new()), KerneletPolicy::default()),
            alloc::vec![CpuId::bsp()],
            host_run::ExecutionResources::new(4, 1).unwrap(),
        );
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
            identity::Registration::new().unwrap(),
            0,
            Account::new(Arc::new(WaitQueue::new()), KerneletPolicy::default()),
            alloc::vec![CpuId::bsp()],
            host_run::ExecutionResources::new(1, 1).unwrap(),
        );
        let task = Arc::new(crate::task::TaskOptions::new(|| {}).build().unwrap());
        control.tasks.lock().push(task.clone());
        control.stop(ExitReason::Killed(KillReason::Requested));
        control.stop_carriers();
        assert!(!control.try_detach());
        assert!(!control.detached.load(Ordering::Acquire));
        drop(task);
        assert!(control.try_detach());
        assert_eq!(
            control.carriers[0].run_state.load(Ordering::Acquire),
            host_run::DETACHED
        );
    }

    // ---- Destroy admission drain ----

    /// Adoption belongs to the runner Task, which survives a test unwind.
    struct TestAdoption {
        kernelet: Arc<Kernelet>,
        gate: Option<(Arc<AtomicBool>, Arc<WaitQueue>)>,
    }

    impl TestAdoption {
        fn new(kernelet: &Arc<Kernelet>) -> Self {
            kernelet.adopt_current_task().unwrap();
            Self {
                kernelet: kernelet.clone(),
                gate: None,
            }
        }
    }

    impl Drop for TestAdoption {
        fn drop(&mut self) {
            self.kernelet.disown_current_task();
            if let Some((gate, queue)) = &self.gate {
                gate.store(true, Ordering::Release);
                queue.wake_all();
            }
        }
    }

    /// Builds an instance in the `Created` state with one grant grain, no
    /// carriers and no hooks. Tests drive the lifecycle to `Exited` through
    /// the same stop/detach/reap path the reaper uses.
    fn created_fixture(initial_grains: u32) -> Arc<Kernelet> {
        let image =
            RegisteredImage::register(&super::super::host_image::fixture_image(), [0; 32]).unwrap();
        // Match create's grant-before-identity cleanup on a fixture unwind.
        let control;
        let execution = host_run::ExecutionResources::new(1, 1).unwrap();
        let identity = identity::Registration::new().unwrap();
        let grant = Grant::new(identity.owner(), initial_grains, initial_grains, 1).unwrap();
        let cpu = crate::irq::disable_local().current_cpu();
        control = RunControl::new(
            identity,
            grant.dying_address(),
            Account::new(grant.drain_queue(), KerneletPolicy::default()),
            alloc::vec![cpu],
            execution,
        );
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
        let boot = boot_args(&image, &config, control.cpu_slot(0)).unwrap();
        let instance = image.instantiate(&boot, "", &[], &grant).unwrap();
        grant.bind_lifecycle(control.lifecycle.clone());
        Arc::new(Kernelet {
            memory: grant.guest_memory(),
            resources: SpinLock::new(Some(Arc::new(InstanceResources { instance, grant }))),
            device_lines: Vec::new(),
            control,
        })
    }

    #[ktest]
    fn stats_aggregate_private_carrier_counters() {
        let owner = created_fixture(1);
        let counters = &owner.control.carriers[0].counters;
        assert_eq!((counters as *const CarrierCounters as usize) % 64, 0);
        counters.service_calls.store(17, Ordering::Relaxed);
        counters.mmio_accesses.store(11, Ordering::Relaxed);
        counters.irqs_raised.store(3, Ordering::Relaxed);
        let stats = owner.stats();
        assert_eq!(stats.service_calls, 17);
        assert_eq!(stats.mmio_accesses, 11);
        assert_eq!(stats.irqs_raised, 3);
        drive_to_exited(&owner);
        owner.destroy().unwrap();
    }

    fn drive_to_exited(kernelet: &Kernelet) {
        kernelet.control.active.store(1, Ordering::Release);
        kernelet
            .control
            .stop(ExitReason::Killed(KillReason::Requested));
        kernelet.control.detach_carrier();
        assert!(kernelet.reap_for_test().is_some());
        assert_eq!(kernelet.state(), KerneletState::Exited);
    }

    fn init_test_reaper() {
        // OSTD ktests use the real FIFO scheduler, which accepts bare Tasks.
        // Asterinas supplies its ThreadOptions adapter in endovisor::reaper.
        init_reaper(|body| Ok(Arc::new(crate::task::TaskOptions::new(body).build()?))).unwrap();
        init_reaper(|_| panic!("repeated init must not build another worker")).unwrap();
    }

    struct FailingCarrierHooks {
        retained: SpinLock<Option<(CpuSlot, GuestMemory)>>,
    }

    impl KerneletHooks for FailingCarrierHooks {
        fn realtime_now(&self) -> Duration {
            Duration::ZERO
        }

        fn create_vcpu_thread(
            &self,
            kernelet: &Arc<Kernelet>,
            _: u16,
            _: CpuId,
            _: i8,
        ) -> crate::Result<Arc<Task>> {
            *self.retained.lock() = Some((kernelet.control.cpu_slot(0), kernelet.guest_memory()));
            Err(Error::NoMemory)
        }

        fn mmio_read(&self, device: u16, offset: u32, width: u32) -> MmioResult {
            FaultHooks.mmio_read(device, offset, width)
        }

        fn mmio_write(&self, device: u16, offset: u32, width: u32, value: u64) -> i64 {
            FaultHooks.mmio_write(device, offset, width, value)
        }

        fn log(&self, level: u32, module: &str, text: &str) -> bool {
            FaultHooks.log(level, module, text)
        }

        fn set_vcpu_nice(&self, nice: i8) -> crate::Result<()> {
            FaultHooks.set_vcpu_nice(nice)
        }
    }

    // This fixture uses a valid existing test image and never enters its text.
    // Only the ordinary carrier-factory error and scoped Host pin are exercised.
    struct CreationCleanupProbe {
        events: Arc<WaitQueue>,
        entered: AtomicBool,
        release: AtomicBool,
        finished: AtomicBool,
        injected: AtomicBool,
        creation_finished: AtomicBool,
        no_memory: AtomicBool,
        range_ok: AtomicBool,
        creator_task: AtomicUsize,
        worker_task: AtomicUsize,
        retained: SpinLock<Option<(CpuSlot, GuestMemory, usize)>>,
    }

    impl CreationCleanupProbe {
        fn wait(&self, seconds: u64, condition: impl Fn() -> bool) -> bool {
            let alarm = Deadline::after(Duration::from_secs(seconds), &self.events);
            self.events.wait_until(|| {
                condition()
                    .then_some(true)
                    .or_else(|| alarm.is_expired().then_some(false))
            })
        }
    }

    struct PinnedFactoryFailureHooks(Arc<CreationCleanupProbe>);

    impl KerneletHooks for PinnedFactoryFailureHooks {
        fn realtime_now(&self) -> Duration {
            Duration::ZERO
        }

        fn create_vcpu_thread(
            &self,
            kernelet: &Arc<Kernelet>,
            _: u16,
            _: CpuId,
            _: i8,
        ) -> crate::Result<Arc<Task>> {
            let memory = kernelet.guest_memory();
            // The one-grain grant is aligned; use only its safe membership
            // query to locate it, without inspecting shared-memory pointers.
            let base = (0..crate::mm::frame::max_paddr())
                .step_by(super::super::abi::GRAIN_SIZE)
                .find(|base| memory.contains(*base as u64, 1))
                .ok_or(Error::AccessDenied)?;
            *self.0.retained.lock() = Some((kernelet.control.cpu_slot(0), memory.clone(), base));
            let probe = self.0.clone();
            crate::task::TaskOptions::new(move || {
                probe.worker_task.store(
                    &*Task::current().unwrap() as *const Task as usize,
                    Ordering::Release,
                );
                // Keep only GuestMemory: retaining Kernelet or RunControl
                // would extend the identity lifetime and hide cleanup errors.
                let result = memory.with_range(base as u64, 1, |_reader, _writer| {
                    probe.entered.store(true, Ordering::Release);
                    probe.events.wake_all();
                    // Accessors stay unused: this is a lifecycle check only.
                    probe.wait(10, || probe.release.load(Ordering::Acquire))
                });
                probe
                    .range_ok
                    .store(matches!(result, Ok(true)), Ordering::Release);
                probe.finished.store(true, Ordering::Release);
                probe.events.wake_all();
            })
            .spawn()?;
            if self.0.wait(2, || self.0.entered.load(Ordering::Acquire)) {
                self.0.injected.store(true, Ordering::Release);
                self.0.events.wake_all();
            }
            Err(Error::NoMemory)
        }

        fn mmio_read(&self, device: u16, offset: u32, width: u32) -> MmioResult {
            FaultHooks.mmio_read(device, offset, width)
        }

        fn mmio_write(&self, device: u16, offset: u32, width: u32, value: u64) -> i64 {
            FaultHooks.mmio_write(device, offset, width, value)
        }

        fn log(&self, level: u32, module: &str, text: &str) -> bool {
            FaultHooks.log(level, module, text)
        }

        fn set_vcpu_nice(&self, nice: i8) -> crate::Result<()> {
            FaultHooks.set_vcpu_nice(nice)
        }
    }

    #[ktest]
    fn creation_failure_keeps_identity_until_host_pin_releases_owners() {
        init_test_reaper();
        let kind = KerneletKind {
            image: RegisteredImage::register(&super::super::host_image::fixture_image(), [0; 32])
                .unwrap(),
        };
        let probe = Arc::new(CreationCleanupProbe {
            events: Arc::new(WaitQueue::new()),
            entered: AtomicBool::new(false),
            release: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            injected: AtomicBool::new(false),
            creation_finished: AtomicBool::new(false),
            no_memory: AtomicBool::new(false),
            range_ok: AtomicBool::new(false),
            creator_task: AtomicUsize::new(0),
            worker_task: AtomicUsize::new(0),
            retained: SpinLock::new(None),
        });
        let creator_probe = probe.clone();
        let creator = crate::task::TaskOptions::new(move || {
            creator_probe.creator_task.store(
                &*Task::current().unwrap() as *const Task as usize,
                Ordering::Release,
            );
            let mut cpus = CpuSet::new_empty();
            cpus.add(CpuId::bsp());
            let config = KerneletConfig {
                cmdline: "",
                initial_grains: 1,
                max_grains: 1,
                max_meta_sections: 1,
                budget: CpuBudget::default(),
                policy: KerneletPolicy::default(),
                max_tasks: 1,
                devices: &[],
                cpus,
            };
            let result = kind.create(
                &config,
                Arc::new(PinnedFactoryFailureHooks(creator_probe.clone())),
            );
            creator_probe
                .no_memory
                .store(matches!(result, Err(Error::NoMemory)), Ordering::Release);
            creator_probe
                .creation_finished
                .store(true, Ordering::Release);
            creator_probe.events.wake_all();
        })
        .spawn()
        .unwrap();
        let injected = probe.wait(2, || probe.injected.load(Ordering::Acquire));
        let observed = probe.retained.lock().clone();
        // Also support a cleanup implementation that waits for the Host pin.
        // The alarm bounds this wait if closing admission wakes no observer.
        let rollback_started = probe.wait(2, || {
            probe.creation_finished.load(Ordering::Acquire)
                || observed
                    .as_ref()
                    .is_some_and(|(_, memory, _)| !memory.contains(0, 0))
        });
        let owners = super::super::owner::OwnerTable::shared().unwrap();
        let pin_active = !probe.finished.load(Ordering::Acquire);
        let before = observed.as_ref().map(|(slot, memory, base)| {
            let owner = super::super::owner::KerneletId::from_slot(*slot);
            (
                !memory.contains(0, 0),
                owners.contains(&(*base..*base + 1), owner),
            )
        });
        // No other instance is created in this one-test run. A reservation
        // must not reuse the failed identity while its owner entries remain.
        let during = identity::Registration::new();
        let during_slot = during.as_ref().ok().map(|entry| entry.cpu_slot(0));
        probe.release.store(true, Ordering::Release);
        probe.events.wake_all();
        let finished = probe.wait(2, || probe.finished.load(Ordering::Acquire));
        let creation_finished = probe.wait(2, || probe.creation_finished.load(Ordering::Acquire));
        let after = observed.as_ref().map(|(slot, memory, base)| {
            let owner = super::super::owner::KerneletId::from_slot(*slot);
            (
                !memory.contains(0, 0),
                owners.contains(&(*base..*base + 1), owner),
            )
        });
        // Keep the during-pin reservation held while testing final reuse.
        let next = identity::Registration::new();
        let next_slot = next.as_ref().ok().map(|entry| entry.cpu_slot(0));
        crate::early_println!(
            "creation-cleanup: injected={injected} rollback_started={rollback_started} pin_active={pin_active} before={before:?} during={during_slot:?} finished={finished} creation_finished={creation_finished} after={after:?} next={next_slot:?}",
            injected = injected,
            rollback_started = rollback_started,
            pin_active = pin_active,
            before = before,
            during_slot = during_slot,
            finished = finished,
            creation_finished = creation_finished,
            after = after,
            next_slot = next_slot,
        );
        // Release all gates and local reservations before reporting failures.
        drop(next);
        drop(during);
        drop(creator);
        assert!(injected && rollback_started && pin_active);
        assert!(finished && creation_finished);
        assert!(probe.no_memory.load(Ordering::Acquire));
        assert!(probe.range_ok.load(Ordering::Acquire));
        assert_ne!(
            probe.worker_task.load(Ordering::Acquire),
            probe.creator_task.load(Ordering::Acquire)
        );
        let (failed, _, _) = observed.unwrap();
        assert_eq!(before, Some((true, true)));
        assert_eq!(after, Some((true, false)));
        let during_slot = during_slot.unwrap();
        assert_ne!(
            during_slot.kernelet, failed.kernelet,
            "identity was recycled while its grant still had a legitimate Host pin and owner entry"
        );
        let next_slot = next_slot.unwrap();
        assert_eq!(next_slot.kernelet, failed.kernelet);
        assert_eq!(next_slot.generation, failed.generation + 1);
    }

    #[ktest]
    fn creation_errors_release_owners_and_recycle_identity() {
        init_test_reaper();
        let kind = KerneletKind {
            image: RegisteredImage::register(&super::super::host_image::fixture_image(), [0; 32])
                .unwrap(),
        };
        let mut cpus = CpuSet::new_empty();
        cpus.add(CpuId::bsp());
        // Exercise instantiate's real boot-page size rejection, then an error
        // from the carrier factory after the instance has been assembled.
        for cmdline in ["x".repeat(crate::mm::PAGE_SIZE), String::new()] {
            let reservation = identity::Registration::new().unwrap();
            let previous = reservation.cpu_slot(0);
            drop(reservation);
            let hooks = Arc::new(FailingCarrierHooks {
                retained: SpinLock::new(None),
            });
            let config = KerneletConfig {
                cmdline: &cmdline,
                initial_grains: 1,
                max_grains: 1,
                max_meta_sections: 1,
                budget: CpuBudget::default(),
                policy: KerneletPolicy::default(),
                max_tasks: 1,
                devices: &[],
                cpus: cpus.clone(),
            };
            let expected = if cmdline.is_empty() {
                Error::NoMemory
            } else {
                Error::InvalidArgs
            };
            assert!(matches!(kind.create(&config, hooks.clone()), Err(error) if error == expected));
            let failed_slot = CpuSlot {
                generation: previous.generation + 1,
                ..previous
            };
            let retained = hooks.retained.lock();
            if cmdline.is_empty() {
                let (slot, memory) = retained.as_ref().unwrap();
                assert_eq!(*slot, failed_slot);
                assert!(!memory.contains(0, 0));
            } else {
                assert!(retained.is_none());
            }
            // Keeping the idle capability alive must not keep the identity
            // reserved once the failed instance's grant has been reclaimed.
            let next = identity::Registration::new().unwrap();
            assert_eq!(next.cpu_slot(0).kernelet, previous.kernelet);
            assert_eq!(next.cpu_slot(0).generation, previous.generation + 2);
            let owners = super::super::owner::OwnerTable::shared().unwrap();
            let failed_owner = super::super::owner::KerneletId::from_slot(failed_slot);
            for base in (0..crate::mm::frame::max_paddr()).step_by(super::super::abi::GRAIN_SIZE) {
                assert!(!owners.contains(&(base..base + 1), failed_owner));
            }
        }
    }

    fn wait_for_reaper_flag(flag: &AtomicBool, queue: &Arc<WaitQueue>) {
        let alarm = Deadline::after(Duration::from_secs(2), queue);
        let completed = queue.wait_until(|| {
            flag.load(Ordering::Acquire)
                .then_some(true)
                .or_else(|| alarm.is_expired().then_some(false))
        });
        assert!(
            completed,
            "kernelet reaper did not complete before deadline"
        );
    }

    struct LifecycleProbe {
        carrier: Weak<Task>,
        worker: AtomicUsize,
        dying: AtomicUsize,
        exited: AtomicUsize,
    }

    impl KerneletHooks for LifecycleProbe {
        fn realtime_now(&self) -> Duration {
            FaultHooks.realtime_now()
        }

        fn create_vcpu_thread(
            &self,
            kernelet: &Arc<Kernelet>,
            vcpu: u16,
            cpu: CpuId,
            nice: i8,
        ) -> crate::Result<Arc<Task>> {
            FaultHooks.create_vcpu_thread(kernelet, vcpu, cpu, nice)
        }

        fn mmio_read(&self, device: u16, offset: u32, width: u32) -> MmioResult {
            FaultHooks.mmio_read(device, offset, width)
        }

        fn mmio_write(&self, device: u16, offset: u32, width: u32, value: u64) -> i64 {
            FaultHooks.mmio_write(device, offset, width, value)
        }

        fn log(&self, level: u32, module: &str, text: &str) -> bool {
            FaultHooks.log(level, module, text)
        }

        fn set_vcpu_nice(&self, nice: i8) -> crate::Result<()> {
            FaultHooks.set_vcpu_nice(nice)
        }

        fn on_dying(&self, kernelet: &Kernelet, reason: &ExitReason) {
            assert_eq!(self.dying.fetch_add(1, Ordering::Relaxed), 0);
            assert_eq!(kernelet.state(), KerneletState::Dying);
            assert!(matches!(reason, ExitReason::Killed(KillReason::Requested)));
            assert!(crate::arch::irq::is_local_enabled());
            assert!(crate::irq::InterruptLevel::current().is_task_context());
            assert!(*kernelet.control.reaping.lock());
            let current = Task::current().unwrap();
            self.worker
                .store(&*current as *const Task as usize, Ordering::Release);
        }

        fn on_exited(&self, kernelet: &Kernelet, _: &ExitStatus) {
            assert_eq!(self.dying.load(Ordering::Acquire), 1);
            assert_eq!(self.exited.fetch_add(1, Ordering::Relaxed), 0);
            assert_eq!(kernelet.state(), KerneletState::Exited);
            assert!(self.carrier.upgrade().is_none());
            assert!(kernelet.control.hooks.lock().is_none());
            assert_eq!(
                self.worker.load(Ordering::Acquire),
                &*Task::current().unwrap() as *const Task as usize,
            );
            // Exited callbacks may enter sleeping control paths. This also
            // detects a reaping lock held across callback execution.
            Task::yield_now();
            kernelet.destroy().unwrap();
        }
    }

    #[ktest]
    fn public_kill_and_wait_progress_on_reaper_without_manual_reap() {
        init_test_reaper();
        // The fixture substitutes the image, retaining the actual native Task
        // lifetime, public start/kill/wait path, and production worker loop.
        let kernelet = created_fixture(1);
        let weak = Arc::downgrade(&kernelet);
        let ready = Arc::new(AtomicBool::new(false));
        let ready_queue = Arc::new(WaitQueue::new());
        let task_ready = ready.clone();
        let task_ready_queue = ready_queue.clone();
        let task = Arc::new(
            crate::task::TaskOptions::new(move || {
                let kernelet = weak.upgrade().unwrap();
                task_ready.store(true, Ordering::Release);
                task_ready_queue.wake_all();
                kernelet.control.carriers[0]
                    .wait
                    .wait_until(|| kernelet.control.stop_requested().then_some(()));
                kernelet.control.carriers[0]
                    .run_state
                    .store(host_run::LEAVING, Ordering::Release);
                kernelet.control.detach_carrier();
            })
            .build()
            .unwrap(),
        );
        let hooks = Arc::new(LifecycleProbe {
            carrier: Arc::downgrade(&task),
            worker: AtomicUsize::new(0),
            dying: AtomicUsize::new(0),
            exited: AtomicUsize::new(0),
        });
        let hooks_weak = Arc::downgrade(&hooks);
        kernelet.control.tasks.lock().push(task);
        *kernelet.control.hooks.lock() = Some(hooks.clone());
        reaper::track(&kernelet);
        let observed = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(WaitQueue::new());
        let observer_flag = observed.clone();
        let observer_queue = completed.clone();
        watch_exit(
            kernelet.clone(),
            alloc::boxed::Box::new(move |status| {
                assert!(matches!(
                    status.reason,
                    ExitReason::Killed(KillReason::Requested)
                ));
                observer_flag.store(true, Ordering::Release);
                observer_queue.wake_all();
            }),
        )
        .unwrap();
        kernelet.start().unwrap();
        wait_for_reaper_flag(&ready, &ready_queue);
        kernelet.kill(KillReason::Requested).unwrap();
        assert!(
            kernelet
                .wait_exited_timeout(Duration::from_secs(2))
                .is_some()
        );
        wait_for_reaper_flag(&observed, &completed);
        assert_eq!(hooks.dying.load(Ordering::Acquire), 1);
        assert_eq!(hooks.exited.load(Ordering::Acquire), 1);
        assert_eq!(kernelet.state(), KerneletState::Destroyed);
        drop(hooks);
        assert!(hooks_weak.upgrade().is_none());
    }

    #[ktest]
    fn reaper_retries_zombie_after_host_gate_and_adoption_release() {
        init_test_reaper();
        let kernelet = created_fixture(1);
        let mut adoption = TestAdoption::new(&kernelet);
        kernelet.kill(KillReason::Requested).unwrap();
        assert!(matches!(
            kernelet.destroy(),
            Err(DestroyError::Zombie { .. })
        ));
        let gate = Arc::new(AtomicBool::new(false));
        let gate_queue = Arc::new(WaitQueue::new());
        adoption.gate = Some((gate.clone(), gate_queue.clone()));
        let completed = Arc::new(WaitQueue::new());
        let finished = Arc::new(AtomicBool::new(false));
        let prepared = Arc::new(AtomicBool::new(false));
        let callback_prepared = prepared.clone();
        let prepare_completed = completed.clone();
        let callback_gate = gate.clone();
        let callback_queue = gate_queue.clone();
        let callback_finished = finished.clone();
        let callback_completed = completed.clone();
        enqueue_reclaim(
            kernelet.clone(),
            ReclaimCallbacks {
                prepare: Some(alloc::boxed::Box::new(move || {
                    callback_prepared.store(true, Ordering::Release);
                    prepare_completed.wake_all();
                })),
                ready: alloc::boxed::Box::new(move |waker| {
                    callback_queue.enqueue_once(waker.clone());
                    callback_gate.load(Ordering::Acquire)
                }),
                complete: Some(alloc::boxed::Box::new(move || {
                    callback_finished.store(true, Ordering::Release);
                    callback_completed.wake_all();
                })),
            },
        )
        .unwrap();
        wait_for_reaper_flag(&prepared, &completed);
        assert_eq!(kernelet.state(), KerneletState::Exited);
        drop(adoption);
        wait_for_reaper_flag(&finished, &completed);
        assert_eq!(kernelet.state(), KerneletState::Destroyed);
    }

    #[ktest]
    fn reaper_registration_does_not_retain_abandoned_created_instance() {
        init_test_reaper();
        let kernelet = created_fixture(1);
        let weak = Arc::downgrade(&kernelet);
        reaper::track(&kernelet);
        drop(kernelet);
        assert!(weak.upgrade().is_none());
    }

    #[ktest]
    fn kill_created_retires_dormant_tasks_inline() {
        let kernelet = created_fixture(1);
        let ran = Arc::new(AtomicBool::new(false));
        let task_ran = ran.clone();
        let task = Arc::new(
            crate::task::TaskOptions::new(move || {
                task_ran.store(true, Ordering::Release);
            })
            .build()
            .unwrap(),
        );
        let retired = Arc::downgrade(&task);
        kernelet.control.tasks.lock().push(task);
        // A start already admitted before kill must still recheck Created
        // under the transition lock before it may borrow a dormant Task.
        let admitted_start = kernelet
            .control
            .admit_operation(&[KerneletState::Created])
            .unwrap();

        kernelet.kill(KillReason::Requested).unwrap();
        assert_eq!(kernelet.state(), KerneletState::Exited);
        assert!(retired.upgrade().is_none());
        assert!(kernelet.control.detached.load(Ordering::Acquire));
        assert!(!ran.load(Ordering::Acquire));
        assert!(matches!(
            kernelet.exit_status().unwrap().reason,
            ExitReason::Killed(KillReason::Requested)
        ));
        assert!(matches!(kernelet.start(), Err(Error::AccessDenied)));
        drop(admitted_start);
        kernelet.destroy().unwrap();
    }

    #[ktest]
    fn kill_created_preserves_retirement_of_retained_native_task() {
        let kernelet = created_fixture(1);
        let task = Arc::new(crate::task::TaskOptions::new(|| {}).build().unwrap());
        kernelet.control.tasks.lock().push(task.clone());

        kernelet.kill(KillReason::Requested).unwrap();
        assert_eq!(kernelet.state(), KerneletState::Dying);
        assert!(!kernelet.control.detached.load(Ordering::Acquire));
        assert!(kernelet.reap_for_test().is_none());
        assert!(matches!(
            kernelet.destroy(),
            Err(DestroyError::NotExited(KerneletState::Dying))
        ));
        drop(task);
        assert!(kernelet.reap_for_test().is_some());
        assert_eq!(kernelet.state(), KerneletState::Exited);
        kernelet.destroy().unwrap();
    }

    #[ktest]
    fn destroy_recycles_identity_while_old_handle_remains_live() {
        let old = created_fixture(1);
        let stale = old.control.cpu_slot(0);
        assert!(RunControl::lookup_cpu_slot(stale, &old.control).is_some());
        drive_to_exited(&old);
        old.destroy().unwrap();
        assert!(RunControl::lookup_cpu_slot(stale, &old.control).is_none());

        let new = created_fixture(1);
        let current = new.control.cpu_slot(0);
        assert_eq!(current.kernelet, stale.kernelet);
        assert_eq!(current.generation, stale.generation + 1);
        assert!(RunControl::lookup_cpu_slot(stale, &new.control).is_none());
        assert!(RunControl::lookup_cpu_slot(current, &new.control).is_some());
        assert!(RunControl::lookup_cpu_slot(current, &old.control).is_none());
        drive_to_exited(&new);
        new.destroy().unwrap();
    }

    #[ktest]
    fn kill_notifies_reaper_before_carrier_wakeup() {
        let kernelet = created_fixture(1);
        kernelet
            .control
            .lifecycle
            .store(KerneletState::Running as u8, Ordering::Release);
        let (_exit_waiter, exit_waker) = crate::sync::Waiter::new_pair();
        kernelet.exit_wait_queue().enqueue(exit_waker.clone());
        let (_carrier_waiter, carrier_waker) = crate::sync::Waiter::new_pair();
        kernelet.control.carriers[0]
            .wait
            .enqueue(carrier_waker.clone());

        {
            let _irq_guard = crate::irq::disable_local();
            kernelet.kill(KillReason::Requested).unwrap();
            assert_eq!(kernelet.state(), KerneletState::Dying);
            assert!(kernelet.control.stop_requested());
            assert!(take_reaper_notification());
            assert!(!take_reaper_notification());
            assert!(exit_waker.wake_up(), "mark must defer exit-queue wakeup");
            assert!(carrier_waker.wake_up(), "mark must defer carrier wakeup");
        }

        let (_exit_waiter, exit_waker) = crate::sync::Waiter::new_pair();
        kernelet.exit_wait_queue().enqueue(exit_waker.clone());
        let (_carrier_waiter, carrier_waker) = crate::sync::Waiter::new_pair();
        kernelet.control.carriers[0]
            .wait
            .enqueue(carrier_waker.clone());
        let status = kernelet.reap_for_test().unwrap();
        assert!(matches!(
            status.reason,
            ExitReason::Killed(KillReason::Requested)
        ));
        assert_eq!(kernelet.state(), KerneletState::Exited);
        assert!(!exit_waker.wake_up(), "reap must publish and wake exit");
        assert!(!carrier_waker.wake_up(), "reap must wake the carrier");
        kernelet.destroy().unwrap();
    }

    fn reaper_releases_blocked_carrier() {
        let kernelet = created_fixture(1);
        kernelet.control.active.store(1, Ordering::Release);
        kernelet
            .control
            .lifecycle
            .store(KerneletState::Running as u8, Ordering::Release);
        let started = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let worker_kernelet = kernelet.clone();
        let worker_started = started.clone();
        let worker_finished = finished.clone();
        let task = Arc::new(
            crate::task::TaskOptions::new(move || {
                let control = &worker_kernelet.control;
                let stopped = || control.stop_requested();
                worker_started.store(true, Ordering::Release);
                control.carriers[0]
                    .wait
                    .wait_until(|| stopped().then_some(()));
                worker_finished.store(true, Ordering::Release);
                control.carriers[0]
                    .run_state
                    .store(host_run::LEAVING, Ordering::Release);
                control.detach_carrier();
            })
            .data(())
            .build()
            .unwrap(),
        );
        kernelet.control.tasks.lock().push(task.clone());
        task.run();
        // The OSTD FIFO scheduler clears this CPU tag when a Task parks.
        // Wait for that transition so the test exercises a registered,
        // blocked waiter rather than stopping before it enters the wait.
        while !started.load(Ordering::Acquire) || task.schedule_info().cpu.get().is_some() {
            Task::yield_now();
        }
        drop(task);

        kernelet.kill(KillReason::Requested).unwrap();
        kernelet.kill(KillReason::EntryFailed).unwrap();
        assert_eq!(kernelet.state(), KerneletState::Dying);
        assert!(!finished.load(Ordering::Acquire));
        let status = loop {
            if let Some(status) = kernelet.reap_for_test() {
                break status;
            }
            Task::yield_now();
        };
        assert!(finished.load(Ordering::Acquire));
        assert!(matches!(
            status.reason,
            ExitReason::Killed(KillReason::Requested)
        ));
        assert_eq!(kernelet.state(), KerneletState::Exited);
        kernelet.destroy().unwrap();
    }

    #[ktest]
    fn reaper_releases_idle_carrier() {
        reaper_releases_blocked_carrier();
    }

    #[ktest]
    fn destroy_waits_for_service_and_native_task_retirement_without_operation_guard() {
        let kernelet = created_fixture(1);
        let resources = kernelet.resources.lock().as_ref().unwrap().clone();
        let mut execution = host_run::ExecutionResources::new(1, 1).unwrap();
        execution.prepare().unwrap();
        let execution = Arc::new(execution);
        let old_execution = kernelet.control.execution.lock().replace(execution.clone());
        // The old stack arena synchronously retires its virtual reservation.
        // Drop it only after releasing the IRQ-disabling execution lock.
        drop(old_execution);
        let resources_weak = Arc::downgrade(&resources);
        let execution_weak = Arc::downgrade(&execution);
        let hooks = Arc::new(FaultHooks);
        let hooks_weak = Arc::downgrade(&hooks);
        KERNELET_TEST_SERVICE_RETURNED.store(false, Ordering::Release);
        kernelet.control.active.store(1, Ordering::Release);
        kernelet
            .control
            .lifecycle
            .store(KerneletState::Running as u8, Ordering::Release);
        kernelet.control.carriers[0]
            .run_state
            .store(host_run::STARTING, Ordering::Release);
        let finished = Arc::new(AtomicBool::new(false));
        let worker_finished = finished.clone();
        let worker_kernelet = kernelet.clone();
        let worker_resources = resources.clone();
        let worker_execution = execution.clone();
        let worker_hooks = hooks.clone();
        let task = Arc::new(
            crate::task::TaskOptions::new(move || {
                let entry = kernelet_test_idle_service as *const () as usize;
                let end = kernelet_test_idle_service_end as *const () as usize;
                // SAFETY: The actual service caller, image records and shared
                // stacks remain pinned by this closure's Arcs through fixed
                // exit. The native Task is registered below before enqueue.
                let result = unsafe {
                    host_run::enter(
                        entry,
                        entry..end,
                        entry..end,
                        entry,
                        entry,
                        kernelet_test_exit as *const () as usize,
                        (kernelet_test_exit as *const () as usize)
                            ..(kernelet_test_exit_end as *const () as usize),
                        0..0,
                        0..0,
                        worker_resources.instance.boot_args_address() as *const BootArgs,
                        worker_resources.instance.vcpu_record_address() as *const VcpuRecord,
                        worker_resources.grant.guest_memory(),
                        worker_kernelet.control.carriers[0].wait.clone(),
                        worker_hooks,
                        &worker_kernelet.control,
                        &worker_resources.grant,
                        &worker_execution,
                        0,
                    )
                }
                .unwrap();
                assert!(
                    host_run::test_carrier_context_is_clear(),
                    "carrier exit retained CPU-local state"
                );
                assert_eq!(result, (-super::super::abi::STATE) as u32);
                worker_kernelet.control.detach_carrier();
                worker_finished.store(true, Ordering::Release);
            })
            .data(())
            .build()
            .unwrap(),
        );
        let task_weak = Arc::downgrade(&task);
        kernelet.control.tasks.lock().push(task.clone());
        task.run();
        while task.schedule_info().cpu.get().is_some() {
            assert!(!finished.load(Ordering::Acquire));
            Task::yield_now();
        }
        assert!(!finished.load(Ordering::Acquire));
        // The real idle service is suspended with no external operation
        // admission. Stop and destroy must still retain its live frames.
        assert!(
            host_run::test_carrier_context_is_clear(),
            "native Task inherited the parked carrier identity"
        );
        assert_eq!(kernelet.control.admitted.load(Ordering::Acquire), 0);
        assert_eq!(kernelet.control.active.load(Ordering::Acquire), 1);
        assert!(matches!(
            kernelet.destroy(),
            Err(DestroyError::NotExited(KerneletState::Running))
        ));
        kernelet.kill(KillReason::Requested).unwrap();
        assert!(kernelet.reap_for_test().is_none());
        assert!(matches!(
            kernelet.destroy(),
            Err(DestroyError::NotExited(KerneletState::Dying))
        ));
        while !finished.load(Ordering::Acquire) {
            Task::yield_now();
        }
        assert!(!KERNELET_TEST_SERVICE_RETURNED.load(Ordering::Acquire));
        assert_eq!(kernelet.control.admitted.load(Ordering::Acquire), 0);
        assert_eq!(
            kernelet.control.active.load(Ordering::Acquire),
            host_run::STOP_REQUESTED
        );
        // Even after fixed exit and reservation release, the externally held
        // native Task must retire before Exited permits reclamation.
        assert!(task_weak.upgrade().is_some());
        assert!(kernelet.reap_for_test().is_none());
        assert!(matches!(
            kernelet.destroy(),
            Err(DestroyError::NotExited(KerneletState::Dying))
        ));
        drop(task);
        let status = loop {
            if let Some(status) = kernelet.reap_for_test() {
                break status;
            }
            Task::yield_now();
        };
        assert!(matches!(
            status.reason,
            ExitReason::Killed(KillReason::Requested)
        ));
        assert!(task_weak.upgrade().is_none());
        drop((resources, execution, hooks));
        assert!(hooks_weak.upgrade().is_none());
        kernelet.destroy().unwrap();
        assert!(resources_weak.upgrade().is_none());
        assert!(execution_weak.upgrade().is_none());
    }

    struct RootProbeHooks {
        kernelet: Arc<Kernelet>,
        roots: [usize; 2],
        host_root: usize,
        execution: Arc<host_run::ExecutionResources>,
        calls: AtomicUsize,
        panic_in_hook: bool,
        stop_in_hook: bool,
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
        fn mmio_read(&self, stage: u16, _: u32, _: u32) -> MmioResult {
            let stage = usize::from(stage);
            assert!(stage < KERNELET_TEST_ROOTS.len());
            let [root_a, root_b] = self.roots;
            let expected_root = match stage {
                1 => root_b,
                5 => self.host_root,
                _ => root_a,
            };
            {
                let _irq_guard = crate::irq::disable_local();
                assert_eq!(
                    super::super::vcpu_slot::current(),
                    self.kernelet.control.cpu_slot(0)
                );
                let cpu = _irq_guard.current_cpu();
                assert_eq!(crate::arch::mm::current_page_table_paddr(), expected_root);
                for root in self.roots {
                    assert_eq!(
                        self.execution.test_root_is_active(root as u64, cpu),
                        root == expected_root
                    );
                }
                if stage != 5 {
                    let expected_previous = match stage {
                        0 | 6 => self.host_root,
                        2 => root_b,
                        _ => root_a,
                    };
                    // The direct-commit probe survives unrelated carrier
                    // restoration and checks the actual CR3 before its write.
                    assert_eq!(
                        self.execution
                            .test_root_last_direct_activation_from(expected_root as u64),
                        Some(expected_previous)
                    );
                }
                assert_eq!(
                    self.kernelet.control.carriers[0]
                        .active_root
                        .load(Ordering::Acquire),
                    if stage == 5 { 0 } else { expected_root as u64 }
                );
            }
            assert_eq!(self.kernelet.control.admitted.load(Ordering::Acquire), 0);
            self.kernelet.charge_host_bytes(8).unwrap();
            self.kernelet.uncharge_host_bytes(8);
            assert_eq!(self.kernelet.control.admitted.load(Ordering::Acquire), 0);
            assert_eq!(self.calls.fetch_add(1, Ordering::Relaxed), stage);
            if self.stop_in_hook && stage == 6 {
                self.kernelet
                    .control
                    .stop(ExitReason::Killed(KillReason::Requested));
                // Stop must not overwrite the phase while this Host callback
                // still owns service state. The fixed epilogue stops it later.
                assert_eq!(
                    self.kernelet.control.carriers[0]
                        .run_state
                        .load(Ordering::Acquire),
                    host_run::SERVICE
                );
            }
            if self.panic_in_hook && stage == 6 {
                let _nested = self
                    .kernelet
                    .control
                    .admit_operation(&[KerneletState::Running])
                    .unwrap();
                assert_eq!(self.kernelet.control.admitted.load(Ordering::Acquire), 1);
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
    fn bounded_service_preserves_root_and_carrier_owners() {
        run_root_probe(false, false);
    }

    #[ktest]
    fn hook_unwind_drains_external_admission_and_carrier_owners() {
        run_root_probe(true, false);
    }

    fn run_root_probe(panic_in_hook: bool, stop_in_hook: bool) {
        use crate::mm::{FrameAllocOptions, VmIo};
        let kernelet = created_fixture(1);
        let resources = kernelet.resources.lock().as_ref().unwrap().clone();
        let native_root = crate::arch::mm::current_page_table_paddr();
        let root = FrameAllocOptions::new().alloc_frame().unwrap();
        let second_root = FrameAllocOptions::new().alloc_frame().unwrap();
        // SAFETY: The current root is live and linearly mapped. The fixture
        // retains both this copy and every shared kernel mapping through exit.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                crate::mm::kspace::paddr_to_vaddr(native_root) as *const u8,
                PAGE_SIZE,
            )
        };
        root.write_bytes(0, bytes).unwrap();
        second_root.write_bytes(0, bytes).unwrap();
        for (request, value) in KERNELET_TEST_ROOTS.iter().zip([
            root.paddr(),
            second_root.paddr(),
            root.paddr(),
            root.paddr(),
            1,
            0,
            root.paddr(),
        ]) {
            request.store(value as u64, Ordering::Release);
        }
        KERNELET_TEST_SERVICE_RETURNED.store(false, Ordering::Release);
        let mut execution = host_run::ExecutionResources::new(2, 1).unwrap();
        execution.prepare().unwrap();
        execution.register_test_root(root.paddr() as u64);
        execution.register_test_root(second_root.paddr() as u64);
        let execution = Arc::new(execution);
        let hooks = Arc::new(RootProbeHooks {
            kernelet: kernelet.clone(),
            roots: [root.paddr(), second_root.paddr()],
            host_root: crate::mm::VmSpace::kernel_root_paddr(),
            execution: execution.clone(),
            calls: AtomicUsize::new(0),
            panic_in_hook,
            stop_in_hook,
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
        // this test exercises activation/crossing, not registration validation
        // or actual root-frame reclamation: both copied frames remain owned here.
        let result = unsafe {
            host_run::enter(
                entry,
                entry..end,
                entry..end,
                entry,
                entry,
                kernelet_test_exit as *const () as usize,
                (kernelet_test_exit as *const () as usize)
                    ..(kernelet_test_exit_end as *const () as usize),
                0..0,
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
        assert_eq!(
            result,
            if panic_in_hook || stop_in_hook {
                (-5i32) as u32
            } else {
                42
            }
        );
        assert!(
            host_run::test_carrier_context_is_clear(),
            "service exit retained CPU-local carrier state"
        );
        assert_eq!(
            KERNELET_TEST_SERVICE_RETURNED.load(Ordering::Acquire),
            !panic_in_hook && !stop_in_hook
        );
        assert_eq!(
            hooks.calls.load(Ordering::Acquire),
            KERNELET_TEST_ROOTS.len()
        );
        assert_eq!(kernelet.control.admitted.load(Ordering::Acquire), 0);
        assert_eq!(Arc::strong_count(&hooks), 1);
        assert_eq!(Arc::strong_count(&execution), 2);
        assert_eq!(Arc::strong_count(&resources), 2);
        assert_eq!(crate::arch::mm::current_page_table_paddr(), native_root);
        kernelet.control.detach_carrier();
        let status = kernelet.reap_for_test().unwrap();
        if panic_in_hook {
            assert!(matches!(
                status.reason,
                ExitReason::Killed(KillReason::HostHookPanicked)
            ));
        } else if stop_in_hook {
            assert!(matches!(
                status.reason,
                ExitReason::Killed(KillReason::Requested)
            ));
        } else {
            assert!(matches!(status.reason, ExitReason::Exited(42)));
        }
        {
            let irq_guard = crate::irq::disable_local();
            for root in hooks.roots {
                assert!(!execution.test_root_is_active(root as u64, irq_guard.current_cpu()));
            }
        }
        drop((execution, hooks, resources, root, second_root));
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
        let adoption = TestAdoption::new(&kernelet);
        drive_to_exited(&kernelet);

        assert!(matches!(
            kernelet.destroy(),
            Err(DestroyError::Zombie {
                pins: 0,
                adopted: 1
            })
        ));
        assert_eq!(kernelet.state(), KerneletState::Exited);
        drop(adoption);
        let report = kernelet.destroy().unwrap();
        assert_eq!(report.grains_released, 1);
        assert_eq!(kernelet.state(), KerneletState::Destroyed);
    }

    #[ktest]
    fn adopted_worker_exit_releases_ownership_before_task_drop() {
        let kernelet = created_fixture(1);
        let runner_kernelet = created_fixture(1);
        let ready = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let events = Arc::new(WaitQueue::new());
        let mut runner_adoption = TestAdoption::new(&runner_kernelet);
        // An assertion unwind must also let the worker finish.
        runner_adoption.gate = Some((release.clone(), events.clone()));

        let worker_kernelet = kernelet.clone();
        let worker_ready = ready.clone();
        let worker_release = release.clone();
        let worker_events = events.clone();
        let worker = crate::task::TaskOptions::new(move || {
            worker_kernelet.adopt_current_task().unwrap();
            worker_ready.store(true, Ordering::Release);
            worker_events.wake_all();
            worker_events.wait_until(|| worker_release.load(Ordering::Acquire).then_some(()));
            // Deliberately leave adoption to the normal Task exit cleanup.
        })
        .data(())
        .spawn()
        .unwrap();

        events.wait_until(|| ready.load(Ordering::Acquire).then_some(()));
        drive_to_exited(&kernelet);
        assert!(matches!(
            kernelet.destroy(),
            Err(DestroyError::Zombie {
                pins: 0,
                adopted: 1
            })
        ));
        assert_eq!(
            runner_kernelet
                .control
                .account
                .adopted
                .load(Ordering::Acquire),
            1
        );

        release.store(true, Ordering::Release);
        events.wake_all();
        kernelet.control.account.drained.wait_until(|| {
            (kernelet.control.account.adopted.load(Ordering::Acquire) == 0).then_some(())
        });
        // Retaining the Task Arc proves this was exit cleanup, not Task Drop.
        let report = kernelet.destroy().unwrap();
        assert_eq!(report.grains_released, 1);
        assert_eq!(kernelet.state(), KerneletState::Destroyed);
        assert_eq!(
            runner_kernelet
                .control
                .account
                .adopted
                .load(Ordering::Acquire),
            1
        );
        drop(worker);

        drop(runner_adoption);
        assert_eq!(
            runner_kernelet
                .control
                .account
                .adopted
                .load(Ordering::Acquire),
            0
        );
        drive_to_exited(&runner_kernelet);
        runner_kernelet.destroy().unwrap();
    }

    #[ktest]
    fn failed_test_scope_releases_adoption_and_reaper_gate() {
        let kernelet = created_fixture(1);
        let gate = Arc::new(AtomicBool::new(false));
        let queue = Arc::new(WaitQueue::new());
        let result = crate::panic::catch_unwind(|| {
            let mut adoption = TestAdoption::new(&kernelet);
            adoption.gate = Some((gate.clone(), queue.clone()));
            panic!("adoption cleanup probe");
        });
        assert!(result.is_err());
        assert!(gate.load(Ordering::Acquire));
        assert_eq!(kernelet.control.account.adopted.load(Ordering::Acquire), 0);
        // The runner Task must remain available to a following test.
        drop(TestAdoption::new(&kernelet));
        drive_to_exited(&kernelet);
        kernelet.destroy().unwrap();
    }

    #[ktest]
    fn host_buffer_split_refunds_both_owner_drop_orders() {
        const TOTAL: usize = 512 * 1024;
        const NATIVE: usize = 288 * 1024;

        for native_first in [false, true] {
            let kernelet = created_fixture(1);
            let counter = kernelet.control.account.host_bytes.clone();
            let mut frontend = kernelet.reserve_host_bytes(TOTAL).unwrap();
            let native = frontend.split_off(NATIVE).unwrap();
            assert_eq!(counter.load(Ordering::Acquire), TOTAL);

            if native_first {
                drop(native);
                assert_eq!(counter.load(Ordering::Acquire), TOTAL - NATIVE);
                drop(frontend);
            } else {
                drop(frontend);
                assert_eq!(counter.load(Ordering::Acquire), NATIVE);
                drop(native);
            }
            assert_eq!(counter.load(Ordering::Acquire), 0);
            drive_to_exited(&kernelet);
            kernelet.destroy().unwrap();
        }
    }

    #[ktest]
    fn host_buffer_invalid_and_full_splits_preserve_accounting() {
        const TOTAL: usize = 512 * 1024;

        let kernelet = created_fixture(1);
        let counter = kernelet.control.account.host_bytes.clone();
        let mut frontend = kernelet.reserve_host_bytes(TOTAL).unwrap();
        assert!(frontend.split_off(0).is_none());
        assert!(frontend.split_off(TOTAL + 1).is_none());
        assert_eq!(counter.load(Ordering::Acquire), TOTAL);

        let all_bytes = frontend.split_off(TOTAL).unwrap();
        drop(frontend);
        assert_eq!(counter.load(Ordering::Acquire), TOTAL);
        drop(all_bytes);
        assert_eq!(counter.load(Ordering::Acquire), 0);
        drive_to_exited(&kernelet);
        kernelet.destroy().unwrap();
    }

    #[ktest]
    fn host_buffer_charge_refunds_after_instance_and_account_drop() {
        const TOTAL: usize = 512 * 1024;

        let kernelet = created_fixture(1);
        let instance = Arc::downgrade(&kernelet);
        let account = Arc::downgrade(&kernelet.control.account);
        let counter = kernelet.control.account.host_bytes.clone();
        let counter_weak = Arc::downgrade(&counter);
        let charge = kernelet.reserve_host_bytes(TOTAL).unwrap();

        drive_to_exited(&kernelet);
        kernelet.destroy().unwrap();
        assert_eq!(kernelet.state(), KerneletState::Destroyed);
        assert_eq!(counter.load(Ordering::Acquire), TOTAL);
        drop(kernelet);
        assert!(instance.upgrade().is_none());
        assert!(account.upgrade().is_none());
        assert_eq!(counter.load(Ordering::Acquire), TOTAL);

        drop(charge);
        assert_eq!(counter.load(Ordering::Acquire), 0);
        drop(counter);
        assert!(counter_weak.upgrade().is_none());
    }
}
