// SPDX-License-Identifier: MPL-2.0

#[cfg(feature = "kernelet-host")]
use core::num::NonZeroU16;

use ostd::{
    cpu::CpuSet,
    mm::VmSpace,
    task::{Task, TaskOptions},
};

use super::{AsThread, Thread, oops};
use crate::{
    prelude::*,
    sched::{Nice, SchedPolicy},
    vm::vmar::Vmar,
};

/// The inner data of a kernel thread.
pub(super) struct KernelThread {
    address_space: AddressSpace,
}

/// A process mapping owner or carrier restoration state, never both.
enum AddressSpace {
    None,
    Process(Arc<Vmar>),
    #[cfg(feature = "kernelet-host")]
    Carrier(Arc<VmSpace>),
}

impl KernelThread {
    /// Returns the VMAR associated with the kernel thread.
    pub(super) fn vmar(&self) -> Option<&Arc<Vmar>> {
        match &self.address_space {
            AddressSpace::Process(vmar) => Some(vmar),
            _ => None,
        }
    }

    /// Returns the address space to activate when this thread is scheduled.
    pub(super) fn vm_space(&self) -> Option<&Arc<VmSpace>> {
        match &self.address_space {
            AddressSpace::None => None,
            AddressSpace::Process(vmar) => Some(vmar.vm_space()),
            #[cfg(feature = "kernelet-host")]
            AddressSpace::Carrier(space) => Some(space),
        }
    }
}

/// A trait to provide the `as_kernel_thread` method for tasks and threads.
pub(super) trait AsKernelThread {
    /// Returns the associated [`KernelThread`].
    fn as_kernel_thread(&self) -> Option<&KernelThread>;
}

impl AsKernelThread for Thread {
    fn as_kernel_thread(&self) -> Option<&KernelThread> {
        self.data().downcast_ref::<KernelThread>()
    }
}

impl AsKernelThread for Task {
    fn as_kernel_thread(&self) -> Option<&KernelThread> {
        self.as_thread()?.as_kernel_thread()
    }
}

/// Options to create or spawn a new kernel thread.
pub(crate) struct ThreadOptions {
    func: Option<Box<dyn FnOnce() + Send>>,
    cpu_affinity: CpuSet,
    sched_policy: SchedPolicy,
    #[cfg(feature = "kernelet-host")]
    fair_weight_divisor: NonZeroU16,
    address_space: AddressSpace,
}

impl ThreadOptions {
    /// Creates the thread options with the thread function.
    pub(crate) fn new<F>(func: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        let cpu_affinity = CpuSet::new_full();
        let sched_policy = SchedPolicy::Fair(Nice::default());
        Self {
            func: Some(Box::new(func)),
            cpu_affinity,
            sched_policy,
            #[cfg(feature = "kernelet-host")]
            fair_weight_divisor: NonZeroU16::MIN,
            address_space: AddressSpace::None,
        }
    }

    /// Sets the CPU affinity of the new thread.
    pub(crate) fn cpu_affinity(mut self, cpu_affinity: CpuSet) -> Self {
        self.cpu_affinity = cpu_affinity;
        self
    }

    /// Sets the scheduling policy.
    pub(crate) fn sched_policy(mut self, sched_policy: SchedPolicy) -> Self {
        self.sched_policy = sched_policy;
        self
    }

    /// Associates a VMAR with the kernel thread.
    ///
    /// The VMAR is activated whenever the thread is scheduled, allowing fallible userspace memory
    /// operations to access it directly and handle page faults against it. The association cannot
    /// be changed after the thread is built.
    ///
    /// The `Arc` keeps the VMAR object alive, but does not prevent its mappings from being cleared
    /// after the last [`VmarHandle`](crate::vm::vmar::VmarHandle) is dropped. A caller that needs
    /// the mappings to outlive their userspace owner must hold a separate owner-memory lease.
    #[cfg_attr(all(not(ktest), not(feature = "kernelet-host")), expect(dead_code))]
    pub(crate) fn vmar(mut self, vmar: Arc<Vmar>) -> Self {
        self.address_space = AddressSpace::Process(vmar);
        self
    }

    /// Associates a carrier's page-table restoration state with this thread.
    ///
    /// This does not supply a Host process VMAR for resolving page faults.
    /// Activation still validates the registered root through `VmSpace`.
    #[cfg(feature = "kernelet-host")]
    pub(crate) fn carrier_vm_space(mut self, vm_space: Arc<VmSpace>) -> Self {
        self.address_space = AddressSpace::Carrier(vm_space);
        self
    }

    /// Divides this Host carrier thread scheduling weight.
    #[cfg(feature = "kernelet-host")]
    pub(crate) fn fair_weight_divisor(mut self, divisor: NonZeroU16) -> Self {
        self.fair_weight_divisor = divisor;
        self
    }
}

impl ThreadOptions {
    /// Builds a new kernel thread without running it immediately.
    pub(crate) fn build(mut self) -> Arc<Task> {
        let task_fn = self.func.take().unwrap();
        let thread_fn = move || {
            let _ = oops::catch_panics_as_oops(task_fn);
            // Ensure that the thread exits.
            current_thread!().exit();
        };

        Arc::new_cyclic(|weak_task| {
            let thread = {
                let kernel_thread = KernelThread {
                    address_space: self.address_space,
                };
                let cpu_affinity = self.cpu_affinity;
                let sched_policy = self.sched_policy;
                let thread =
                    Thread::new(weak_task.clone(), kernel_thread, cpu_affinity, sched_policy);
                #[cfg(feature = "kernelet-host")]
                let thread = {
                    let mut thread = thread;
                    if self.fair_weight_divisor != NonZeroU16::MIN {
                        thread.sched_attr = thread
                            .sched_attr
                            .with_fair_weight_divisor(self.fair_weight_divisor);
                    }
                    thread
                };
                Arc::new(thread)
            };

            TaskOptions::new(thread_fn).data(thread).build().unwrap()
        })
    }

    /// Builds a new kernel thread and runs it immediately.
    #[track_caller]
    pub(crate) fn spawn(self) -> Arc<Thread> {
        let task = self.build();
        let thread = task.as_thread().unwrap().clone();
        thread.run();
        thread
    }
}

#[cfg(ktest)]
mod tests {
    use ostd::{Error, cpu::CpuId, prelude::ktest};

    use super::*;
    use crate::{
        fs::pseudofs::SockFs,
        process::ProcessVm,
        vm::{
            page_cache::VmoOptions,
            perms::VmPerms,
            vmar::{VmarHandle, VmarMapOffset},
        },
    };

    fn new_process_vm() -> ProcessVm {
        crate::time::clocks::init_for_ktest();
        crate::util::random::init();
        ProcessVm::new(SockFs::new_path())
    }

    #[ktest]
    fn associated_vmar_is_reactivated_after_context_switch() {
        super::super::init();

        let vmar = VmarHandle::new(new_process_vm());
        let map_addr = PAGE_SIZE * 16;
        let map_size = PAGE_SIZE * 4;
        let vmo = VmoOptions::new(map_size).alloc().unwrap();
        assert_eq!(
            vmar.new_map(map_size, VmPerms::READ | VmPerms::WRITE)
                .offset(VmarMapOffset::FixedNoReplace(map_addr))
                .vmo(vmo)
                .build()
                .unwrap(),
            map_addr
        );

        let access_addr = map_addr + 17;
        let access_len = PAGE_SIZE * 3 + 37;
        let mut expected = vec![0; access_len];
        for (index, byte) in expected.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }

        let source = expected.clone();
        let result = Arc::new(Mutex::new(None));
        let worker_result = result.clone();
        let worker_vmar = vmar.clone_arc();
        let associated_vmar = worker_vmar.clone();
        let test_cpu = CpuId::current_racy();

        let switcher_vmar_handle = VmarHandle::new(new_process_vm());
        let switcher_vmar = switcher_vmar_handle.clone_arc();
        let associated_switcher_vmar = switcher_vmar.clone();

        let worker = ThreadOptions::new(move || {
            let current = Thread::current().unwrap();
            assert!(
                current
                    .as_kernel_thread()
                    .and_then(|kernel_thread| kernel_thread.vmar())
                    .is_some_and(|vmar| Arc::ptr_eq(vmar, &worker_vmar))
            );

            let mut user_writer = worker_vmar
                .vm_space()
                .writer(access_addr, access_len)
                .unwrap();
            let mut source_reader = VmReader::from(source.as_slice()).to_fallible();
            assert_eq!(
                user_writer.write_fallible(&mut source_reader).unwrap(),
                access_len
            );

            let switcher = ThreadOptions::new(move || {
                let current = Thread::current().unwrap();
                assert!(
                    current
                        .as_kernel_thread()
                        .and_then(|kernel_thread| kernel_thread.vmar())
                        .is_some_and(|vmar| Arc::ptr_eq(vmar, &switcher_vmar))
                );
                assert!(switcher_vmar.vm_space().reader(map_addr, 0).is_ok());
            })
            .cpu_affinity(test_cpu.into())
            .vmar(associated_switcher_vmar)
            .spawn();

            switcher.join();

            let mut user_reader = worker_vmar
                .vm_space()
                .reader(access_addr, access_len)
                .unwrap();
            let mut output = vec![0; access_len];
            let mut output_writer = VmWriter::from(output.as_mut_slice()).to_fallible();
            assert_eq!(
                user_reader.read_fallible(&mut output_writer).unwrap(),
                access_len
            );
            *worker_result.lock() = Some(output);
        })
        .cpu_affinity(test_cpu.into())
        .vmar(associated_vmar)
        .spawn();

        worker.join();
        assert_eq!(result.lock().take().unwrap(), expected);
    }

    #[cfg(feature = "kernelet-host")]
    #[ktest]
    fn carrier_vm_space_is_restored_without_process_vmar() {
        super::super::init();

        let space = Arc::new(VmSpace::new());
        let worker_space = space.clone();
        let completed = Arc::new(Mutex::new(false));
        let worker_completed = completed.clone();
        let test_cpu = CpuId::current_racy();
        let worker = ThreadOptions::new(move || {
            let current = Thread::current().unwrap();
            let kernel_thread = current.as_kernel_thread().unwrap();
            assert!(kernel_thread.vmar().is_none());
            assert!(Arc::ptr_eq(
                kernel_thread.vm_space().unwrap(),
                &worker_space
            ));

            // A different association forces a real root switch before resuming.
            let switcher = ThreadOptions::new(|| {})
                .cpu_affinity(test_cpu.into())
                .carrier_vm_space(Arc::new(VmSpace::new()))
                .spawn();
            switcher.join();

            const UNMAPPED_ADDR: usize = PAGE_SIZE * 16;
            let mut reader = worker_space.reader(UNMAPPED_ADDR, 1).unwrap();
            let mut output = [0u8; 1];
            let mut writer = VmWriter::from(output.as_mut_slice()).to_fallible();
            // The root was restored, but no Host process VMAR may resolve this fault.
            assert_eq!(
                reader.read_fallible(&mut writer),
                Err((Error::PageFault, 0))
            );
            *worker_completed.lock() = true;
        })
        .cpu_affinity(test_cpu.into())
        .carrier_vm_space(space)
        .spawn();

        worker.join();
        assert!(*completed.lock());
    }

    #[cfg(not(feature = "kernelet"))]
    #[ktest]
    fn unassociated_kernel_thread_preserves_native_address_space() {
        super::super::init();

        let vmar_handle = VmarHandle::new(new_process_vm());
        let associated_vmar = vmar_handle.clone_arc();
        let worker_vmar = associated_vmar.clone();
        let completed = Arc::new(Mutex::new(false));
        let worker_completed = completed.clone();
        let test_cpu = CpuId::current_racy();
        let worker = ThreadOptions::new(move || {
            let inherited_vmar = worker_vmar.clone();
            let child_completed = worker_completed.clone();
            let child = ThreadOptions::new(move || {
                assert!(
                    Thread::current()
                        .unwrap()
                        .as_kernel_thread()
                        .unwrap()
                        .vmar()
                        .is_none()
                );
                assert!(inherited_vmar.vm_space().reader(PAGE_SIZE * 16, 0).is_ok());
                *child_completed.lock() = true;
            })
            .cpu_affinity(test_cpu.into())
            .spawn();
            child.join();
            assert!(worker_vmar.vm_space().reader(PAGE_SIZE * 16, 0).is_ok());
        })
        .cpu_affinity(test_cpu.into())
        .vmar(associated_vmar)
        .spawn();

        worker.join();
        assert!(*completed.lock());
    }

    #[ktest]
    fn unmapped_vmar_access_returns_page_fault() {
        super::super::init();

        const UNMAPPED_ADDR: usize = PAGE_SIZE * 16;
        let vmar_handle = VmarHandle::new(new_process_vm());
        let vmar = vmar_handle.clone_arc();
        let associated_vmar = vmar.clone();

        let worker = ThreadOptions::new(move || {
            let mut output = [0u8; 1];
            let mut output_writer = VmWriter::from(output.as_mut_slice()).to_fallible();
            let mut user_reader = vmar.vm_space().reader(UNMAPPED_ADDR, 1).unwrap();
            assert_eq!(
                user_reader.read_fallible(&mut output_writer),
                Err((Error::PageFault, 0))
            );

            let input = [1u8; 1];
            let mut input_reader = VmReader::from(input.as_slice()).to_fallible();
            let mut user_writer = vmar.vm_space().writer(UNMAPPED_ADDR, 1).unwrap();
            assert_eq!(
                user_writer.write_fallible(&mut input_reader),
                Err((Error::PageFault, 0))
            );
        })
        .vmar(associated_vmar)
        .spawn();

        worker.join();
    }
}
