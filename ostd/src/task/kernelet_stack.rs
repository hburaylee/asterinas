// SPDX-License-Identifier: MPL-2.0

//! Internal Task stacks supplied by the Host's per-kernelet guarded pool.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::{
    Error, Result,
    irq::DisabledLocalIrqGuard,
    kernelet::{
        abi::{KSTACK_MAPPING_BYTES, KSTACK_USABLE_BYTES},
        entry,
    },
    mm::{PAGE_SIZE, Vaddr},
};

/// The stack size agreed with the Host stack pool.
const STACK_SIZE_IN_PAGES: usize = 64;
const STACK_SIZE: usize = STACK_SIZE_IN_PAGES * PAGE_SIZE;
const _: () = assert!(STACK_SIZE == KSTACK_MAPPING_BYTES);

#[derive(Debug)]
pub(crate) struct KernelStack {
    start_vaddr: Vaddr,
    boot: bool,
    retired: AtomicBool,
}

impl KernelStack {
    pub(crate) fn new_with_guard_page() -> Result<Self> {
        let start_vaddr = (entry::services().kstack_alloc)() as Vaddr;
        if start_vaddr == 0 {
            return Err(Error::NoMemory);
        }
        debug_assert!(start_vaddr.is_multiple_of(PAGE_SIZE));
        Ok(Self {
            start_vaddr,
            boot: false,
            retired: AtomicBool::new(false),
        })
    }

    /// Adopts a Host boot slot without allocating another stack.
    ///
    /// # Safety
    ///
    /// The caller must be executing on this vCPU's live boot slot, and must
    /// retire it on a different stack before enabling virtual IRQs after exit.
    /// Unlike ordinary stacks, an uncommitted boot owner cannot free its
    /// currently executing storage through Drop.
    pub(crate) unsafe fn adopt_boot(start_vaddr: Vaddr) -> Self {
        Self {
            start_vaddr,
            boot: true,
            retired: AtomicBool::new(false),
        }
    }

    pub(crate) fn is_boot(&self) -> bool {
        self.boot
    }

    /// Returns an exited boot Task's slot on the new stack, on its original vCPU.
    ///
    /// # Safety
    ///
    /// The Task must have exited permanently. The caller must hold virtual
    /// IRQs disabled on its original vCPU and be executing on a different stack.
    pub(crate) unsafe fn retire_boot(&self) {
        if !self.boot {
            return;
        }
        assert!(
            !self.retired.load(Ordering::Relaxed),
            "boot stack retired twice"
        );
        let result = (entry::services().kstack_free)(self.start_vaddr as u64);
        assert_eq!(result, 0, "Host refused to retire a boot Task stack");
        self.retired.store(true, Ordering::Release);
    }

    /// The Host flushes stale translations before returning a pooled stack.
    pub(crate) fn flush_tlb(&self, _irq_guard: &DisabledLocalIrqGuard) {}

    pub(crate) fn end_vaddr(&self) -> Vaddr {
        self.start_vaddr + KSTACK_USABLE_BYTES
    }

    pub(crate) fn lower_bound(&self) -> Vaddr {
        self.start_vaddr
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        // Boot ownership is retired explicitly after switching. This also
        // keeps an unpublished constructor from freeing its own live stack.
        if self.boot {
            return;
        }
        let result = (entry::services().kstack_free)(self.start_vaddr as u64);
        assert_eq!(result, 0, "Host refused to release a kernelet Task stack");
    }
}
