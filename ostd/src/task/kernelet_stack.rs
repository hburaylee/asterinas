// SPDX-License-Identifier: MPL-2.0

//! Internal Task stacks supplied by the Host's per-kernelet guarded pool.

use crate::{
    Error, Result,
    irq::DisabledLocalIrqGuard,
    kernelet::entry,
    mm::{PAGE_SIZE, Vaddr},
};

/// The stack size agreed with the Host stack pool.
const STACK_SIZE_IN_PAGES: usize = 64;
const STACK_SIZE: usize = STACK_SIZE_IN_PAGES * PAGE_SIZE;

#[derive(Debug)]
pub(crate) struct KernelStack {
    start_vaddr: Vaddr,
}

impl KernelStack {
    pub(crate) fn new_with_guard_page() -> Result<Self> {
        let start_vaddr = (entry::services().kstack_alloc)() as Vaddr;
        if start_vaddr == 0 {
            return Err(Error::NoMemory);
        }
        debug_assert!(start_vaddr.is_multiple_of(PAGE_SIZE));
        Ok(Self { start_vaddr })
    }

    /// The Host flushes stale translations before returning a pooled stack.
    pub(crate) fn flush_tlb(&self, _irq_guard: &DisabledLocalIrqGuard) {}

    pub(crate) fn end_vaddr(&self) -> Vaddr {
        self.start_vaddr + STACK_SIZE
    }

    pub(crate) fn lower_bound(&self) -> Vaddr {
        self.start_vaddr
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        let result = (entry::services().kstack_free)(self.start_vaddr as u64);
        assert_eq!(result, 0, "Host refused to release a kernelet Task stack");
    }
}
