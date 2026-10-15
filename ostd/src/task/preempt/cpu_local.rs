// SPDX-License-Identifier: MPL-2.0

//! This module maintains preemption-related information for the current task
//! on a CPU with a single 32-bit, CPU-local integer value.
//!
//! * Bits from 0 to 30 (0 to 29 in a kernelet) represent `guard_count`,
//!   which is the number of `DisabledPreemptGuard` instances held by the
//!   current CPU;
//! * Bit 31 is set to `!need_preempt`, where `need_preempt` is a boolean value
//!   that will be set by the scheduler when it decides that the current task
//!   _needs_ to be preempted.
//! * In a kernelet, bit 30 defers scheduling of its non-enqueued boot Task.
//!   It is not included in `guard_count` and does not mask virtual IRQs or
//!   represent an RCU read-side critical section.
//!
//! Thus, the current task on a CPU _should_ be preempted if and only if this
//! integer is equal to zero.
//!
//! The initial value of this integer is equal to `1 << 31`.
//!
//! This module provides a set of functions to access and manipulate
//! the guard count, preemption request, and kernelet boot phase.

use crate::cpu_local_cell;

/// Returns whether the current task _should_ be preempted or not.
///
/// This requires a preemption request, no guards, and (in a kernelet) no boot Task.
pub(in crate::task) fn should_preempt() -> bool {
    PREEMPT_INFO.load() == 0
}

pub(in crate::task) fn need_preempt() -> bool {
    PREEMPT_INFO.load() & NEED_PREEMPT_MASK == 0
}

pub(in crate::task) fn set_need_preempt() {
    PREEMPT_INFO.bitand_assign(!NEED_PREEMPT_MASK);
}

pub(in crate::task) fn clear_need_preempt() {
    PREEMPT_INFO.bitor_assign(NEED_PREEMPT_MASK);
}

pub(in crate::task) fn get_guard_count() -> u32 {
    PREEMPT_INFO.load() & GUARD_COUNT_MASK
}

/// Defers inner scheduling while a non-enqueued boot Task owns this CPU.
///
/// This is not a preemption guard or an RCU reader. Virtual IRQs remain
/// deliverable, and `should_preempt` retains its single comparison with zero.
#[cfg(feature = "kernelet")]
pub(in crate::task) fn enter_boot_task() {
    debug_assert_eq!(PREEMPT_INFO.load() & (BOOT_TASK_MASK | GUARD_COUNT_MASK), 0);
    PREEMPT_INFO.bitor_assign(BOOT_TASK_MASK);
}

#[cfg(feature = "kernelet")]
pub(in crate::task) fn in_boot_task() -> bool {
    PREEMPT_INFO.load() & BOOT_TASK_MASK != 0
}

/// Transfers boot's scheduling exclusion to an already-held SchedulingGuard.
#[cfg(feature = "kernelet")]
pub(in crate::task) fn leave_boot_task() {
    debug_assert!(super::super::scheduling_in_progress());
    debug_assert!(in_boot_task());
    PREEMPT_INFO.bitand_assign(!BOOT_TASK_MASK);
}

pub(in crate::task) fn inc_guard_count() {
    PREEMPT_INFO.add_assign(1);
}

pub(in crate::task) fn dec_guard_count() {
    debug_assert!(get_guard_count() > 0);
    PREEMPT_INFO.sub_assign(1);
}

cpu_local_cell! {
    static PREEMPT_INFO: u32 = NEED_PREEMPT_MASK;
}

const NEED_PREEMPT_MASK: u32 = 1 << 31;
#[cfg(feature = "kernelet")]
const BOOT_TASK_MASK: u32 = 1 << 30;
#[cfg(feature = "kernelet")]
const GUARD_COUNT_MASK: u32 = BOOT_TASK_MASK - 1;
#[cfg(not(feature = "kernelet"))]
const GUARD_COUNT_MASK: u32 = (1 << 31) - 1;
