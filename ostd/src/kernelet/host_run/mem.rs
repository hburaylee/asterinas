// SPDX-License-Identifier: MPL-2.0

//! Image memory-provisioning services: grant growth and kernel-stack
//! allocation.
//!
//! Grant growth and its Host policy hooks do not sleep, including when the
//! image holds a preemption guard. Stack allocation maps on-demand pool slots.

use core::sync::atomic::Ordering;

use super::{RETURNING, current_carrier_state, resources::STACK_BYTES};
use crate::kernelet::abi::{INVALID, LIMIT, STATE};

// SAFETY: The entry stub authenticates the carrier and validates its shared stack.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_grains_request_impl(count: u32, contiguous: u32) -> i64 {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    // Keep the image's virtual guard ownership intact. Allocation and policy
    // hooks must not sleep; physical IRQs can still run during bounded zeroing.
    let _preempt_guard = crate::task::disable_preempt();
    crate::arch::irq::enable_local();
    let mut result = state.grant.grow_within_ceiling(count, contiguous);
    if matches!(result, Err(crate::Error::AccessDenied))
        && state.control.account.policy.ask_before_oom
    {
        crate::arch::irq::disable_local();
        let reserved = state
            .call_hook(|| state.hooks.on_grant_exhausted(count))
            .unwrap_or(0);
        crate::arch::irq::enable_local();
        if reserved != 0 {
            let committed;
            (result, committed) = state.grant.grow_authorized(count, contiguous, reserved);
            crate::arch::irq::disable_local();
            state.call_hook(|| state.hooks.on_grant_settled(reserved, committed));
            crate::arch::irq::enable_local();
        }
    }
    // An authorized ceiling persists even when this allocation could not finish.
    state
        .control
        .account
        .ceiling
        .fetch_max(state.grant.ceiling(), Ordering::Release);
    if result.is_ok() {
        state
            .control
            .account
            .grains
            .fetch_max(state.grant.grains(), Ordering::Release);
        state
            .control
            .account
            .grant_overhead
            .fetch_max(state.grant.overhead_bytes(), Ordering::Relaxed);
    }
    crate::arch::irq::disable_local();
    state.set_phase(RETURNING);
    match result {
        Ok(grains) => grains as i64,
        Err(crate::Error::NoMemory) => 0,
        Err(crate::Error::InvalidArgs) => -INVALID,
        Err(_) => -LIMIT,
    }
}
// SAFETY: The assembly stub has authenticated the carrier and service phase,
// and validated its shared stack and reserve before calling this function.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_kstack_alloc_impl() -> u64 {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return 0;
    };
    let Some(_admission) = state.admit_service() else {
        return 0;
    };
    state.enter_schedulable_service();
    crate::arch::irq::enable_local();
    let result = state.execution.allocate_stack().unwrap_or((0, false));
    crate::arch::irq::disable_local();
    if result.0 != 0 {
        state.control.account.stacks.fetch_add(1, Ordering::Relaxed);
        if result.1 {
            state
                .control
                .account
                .overhead
                .fetch_add(STACK_BYTES, Ordering::Relaxed);
        }
    }
    state.set_phase(RETURNING);
    result.0
}

// SAFETY: The assembly stub has authenticated the carrier and service phase,
// and validated its shared stack and reserve before calling this function.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_kstack_free_impl(base: u64) -> i64 {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    let result = state.execution.release_stack(
        base as usize,
        state.image_rsp,
        state.vcpu as usize,
        &state.control.account.stacks,
    );
    state.set_phase(RETURNING);
    match result {
        Ok(()) => 0,
        Err(error) => error,
    }
}
