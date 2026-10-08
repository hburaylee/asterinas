// SPDX-License-Identifier: MPL-2.0

//! Image memory-provisioning services: grant growth and kernel-stack
//! allocation.
//!
//! Grant growth may wait on the instance growth mutex and consult the Host
//! grant-exhaustion hooks; stack allocation maps on-demand pool slots.

use core::sync::atomic::Ordering;

use super::{RETURNING, current_carrier_state, resources::STACK_BYTES};
use crate::kernelet::abi::{INVALID, LIMIT, STATE, VcpuRecord};

// SAFETY: The entry stub authenticates and switches to the carrier's Host stack.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_grains_request_impl(count: u32, contiguous: u32) -> i64 {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    state.enter_schedulable_service();
    // SAFETY: The current instance retains this shared record throughout the service.
    let record = unsafe { &*(state.vcpu_record as *const VcpuRecord) };
    if record.irq_level.load(Ordering::Acquire) != 0 {
        state.set_phase(RETURNING);
        return -STATE;
    }
    // Growth may wait for the instance growth mutex. Physical IRQs and native
    // preemption remain enabled while zeroing and mapping bounded memory.
    crate::arch::irq::enable_local();
    let mut result = state.grant.grow(count, contiguous, false);
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
            .ceiling
            .fetch_max(state.grant.ceiling(), Ordering::Release);
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
// SAFETY: The assembly stub has switched to the native Host stack and
// authenticated the service phase before calling this function.
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

// SAFETY: The assembly stub has switched to the native Host stack and
// authenticated the service phase before calling this function.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_kstack_free_impl(base: u64) -> i64 {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    let result = state
        .execution
        .stacks
        .lock()
        .free(base as usize, state.image_rsp);
    if result == 0 {
        state.control.account.stacks.fetch_sub(1, Ordering::Relaxed);
    }
    state.set_phase(RETURNING);
    result
}
