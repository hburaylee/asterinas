// SPDX-License-Identifier: MPL-2.0

//! Host-hook services: device MMIO dispatch, log forwarding, and oops
//! reporting.
//!
//! These services never block. Each validates its bounded image arguments
//! and delegates to the registered `KerneletHooks` implementation.

use core::sync::atomic::Ordering;

use super::{CarrierState, RETURNING, current_carrier_state, image_bytes};
use crate::kernelet::{
    abi::{
        INVALID, LEVEL_CONSOLE, MAX_LOG_MODULE_BYTES, MAX_LOG_TEXT_BYTES, MAX_OOPS_BYTES,
        MmioResult, STATE,
    },
    control::{ExitReason, KillReason},
};

// SAFETY: The assembly stub has authenticated this service crossing and
// switched to the carrier's native Host stack.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_mmio_read_impl(device: u32, offset: u32, width: u32) -> MmioResult {
    let failure = MmioResult {
        status: -INVALID,
        value: 0,
    };
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return failure;
    };
    let Some(_admission) = state.admit_service() else {
        return failure;
    };
    if device > u16::MAX as u32 || !matches!(width, 1 | 2 | 4 | 8) || !offset.is_multiple_of(width)
    {
        state.set_phase(RETURNING);
        return failure;
    }
    state
        .control
        .account
        .mmio_accesses
        .fetch_add(1, Ordering::Relaxed);
    let result = state
        .call_hook(|| state.hooks.mmio_read(device as u16, offset, width))
        .unwrap_or(failure);
    state.set_phase(RETURNING);
    result
}

// SAFETY: The assembly stub has authenticated this service crossing and
// switched to the carrier's native Host stack.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_mmio_write_impl(
    device: u32,
    offset: u32,
    width: u32,
    value: u64,
) -> i64 {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    if device > u16::MAX as u32 || !matches!(width, 1 | 2 | 4 | 8) || !offset.is_multiple_of(width)
    {
        state.set_phase(RETURNING);
        return -INVALID;
    }
    state
        .control
        .account
        .mmio_accesses
        .fetch_add(1, Ordering::Relaxed);
    let result = state
        .call_hook(|| state.hooks.mmio_write(device as u16, offset, width, value))
        .unwrap_or(-STATE);
    state.set_phase(RETURNING);
    result
}
// SAFETY: Only the assembly log stub calls this after switching to the native
// Host stack with physical interrupts disabled.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_log_write_impl(
    level: u32,
    module: *const u8,
    module_len: u32,
    text: *const u8,
    text_len: u32,
) -> i64 {
    // SAFETY: The assembly stub entered from the current carrier and retains
    // its state until this Host service returns.
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    let result = log_write_service(state, level, module, module_len, text, text_len);
    state.set_phase(RETURNING);
    result
}

fn log_write_service(
    state: &CarrierState,
    level: u32,
    module: *const u8,
    module_len: u32,
    text: *const u8,
    text_len: u32,
) -> i64 {
    if level > LEVEL_CONSOLE {
        return -INVALID;
    }
    // SAFETY: The carrier retains the image for this service crossing.
    let Ok(module) = (unsafe { image_bytes(module, module_len, MAX_LOG_MODULE_BYTES) }) else {
        return -INVALID;
    };
    // SAFETY: The carrier retains the image for this service crossing.
    let Ok(text) = (unsafe { image_bytes(text, text_len, MAX_LOG_TEXT_BYTES) }) else {
        return -INVALID;
    };
    let (Ok(module), Ok(text)) = (core::str::from_utf8(module), core::str::from_utf8(text)) else {
        return -INVALID;
    };
    if !state.control.account.admit_log(text_len) {
        return 0;
    }
    match state.call_hook(|| state.hooks.log(level, module, text)) {
        Some(true) => {
            state
                .control
                .account
                .log_bytes
                .fetch_add(text_len as u64, Ordering::Relaxed);
        }
        Some(false) => {
            state
                .control
                .account
                .logs_dropped
                .fetch_add(1, Ordering::Relaxed);
        }
        None => return -STATE,
    }
    0
}

// SAFETY: The assembly adapter authenticated this carrier and installed its Host stack.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_oops_impl(msg: *const u8, len: u32) -> i64 {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    let result = (|| {
        // SAFETY: The carrier pins image and stack mappings during this call.
        let bytes = unsafe { image_bytes(msg, len, MAX_OOPS_BYTES) }?;
        let message = core::str::from_utf8(bytes).map_err(|_| -INVALID)?;
        let previous = state.control.account.oopses.fetch_add(1, Ordering::Relaxed);
        let _ = state.call_hook(|| state.hooks.on_oops(message));
        if previous >= state.control.account.policy.oops_budget {
            state
                .control
                .stop(ExitReason::Killed(KillReason::OopsBudget));
        }
        Ok::<_, i64>(0)
    })()
    .unwrap_or_else(|error| error);
    state.set_phase(RETURNING);
    result
}
