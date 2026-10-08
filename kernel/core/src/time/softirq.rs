// SPDX-License-Identifier: MPL-2.0

use alloc::{boxed::Box, vec, vec::Vec};

use aster_softirq::{BottomHalfDisabled, SoftIrqLine, softirq_id::TIMER_SOFTIRQ_ID};
use ostd::{
    sync::{RcuOption, SpinGuardian},
    timer,
};

#[expect(clippy::type_complexity)]
static TIMER_SOFTIRQ_CALLBACKS: RcuOption<Box<Vec<fn()>>> = RcuOption::new_none();

pub(super) fn init() {
    SoftIrqLine::get(TIMER_SOFTIRQ_ID).enable(timer_softirq_handler);

    timer::register_callback_on_cpu(raise_timer_softirq);
    timer::register_next_expiry_callback(super::clocks::next_timer_expiry);
    timer::register_deadline_callback(process_timer_deadline);
}

fn raise_timer_softirq() {
    SoftIrqLine::get(TIMER_SOFTIRQ_ID).raise();
}

fn process_timer_deadline() {
    // Dropping this guard drains the raised softirq in task context, including
    // when no physical or virtual execution tick accompanies the wakeup.
    let guard = BottomHalfDisabled::guard();
    raise_timer_softirq();
    drop(guard);
}

/// Registers a function that will be executed during timer softirq.
pub(super) fn register_callback(func: fn()) {
    loop {
        let callbacks = TIMER_SOFTIRQ_CALLBACKS.read();
        match callbacks.get() {
            // Initialized, copy the vector, push the function and update.
            Some(callbacks_vec) => {
                let mut callbacks_cloned = callbacks_vec.clone();
                callbacks_cloned.push(func);
                if callbacks.compare_exchange(Some(callbacks_cloned)).is_ok() {
                    break;
                }
            }
            // Uninitialized, initialize it.
            None => {
                if callbacks
                    .compare_exchange(Some(Box::new(vec![func])))
                    .is_ok()
                {
                    break;
                }
            }
        }
        // Contention on initialization or pushing, retry.
        core::hint::spin_loop();
    }
}

fn timer_softirq_handler() {
    let callbacks = TIMER_SOFTIRQ_CALLBACKS.read();
    if let Some(callbacks) = callbacks.get() {
        for callback in callbacks.iter() {
            (callback)();
        }
    }
}
