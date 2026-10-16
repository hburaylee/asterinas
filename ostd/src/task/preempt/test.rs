// SPDX-License-Identifier: MPL-2.0

use core::{
    cell::RefCell,
    sync::atomic::{AtomicBool, Ordering},
};

use super::{cpu_local, disable_preempt};
use crate::{
    prelude::*,
    task::{Task, TaskOptions},
    timer::Jiffies,
};

#[ktest]
fn irq_enable_keeps_pending_request_during_borrow() {
    check_borrowed_irq_boundary(false);
}

#[ktest]
fn irq_enable_and_halt_keeps_pending_request_during_borrow() {
    check_borrowed_irq_boundary(true);
}

fn check_borrowed_irq_boundary(halt: bool) {
    // FIFO workers run on the BSP. One CPU excludes remote progress.
    if crate::cpu::num_cpus() != 1 {
        crate::early_println!("skipping borrowed IRQ-boundary test: requires one CPU");
        return;
    }
    assert!(Task::current().is_some());
    assert!(crate::arch::irq::is_local_enabled());
    assert_eq!(cpu_local::get_guard_count(), 0);

    for _ in 0..8 {
        let ran = Arc::new(AtomicBool::new(false));
        let worker_ran = ran.clone();
        let preempt_guard = disable_preempt();
        let irq_guard = crate::irq::disable_local();
        let worker = TaskOptions::new(move || {
            worker_ran.store(true, Ordering::Release);
        })
        .spawn()
        .unwrap();

        let cell = RefCell::new(0usize);
        let mut borrowed = cell.borrow_mut();
        cpu_local::set_need_preempt();
        drop(preempt_guard);
        let ran_while_masked = ran.load(Ordering::Acquire);
        let pending_while_masked = cpu_local::need_preempt();
        let before = Jiffies::elapsed().as_u64();
        if halt {
            // The periodic timer supplies a real wakeup. Its ordinary native
            // IRQ return must not schedule this non-carrier Task either.
            core::mem::forget(irq_guard);
            crate::arch::irq::enable_local_and_halt();
        } else {
            drop(irq_guard);
        }
        let irq_guard = crate::irq::disable_local();
        let after = Jiffies::elapsed().as_u64();
        let ran_at_boundary = ran.load(Ordering::Acquire);
        let pending_at_boundary = cpu_local::need_preempt();
        *borrowed += 1;
        drop(borrowed);
        // Remove the injected request before restoring IRQs. Cleanup must
        // happen through explicit yield, outside the live RefCell borrow.
        cpu_local::clear_need_preempt();
        drop(irq_guard);

        for _ in 0..16 {
            Task::yield_now();
            if ran.load(Ordering::Acquire) {
                break;
            }
        }
        let completed = ran.load(Ordering::Acquire);
        drop(worker);
        assert!(
            completed,
            "IRQ-boundary worker did not complete after explicit yields"
        );
        assert_eq!(cell.into_inner(), 1);
        assert!(
            !ran_while_masked,
            "IRQ-off boundary ran a worker during a RefCell borrow"
        );
        assert!(
            pending_while_masked,
            "IRQ-off boundary consumed the pending request"
        );

        // Exclude a competing timer return from the short IRQ-enable window.
        // HLT deliberately wakes through that real interrupt instead.
        if !halt && before != after {
            continue;
        }
        assert!(
            !ran_at_boundary,
            "IRQ enable boundary ran a worker during a RefCell borrow"
        );
        assert!(
            pending_at_boundary,
            "IRQ enable boundary consumed the pending request"
        );
        return;
    }
    panic!("borrowed IRQ-boundary test could not observe a window without a timer IRQ");
}
