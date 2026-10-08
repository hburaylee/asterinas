// SPDX-License-Identifier: MPL-2.0

//! CPU execution attributed to device completion and receive-copy work.

use ostd::{
    kernelet::control::Kernelet,
    task::{CpuTimeMeasurement, Task},
};

/// A breakdown of work already included in carrier or adopted-Task CPU time.
#[derive(Clone, Copy)]
pub(super) enum WorkCategory {
    Completion,
    Ingress,
}

/// Attributes one synchronous region to its device or receiving instance.
///
/// Task execution measurements exclude descheduling, including preemption
/// during large receive copies. These counters describe work; they do not
/// add the same execution to the instance's aggregate quota a second time.
pub(super) struct ChargedSpan<'a> {
    kernelet: &'a Kernelet,
    category: WorkCategory,
    measurement: CpuTimeMeasurement,
}

impl<'a> ChargedSpan<'a> {
    pub(super) fn new(kernelet: &'a Kernelet, category: WorkCategory) -> Self {
        Self {
            kernelet,
            category,
            measurement: Task::current()
                .expect("device work runs on a native Task")
                .measure_cpu_time(),
        }
    }

    pub(super) fn measure<R>(
        kernelet: &'a Kernelet,
        category: WorkCategory,
        work: impl FnOnce() -> R,
    ) -> R {
        let span = Self::new(kernelet, category);
        let result = work();
        drop(span);
        result
    }
}

impl Drop for ChargedSpan<'_> {
    fn drop(&mut self) {
        let elapsed = self.measurement.elapsed();
        match self.category {
            WorkCategory::Completion => self.kernelet.charge_completion_time(elapsed),
            WorkCategory::Ingress => self.kernelet.charge_ingress_time(elapsed),
        }
    }
}
