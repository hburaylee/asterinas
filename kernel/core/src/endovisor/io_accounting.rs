// SPDX-License-Identifier: MPL-2.0

//! Optional CPU attribution for device completion and receive-copy work.

#[cfg(not(kernelet_rq1_diagnostics))]
use core::marker::PhantomData;

use ostd::kernelet::control::Kernelet;
#[cfg(kernelet_rq1_diagnostics)]
use ostd::task::{CpuTimeMeasurement, Task};

/// Categories of optional device-work CPU observations.
#[derive(Clone, Copy)]
pub(super) enum WorkCategory {
    Completion,
    Ingress,
}

/// Attributes one synchronous region to its device or receiving instance.
///
/// Task execution measurements exclude descheduling, including preemption
/// during large receive copies. These counters describe work and do not
/// control scheduling. Ordinary builds retain only a zero-sized guard.
pub(super) struct ChargedSpan<'a> {
    #[cfg(kernelet_rq1_diagnostics)]
    kernelet: &'a Kernelet,
    #[cfg(kernelet_rq1_diagnostics)]
    category: WorkCategory,
    #[cfg(kernelet_rq1_diagnostics)]
    measurement: CpuTimeMeasurement,
    // Preserve the diagnostic guard's borrow and !Send/!Sync properties.
    #[cfg(not(kernelet_rq1_diagnostics))]
    _marker: PhantomData<(&'a Kernelet, *mut ())>,
}

impl<'a> ChargedSpan<'a> {
    #[cfg(kernelet_rq1_diagnostics)]
    #[inline]
    pub(super) fn new(kernelet: &'a Kernelet, category: WorkCategory) -> Self {
        Self {
            kernelet,
            category,
            measurement: Task::current()
                .expect("device work runs on a native Task")
                .measure_cpu_time(),
        }
    }

    #[cfg(not(kernelet_rq1_diagnostics))]
    #[inline]
    pub(super) fn new(_kernelet: &'a Kernelet, _category: WorkCategory) -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    #[inline]
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
    #[inline]
    fn drop(&mut self) {
        #[cfg(kernelet_rq1_diagnostics)]
        {
            let elapsed = self.measurement.elapsed();
            match self.category {
                WorkCategory::Completion => self.kernelet.charge_completion_time(elapsed),
                WorkCategory::Ingress => self.kernelet.charge_ingress_time(elapsed),
            }
        }
    }
}
