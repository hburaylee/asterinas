// SPDX-License-Identifier: MPL-2.0

//! Host-only payload-copy diagnostics, separate from ordinary CPU accounting.
//!
//! Callers construct readers/writers and pin memory before calling `measure`.
//! Only the actual payload transfer belongs in the closure. IRQ execution is
//! included; descheduled time is excluded. Timer setup/teardown and aggregation
//! perturb execution, so empty timer pairs are reported separately.

use ostd::{
    sync::{LocalIrqDisabled, SpinLock},
    task::Task,
};

#[derive(Clone, Copy)]
pub(crate) enum Category {
    BlockRead,
    BlockWrite,
    NetTx,
    NetRx,
    NatToHost,
    NatToGuest,
    VsockTx,
    VsockRx,
    RamRead,
    RamWrite,
}

impl Category {
    pub(crate) const ALL: [Self; 10] = [
        Self::BlockRead,
        Self::BlockWrite,
        Self::NetTx,
        Self::NetRx,
        Self::NatToHost,
        Self::NatToGuest,
        Self::VsockTx,
        Self::VsockRx,
        Self::RamRead,
        Self::RamWrite,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::BlockRead => "block_read",
            Self::BlockWrite => "block_write",
            Self::NetTx => "net_tx",
            Self::NetRx => "net_rx",
            Self::NatToHost => "nat_to_host",
            Self::NatToGuest => "nat_to_guest",
            Self::VsockTx => "vsock_tx",
            Self::VsockRx => "vsock_rx",
            Self::RamRead => "ram_read",
            Self::RamWrite => "ram_write",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Counter {
    pub(crate) bytes: u64,
    pub(crate) calls: u64,
    pub(crate) cpu_ns: u64,
    pub(crate) errors: u64,
    pub(crate) saturated: bool,
}

impl Counter {
    const ZERO: Self = Self {
        bytes: 0,
        calls: 0,
        cpu_ns: 0,
        errors: 0,
        saturated: false,
    };

    fn record(&mut self, bytes: usize, cpu_ns: u64, error: bool) {
        for (total, added) in [
            (&mut self.bytes, bytes as u64),
            (&mut self.calls, 1),
            (&mut self.cpu_ns, cpu_ns),
            (&mut self.errors, u64::from(error)),
        ] {
            self.saturated |= total.checked_add(added).is_none();
            *total = total.saturating_add(added);
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Snapshot {
    pub(crate) categories: [Counter; 10],
    pub(crate) empty_timer: Counter,
}

static COUNTERS: SpinLock<Snapshot, LocalIrqDisabled> = SpinLock::new(Snapshot {
    categories: [Counter::ZERO; 10],
    empty_timer: Counter::ZERO,
});

/// Measures one copy, retaining its actual transferred-byte return value.
pub(crate) fn measure(
    category: Category,
    expected_bytes: usize,
    copy_fn: impl FnOnce() -> usize,
) -> usize {
    let (copied, cpu_ns) = time_copy(copy_fn);
    COUNTERS.lock().categories[category as usize].record(copied, cpu_ns, copied != expected_bytes);
    copied
}

/// Preserves the original error and partial-byte count of a fallible copy.
pub(crate) fn measure_fallible<E>(
    category: Category,
    expected_bytes: usize,
    copy_fn: impl FnOnce() -> core::result::Result<usize, (E, usize)>,
) -> core::result::Result<usize, (E, usize)> {
    let (result, cpu_ns) = time_copy(copy_fn);
    let (copied, error) = match &result {
        Ok(copied) => (*copied, *copied != expected_bytes),
        Err((_, copied)) => (*copied, true),
    };
    COUNTERS.lock().categories[category as usize].record(copied, cpu_ns, error);
    result
}

/// Samples empty timer pairs; these observations are never subtracted.
pub(crate) fn sample_empty_timer(samples: usize) {
    for _ in 0..samples {
        let (_, cpu_ns) = time_copy(|| ());
        COUNTERS.lock().empty_timer.record(0, cpu_ns, false);
    }
}

/// Returns one coherent, global cumulative snapshot.
pub(crate) fn snapshot() -> Snapshot {
    *COUNTERS.lock()
}

fn time_copy<R>(copy_fn: impl FnOnce() -> R) -> (R, u64) {
    let measurement = Task::current()
        .expect("copy diagnostics run on a native Task")
        .measure_cpu_time();
    let result = copy_fn();
    let cpu_ns = measurement.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    drop(measurement);
    (result, cpu_ns)
}
