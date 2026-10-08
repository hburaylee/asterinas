// SPDX-License-Identifier: MPL-2.0

//! Admission and least-loaded placement for kernelet carriers.

use ostd::cpu::{self, CpuId, CpuSet};

use crate::prelude::*;

static ACTIVE_VCPUS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

/// Holds one admission count for each selected Host CPU until the sandbox is
/// reclaimed. A CPU is selected at most once for one kernelet.
pub(super) struct CpuReservation {
    cpus: Vec<CpuId>,
}

impl CpuReservation {
    pub(super) fn reserve(num_vcpus: u16) -> Result<Self> {
        let mut counts = ACTIVE_VCPUS.lock();
        counts.resize(cpu::num_cpus(), 0);
        let mut cpus = Vec::with_capacity(num_vcpus as usize);
        for _ in 0..num_vcpus {
            let Some(index) = (0..counts.len())
                .filter(|index| !cpus.contains(&CpuId::new(*index as u32)))
                .min_by_key(|index| (counts[*index], *index))
            else {
                return_errno_with_message!(Errno::ENOSPC, "not enough Host CPUs for kernelet");
            };
            if counts[index] == u32::MAX {
                return_errno_with_message!(Errno::ENOSPC, "Host CPU placement is saturated");
            }
            cpus.push(CpuId::new(index as u32));
        }
        for cpu in &cpus {
            counts[u32::from(*cpu) as usize] += 1;
        }
        Ok(Self { cpus })
    }

    pub(super) fn cpu_set(&self) -> CpuSet {
        let mut set = CpuSet::new_empty();
        for cpu in &self.cpus {
            set.add(*cpu);
        }
        set
    }
}

impl Drop for CpuReservation {
    fn drop(&mut self) {
        let mut counts = ACTIVE_VCPUS.lock();
        for cpu in &self.cpus {
            counts[u32::from(*cpu) as usize] -= 1;
        }
    }
}
