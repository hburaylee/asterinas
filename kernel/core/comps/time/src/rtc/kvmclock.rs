// SPDX-License-Identifier: MPL-2.0

//! KVM wall clock RTC driver.
//!
//! KVM exposes the host's wall-clock time via `MSR_KVM_WALL_CLOCK_NEW`, which
//! Linux refers to as the `kvmclock` wall clock. This driver is a fallback for
//! environments such as Firecracker that provide KVM pvclock but no legacy
//! CMOS RTC.

use ostd::arch::kernel::{KvmWallClock, read_kvm_wall_clock};

use super::Driver;
use crate::SystemTime;

pub struct RtcKvmClock {
    wall_clock: SystemTime,
}

impl Driver for RtcKvmClock {
    fn try_new() -> Option<Self> {
        // Read the wall clock once to verify that KVM actually provides it.
        let wall_clock = read_kvm_wall_clock()?;
        Some(Self {
            wall_clock: wall_clock_to_system_time(wall_clock),
        })
    }

    fn read_rtc(&self) -> SystemTime {
        self.wall_clock
    }
}

fn wall_clock_to_system_time(wall_clock: KvmWallClock) -> SystemTime {
    let Ok(datetime) = time::OffsetDateTime::from_unix_timestamp(wall_clock.sec as i64) else {
        return SystemTime {
            year: 1970,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
            nanos: wall_clock.nsec as u64,
        };
    };

    SystemTime {
        year: datetime.year() as u16,
        month: datetime.month() as u8,
        day: datetime.day(),
        hour: datetime.hour(),
        minute: datetime.minute(),
        second: datetime.second(),
        nanos: wall_clock.nsec as u64,
    }
}
