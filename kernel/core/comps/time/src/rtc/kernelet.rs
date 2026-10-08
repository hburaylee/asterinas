// SPDX-License-Identifier: MPL-2.0

//! RTC backed by the Host realtime snapshot exposed through vOSTD.

use time::OffsetDateTime;

use crate::{SystemTime, rtc::Driver};

pub(super) struct RtcKernelet;

impl Driver for RtcKernelet {
    fn try_new() -> Option<Self> {
        Some(Self)
    }

    fn read_rtc(&self) -> SystemTime {
        let nanos = ostd::kernelet::entry::realtime_now_ns();
        // A u64 nanosecond timestamp is within time's supported date range.
        let time = OffsetDateTime::from_unix_timestamp_nanos(i128::from(nanos)).unwrap();

        SystemTime {
            year: time.year() as u16,
            month: u8::from(time.month()),
            day: time.day() as u8,
            hour: time.hour() as u8,
            minute: time.minute() as u8,
            second: time.second() as u8,
            nanos: u64::from(time.nanosecond()),
        }
    }
}
