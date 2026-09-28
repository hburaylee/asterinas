// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::{Ordering, fence};

use spin::Once;
use x86::msr;

use crate::{
    arch::{cpu::cpuid, io::io_mem::read_once},
    impl_frame_meta_for,
    mm::{self, Frame, FrameAllocOptions, HasPaddr},
};

// KVM feature bits and MSR values.
// Reference: <https://elixir.bootlin.com/linux/v7.0/source/arch/x86/include/uapi/asm/kvm_para.h>.
const KVM_FEATURE_CLOCKSOURCE2: u32 = 3;
const MSR_KVM_SYSTEM_TIME_NEW: u32 = 0x4b56_4d01;
const MSR_KVM_WALL_CLOCK_NEW: u32 = 0x4b56_4d00;
const KVM_MSR_ENABLE_BIT: u64 = 1;
const MAX_RETRIES: usize = 1_000_000;

/// Metadata for the KVM pvclock frame.
///
/// The frame is written by the hypervisor and read by the guest clock code,
/// so it is kept typed to prevent OSTD users from reading or writing it as
/// untyped memory via [`VmReader`] and [`VmWriter`].
///
/// [`VmReader`]: crate::mm::VmReader
/// [`VmWriter`]: crate::mm::VmWriter
struct PvclockPageMeta;
impl_frame_meta_for!(PvclockPageMeta);

/// Metadata for the KVM wall clock frame.
///
/// The frame is written by the hypervisor and read by the guest clock code,
/// so it is kept typed to prevent OSTD users from reading or writing it as
/// untyped memory via [`VmReader`] and [`VmWriter`].
///
/// [`VmReader`]: crate::mm::VmReader
/// [`VmWriter`]: crate::mm::VmWriter
struct WallClockPageMeta;
impl_frame_meta_for!(WallClockPageMeta);

/// Guest-visible layout of the KVM pvclock page.
///
/// This is Linux's `struct pvclock_vcpu_time_info`. KVM writes this structure
/// directly into the page we hand it via `MSR_KVM_SYSTEM_TIME_NEW`.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.0/source/arch/x86/include/asm/pvclock-abi.h#L26>.
#[repr(C, align(4))]
struct PvclockVcpuTimeInfo {
    version: u32,
    _pad0: u32,
    _tsc_timestamp: u64,
    _system_time: u64,
    tsc_to_system_mul: u32,
    tsc_shift: i8,
    _flags: u8,
    _pad: [u8; 2],
}

/// Guest-visible layout of the KVM wall clock page.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.0/source/arch/x86/include/asm/pvclock-abi.h#L37>.
#[repr(C, align(4))]
struct PvclockWallClock {
    version: u32,
    sec: u32,
    nsec: u32,
}

/// KVM-provided wall-clock time at guest boot.
#[derive(Clone, Copy, Debug)]
pub struct KvmWallClock {
    /// Seconds since the Unix epoch.
    pub sec: u32,
    /// Nanoseconds within the current second.
    pub nsec: u32,
}

/// A handle to the KVM pvclock page shared with the hypervisor.
struct PvclockPage(Frame<PvclockPageMeta>);

impl PvclockPage {
    /// Sets up the KVM pvclock page and returns a handle to it.
    fn setup() -> Option<&'static Self> {
        static PVCLOCK_PAGE: Once<PvclockPage> = Once::new();

        if !has_kvm_clocksource2() {
            return None;
        }

        if let Some(page) = PVCLOCK_PAGE.get() {
            return Some(page);
        }

        let frame = FrameAllocOptions::new()
            .alloc_frame_with(PvclockPageMeta)
            .ok()?;
        Some(PVCLOCK_PAGE.call_once(|| {
            // SAFETY: `frame` is a live page that will be retained by
            // `PVCLOCK_PAGE`, and this MSR is supported per
            // `has_kvm_clocksource2()` above.
            unsafe {
                msr::wrmsr(
                    MSR_KVM_SYSTEM_TIME_NEW,
                    frame.paddr() as u64 | KVM_MSR_ENABLE_BIT,
                )
            };
            Self(frame)
        }))
    }

    /// Returns a consistent snapshot read from the KVM pvclock page.
    fn read_time_snapshot(&self) -> Option<PvclockTimeSnapshot> {
        for _ in 0..MAX_RETRIES {
            // KVM marks an in-progress pvclock update with an odd `version`.
            // Accept fields only when `version` is even and unchanged across the read.
            // Reference: <https://elixir.bootlin.com/linux/v7.0/source/Documentation/virt/kvm/x86/msr.rst#L86-L90>.
            let version_before = self.read_version();
            if version_before & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }

            // FIXME: All synchronization below is based on the assumption that we are performing
            // atomic operations under the same memory model as the KVM side. However:
            // 1. The Linux memory model is incompatible with Rust's.
            // 2. We use non-atomic volatile operations to safely communicate with untrusted
            //    parties. But these operations cannot establish synchronization.

            // Synchronize with the (even) version update so that we can see the data written before
            // the version is written.
            fence(Ordering::Acquire);

            let tsc_to_system_mul = self.read_tsc_to_system_mul();
            let tsc_shift = self.read_tsc_shift();

            // Synchronize with the data update so that we can see the (odd) version update before
            // the data is written (if the data is changed concurrently).
            fence(Ordering::Acquire);

            let version_after = self.read_version();
            if version_before == version_after && tsc_to_system_mul != 0 {
                return Some(PvclockTimeSnapshot {
                    tsc_to_system_mul,
                    tsc_shift,
                });
            }

            core::hint::spin_loop();
        }

        None
    }

    fn read_version(&self) -> u32 {
        // SAFETY: `self.as_ptr()` points to a live KVM pvclock page.
        unsafe { read_once(core::ptr::addr_of!((*self.as_ptr()).version)) }
    }

    fn read_tsc_to_system_mul(&self) -> u32 {
        // SAFETY: `self.as_ptr()` points to a live KVM pvclock page.
        unsafe { read_once(core::ptr::addr_of!((*self.as_ptr()).tsc_to_system_mul)) }
    }

    fn read_tsc_shift(&self) -> i8 {
        // SAFETY: `self.as_ptr()` points to a live KVM pvclock page.
        unsafe { read_once(core::ptr::addr_of!((*self.as_ptr()).tsc_shift)) }
    }

    /// Returns a pointer that points to the pvclock page.
    fn as_ptr(&self) -> *const PvclockVcpuTimeInfo {
        mm::paddr_to_vaddr(self.0.paddr()) as *const PvclockVcpuTimeInfo
    }
}

/// A consistent snapshot read from the KVM pvclock page.
struct PvclockTimeSnapshot {
    tsc_to_system_mul: u32,
    tsc_shift: i8,
}

impl PvclockTimeSnapshot {
    /// Returns the TSC frequency in Hz derived from this snapshot.
    fn tsc_freq_hz(&self) -> Option<u64> {
        // The pvclock ABI encodes the TSC frequency using a scale factor
        // (`tsc_to_system_mul`) and a shift (`tsc_shift`) instead of a direct
        // frequency.
        // Reference: <https://elixir.bootlin.com/linux/v7.0/source/arch/x86/kernel/pvclock.c#L27>.

        let base_khz = (1_000_000u64 << 32).checked_div(u64::from(self.tsc_to_system_mul))?;

        let tsc_khz = if self.tsc_shift < 0 {
            base_khz.checked_shl((self.tsc_shift as i32).unsigned_abs())?
        } else {
            base_khz.checked_shr(self.tsc_shift as u32)?
        };

        let freq = tsc_khz.checked_mul(1000)?;
        (freq != 0).then_some(freq)
    }
}

/// Determines the TSC frequency from KVM's paravirtual clock.
pub(super) fn determine_tsc_freq() -> Option<u64> {
    let pvclock_page = PvclockPage::setup()?;
    let time_snapshot = pvclock_page.read_time_snapshot()?;
    time_snapshot.tsc_freq_hz()
}

/// Returns whether the current environment supports the KVM clocksource v2.
pub fn has_kvm_clocksource2() -> bool {
    cpuid::query_if_running_under_kvm() && cpuid::query_kvm_feature(KVM_FEATURE_CLOCKSOURCE2)
}

/// A handle to the KVM wall clock page shared with the hypervisor.
struct WallClockPage(Frame<WallClockPageMeta>);

impl WallClockPage {
    /// Sets up the KVM wall clock page and returns a handle to it.
    fn setup() -> Option<&'static Self> {
        static WALL_CLOCK_PAGE: Once<WallClockPage> = Once::new();

        if !has_kvm_clocksource2() {
            return None;
        }

        if let Some(page) = WALL_CLOCK_PAGE.get() {
            return Some(page);
        }

        let frame = FrameAllocOptions::new()
            .alloc_frame_with(WallClockPageMeta)
            .ok()?;
        Some(WALL_CLOCK_PAGE.call_once(|| {
            // SAFETY: `frame` is a live page that will be retained by
            // `WALL_CLOCK_PAGE`, and this MSR is supported per
            // `has_kvm_clocksource2()` above.
            unsafe {
                msr::wrmsr(MSR_KVM_WALL_CLOCK_NEW, frame.paddr() as u64);
            };
            Self(frame)
        }))
    }

    /// Returns the wall-clock time written by KVM to this page.
    fn read_wall_clock(&self) -> Option<KvmWallClock> {
        for _ in 0..MAX_RETRIES {
            // KVM marks an in-progress pvclock update with an odd `version`.
            // Accept fields only when `version` is even and unchanged across the read.
            // Reference: <https://elixir.bootlin.com/linux/v7.0/source/arch/x86/include/asm/pvclock-abi.h#L19-L24>.
            let version_before = self.read_version();
            if version_before & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }

            // FIXME: All synchronization below is based on the assumption that we are performing
            // atomic operations under the same memory model as the KVM side. However:
            // 1. The Linux memory model is incompatible with Rust's.
            // 2. We use non-atomic volatile operations to safely communicate with untrusted
            //    parties. But these operations cannot establish synchronization.

            fence(Ordering::Acquire);

            let sec = self.read_sec();
            let nsec = self.read_nsec();

            fence(Ordering::Acquire);

            let version_after = self.read_version();

            // A nonzero, unchanged version indicates KVM has actually written the page.
            if version_before != 0 && version_before == version_after {
                return Some(KvmWallClock { sec, nsec });
            }

            core::hint::spin_loop();
        }

        None
    }

    fn read_version(&self) -> u32 {
        // SAFETY: `self.as_ptr()` points to a live KVM wall clock page.
        unsafe { read_once(core::ptr::addr_of!((*self.as_ptr()).version)) }
    }

    fn read_sec(&self) -> u32 {
        // SAFETY: `self.as_ptr()` points to a live KVM wall clock page.
        unsafe { read_once(core::ptr::addr_of!((*self.as_ptr()).sec)) }
    }

    fn read_nsec(&self) -> u32 {
        // SAFETY: `self.as_ptr()` points to a live KVM wall clock page.
        unsafe { read_once(core::ptr::addr_of!((*self.as_ptr()).nsec)) }
    }

    /// Returns a pointer that points to the wall clock page.
    fn as_ptr(&self) -> *const PvclockWallClock {
        mm::paddr_to_vaddr(self.0.paddr()) as *const PvclockWallClock
    }
}

/// Reads the KVM wall clock via `MSR_KVM_WALL_CLOCK_NEW`.
pub fn read_kvm_wall_clock() -> Option<KvmWallClock> {
    let wall_clock_page = WallClockPage::setup()?;
    wall_clock_page.read_wall_clock()
}
