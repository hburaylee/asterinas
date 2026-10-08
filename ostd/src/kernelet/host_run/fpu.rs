// SPDX-License-Identifier: MPL-2.0

//! FPU crossing policy for the `fpu_save` and `fpu_load` services.
//!
//! [`FpuRestorePolicy`] captures what this CPU actually enables and reports
//! for extended state, so that every architectural field which could fault
//! during `FXRSTOR`/`XRSTOR` is validated before the Host loads a Guest image.

use super::{CarrierState, RETURNING, current_carrier_state};
use crate::{
    arch::cpu::context::FpuContext,
    kernelet::abi::{BootArgs, INVALID, STATE},
};

const MAX_FPU_IMAGE_BYTES: usize = 4096;
const FPU_LEGACY_BYTES: usize = 512;
const FPU_XSAVE_HEADER_BYTES: usize = 64;
const FPU_MXCSR_OFFSET: usize = 24;
const FPU_MXCSR_MASK_OFFSET: usize = 28;
const FPU_XSTATE_BV_OFFSET: usize = 512;
const FPU_XCOMP_BV_OFFSET: usize = 520;
const FPU_XSAVE_RESERVED_OFFSET: usize = 528;
const FPU_LEGACY_RESERVED_START: usize = 416;
const FPU_LEGACY_RESERVED_END: usize = 464;
// Only the architectural x87 control and opcode bits may be restored.
const FPU_CONTROL_MASK: u16 = 0x1f7f;
const FPU_OPCODE_MASK: u16 = 0x07ff;
// Matches the user-state restore mask in x86 FpuContext::load. A Guest may
// only name components that the Host actually enabled on this CPU.
const FPU_RESTORED_XSTATE: u64 = 0b1110_0111;
// The DAZ bit is not universally supported. If FXSAVE reports no mask, use
// only the baseline MXCSR bits that every x86-64 CPU accepts.
const BASELINE_MXCSR_MASK: u32 = 0xffbf;
#[derive(Clone, Copy)]
pub(super) struct FpuRestorePolicy {
    xstate_mask: u64,
    mxcsr_mask: u32,
}
impl FpuRestorePolicy {
    pub(super) fn from_host(stage: &mut FpuContext) -> Self {
        let initial = stage.as_bytes();
        let xstate_mask = if initial.len() >= FPU_LEGACY_BYTES + FPU_XSAVE_HEADER_BYTES {
            u64::from_le_bytes(
                initial[FPU_XSTATE_BV_OFFSET..FPU_XSTATE_BV_OFFSET + size_of::<u64>()]
                    .try_into()
                    .unwrap(),
            ) & FPU_RESTORED_XSTATE
        } else {
            0
        };
        // The saved legacy area contains the processor's actual MXCSR_MASK.
        // The initial image provides the enabled XCR0 bits before this save.
        stage.save();
        let reported_mask = u32::from_le_bytes(
            stage.as_bytes()[FPU_MXCSR_MASK_OFFSET..FPU_MXCSR_MASK_OFFSET + size_of::<u32>()]
                .try_into()
                .unwrap(),
        ) & 0xffff;
        let mxcsr_mask = if reported_mask == 0 {
            BASELINE_MXCSR_MASK
        } else {
            reported_mask
        };
        Self {
            xstate_mask,
            mxcsr_mask,
        }
    }

    /// Checks every architectural field that can fault during FXRSTOR/XRSTOR.
    /// The software-reserved tail of FXSAVE is deliberately left opaque.
    fn validate(self, image: &mut [u8]) -> bool {
        if image.len() < FPU_LEGACY_BYTES || image.len() > MAX_FPU_IMAGE_BYTES {
            return false;
        }
        let control = u16::from_le_bytes(image[0..2].try_into().unwrap());
        let opcode = u16::from_le_bytes(image[6..8].try_into().unwrap());
        let mxcsr = u32::from_le_bytes(
            image[FPU_MXCSR_OFFSET..FPU_MXCSR_OFFSET + size_of::<u32>()]
                .try_into()
                .unwrap(),
        );
        if control & !FPU_CONTROL_MASK != 0
            || image[5] != 0
            || opcode & !FPU_OPCODE_MASK != 0
            || mxcsr & !self.mxcsr_mask != 0
            || image[FPU_LEGACY_RESERVED_START..FPU_LEGACY_RESERVED_END]
                .iter()
                .any(|byte| *byte != 0)
        {
            return false;
        }
        if image.len() != FPU_LEGACY_BYTES {
            if image.len() < FPU_LEGACY_BYTES + FPU_XSAVE_HEADER_BYTES {
                return false;
            }
            let features = u64::from_le_bytes(
                image[FPU_XSTATE_BV_OFFSET..FPU_XSTATE_BV_OFFSET + size_of::<u64>()]
                    .try_into()
                    .unwrap(),
            );
            let compaction = u64::from_le_bytes(
                image[FPU_XCOMP_BV_OFFSET..FPU_XCOMP_BV_OFFSET + size_of::<u64>()]
                    .try_into()
                    .unwrap(),
            );
            if features & !self.xstate_mask != 0
                || compaction != 0
                || image[FPU_XSAVE_RESERVED_OFFSET..FPU_LEGACY_BYTES + FPU_XSAVE_HEADER_BYTES]
                    .iter()
                    .any(|byte| *byte != 0)
            {
                return false;
            }
        }
        // XRSTOR ignores this image field, but a forged mask must not be
        // carried into a later image-side FPU save.
        image[FPU_MXCSR_MASK_OFFSET..FPU_MXCSR_MASK_OFFSET + size_of::<u32>()]
            .copy_from_slice(&self.mxcsr_mask.to_le_bytes());
        true
    }
}

#[cfg(ktest)]
mod fpu_restore_tests {
    use ostd_macros::ktest;

    use super::*;

    fn saved_image() -> [u8; FPU_LEGACY_BYTES + FPU_XSAVE_HEADER_BYTES] {
        let mut image = [0u8; FPU_LEGACY_BYTES + FPU_XSAVE_HEADER_BYTES];
        image[0..2].copy_from_slice(&0x037fu16.to_le_bytes());
        image[FPU_MXCSR_OFFSET..FPU_MXCSR_OFFSET + 4].copy_from_slice(&0x1f80u32.to_le_bytes());
        image[FPU_XSTATE_BV_OFFSET..FPU_XSTATE_BV_OFFSET + 8]
            .copy_from_slice(&0x03u64.to_le_bytes());
        image
    }

    #[ktest]
    fn rejects_fpu_images_that_could_fault_on_restore() {
        let policy = FpuRestorePolicy {
            xstate_mask: FPU_RESTORED_XSTATE,
            mxcsr_mask: BASELINE_MXCSR_MASK,
        };
        let valid = saved_image();
        let mut image = valid;
        assert!(policy.validate(&mut image));
        assert_eq!(
            &image[FPU_MXCSR_MASK_OFFSET..FPU_MXCSR_MASK_OFFSET + 4],
            &BASELINE_MXCSR_MASK.to_le_bytes()
        );

        let mut legacy = [0u8; FPU_LEGACY_BYTES];
        legacy.copy_from_slice(&valid[..FPU_LEGACY_BYTES]);
        assert!(policy.validate(&mut legacy));
        let mut truncated_xsave = [0u8; FPU_LEGACY_BYTES + 1];
        truncated_xsave.copy_from_slice(&valid[..FPU_LEGACY_BYTES + 1]);
        assert!(!policy.validate(&mut truncated_xsave));

        let mut image = valid;
        image[FPU_MXCSR_OFFSET..FPU_MXCSR_OFFSET + 4]
            .copy_from_slice(&0x8000_1f80u32.to_le_bytes());
        assert!(!policy.validate(&mut image));

        let mut image = valid;
        image[FPU_XSTATE_BV_OFFSET..FPU_XSTATE_BV_OFFSET + 8]
            .copy_from_slice(&(1u64 << 63).to_le_bytes());
        assert!(!policy.validate(&mut image));

        let mut image = valid;
        image[FPU_XCOMP_BV_OFFSET] = 1;
        assert!(!policy.validate(&mut image));

        let mut image = valid;
        image[FPU_XSAVE_RESERVED_OFFSET] = 1;
        assert!(!policy.validate(&mut image));

        let mut image = valid;
        image[FPU_LEGACY_RESERVED_START] = 1;
        assert!(!policy.validate(&mut image));

        let mut image = valid;
        image[5] = 1;
        assert!(!policy.validate(&mut image));

        let mut image = valid;
        image[FPU_LEGACY_RESERVED_END] = 1;
        assert!(policy.validate(&mut image));
    }
}

fn fpu_image_paddr(state: &CarrierState, area: usize, len: u32) -> Option<u64> {
    // SAFETY: The carrier pins its Host-built boot page until fixed exit.
    let boot = unsafe { &*(state.boot_args as *const BootArgs) };
    if len == 0
        || len as usize > MAX_FPU_IMAGE_BYTES
        || len != boot.fpu_area_bytes
        || !area.is_multiple_of(64)
    {
        return None;
    }
    let paddr = area.checked_sub(boot.linear_map_base as usize)? as u64;
    state
        .guest_memory
        .contains(paddr, len as usize)
        .then_some(paddr)
}

// SAFETY: The service stub enters on the native Host stack and the borrowed
// image buffer is checked against the pinned grant before any access.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_fpu_save_impl(area: *mut u8, len: u32) -> i64 {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    let result = if let Some(paddr) = fpu_image_paddr(state, area as usize, len) {
        let mut stage = state.fpu_stage.borrow_mut();
        stage.save();
        state
            .guest_memory
            .write(paddr, stage.as_bytes())
            .map(|()| 0)
            .unwrap_or(-INVALID)
    } else {
        -INVALID
    };
    state.set_phase(RETURNING);
    result
}

// SAFETY: The service stub enters on the native Host stack and the borrowed
// image buffer is checked against the pinned grant before any access.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_fpu_load_impl(area: *const u8, len: u32) -> i64 {
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    let result = if let Some(paddr) = fpu_image_paddr(state, area as usize, len) {
        let mut image = [0u8; MAX_FPU_IMAGE_BYTES];
        let image = &mut image[..len as usize];
        if state.guest_memory.read(paddr, image).is_err() || !state.fpu_restore.validate(image) {
            -INVALID
        } else {
            let mut stage = state.fpu_stage.borrow_mut();
            if stage.as_bytes().len() != image.len() {
                -INVALID
            } else {
                stage.as_bytes_mut().copy_from_slice(image);
                stage.load();
                state.fpu_active.set(true);
                0
            }
        }
    } else {
        -INVALID
    };
    state.set_phase(RETURNING);
    result
}
