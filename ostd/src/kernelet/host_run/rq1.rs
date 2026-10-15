// SPDX-License-Identifier: MPL-2.0

//! A successful, side-effect-free service body for boundary measurements.
//!
//! The normal assembly gate authenticates the carrier and stack. Admission
//! counts this call, and the shared return path retains root and stop checks.

use super::{RETURNING, current_carrier_state};
use crate::kernelet::abi::STATE;

// SAFETY: The normal service stub authenticates the carrier and validates its
// shared Task stack before calling this body with physical IRQs disabled.
#[unsafe(no_mangle)]
extern "C" fn kernelet_host_rq1_echo_impl(token: u64) -> i64 {
    #[cfg(kernelet_rq1_crossing_diag)]
    let entry = crate::kernelet::crossing_profile::BodyStamp::now();
    // SAFETY: The assembly stub retains this carrier until service return.
    let Some(state) = (unsafe { current_carrier_state() }) else {
        return -STATE;
    };
    let Some(_admission) = state.admit_service() else {
        return -STATE;
    };
    #[cfg(kernelet_rq1_crossing_diag)]
    let capture =
        state
            .control
            .crossing_profile
            .begin(state.control.cpu_slot(state.vcpu), token, entry);
    state.set_phase(RETURNING);
    #[cfg(kernelet_rq1_crossing_diag)]
    {
        let exit = crate::kernelet::crossing_profile::BodyStamp::now();
        if let Some(call) = capture {
            // Publication, guard cleanup and the epilogue belong to suffix.
            call.complete(exit);
        }
    }
    token as i64
}
