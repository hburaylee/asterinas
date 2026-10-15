// SPDX-License-Identifier: MPL-2.0

//! Hardware user TLS saved only when a native carrier leaves its CPU.
//!
//! Ordinary user round trips leave FS and the inactive user GS live. The
//! carrier's native pause and restore hooks preserve them across other Host
//! tasks, without temporarily replacing the active native GS base.

use crate::arch::cpu::context::{FsBase, GsBase};

#[derive(Clone, Copy)]
pub(super) struct TlsState {
    fs: FsBase,
    gs: GsBase,
}

impl TlsState {
    /// Captures the current carrier's hardware bases with physical IRQs masked.
    pub(super) fn capture() -> Self {
        debug_assert!(!crate::arch::irq::is_local_enabled());
        let mut fs = FsBase::default();
        let mut gs = GsBase::default();
        fs.save();
        gs.save_inactive();
        Self { fs, gs }
    }

    /// Restores the carrier's hardware bases with physical IRQs masked.
    pub(super) fn restore(&self) {
        debug_assert!(!crate::arch::irq::is_local_enabled());
        self.fs.load();
        self.gs.load_inactive();
    }
}

#[cfg(ktest)]
mod test {
    use x86::bits64::segmentation::rdgsbase;

    use super::*;
    use crate::prelude::*;

    struct RestoreTls(TlsState);

    impl Drop for RestoreTls {
        fn drop(&mut self) {
            self.0.restore();
        }
    }

    #[ktest]
    fn carrier_tls_snapshot_restores_user_bases_without_changing_native_gs() {
        let _irq_guard = crate::irq::disable_local();
        let original = TlsState::capture();
        let _restore = RestoreTls(original);
        // SAFETY: Reading the active native GS base leaves it unchanged.
        let native_gs = unsafe { rdgsbase() };

        FsBase::new(0x1234_5000).load();
        GsBase::new(0x2345_6000).load_inactive();
        let carrier = TlsState::capture();
        FsBase::new(0x3456_7000).load();
        GsBase::new(0x4567_8000).load_inactive();
        carrier.restore();

        let restored = TlsState::capture();
        assert_eq!(restored.fs.addr(), 0x1234_5000);
        assert_eq!(restored.gs.addr(), 0x2345_6000);
        // SAFETY: The read checks that inactive-MSR accesses kept native GS.
        assert_eq!(unsafe { rdgsbase() }, native_gs);
    }
}
