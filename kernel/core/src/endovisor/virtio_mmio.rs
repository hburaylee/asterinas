// SPDX-License-Identifier: MPL-2.0

//! Common register operations for the endovisor's virtio MMIO models.
//!
//! The common register file is specified in VirtIO 1.3 §4.2.2: the magic,
//! version and device identifiers, the feature words, the queue
//! configuration registers, the notify register, the interrupt and status
//! registers, and the device-specific configuration starting at
//! [`CONFIG_OFFSET`]. A queue's size and table addresses must not change
//! while it is ready (§4.2.2.2); [`Queue`] enforces this on every write and
//! additionally refuses to deactivate a queue that still holds accepted
//! requests, so no completion can run against a reconfigured queue. The
//! descriptor table and rings of a validated queue follow the
//! split-virtqueue layout of §2.6, and `VIRTIO_F_VERSION_1` (bit 32) is the
//! feature bit of §6.
//!
//! See <https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.html>.

use ostd::kernelet::abi::{INVALID, MmioResult};

/// The offset at which a device's configuration space starts, relative to
/// the MMIO register base. Reads and writes below it address the common
/// registers, and reads and writes at or above it address the
/// device-specific configuration (VirtIO 1.3 §4.2.2).
pub(super) const CONFIG_OFFSET: u32 = 0x100;

/// Reads one 32-bit word from the supported 64-bit feature set.
pub(super) fn feature_word(features: u64, selector: u32) -> u32 {
    match selector {
        0 => features as u32,
        1 => (features >> 32) as u32,
        _ => 0,
    }
}

/// Records a driver feature word without aliasing unsupported selectors.
pub(super) fn write_driver_feature_word(features: &mut u64, selector: u32, word: u32) {
    let shift = match selector {
        0 => 0,
        1 => 32,
        _ => return,
    };
    let mask = u64::from(u32::MAX) << shift;
    *features = (*features & !mask) | (u64::from(word) << shift);
}

/// The outcome of a driver write to a queue's ready register
/// (VirtIO 1.3 §4.2.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReadyWrite {
    /// The requested ready state was recorded.
    Applied,
    /// The write was refused without further effect.
    Refused,
    /// The write was refused and the device flagged itself for reset.
    NeedsReset,
}

/// One virtqueue's driver-visible configuration and device-side progress.
///
/// `N` bounds the descriptor count. `pending[h]` marks a descriptor head
/// accepted by the device whose completion has not been published yet.
///
/// While the queue is ready, the driver must not change its size or table
/// addresses (VirtIO 1.3 §4.2.2.2). This model additionally refuses to
/// clear ready while heads are pending, so a queue may be reconfigured only
/// once every accepted request has completed or the whole device has been
/// reset; otherwise a stale completion could publish into a reconfigured
/// ring or take the modulo of a new, smaller size.
#[derive(Clone, Copy)]
pub(super) struct Queue<const N: usize> {
    pub(super) num: u32,
    pub(super) ready: bool,
    pub(super) desc: u64,
    pub(super) avail: u64,
    pub(super) used: u64,
    pub(super) last_avail: u16,
    pub(super) next_used: u16,
    pub(super) pending: [bool; N],
}

impl<const N: usize> Default for Queue<N> {
    fn default() -> Self {
        Self {
            num: 0,
            ready: false,
            desc: 0,
            avail: 0,
            used: 0,
            last_avail: 0,
            next_used: 0,
            pending: [false; N],
        }
    }
}

impl<const N: usize> Queue<N> {
    /// Applies a `QueueNum` write; refused while the queue is ready.
    pub(super) fn set_num(&mut self, num: u32) -> bool {
        if self.ready {
            return false;
        }
        self.num = num;
        true
    }

    /// Applies a queue table address write (`QueueDesc`, `QueueAvail` or
    /// `QueueUsed`, low or high word); refused while the queue is ready.
    pub(super) fn set_address_register(&mut self, offset: u32, value: u32) -> bool {
        if self.ready {
            return false;
        }
        let address = match offset {
            0x80 | 0x84 => &mut self.desc,
            0x90 | 0x94 => &mut self.avail,
            0xa0 | 0xa4 => &mut self.used,
            _ => return false,
        };
        if offset & 0x4 == 0 {
            set_low(address, value);
        } else {
            set_high(address, value);
        }
        true
    }

    /// Applies a `QueueReady` write, where `valid` reports whether the
    /// current configuration may be activated. Activation with an invalid
    /// configuration flags the device for reset; deactivation is refused
    /// while accepted requests are pending, so their completions can never
    /// run against a reconfigured queue.
    pub(super) fn set_ready(&mut self, value: u32, valid: bool) -> ReadyWrite {
        match value {
            1 => {
                if !valid {
                    return ReadyWrite::NeedsReset;
                }
                self.ready = true;
                ReadyWrite::Applied
            }
            0 => {
                if self.pending.iter().any(|pending| *pending) {
                    return ReadyWrite::Refused;
                }
                self.ready = false;
                ReadyWrite::Applied
            }
            _ => ReadyWrite::Refused,
        }
    }

    /// Reports whether a descriptor head may be accepted: it must be inside
    /// the queue and must not already hold an accepted request.
    pub(super) fn head_acceptable(&self, head: u16) -> bool {
        u32::from(head) < self.num && self.pending.get(head as usize) == Some(&false)
    }

    /// Records an accepted descriptor head until its completion. Only call
    /// this for a head that [`Queue::head_acceptable`] just accepted.
    pub(super) fn mark_accepted(&mut self, head: u16) {
        self.pending[head as usize] = true;
    }

    /// Clears the pending mark of a completed descriptor head.
    pub(super) fn retire(&mut self, head: u16) {
        self.pending[head as usize] = false;
    }
}

/// Replaces the low word of a 64-bit register pair.
pub(super) fn set_low(word: &mut u64, value: u32) {
    *word = (*word & !u32::MAX as u64) | value as u64;
}

/// Replaces the high word of a 64-bit register pair.
pub(super) fn set_high(word: &mut u64, value: u32) {
    *word = (*word & u32::MAX as u64) | ((value as u64) << 32);
}

/// Reports an unsupported read.
pub(super) fn invalid_read() -> MmioResult {
    MmioResult {
        status: -INVALID,
        value: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::{feature_word, write_driver_feature_word};

    #[test]
    fn unsupported_selector_does_not_alias_a_feature_word() {
        let mut features = 0x1234_5678_9abc_def0;
        assert_eq!(feature_word(features, 0), 0x9abc_def0);
        assert_eq!(feature_word(features, 1), 0x1234_5678);
        assert_eq!(feature_word(features, 2), 0);
        write_driver_feature_word(&mut features, 2, u32::MAX);
        assert_eq!(features, 0x1234_5678_9abc_def0);
        write_driver_feature_word(&mut features, 1, 0xdead_beef);
        assert_eq!(features, 0xdead_beef_9abc_def0);
    }
}

#[cfg(ktest)]
mod queue_tests {
    use ostd::prelude::*;

    use super::{Queue, ReadyWrite};

    /// A small descriptor bound keeps the tests fast; the guards are
    /// generic over the queue capacity.
    const N: usize = 8;

    /// Builds a queue whose configuration would pass the models'
    /// address-alignment and size validation.
    fn configured_queue() -> Queue<N> {
        let mut queue = Queue::<N>::default();
        assert!(queue.set_num(N as u32));
        assert!(queue.set_address_register(0x80, 0x1000));
        assert!(queue.set_address_register(0x84, 0));
        assert!(queue.set_address_register(0x90, 0x2000));
        assert!(queue.set_address_register(0x94, 0));
        assert!(queue.set_address_register(0xa0, 0x3000));
        assert!(queue.set_address_register(0xa4, 0));
        assert_eq!(queue.desc, 0x1000);
        assert_eq!(queue.avail, 0x2000);
        assert_eq!(queue.used, 0x3000);
        queue
    }

    #[ktest]
    fn ready_queue_refuses_size_and_address_writes() {
        let mut queue = configured_queue();
        assert_eq!(queue.set_ready(1, true), ReadyWrite::Applied);
        assert!(!queue.set_num(4));
        assert_eq!(queue.num, N as u32);
        assert!(!queue.set_address_register(0x80, 0x9000));
        assert_eq!(queue.desc, 0x1000);
        assert!(!queue.set_address_register(0x94, 0x9000));
        assert_eq!(queue.avail, 0x2000);
    }

    #[ktest]
    fn queue_ready_accepts_only_zero_and_one() {
        let mut queue = configured_queue();
        assert_eq!(queue.set_ready(2, true), ReadyWrite::Refused);
        assert!(!queue.ready);
        assert_eq!(queue.set_ready(u32::MAX, true), ReadyWrite::Refused);
        assert!(!queue.ready);
        // Activating an unvalidated configuration asks the driver to reset.
        assert_eq!(queue.set_ready(1, false), ReadyWrite::NeedsReset);
        assert!(!queue.ready);
        assert_eq!(queue.set_ready(1, true), ReadyWrite::Applied);
        assert!(queue.ready);
    }

    // Regression: a driver could clear QueueReady while the device still
    // held accepted requests, then shrink the queue; the next completion
    // took the modulo of the new size and published into a ring that was
    // never revalidated (or panicked on size zero).
    #[ktest]
    fn deactivation_is_refused_while_requests_are_pending() {
        let mut queue = configured_queue();
        assert_eq!(queue.set_ready(1, true), ReadyWrite::Applied);
        assert!(queue.head_acceptable(0));
        queue.mark_accepted(0);
        assert!(!queue.head_acceptable(0));
        assert_eq!(queue.set_ready(0, true), ReadyWrite::Refused);
        assert!(queue.ready);
        assert!(!queue.set_num(2));
        assert_eq!(queue.num, N as u32);
        // Completing the request frees the queue for reconfiguration.
        queue.retire(0);
        assert_eq!(queue.set_ready(0, true), ReadyWrite::Applied);
        assert!(!queue.ready);
        assert!(queue.set_num(2));
    }

    #[ktest]
    fn quiescent_deactivation_allows_reconfiguration() {
        let mut queue = configured_queue();
        assert_eq!(queue.set_ready(1, true), ReadyWrite::Applied);
        assert_eq!(queue.set_ready(0, true), ReadyWrite::Applied);
        assert!(!queue.ready);
        assert!(queue.set_num(4));
        assert_eq!(queue.num, 4);
        assert!(queue.set_address_register(0x80, 0x5000));
        assert_eq!(queue.desc, 0x5000);
    }

    #[ktest]
    fn duplicate_and_out_of_range_heads_are_not_accepted() {
        let mut queue = configured_queue();
        assert!(queue.set_num(4));
        assert!(!queue.head_acceptable(4));
        assert!(!queue.head_acceptable(N as u16));
        assert!(!queue.head_acceptable(u16::MAX));
        assert!(queue.head_acceptable(3));
        queue.mark_accepted(3);
        assert!(!queue.head_acceptable(3));
        queue.retire(3);
        assert!(queue.head_acceptable(3));
    }
}
