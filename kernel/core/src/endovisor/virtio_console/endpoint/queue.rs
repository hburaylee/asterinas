// SPDX-License-Identifier: MPL-2.0

//! One bounded byte queue of a console endpoint, with its producer and
//! consumer halves.
//!
//! Lock discipline: each queue guards its producer and consumer halves with
//! a separate blocking [`Mutex`], as `crate::fs::pipe` does. The mutexes are
//! leaf locks and never nested. A queue mutex is held while copying to or
//! from the descriptor's user buffer; it is `ostd::sync::Mutex`, on which
//! contenders sleep, so a fault inside such a copy never spins a CPU.

use crate::{
    prelude::*,
    util::ring_buffer::{ConsumerU8Ext, ProducerU8Ext, RbConsumer, RbProducer, RingBuffer},
};

/// The fixed capacity of each queue, in bytes.
///
/// The value must remain a power of two, as the ring buffer requires.
pub(super) const QUEUE_CAPACITY: usize = 4096;

/// One bounded byte queue with its producer and consumer halves.
pub(super) struct Queue {
    pub(super) producer: Mutex<Option<RbProducer<u8>>>,
    pub(super) consumer: Mutex<Option<RbConsumer<u8>>>,
}

impl Queue {
    pub(super) fn new() -> Self {
        let (producer, consumer) = RingBuffer::new(QUEUE_CAPACITY).split();
        Self {
            producer: Mutex::new(Some(producer)),
            consumer: Mutex::new(Some(consumer)),
        }
    }

    pub(super) fn revoke(&self) {
        self.producer.lock().take();
        self.consumer.lock().take();
    }

    /// Appends as many bytes of `src` as fit, returning the number queued.
    pub(super) fn push(&self, src: &[u8]) -> usize {
        let mut reader = VmReader::from(src).to_fallible();
        let mut producer = self.producer.lock();
        // The reader reads from an in-kernel slice and cannot fail.
        producer
            .as_mut()
            .map(|producer| producer.write_fallible(&mut reader).unwrap_or(0))
            .unwrap_or(0)
    }

    /// Removes up to `dst.len()` bytes into `dst`, returning the number moved.
    pub(super) fn pop(&self, dst: &mut [u8]) -> usize {
        let mut writer = VmWriter::from(dst).to_fallible();
        let mut consumer = self.consumer.lock();
        // The writer writes into an in-kernel slice and cannot fail.
        consumer
            .as_mut()
            .map(|consumer| consumer.read_fallible(&mut writer).unwrap_or(0))
            .unwrap_or(0)
    }

    /// Returns whether any byte is queued.
    pub(super) fn is_empty(&self) -> bool {
        self.consumer
            .lock()
            .as_ref()
            .is_none_or(RbConsumer::is_empty)
    }

    /// Returns whether at least one byte fits.
    pub(super) fn has_space(&self) -> bool {
        self.producer
            .lock()
            .as_ref()
            .is_some_and(|producer| producer.free_len() > 0)
    }
}
