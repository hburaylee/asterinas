// SPDX-License-Identifier: MPL-2.0

//! Bounded virtio-vsock wire packets owned by the Host.

use alloc::{sync::Arc, vec::Vec};
use core::mem::size_of;

use ostd::kernelet::control::Kernelet;

use super::MAX_PAYLOAD;
use crate::{
    endovisor::{policy::Admission, virtio_vsock::PacketCharge},
    prelude::{Errno, Error},
};

/// A packet copied out of a tenant's virtqueue, independent of guest memory.
pub(in crate::endovisor) struct Packet {
    pub(in crate::endovisor) src_cid: u32,
    pub(in crate::endovisor) dst_cid: u32,
    pub(in crate::endovisor) src_port: u32,
    pub(in crate::endovisor) dst_port: u32,
    pub(in crate::endovisor) op: u16,
    pub(in crate::endovisor) flags: u32,
    pub(in crate::endovisor) buf_alloc: u32,
    pub(in crate::endovisor) fwd_cnt: u32,
    pub(in crate::endovisor) payload: Vec<u8>,
    // Field order releases the allocated payload before its reservation.
    pub(in crate::endovisor) payload_charge: Option<PacketCharge>,
}

impl Packet {
    pub(in crate::endovisor) const HEADER_LEN: usize = 44;
    pub(in crate::endovisor) const REQUEST: u16 = 1;
    pub(in crate::endovisor) const RESPONSE: u16 = 2;
    pub(in crate::endovisor) const RST: u16 = 3;
    pub(in crate::endovisor) const SHUTDOWN: u16 = 4;
    pub(in crate::endovisor) const RW: u16 = 5;
    pub(in crate::endovisor) const CREDIT_UPDATE: u16 = 6;
    pub(in crate::endovisor) const CREDIT_REQUEST: u16 = 7;

    /// Reads and validates only the fixed header, without allocating payload.
    pub(in crate::endovisor) fn read_header_from<E>(
        len: usize,
        mut read: impl FnMut(&mut [u8]) -> Result<(), E>,
    ) -> Result<Option<(Self, usize)>, E> {
        if len < Self::HEADER_LEN {
            return Ok(None);
        }
        let mut header = [0u8; Self::HEADER_LEN];
        read(&mut header)?;
        Ok(Self::from_header(&header, len).map(|packet| (packet, len - Self::HEADER_LEN)))
    }

    /// Precharges the packet and its exact payload capacity before allocation.
    /// The charge follows the owned packet until a receive queue takes it.
    pub(in crate::endovisor) fn prepare_payload(
        &mut self,
        len: usize,
        owner: Arc<Kernelet>,
        admission: Arc<Admission>,
    ) -> Result<(), Error> {
        if len > MAX_PAYLOAD || self.payload.capacity() != 0 || self.payload_charge.is_some() {
            return Err(Error::with_message(
                Errno::EINVAL,
                "invalid vsock payload allocation",
            ));
        }
        if len == 0 {
            return Ok(());
        }
        let charge = PacketCharge::try_reserve(owner, admission, size_of::<Self>() + len)?;
        // The local guard covers allocation. On failure Vec is unchanged and
        // the guard refunds before the caller sends a resource-rejection RST.
        self.payload
            .try_reserve_exact(len)
            .map_err(|_| Error::with_message(Errno::ENOMEM, "cannot allocate vsock payload"))?;
        self.payload_charge = Some(charge);
        self.payload.resize(len, 0);
        Ok(())
    }

    fn from_header(bytes: &[u8; Self::HEADER_LEN], packet_len: usize) -> Option<Self> {
        if packet_len < Self::HEADER_LEN {
            return None;
        }
        let get_u16 = |at: usize| u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
        let get_u32 = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let get_u64 = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        // The switch overwrites this field with the sender's assigned CID.
        let src_cid = 0;
        let dst_cid = u32::try_from(get_u64(8)).ok()?;
        let len = get_u32(24) as usize;
        if get_u16(28) != 1 || len > MAX_PAYLOAD || packet_len != Self::HEADER_LEN + len {
            return None;
        }
        let op = get_u16(30);
        if !(Self::REQUEST..=Self::CREDIT_REQUEST).contains(&op) || (op != Self::RW && len != 0) {
            return None;
        }
        let flags = get_u32(32);
        if (op == Self::SHUTDOWN && flags & !3 != 0) || (op != Self::SHUTDOWN && flags != 0) {
            return None;
        }
        Some(Self {
            src_cid,
            dst_cid,
            src_port: get_u32(16),
            dst_port: get_u32(20),
            op,
            flags,
            buf_alloc: get_u32(36),
            fwd_cnt: get_u32(40),
            payload: Vec::new(),
            payload_charge: None,
        })
    }

    /// Writes a range of the same owned payload without copying a remainder.
    pub(in crate::endovisor) fn write_range_to<E>(
        &self,
        range: core::ops::Range<usize>,
        mut write: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<Option<usize>, E> {
        let Some(payload) = self.payload.get(range) else {
            return Ok(None);
        };
        if payload.len() > MAX_PAYLOAD {
            return Ok(None);
        }
        let len = Self::HEADER_LEN + payload.len();
        let mut bytes = [0u8; Self::HEADER_LEN];
        bytes[0..8].copy_from_slice(&u64::from(self.src_cid).to_le_bytes());
        bytes[8..16].copy_from_slice(&u64::from(self.dst_cid).to_le_bytes());
        bytes[16..20].copy_from_slice(&self.src_port.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.dst_port.to_le_bytes());
        bytes[24..28].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes[28..30].copy_from_slice(&1u16.to_le_bytes());
        bytes[30..32].copy_from_slice(&self.op.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.flags.to_le_bytes());
        bytes[36..40].copy_from_slice(&self.buf_alloc.to_le_bytes());
        bytes[40..44].copy_from_slice(&self.fwd_cnt.to_le_bytes());
        write(&bytes)?;
        if !payload.is_empty() {
            write(payload)?;
        }
        Ok(Some(len))
    }

    pub(in crate::endovisor) fn reply(&self, op: u16, buf_alloc: u32, fwd_cnt: u32) -> Self {
        Self {
            src_cid: self.dst_cid,
            dst_cid: self.src_cid,
            src_port: self.dst_port,
            dst_port: self.src_port,
            op,
            flags: 0,
            buf_alloc,
            fwd_cnt,
            payload: Vec::new(),
            payload_charge: None,
        }
    }
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn vsock_payload_ranges_keep_the_original_allocation_and_wire_length() {
        let packet = Packet {
            src_cid: 3,
            dst_cid: 4,
            src_port: 100,
            dst_port: 200,
            op: Packet::RW,
            flags: 0,
            buf_alloc: 65536,
            fwd_cnt: 0,
            payload: (0..MAX_PAYLOAD).map(|at| at as u8).collect(),
            payload_charge: None,
        };
        let pointer = packet.payload.as_ptr();
        let capacity = packet.payload.capacity();
        let mut received = Vec::new();
        for offset in 0..MAX_PAYLOAD {
            let mut wire = Vec::new();
            let len = packet
                .write_range_to(offset..offset + 1, |bytes| {
                    wire.extend_from_slice(bytes);
                    Ok::<_, ()>(())
                })
                .unwrap()
                .unwrap();
            assert_eq!(len, Packet::HEADER_LEN + 1);
            assert_eq!(u32::from_le_bytes(wire[24..28].try_into().unwrap()), 1);
            received.push(wire[Packet::HEADER_LEN]);
            assert_eq!(packet.payload.as_ptr(), pointer);
            assert_eq!(packet.payload.capacity(), capacity);
        }
        assert_eq!(received, packet.payload);
        assert_eq!(
            packet.write_range_to(MAX_PAYLOAD..MAX_PAYLOAD + 1, |_| {
                panic!("an invalid range must not publish any bytes")
            }),
            Ok::<_, ()>(None)
        );
    }
}
