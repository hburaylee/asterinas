// SPDX-License-Identifier: MPL-2.0

//! Bounded virtio-vsock wire packets owned by the Host.

use alloc::vec::Vec;

use super::MAX_PAYLOAD;

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

    pub(in crate::endovisor) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::HEADER_LEN {
            return None;
        }
        let get_u16 = |at: usize| u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
        let get_u32 = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let get_u64 = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        // The switch overwrites this field with the sender's assigned CID.
        let src_cid = 0;
        let dst_cid = u32::try_from(get_u64(8)).ok()?;
        let len = get_u32(24) as usize;
        if get_u16(28) != 1 || len > MAX_PAYLOAD || bytes.len() != Self::HEADER_LEN + len {
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
            payload: bytes[Self::HEADER_LEN..].to_vec(),
        })
    }

    pub(in crate::endovisor) fn to_bytes(&self, bytes: &mut [u8]) -> Option<usize> {
        let len = Self::HEADER_LEN.checked_add(self.payload.len())?;
        if bytes.len() < len || self.payload.len() > MAX_PAYLOAD {
            return None;
        }
        bytes[0..8].copy_from_slice(&u64::from(self.src_cid).to_le_bytes());
        bytes[8..16].copy_from_slice(&u64::from(self.dst_cid).to_le_bytes());
        bytes[16..20].copy_from_slice(&self.src_port.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.dst_port.to_le_bytes());
        bytes[24..28].copy_from_slice(&(self.payload.len() as u32).to_le_bytes());
        bytes[28..30].copy_from_slice(&1u16.to_le_bytes());
        bytes[30..32].copy_from_slice(&self.op.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.flags.to_le_bytes());
        bytes[36..40].copy_from_slice(&self.buf_alloc.to_le_bytes());
        bytes[40..44].copy_from_slice(&self.fwd_cnt.to_le_bytes());
        bytes[Self::HEADER_LEN..len].copy_from_slice(&self.payload);
        Some(len)
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
        }
    }
}
