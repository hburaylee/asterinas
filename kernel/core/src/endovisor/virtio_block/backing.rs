// SPDX-License-Identifier: MPL-2.0

//! Reusable, charged DMA buffers for a raw block-device backing.
//!
//! One guest request becomes one Host BIO. Guest buffers remain accessed through
//! scoped pins, and payload is copied once between them and the Host DMA buffer.
//! The worker owns the buffers and reuses them only after the BIO completes.

use aster_block::{
    BlockDevice,
    bio::{Bio, BioDirection, BioSegment, BioStatus, BioType},
    id::Sid,
};
use ostd::{
    kernelet::{
        control::{HostByteCharge, Kernelet},
        guest_memory::GuestMemory,
    },
    mm::io::util::HasVmReaderWriter,
};

use super::{Buffer, MAX_REQUEST_BYTES, REQUEST_READ};
use crate::{
    endovisor::policy::{Admission, EndpointReservation},
    prelude::*,
};

pub(super) struct BlockIo {
    device: Arc<dyn BlockDevice>,
    owner: Arc<Kernelet>,
    admission: Arc<Admission>,
    read_buffer: Option<ChargedBuffer>,
    write_buffer: Option<ChargedBuffer>,
}

struct ChargedBuffer {
    // Fields drop in declaration order: release our DMA ownership before
    // refunding either charge.
    segment: BioSegment,
    _host_charge: HostByteCharge,
    bytes: usize,
    _reservation: EndpointReservation,
}

impl ChargedBuffer {
    fn new(
        owner: &Arc<Kernelet>,
        admission: &Arc<Admission>,
        bytes: usize,
        direction: BioDirection,
    ) -> Result<Self> {
        let reservation = admission.reserve_endpoint_bytes(bytes)?;
        let host_charge = owner.reserve_host_bytes(bytes)?;
        let segment = BioSegment::try_alloc(bytes / PAGE_SIZE, direction)?;
        Ok(Self {
            segment,
            _host_charge: host_charge,
            bytes,
            _reservation: reservation,
        })
    }
}

impl BlockIo {
    pub(super) fn new(
        device: Arc<dyn BlockDevice>,
        owner: Arc<Kernelet>,
        admission: Arc<Admission>,
    ) -> Self {
        Self {
            device,
            owner,
            admission,
            read_buffer: None,
            write_buffer: None,
        }
    }

    fn buffer(&mut self, len: usize, direction: BioDirection) -> Result<BioSegment> {
        let slot = match direction {
            BioDirection::FromDevice => &mut self.read_buffer,
            BioDirection::ToDevice => &mut self.write_buffer,
        };
        if slot.as_ref().is_none_or(|buffer| buffer.bytes < len) {
            let bytes = len.div_ceil(PAGE_SIZE) * PAGE_SIZE;
            // This worker is serial. The preceding synchronous BIO released
            // its segments before publishing completion, and transfer() has
            // dropped its local view. Retire the old cache before reserving
            // its replacement, so growth needs only the final capacity.
            drop(slot.take());
            *slot = Some(ChargedBuffer::new(
                &self.owner,
                &self.admission,
                bytes,
                direction,
            )?);
        }
        Ok(slot.as_ref().unwrap().segment.slice(0..len)?)
    }

    pub(super) fn transfer(
        &mut self,
        memory: &GuestMemory,
        buffers: &[Buffer],
        offset: usize,
        len: usize,
        operation: u32,
    ) -> Result<u32, (Error, u32)> {
        if len == 0 {
            return Ok(0);
        }
        if len > MAX_REQUEST_BYTES {
            return Err((
                Error::with_message(Errno::EINVAL, "block request exceeds staging bound"),
                0,
            ));
        }
        let (kind, direction) = if operation == REQUEST_READ {
            (BioType::Read, BioDirection::FromDevice)
        } else {
            (BioType::Write, BioDirection::ToDevice)
        };
        let segment = self.buffer(len, direction).map_err(|error| (error, 0))?;
        if kind == BioType::Write {
            copy_from_guest(memory, buffers, &segment).map_err(|error| (error, 0))?;
        }
        let bio = Bio::new(kind, Sid::from_offset(offset), vec![segment.clone()], None);
        if bio
            .submit_and_wait(self.device.as_ref())
            .map_err(|error| (error.into(), 0))?
            != BioStatus::Complete
        {
            return Err((
                Error::with_message(Errno::EIO, "block backing BIO failed"),
                0,
            ));
        }
        if kind == BioType::Read {
            copy_to_guest(memory, buffers, &segment)?;
            Ok(len as u32)
        } else {
            Ok(0)
        }
    }
}

fn copy_to_guest(
    memory: &GuestMemory,
    buffers: &[Buffer],
    segment: &BioSegment,
) -> Result<(), (Error, u32)> {
    let mut reader = segment.reader().map_err(|error| (error.into(), 0))?;
    let mut offset = 0;
    for buffer in buffers {
        let len = buffer.len as usize;
        if len == 0 {
            continue;
        }
        let result = memory
            .with_writer(buffer.paddr, len, |writer| {
                #[cfg(kernelet_rq1_diagnostics)]
                let copied = crate::endovisor::io_copy_profile::measure_fallible(
                    crate::endovisor::io_copy_profile::Category::BlockRead,
                    len,
                    || reader.read_fallible(writer),
                );
                #[cfg(not(kernelet_rq1_diagnostics))]
                let copied = reader.read_fallible(writer);
                let copied = copied.map_err(|(error, _)| error)?;
                if copied != len {
                    return Err(ostd::Error::IoError);
                }
                Ok(())
            })
            .and_then(|result| result);
        if let Err(error) = result {
            return Err((error.into(), offset as u32));
        }
        offset += len;
    }
    Ok(())
}

fn copy_from_guest(memory: &GuestMemory, buffers: &[Buffer], segment: &BioSegment) -> Result<()> {
    let mut writer = segment.writer()?;
    for buffer in buffers {
        let len = buffer.len as usize;
        if len == 0 {
            continue;
        }
        memory.with_reader(buffer.paddr, len, |reader| {
            #[cfg(kernelet_rq1_diagnostics)]
            let copied = crate::endovisor::io_copy_profile::measure_fallible(
                crate::endovisor::io_copy_profile::Category::BlockWrite,
                len,
                || reader.read_fallible(&mut writer),
            );
            #[cfg(not(kernelet_rq1_diagnostics))]
            let copied = reader.read_fallible(&mut writer);
            let copied = copied.map_err(|(error, _)| error)?;
            if copied != len {
                return Err(ostd::Error::IoError);
            }
            Ok(())
        })??;
    }
    Ok(())
}
