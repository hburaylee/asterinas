// SPDX-License-Identifier: MPL-2.0

//! Reusable, charged DMA buffers for a raw block-device backing.
//!
//! One guest request becomes one Host BIO. Guest buffers remain accessed through
//! scoped pins, and payload is copied once between them and the Host DMA buffer.
//! Bounded slots own buffers and reuse them only after their BIOs complete.

use aster_block::{
    BlockDevice,
    bio::{Bio, BioDirection, BioSegment, BioType},
    id::Sid,
};
use io_util::batch::IoBatch;
use ostd::{
    kernelet::{
        control::{HostByteCharge, Kernelet},
        guest_memory::GuestMemory,
    },
    mm::io::util::HasVmReaderWriter,
};

use super::{Buffer, MAX_REQUEST_BYTES, REQUEST_READ};

pub(super) const IO_DEPTH: usize = 4;
// This is a total per-device staging bound, not a per-slot allocation.
pub(super) const STAGING_BYTES: usize = MAX_REQUEST_BYTES;
use crate::{
    endovisor::policy::{Admission, EndpointReservation},
    prelude::*,
};

pub(super) struct BlockIo {
    device: Arc<dyn BlockDevice>,
    owner: Arc<Kernelet>,
    admission: Arc<Admission>,
    buffers: [Option<Arc<ChargedBuffer>>; IO_DEPTH],
}

struct ChargedBuffer {
    // Fields drop in declaration order: release our DMA ownership before
    // refunding either charge.
    segment: CachedSegment,
    _host_charge: HostByteCharge,
    bytes: usize,
    _reservation: EndpointReservation,
    direction: BioDirection,
}

struct CachedSegment {
    owner: BioSegment,
    view: BioSegment,
}

impl CachedSegment {
    fn new(owner: BioSegment) -> Self {
        Self {
            view: owner.clone(),
            owner,
        }
    }

    fn view(&mut self, len: usize) -> Result<BioSegment> {
        if self.view.nbytes() != len {
            self.view = self.owner.slice(0..len)?;
        }
        Ok(self.view.clone())
    }
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
        let segment = BioSegment::try_alloc_shared(bytes / PAGE_SIZE, direction)?;
        Ok(Self {
            segment: CachedSegment::new(segment),
            _host_charge: host_charge,
            bytes,
            _reservation: reservation,
            direction,
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
            buffers: core::array::from_fn(|_| None),
        }
    }

    fn buffer(
        &mut self,
        slot: usize,
        len: usize,
        direction: BioDirection,
    ) -> Result<(Arc<ChargedBuffer>, BioSegment)> {
        let bytes = len.div_ceil(PAGE_SIZE) * PAGE_SIZE;
        if self.buffers[slot]
            .as_ref()
            .is_none_or(|buffer| buffer.bytes < bytes || buffer.direction != direction)
        {
            // Slots only become reusable after finish() has waited for the BIO.
            debug_assert!(
                self.buffers[slot]
                    .as_ref()
                    .is_none_or(|b| Arc::strong_count(b) == 1)
            );
            drop(self.buffers[slot].take());
            // Retire idle caches before reserving replacement capacity. In-flight
            // buffers retain both charges through the driver's completion callback.
            for other in &mut self.buffers {
                if other.as_ref().is_some_and(|b| Arc::strong_count(b) == 1) {
                    drop(other.take());
                }
            }
            let resident: usize = self.buffers.iter().flatten().map(|b| b.bytes).sum();
            if resident + bytes > STAGING_BYTES {
                return_errno_with_message!(Errno::EAGAIN, "block staging batch is full");
            }
            self.buffers[slot] = Some(Arc::new(ChargedBuffer::new(
                &self.owner,
                &self.admission,
                bytes,
                direction,
            )?));
        }
        let buffer = self.buffers[slot].as_mut().unwrap();
        let segment = Arc::get_mut(buffer)
            .expect("reuse of in-flight block slot")
            .segment
            .view(len)?;
        Ok((buffer.clone(), segment))
    }

    pub(super) fn submit(
        &mut self,
        slot: usize,
        memory: &GuestMemory,
        buffers: &[Buffer],
        offset: usize,
        len: usize,
        operation: u32,
    ) -> Result<PendingTransfer> {
        if len == 0 || len > MAX_REQUEST_BYTES {
            return_errno_with_message!(Errno::EINVAL, "invalid block staging length");
        }
        let (kind, direction) = if operation == REQUEST_READ {
            (BioType::Read, BioDirection::FromDevice)
        } else {
            (BioType::Write, BioDirection::ToDevice)
        };
        let (buffer, segment) = self.buffer(slot, len, direction)?;
        if kind == BioType::Write {
            copy_from_guest(memory, buffers, &segment)?;
        }
        let retained = buffer.clone();
        // Even unwinding the worker cannot refund memory while a driver still
        // owns DMA. SubmittedBio drops its segments before invoking this callback.
        let bio = Bio::new(
            kind,
            Sid::from_offset(offset),
            vec![segment.clone()],
            Some(Box::new(move |_| drop(retained))),
        );
        let mut batch = IoBatch::new();
        bio.submit(self.device.as_ref(), &mut batch)?;
        Ok(PendingTransfer {
            segment,
            batch,
            _buffer: buffer,
            kind,
            len,
        })
    }
}

pub(super) struct PendingTransfer {
    segment: BioSegment,
    batch: IoBatch,
    _buffer: Arc<ChargedBuffer>,
    kind: BioType,
    len: usize,
}

impl PendingTransfer {
    pub(super) fn finish(
        self,
        memory: &GuestMemory,
        buffers: &[Buffer],
        copyback_allowed: impl FnOnce() -> bool,
    ) -> Result<u32, (Error, u32)> {
        self.batch.wait_all().map_err(|_| {
            (
                Error::with_message(Errno::EIO, "block backing BIO failed"),
                0,
            )
        })?;
        if self.kind == BioType::Read && copyback_allowed() {
            copy_to_guest(memory, buffers, &self.segment)?;
            Ok(self.len as u32)
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

#[cfg(ktest)]
mod test {
    use ostd::{cpu::PinCurrentCpu, prelude::ktest};

    use super::*;

    #[derive(Debug)]
    struct DeferredDevice(
        SpinLock<Vec<aster_block::bio::SubmittedBio>, ostd::sync::LocalIrqDisabled>,
    );

    impl BlockDevice for DeferredDevice {
        fn enqueue(
            &self,
            bio: aster_block::bio::SubmittedBio,
        ) -> core::result::Result<(), aster_block::bio::BioEnqueueError> {
            self.0.lock().push(bio);
            Ok(())
        }
        fn metadata(&self) -> aster_block::BlockDeviceMeta {
            aster_block::BlockDeviceMeta {
                max_nr_segments_per_bio: 1,
                nr_sectors: 16384,
            }
        }
        fn name(&self) -> &str {
            "deferred-bio-test"
        }
        fn id(&self) -> device_id::DeviceId {
            device_id::DeviceId::null()
        }
    }

    struct DormantHooks;
    impl ostd::kernelet::control::KerneletHooks for DormantHooks {
        fn create_vcpu_thread(
            &self,
            _: &Arc<Kernelet>,
            _: u16,
            _: ostd::cpu::CpuId,
            _: i8,
        ) -> ostd::Result<Arc<ostd::task::Task>> {
            ostd::task::TaskOptions::new(|| panic!("block fixture stays dormant"))
                .data(())
                .build()
                .map(Arc::new)
        }
        fn realtime_now(&self) -> core::time::Duration {
            core::time::Duration::ZERO
        }
        fn mmio_read(&self, _: u16, _: u32, _: u32) -> ostd::kernelet::abi::MmioResult {
            panic!("no Image MMIO in block fixture")
        }
        fn mmio_write(&self, _: u16, _: u32, _: u32, _: u64) -> i64 {
            panic!("no Image MMIO in block fixture")
        }
        fn log(&self, _: u32, _: &str, _: &str) -> bool {
            panic!("no Image log in block fixture")
        }
        fn set_vcpu_nice(&self, _: i8) -> ostd::Result<()> {
            panic!("no budget updates in block fixture")
        }
    }

    #[ktest]
    fn raw_bios_overlap_and_retain_dma_charges_until_real_completion() {
        use ostd::{
            cpu::CpuSet,
            kernelet::control::{
                CpuBudget, KerneletConfig, KerneletKind, KerneletPolicy, KerneletState, KillReason,
            },
        };
        aster_time::init_for_ktest();
        crate::time::clocks::init_for_ktest();
        crate::endovisor::reaper::init().unwrap();
        let kind = KerneletKind::register_dormant_fixture().unwrap();
        let mut cpus = CpuSet::new_empty();
        cpus.add(ostd::irq::disable_local().current_cpu());
        let admission = Admission::reserve(crate::process::Uid::new(0x6e000001), 1, 1, 0).unwrap();
        let owner = kind
            .create(
                &KerneletConfig {
                    cmdline: "",
                    initial_grains: 1,
                    max_grains: 1,
                    max_meta_sections: 1,
                    budget: CpuBudget::default(),
                    policy: KerneletPolicy::default(),
                    max_tasks: 1,
                    devices: &[],
                    cpus,
                },
                Arc::new(DormantHooks),
            )
            .unwrap();
        admission.mark_created();
        let memory = owner.guest_memory();
        let device = Arc::new(DeferredDevice(SpinLock::new(Vec::with_capacity(IO_DEPTH))));
        let mut io = BlockIo::new(device.clone(), owner.clone(), admission.clone());
        let baseline = owner.stats().host_bytes_charged;
        let mut pending = Vec::new();
        for slot in 0..IO_DEPTH {
            if slot == IO_DEPTH - 1 {
                assert!(
                    io.submit(
                        slot,
                        &memory,
                        &[],
                        slot * 512,
                        STAGING_BYTES / 2,
                        REQUEST_READ
                    )
                    .is_err(),
                    "in-flight DMA exceeded the total staging bound"
                );
                assert_eq!(device.0.lock().len(), IO_DEPTH - 1);
            }
            // Exercise real submit and DMA ownership. Guest copyback is tested
            // by the system regression, not this deferred driver fixture.
            pending.push(
                io.submit(
                    slot,
                    &memory,
                    &[],
                    slot * 512,
                    STAGING_BYTES / IO_DEPTH,
                    REQUEST_READ,
                )
                .unwrap(),
            );
        }
        assert_eq!(
            device.0.lock().len(),
            IO_DEPTH,
            "submit waited before filling the batch"
        );
        assert_eq!(owner.stats().host_bytes_charged - baseline, STAGING_BYTES);
        // Complete in reverse order, with distinct actual DMA payloads.
        while let Some(bio) = device.0.lock().pop() {
            let byte = bio.sid_range().start.to_raw() as u8;
            bio.segments()[0]
                .dma_slice()
                .writer()
                .unwrap()
                .write(&mut ostd::mm::VmReader::from([byte].as_slice()));
            bio.complete(aster_block::bio::BioStatus::Complete);
        }
        for (index, transfer) in pending.drain(..).enumerate() {
            let mut byte = [0];
            transfer
                .segment
                .dma_slice()
                .reader()
                .unwrap()
                .read(&mut ostd::mm::VmWriter::from(byte.as_mut_slice()));
            assert_eq!(byte[0], index as u8);
            transfer.finish(&memory, &[], || false).unwrap();
        }
        // Abandon submitter/cache handles while the driver still owns BIOs.
        // Charges must remain until its actual completion callback runs.
        for slot in 0..IO_DEPTH {
            pending.push(
                io.submit(
                    slot,
                    &memory,
                    &[],
                    slot * 512,
                    STAGING_BYTES / IO_DEPTH,
                    REQUEST_READ,
                )
                .unwrap(),
            );
        }
        drop(pending);
        drop(io);
        assert_eq!(owner.stats().host_bytes_charged - baseline, STAGING_BYTES);
        for remaining in (0..IO_DEPTH).rev() {
            let bio = device.0.lock().pop().unwrap();
            bio.complete(aster_block::bio::BioStatus::IoError);
            assert_eq!(
                owner.stats().host_bytes_charged - baseline,
                remaining * STAGING_BYTES / IO_DEPTH
            );
        }
        owner.kill(KillReason::Requested).unwrap();
        for _ in 0..10000 {
            if owner.state() == KerneletState::Exited {
                break;
            }
            ostd::task::Task::yield_now();
        }
        assert_eq!(owner.state(), KerneletState::Exited);
        owner.destroy().unwrap();
        admission.release_after_destroy();
    }

    #[ktest]
    fn cached_bio_view_reuses_storage_and_preserves_previous_view_on_error() {
        let owner = BioSegment::try_alloc_shared(16, BioDirection::ToDevice).unwrap();
        let mut cache = CachedSegment::new(owner);
        let first = cache.view(PAGE_SIZE).unwrap();
        let second = cache.view(PAGE_SIZE).unwrap();
        assert!(core::ptr::eq(first.dma_slice(), second.dma_slice()));
        assert!(cache.view(17 * PAGE_SIZE).is_err());
        let after_error = cache.view(PAGE_SIZE).unwrap();
        assert!(core::ptr::eq(first.dma_slice(), after_error.dma_slice()));
        let sector = cache.view(512).unwrap();
        assert_eq!(sector.nbytes(), 512);
        assert!(!core::ptr::eq(first.dma_slice(), sector.dma_slice()));
        drop(cache);
        let bytes = [0x5au8; 512];
        assert_eq!(
            sector
                .writer()
                .unwrap()
                .write(&mut ostd::mm::VmReader::from(bytes.as_slice())),
            bytes.len()
        );
        let mut output = [0u8; 512];
        assert_eq!(
            sector
                .dma_slice()
                .reader()
                .unwrap()
                .read(&mut ostd::mm::VmWriter::from(output.as_mut_slice())),
            bytes.len()
        );
        assert_eq!(output, bytes);
    }
}
