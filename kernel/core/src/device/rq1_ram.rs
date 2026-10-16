// SPDX-License-Identifier: MPL-2.0

//! Dedicated, volatile block backing for the opt-in RQ1 I/O experiment.
//!
//! This device has no filesystem. Its first page identifies the fixture and
//! is never overwritten by the probe. Data transfers are synchronous memory
//! copies, so results describe the virtualization path, not physical storage.

use core::fmt;
#[cfg(kernelet_rq1_diagnostics)]
use core::sync::atomic::{AtomicUsize, Ordering};

use aster_block::{
    BlockDevice, BlockDeviceMeta, MajorIdOwner, SECTOR_SIZE,
    bio::{BioEnqueueError, BioStatus, BioType, SubmittedBio},
};
use device_id::{DeviceId, MinorId};
use ostd::mm::{FrameAllocOptions, HasSize, Segment, VmIo, io::util::HasVmReaderWriter};

use crate::prelude::*;

const BYTES: usize = 4 * 1024 * 1024;
const MAGIC: &[u8] = b"KerneletRQ1RAMv1";
#[cfg(kernelet_rq1_diagnostics)]
static READS: AtomicUsize = AtomicUsize::new(0);
#[cfg(kernelet_rq1_diagnostics)]
static WRITES: AtomicUsize = AtomicUsize::new(0);

struct Rq1Ram {
    memory: Segment<()>,
    major: MajorIdOwner,
    transfer: Mutex<()>,
}

/// Registers before the normal block-device worker and devtmpfs scans.
pub(super) fn init_in_first_kthread() -> Result<()> {
    let memory = FrameAllocOptions::new()
        .zeroed(true)
        .alloc_segment(BYTES / PAGE_SIZE)?;
    memory.write_bytes(0, MAGIC)?;
    let major = aster_block::allocate_major()
        .map_err(|_| Error::with_message(Errno::ENOSPC, "RQ1 RAM major allocation failed"))?;
    aster_block::register(Arc::new(Rq1Ram {
        memory,
        major,
        transfer: Mutex::new(()),
    }))
    .map_err(|_| Error::with_message(Errno::EEXIST, "RQ1 RAM registration failed"))
}

/// Successful backend requests, including setup, verification, and scanning.
#[cfg(kernelet_rq1_diagnostics)]
pub(crate) fn counters() -> (usize, usize) {
    (
        READS.load(Ordering::Relaxed),
        WRITES.load(Ordering::Relaxed),
    )
}

impl Debug for Rq1Ram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rq1Ram").field("bytes", &BYTES).finish()
    }
}

impl BlockDevice for Rq1Ram {
    fn enqueue(&self, bio: SubmittedBio) -> core::result::Result<(), BioEnqueueError> {
        let _guard = self.transfer.lock();
        let kind = bio.type_();
        if kind == BioType::Flush {
            drop(_guard);
            bio.complete(BioStatus::Complete);
            return Ok(());
        }
        if !matches!(kind, BioType::Read | BioType::Write) {
            drop(_guard);
            bio.complete(BioStatus::NotSupported);
            return Ok(());
        }
        let offset = usize::try_from(bio.sid_range().start.to_raw())
            .ok()
            .and_then(|sector| sector.checked_mul(SECTOR_SIZE));
        let length = bio
            .segments()
            .iter()
            .try_fold(0usize, |sum, seg| sum.checked_add(seg.nbytes()));
        let Some(mut offset) = offset.filter(|start| {
            length
                .and_then(|len| start.checked_add(len))
                .is_some_and(|end| end <= self.memory.size())
        }) else {
            drop(_guard);
            bio.complete(BioStatus::NoSpace);
            return Ok(());
        };
        for segment in bio.segments() {
            let transferred = match kind {
                BioType::Read => segment.dma_slice().writer().map(|mut writer| {
                    let mut reader = self.memory.reader();
                    reader.skip(offset);
                    reader.limit(segment.nbytes());
                    #[cfg(all(kernelet_rq1_diagnostics, feature = "kernelet-host"))]
                    return crate::endovisor::io_copy_profile::measure(
                        crate::endovisor::io_copy_profile::Category::RamRead,
                        segment.nbytes(),
                        || writer.write(&mut reader),
                    );
                    #[cfg(not(all(kernelet_rq1_diagnostics, feature = "kernelet-host")))]
                    writer.write(&mut reader)
                }),
                BioType::Write => segment.dma_slice().reader().map(|mut reader| {
                    let mut writer = self.memory.writer();
                    writer.skip(offset);
                    #[cfg(all(kernelet_rq1_diagnostics, feature = "kernelet-host"))]
                    return crate::endovisor::io_copy_profile::measure(
                        crate::endovisor::io_copy_profile::Category::RamWrite,
                        segment.nbytes(),
                        || writer.write(&mut reader),
                    );
                    #[cfg(not(all(kernelet_rq1_diagnostics, feature = "kernelet-host")))]
                    writer.write(&mut reader)
                }),
                _ => unreachable!(),
            };
            if transferred != Ok(segment.nbytes()) {
                drop(_guard);
                bio.complete(BioStatus::IoError);
                return Ok(());
            }
            offset += segment.nbytes();
        }
        #[cfg(kernelet_rq1_diagnostics)]
        {
            match kind {
                BioType::Read => {
                    READS.fetch_add(1, Ordering::Relaxed);
                }
                BioType::Write => {
                    WRITES.fetch_add(1, Ordering::Relaxed);
                }
                _ => unreachable!(),
            }
        }
        drop(_guard);
        bio.complete(BioStatus::Complete);
        Ok(())
    }

    fn metadata(&self) -> BlockDeviceMeta {
        BlockDeviceMeta {
            max_nr_segments_per_bio: 62,
            nr_sectors: BYTES / SECTOR_SIZE,
        }
    }

    fn name(&self) -> &str {
        "rq1ram"
    }

    fn id(&self) -> DeviceId {
        DeviceId::new(self.major.get(), MinorId::new(0))
    }
}
