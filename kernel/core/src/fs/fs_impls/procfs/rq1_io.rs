// SPDX-License-Identifier: MPL-2.0

//! Opt-in QD1 BIO probe. The first page identifies a dedicated 4 MiB RAM
//! fixture. Payloads never overwrite that page. The original fragmented probe
//! sums BIO submit-to-completion windows. The separate contiguous probe uses
//! one multi-page segment and one BIO per logical operation, so its window
//! covers that entire operation. Construction, initialization, verification
//! and procfs copying are outside both windows.
//! Interruptions and scheduling remain enabled. This is a RAM-backed path
//! experiment, not a physical-storage throughput measurement.

use aster_block::{
    BlockDevice, SECTOR_SIZE,
    bio::{Bio, BioDirection, BioSegment, BioStatus, BioType},
    id::Sid,
};
use aster_util::printer::VmPrinter;
use ostd::{cpu::CpuId, mm::io::util::HasVmReaderWriter};

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
};

const MAGIC: &[u8] = b"KerneletRQ1RAMv1";
const FIXTURE_BYTES: usize = 4 * 1024 * 1024;
const OPERATIONS: usize = 32;
// Virtio's 64-descriptor queue reserves two descriptors. Its enqueue rejects
// segments.len() >= 62. The fragmented layout deliberately allocates one
// segment per page; the contiguous layout has one segment of any probe size.
const MAX_SEGMENTS: usize = 61;
const BUFFER_BYTES: usize = 16 * 1024;
static PROBE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Eq, PartialEq)]
enum Layout {
    Fragmented4K,
    ContiguousDma,
}

impl Layout {
    fn name(self) -> &'static str {
        match self {
            Self::Fragmented4K => "fragmented_4k",
            Self::ContiguousDma => "contiguous_dma",
        }
    }
}

pub(super) struct Rq1IoFileOps {
    layout: Layout,
}

impl Rq1IoFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        Self::new_inode_with_layout(parent, Layout::Fragmented4K)
    }

    pub(super) fn new_contiguous_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        Self::new_inode_with_layout(parent, Layout::ContiguousDma)
    }

    fn new_inode_with_layout(parent: Weak<dyn Inode>, layout: Layout) -> Arc<dyn Inode> {
        ProcFile::new(Self { layout }, parent, mkmod!(u+r))
    }
}

impl ProcFileOps for Rq1IoFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        if offset != 0 {
            return Ok(0);
        }
        if writer.avail() < BUFFER_BYTES {
            return_errno_with_message!(
                Errno::EINVAL,
                "RQ1 I/O requires one read of at least 16384 bytes"
            );
        }
        let _guard = PROBE_LOCK.lock();
        #[cfg(not(feature = "kernelet"))]
        let name = "rq1ram";
        #[cfg(feature = "kernelet")]
        // The runtime attaches the immutable rootfs as vda, then this
        // explicitly requested diagnostic backing as vdb.
        let name = "vdb";
        let device = aster_block::lookup_by_name(name)
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "RQ1 RAM block device is absent"))?;
        validate_fixture(device.as_ref())?;
        let cpu = CpuId::current_racy();
        let mut results = Vec::with_capacity(6);
        for bytes in [4096usize, 65536, 1048576] {
            for kind in [BioType::Read, BioType::Write] {
                results.push(measure(device.as_ref(), bytes, kind, cpu, self.layout)?);
            }
        }
        let mut printer = VmPrinter::from(writer);
        for result in results {
            result.print(&mut printer)?;
        }
        Ok(printer.bytes_written())
    }
}

fn submit(bio: Bio, device: &dyn BlockDevice) -> Result<()> {
    let status = bio.submit_and_wait(device)?;
    if status != BioStatus::Complete {
        return Err(Error::with_message(
            Errno::EIO,
            "RQ1 BIO did not complete successfully",
        ));
    }
    Ok(())
}

fn validate_fixture(device: &dyn BlockDevice) -> Result<()> {
    let meta = device.metadata();
    if meta.nr_sectors != FIXTURE_BYTES / SECTOR_SIZE || meta.max_nr_segments_per_bio < 62 {
        return_errno_with_message!(
            Errno::EINVAL,
            "RQ1 device has unexpected capacity or BIO limits"
        );
    }
    let page = BioSegment::try_alloc(1, BioDirection::FromDevice)?;
    submit(
        Bio::new(BioType::Read, Sid::new(0), vec![page.clone()], None),
        device,
    )?;
    let mut bytes = [0u8; PAGE_SIZE];
    page.reader()?.read(&mut VmWriter::from(&mut bytes[..]));
    if &bytes[..MAGIC.len()] != MAGIC {
        return_errno_with_message!(Errno::EINVAL, "RQ1 device is not the dedicated RAM fixture");
    }
    Ok(())
}

fn segments(bytes: usize, direction: BioDirection, layout: Layout) -> Result<Vec<BioSegment>> {
    match layout {
        Layout::Fragmented4K => (0..bytes / PAGE_SIZE)
            .map(|_| BioSegment::try_alloc(1, direction).map_err(Error::from))
            .collect(),
        Layout::ContiguousDma => Ok(vec![BioSegment::try_alloc(bytes / PAGE_SIZE, direction)?]),
    }
}

fn bios(segments: &[BioSegment], kind: BioType) -> Vec<Bio> {
    let mut offset = PAGE_SIZE;
    segments
        .chunks(MAX_SEGMENTS)
        .map(|segments| {
            let bio = Bio::new(kind, Sid::from_offset(offset), segments.to_vec(), None);
            offset += segments.iter().map(BioSegment::nbytes).sum::<usize>();
            bio
        })
        .collect()
}

fn fill(segments: &[BioSegment], value: u8) -> Result<()> {
    let bytes = [value; PAGE_SIZE];
    for segment in segments {
        // Device-side access also initializes FromDevice buffers to a sentinel.
        let mut writer = segment.inner_dma_slice().writer()?;
        for _ in 0..segment.nbytes() / PAGE_SIZE {
            if writer.write(&mut VmReader::from(&bytes[..])) != PAGE_SIZE {
                return_errno!(Errno::EIO);
            }
        }
    }
    Ok(())
}

fn verify(segments: &[BioSegment], value: u8) -> Result<()> {
    let mut bytes = [0u8; PAGE_SIZE];
    for segment in segments {
        let mut reader = segment.reader()?;
        for _ in 0..segment.nbytes() / PAGE_SIZE {
            let copied = reader.read(&mut VmWriter::from(&mut bytes[..]));
            if copied != PAGE_SIZE || bytes.iter().any(|&byte| byte != value) {
                return_errno_with_message!(Errno::EIO, "RQ1 RAM data verification failed");
            }
        }
    }
    Ok(())
}

fn transfer(device: &dyn BlockDevice, pages: &[BioSegment], kind: BioType) -> Result<()> {
    for bio in bios(pages, kind) {
        submit(bio, device)?;
    }
    Ok(())
}

struct Measurement {
    layout: Layout,
    kind: BioType,
    bytes: usize,
    duration_ns: u64,
    submitted_bios: usize,
    cpu: u32,
    elapsed_ticks: Vec<u64>,
    logical_elapsed_ticks: Vec<u64>,
    bio_duration_ns: u64,
    logical_duration_ns: u64,
    clock_hz: u64,
    payload_segments: usize,
    bytes_per_bio: Vec<usize>,
    segments_per_bio: Vec<usize>,
}

// Image CLOCK_MONOTONIC reads a Host-published snapshot. It cannot bracket
// microsecond BIOs. Use the same physical elapsed-time clock on both paths.
#[cfg(target_arch = "x86_64")]
fn probe_clock() -> Result<u64> {
    Ok(ostd::arch::read_tsc_ordered())
}

#[cfg(not(target_arch = "x86_64"))]
fn probe_clock() -> Result<u64> {
    Ok(u64::try_from(
        crate::time::read_monotonic_time().as_nanos(),
    )?)
}

fn measure(
    device: &dyn BlockDevice,
    bytes: usize,
    kind: BioType,
    cpu: CpuId,
    layout: Layout,
) -> Result<Measurement> {
    let read_pages = segments(bytes, BioDirection::FromDevice, layout)?;
    let write_pages = segments(bytes, BioDirection::ToDevice, layout)?;
    let measured_pages = if kind == BioType::Read {
        &read_pages
    } else {
        &write_pages
    };
    let mut prepared = (0..OPERATIONS)
        .flat_map(|_| bios(measured_pages, kind))
        .collect::<Vec<_>>()
        .into_iter();
    let bios_per_operation = measured_pages.len().div_ceil(MAX_SEGMENTS);
    let bytes_per_bio = measured_pages
        .chunks(MAX_SEGMENTS)
        .map(|segments| segments.iter().map(BioSegment::nbytes).sum())
        .collect();
    let segments_per_bio = measured_pages
        .chunks(MAX_SEGMENTS)
        .map(|segments| segments.len())
        .collect();
    #[cfg(target_arch = "x86_64")]
    let clock_hz = ostd::arch::tsc_freq();
    #[cfg(not(target_arch = "x86_64"))]
    let clock_hz = 1_000_000_000;
    if clock_hz == 0 {
        return_errno_with_message!(Errno::EIO, "RQ1 BIO clock frequency is zero");
    }
    let mut total_ticks = 0u64;
    let mut logical_total_ticks = 0u64;
    let mut elapsed_ticks = Vec::with_capacity(OPERATIONS * bios_per_operation);
    let mut logical_elapsed_ticks = Vec::with_capacity(OPERATIONS);
    let mut submitted_bios = 0;
    for iteration in 0..OPERATIONS {
        let pattern = iteration as u8 + 1;
        fill(&write_pages, pattern)?;
        fill(&read_pages, 0)?;
        if kind == BioType::Read {
            transfer(device, &write_pages, BioType::Write)?;
        }
        let mut first_start = None;
        let mut last_end = 0;
        for _ in 0..bios_per_operation {
            let bio = prepared.next().ok_or_else(|| Error::new(Errno::EIO))?;
            let start = probe_clock()?;
            let status = bio.submit_and_wait(device);
            let end = probe_clock()?;
            // Reuse the child timestamps without adding clock reads. Keep
            // boundary selection after end so the child span stays unchanged.
            first_start.get_or_insert(start);
            last_end = end;
            let elapsed = end
                .checked_sub(start)
                .ok_or_else(|| Error::new(Errno::EIO))?;
            total_ticks = total_ticks
                .checked_add(elapsed)
                .ok_or_else(|| Error::new(Errno::EOVERFLOW))?;
            elapsed_ticks.push(elapsed);
            if status? != BioStatus::Complete {
                return_errno!(Errno::EIO);
            }
            submitted_bios += 1;
        }
        let logical_elapsed = last_end
            .checked_sub(first_start.ok_or_else(|| Error::new(Errno::EIO))?)
            .ok_or_else(|| Error::new(Errno::EIO))?;
        logical_total_ticks = logical_total_ticks
            .checked_add(logical_elapsed)
            .ok_or_else(|| Error::new(Errno::EOVERFLOW))?;
        logical_elapsed_ticks.push(logical_elapsed);
        if kind == BioType::Write {
            transfer(device, &read_pages, BioType::Read)?;
        }
        verify(&read_pages, pattern)?;
        if CpuId::current_racy() != cpu {
            return_errno_with_message!(Errno::EAGAIN, "RQ1 I/O CPU changed; pin the caller");
        }
    }
    let bio_duration_ns =
        u64::try_from(u128::from(total_ticks) * 1_000_000_000 / u128::from(clock_hz))?;
    let logical_duration_ns =
        u64::try_from(u128::from(logical_total_ticks) * 1_000_000_000 / u128::from(clock_hz))?;
    let duration_ns = match layout {
        Layout::Fragmented4K => bio_duration_ns,
        Layout::ContiguousDma => logical_duration_ns,
    };
    if duration_ns == 0 {
        return_errno_with_message!(Errno::EIO, "RQ1 I/O clock did not advance");
    }
    Ok(Measurement {
        layout,
        kind,
        bytes,
        duration_ns,
        submitted_bios,
        cpu: cpu.into(),
        elapsed_ticks,
        logical_elapsed_ticks,
        bio_duration_ns,
        logical_duration_ns,
        clock_hz,
        payload_segments: measured_pages.len(),
        bytes_per_bio,
        segments_per_bio,
    })
}

impl Measurement {
    fn print(&self, printer: &mut VmPrinter) -> Result<()> {
        let direction = if self.kind == BioType::Read {
            "read"
        } else {
            "write"
        };
        let whole = self.duration_ns / OPERATIONS as u64;
        let fraction = (self.duration_ns % OPERATIONS as u64) * 1_000_000_000 / OPERATIONS as u64;
        let layout = self.layout.name();
        let (metric_prefix, timing_scope) = match self.layout {
            Layout::Fragmented4K => ("io.bio", "sum_submit_and_wait"),
            Layout::ContiguousDma => ("io.bio.contiguous", "logical_submit_and_wait"),
        };
        #[cfg(target_arch = "x86_64")]
        let clock = "physical_ordered_tsc";
        #[cfg(not(target_arch = "x86_64"))]
        let clock = "CLOCK_MONOTONIC";
        write!(
            printer,
            "{{\"metric\":\"{metric_prefix}.{direction}.{}\",\"value\":{whole}.{fraction:09},\"unit\":\"ns/op\",\"verified\":true,\"errors\":0,\"duration_ns\":{},\"operations\":{OPERATIONS},\"bytes_per_operation\":{},\"segments_per_operation\":{},\"submitted_bios\":{},\"qd\":1,\"clock\":\"{clock}\",\"timing_scope\":\"{timing_scope}\",\"backing\":\"dedicated_ram\",\"cpu\":{},\"clock_hz\":{},\"layout\":\"{layout}\",\"payload_segments\":{},\"payload_pages\":{},\"bytes_per_bio\":{:?},\"segments_per_bio\":{:?},\"elapsed_ticks\":[",
            self.bytes,
            self.duration_ns,
            self.bytes,
            self.payload_segments,
            self.submitted_bios,
            self.cpu,
            self.clock_hz,
            self.payload_segments,
            self.bytes / PAGE_SIZE,
            self.bytes_per_bio,
            self.segments_per_bio,
        )?;
        Self::print_ticks(printer, &self.elapsed_ticks)?;
        write!(printer, "]")?;
        write!(
            printer,
            ",\"bio_duration_ns\":{},\"logical_duration_ns\":{},\"logical_elapsed_ticks\":[",
            self.bio_duration_ns, self.logical_duration_ns,
        )?;
        Self::print_ticks(printer, &self.logical_elapsed_ticks)?;
        writeln!(printer, "]}}")?;
        Ok(())
    }

    fn print_ticks(printer: &mut VmPrinter, samples: &[u64]) -> Result<()> {
        for (index, ticks) in samples.iter().enumerate() {
            if index != 0 {
                write!(printer, ",")?;
            }
            write!(printer, "{ticks}")?;
        }
        Ok(())
    }
}

/// Host-only snapshots let the controller compute backend-BIO deltas around
/// an image command. They include setup and verification; no automatic
/// attribution to the timed window is possible from these aggregate counters.
#[cfg(all(kernelet_rq1_diagnostics, not(feature = "kernelet")))]
pub(super) struct Rq1IoStatsFileOps;

#[cfg(all(kernelet_rq1_diagnostics, not(feature = "kernelet")))]
impl Rq1IoStatsFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(u+r))
    }
}

#[cfg(all(kernelet_rq1_diagnostics, not(feature = "kernelet")))]
impl ProcFileOps for Rq1IoStatsFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        if offset != 0 {
            return Ok(0);
        }
        if aster_block::lookup_by_name("rq1ram").is_none() {
            return_errno_with_message!(Errno::ENODEV, "RQ1 RAM block device is absent");
        }
        let (reads, writes) = crate::device::rq1_ram::counters();
        let mut printer = VmPrinter::from(writer);
        writeln!(
            printer,
            "{{\"fixture\":\"rq1ram\",\"read_bios\":{reads},\"write_bios\":{writes},\"scope\":\"all_successful_backend_requests\"}}"
        )?;
        Ok(printer.bytes_written())
    }
}
