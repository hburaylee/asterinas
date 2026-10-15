// SPDX-License-Identifier: MPL-2.0

//! Cached crossing batches and optional per-call Image diagnostics.
//!
//! On one open description, pwrite exactly `batch\n`, then pread from zero.
//! Native measures an ordinary indirect call; Image also measures the existing
//! successful Host service. The numeric `COUNT TOKEN_BASE` request is retained
//! only for Image builds with per-call diagnostics enabled. Raw results precede
//! formatting and user access, so neither faults nor short reads repeat calls.

use core::{
    fmt::{self, Write},
    hint::black_box,
};

#[cfg(all(kernelet_rq1_crossing_diag, feature = "kernelet"))]
use ostd::kernelet::crossing_profile::CALL_CAPACITY;
use ostd::kernelet::crossing_profile::{self, DISTURBANCE, INTERRUPT_COVERAGE};
#[cfg(feature = "kernelet")]
use ostd::kernelet::entry;

use super::CrossingJsonBuffer;
use crate::{
    events::IoEvents,
    fs::{
        file::{AccessMode, PerOpenFileOps, StatusFlags, mkmod},
        procfs::template::{ProcFile, ProcFileOpsByHandle},
        vfs::inode::{FileOps, Inode},
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
};

/// Bounds parsing and stack storage before any service call can run.
const MAX_REQUEST_BYTES: usize = 64;

/// Root-only inode with one request and cached result per open description.
pub(super) struct KerneletRq1EchoFileOps;

impl KerneletRq1EchoFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(u+rw))
    }
}

impl ProcFileOpsByHandle for KerneletRq1EchoFileOps {
    fn open(
        &self,
        _access_mode: AccessMode,
        _status_flags: StatusFlags,
    ) -> Result<Box<dyn PerOpenFileOps>> {
        Ok(Box::new(EchoFile {
            session: Mutex::new(Session {
                request: None,
                records: None,
                report: None,
            }),
        }))
    }
}

struct EchoFile {
    session: Mutex<Session>,
}

struct Session {
    request: Option<Request>,
    records: Option<RawRecords>,
    report: Option<Arc<String>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Request {
    Batch,
    #[cfg(all(kernelet_rq1_crossing_diag, feature = "kernelet"))]
    Capture(CaptureRequest),
}

enum RawRecords {
    Batch(Vec<BatchRecord>),
    #[cfg(all(kernelet_rq1_crossing_diag, feature = "kernelet"))]
    Capture(Vec<EchoRecord>),
}

impl Session {
    // Allocation failure leaves the request retryable; once calls ran, even
    // invalid raw records are retained before formatting or any user copy.
    fn measure_once(
        &mut self,
        measure_fn: impl FnOnce(Request) -> Result<RawRecords>,
    ) -> Result<&RawRecords> {
        if self.records.is_none() {
            let request = self
                .request
                .ok_or_else(|| Error::with_message(Errno::ENODATA, "no echo request is armed"))?;
            self.records = Some(measure_fn(request)?);
        }
        Ok(self.records.as_ref().unwrap())
    }
}

#[cfg(all(kernelet_rq1_crossing_diag, feature = "kernelet"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CaptureRequest {
    count: usize,
    token_base: u64,
}

#[cfg(all(kernelet_rq1_crossing_diag, feature = "kernelet"))]
struct EchoRecord {
    token: u64,
    returned_token: u64,
    i0_tsc: u64,
    i1_tsc: u64,
}

impl FileOps for EchoFile {
    fn read_at(
        &self,
        offset: usize,
        writer: &mut VmWriter,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        if writer.avail() == 0 {
            return Ok(0);
        }
        let report = {
            // This is a sleeping mutex. No spin guard crosses the echo call.
            let mut session = self.session.lock();
            if session.request.is_none() {
                return_errno_with_message!(Errno::ENODATA, "no echo request is armed");
            }
            if session.records.is_none() && offset != 0 {
                return_errno_with_message!(Errno::EINVAL, "the first echo read must start at zero");
            }
            if session.report.is_none() {
                let records = session.measure_once(measure)?;
                // Keep raw records even if formatting runs out of memory.
                let report = serialize(records)?;
                session.report = Some(Arc::new(report));
            }
            session.report.as_ref().unwrap().clone()
        };
        let bytes = report.as_bytes().get(offset..).unwrap_or_default();
        Ok(writer.write_fallible(&mut VmReader::from(bytes))?)
    }

    fn write_at(
        &self,
        offset: usize,
        reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        if offset != 0 {
            return_errno_with_message!(Errno::EINVAL, "echo requests must be written at zero");
        }
        let mut session = self.session.lock();
        if session.request.is_some() {
            return_errno_with_message!(Errno::EBUSY, "this open file already has an echo request");
        }
        let (request, bytes) = read_request(reader)?;
        session.request = Some(request);
        Ok(bytes)
    }
}

impl Pollable for EchoFile {
    fn poll(&self, mask: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        (IoEvents::IN | IoEvents::OUT) & mask
    }
}

impl PerOpenFileOps for EchoFile {
    fn check_seekable(&self) -> Result<()> {
        Ok(())
    }

    fn is_offset_aware(&self) -> bool {
        true
    }
}

fn read_request(reader: &mut VmReader) -> Result<(Request, usize)> {
    let len = reader.remain();
    if len == 0 || len > MAX_REQUEST_BYTES {
        return_errno_with_message!(Errno::EINVAL, "echo request has an invalid byte length");
    }
    let mut bytes = [0; MAX_REQUEST_BYTES];
    let copied = reader.read_fallible(&mut VmWriter::from(&mut bytes[..len]))?;
    if copied != len {
        return_errno_with_message!(Errno::EIO, "echo request was not read completely");
    }
    let text = core::str::from_utf8(&bytes[..len])?;
    Ok((parse_request(text)?, len))
}

fn parse_request(text: &str) -> Result<Request> {
    if text == "batch\n" {
        return Ok(Request::Batch);
    }
    #[cfg(all(kernelet_rq1_crossing_diag, feature = "kernelet"))]
    {
        parse_capture_request(text).map(Request::Capture)
    }
    #[cfg(not(all(kernelet_rq1_crossing_diag, feature = "kernelet")))]
    {
        return_errno_with_message!(Errno::EINVAL, "only the exact batch request is supported");
    }
}

#[cfg(all(kernelet_rq1_crossing_diag, feature = "kernelet"))]
fn parse_capture_request(text: &str) -> Result<CaptureRequest> {
    let mut fields = text.split_ascii_whitespace();
    let count = fields
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "echo count is not a valid integer"))?;
    let token_base = fields
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            Error::with_message(Errno::EINVAL, "echo token base is not a valid integer")
        })?;
    if fields.next().is_some() {
        return_errno_with_message!(Errno::EINVAL, "echo request must have exactly two fields");
    }
    if count == 0 || count > CALL_CAPACITY as u64 {
        return_errno_with_message!(Errno::EINVAL, "echo count is outside the capture capacity");
    }
    if token_base.checked_add(count - 1).is_none() {
        return_errno_with_message!(Errno::EINVAL, "echo token range would overflow");
    }
    Ok(CaptureRequest {
        count: count as usize,
        token_base,
    })
}

fn measure(request: Request) -> Result<RawRecords> {
    match request {
        Request::Batch => measure_batches().map(RawRecords::Batch),
        #[cfg(all(kernelet_rq1_crossing_diag, feature = "kernelet"))]
        Request::Capture(request) => measure_capture(request).map(RawRecords::Capture),
    }
}

#[cfg(all(kernelet_rq1_crossing_diag, feature = "kernelet"))]
fn measure_capture(request: CaptureRequest) -> Result<Vec<EchoRecord>> {
    let mut records = Vec::new();
    records
        .try_reserve_exact(request.count)
        .map_err(|_| Error::with_message(Errno::ENOMEM, "cannot allocate echo records"))?;
    let echo: extern "C" fn(u64) -> i64 = black_box(entry::rq1_echo_service());
    for index in 0..request.count {
        // parse_capture_request checked this range before any service ran.
        let token = black_box(request.token_base + index as u64);
        let i0_tsc = crossing_profile::read_tsc_ordered();
        let returned_token = echo(token) as u64;
        let i1_tsc = crossing_profile::read_tsc_ordered();
        // Preallocated storage and formatting are outside this call's window.
        // Keep mismatched returns and clocks for strict validation above us.
        records.push(EchoRecord {
            token,
            returned_token,
            i0_tsc,
            i1_tsc,
        });
    }
    Ok(records)
}

const BATCH_ITERATIONS: u32 = 100_000;
const BATCH_WARMUP_ITERATIONS: u32 = 1_000;
const BATCH_REPETITIONS: u32 = 5;
const PHYSICAL_IRQ_FLAG: u64 = 1 << 9;
#[cfg(feature = "kernelet")]
const BATCH_CAPACITY: usize = BATCH_REPETITIONS as usize * 5;
#[cfg(not(feature = "kernelet"))]
const BATCH_CAPACITY: usize = BATCH_REPETITIONS as usize * 3;

type BatchOperation = extern "C" fn(u64) -> i64;

#[derive(Clone, Copy)]
enum BatchBody {
    NativeIndirect,
    #[cfg(feature = "kernelet")]
    HostService,
}

impl BatchBody {
    fn name(self) -> &'static str {
        match self {
            Self::NativeIndirect => "native_indirect",
            #[cfg(feature = "kernelet")]
            Self::HostService => "host_service",
        }
    }
}

#[derive(Clone, Copy)]
enum BatchPhase {
    ClockControl,
    Warmup,
    Measured,
}

impl BatchPhase {
    fn name(self) -> &'static str {
        match self {
            Self::ClockControl => "clock_control",
            Self::Warmup => "warmup",
            Self::Measured => "measured",
        }
    }

    fn iterations(self) -> u32 {
        match self {
            Self::ClockControl => 0,
            Self::Warmup => BATCH_WARMUP_ITERATIONS,
            Self::Measured => BATCH_ITERATIONS,
        }
    }
}

struct BatchRecord {
    repetition: u32,
    body: BatchBody,
    phase: BatchPhase,
    iterations: u32,
    t0: u64,
    t1: u64,
    checksum: u64,
    bad_returns: u32,
    first_bad_return: u64,
    cpu_before: u32,
    cpu_after: u32,
    rflags_before: u64,
    rflags_after: u64,
    virtual_irq_before: Option<bool>,
    virtual_irq_after: Option<bool>,
}

impl BatchRecord {
    fn is_valid(&self) -> bool {
        #[cfg(feature = "kernelet")]
        let virtual_irq_valid =
            self.virtual_irq_before == Some(true) && self.virtual_irq_after == Some(true);
        #[cfg(not(feature = "kernelet"))]
        let virtual_irq_valid =
            self.virtual_irq_before.is_none() && self.virtual_irq_after.is_none();
        self.t1 > self.t0
            && self.bad_returns == 0
            && self.first_bad_return == 0
            && self.checksum == 0
            && self.cpu_before == self.cpu_after
            && self.rflags_before & PHYSICAL_IRQ_FLAG != 0
            && self.rflags_after & PHYSICAL_IRQ_FLAG != 0
            && virtual_irq_valid
    }
}

fn measure_batches() -> Result<Vec<BatchRecord>> {
    let mut records = Vec::new();
    records.try_reserve_exact(BATCH_CAPACITY).map_err(|_| {
        Error::with_message(Errno::ENOMEM, "cannot allocate crossing batch records")
    })?;
    let native_fn: BatchOperation =
        black_box(super::kernelet_rq1::native_echo_reference as BatchOperation);
    #[cfg(feature = "kernelet")]
    let service_fn: BatchOperation = black_box(entry::rq1_echo_service());
    for repetition in 0..BATCH_REPETITIONS {
        records.push(measure_batch(
            repetition,
            BatchBody::NativeIndirect,
            BatchPhase::ClockControl,
            native_fn,
        ));
        for phase in [BatchPhase::Warmup, BatchPhase::Measured] {
            records.push(measure_batch(
                repetition,
                BatchBody::NativeIndirect,
                phase,
                native_fn,
            ));
        }
        #[cfg(feature = "kernelet")]
        for phase in [BatchPhase::Warmup, BatchPhase::Measured] {
            records.push(measure_batch(
                repetition,
                BatchBody::HostService,
                phase,
                service_fn,
            ));
        }
    }
    Ok(records)
}

// One shared indirect-call loop for the reference and successful service.
// Keeping it out of line also makes the final call instruction reviewable.
#[inline(never)]
fn measure_batch(
    repetition: u32,
    body: BatchBody,
    phase: BatchPhase,
    call_fn: BatchOperation,
) -> BatchRecord {
    let iterations = phase.iterations();
    let mut checksum = 0u64;
    let mut bad_returns = 0;
    let mut first_bad_return = 0;
    let before = crossing_profile::read_batch_context();
    let t0 = crossing_profile::read_batch_tsc_ordered();
    for _ in 0..iterations {
        // Retain the complete register bit pattern, including negative errors.
        let observed = call_fn(0) as u64;
        checksum = checksum.wrapping_add(observed);
        if observed != 0 {
            if bad_returns == 0 {
                first_bad_return = observed;
            }
            bad_returns += 1;
        }
    }
    let t1 = crossing_profile::read_batch_tsc_ordered();
    let after = crossing_profile::read_batch_context();
    BatchRecord {
        repetition,
        body,
        phase,
        iterations,
        t0,
        t1,
        checksum,
        bad_returns,
        first_bad_return,
        cpu_before: before.cpu(),
        cpu_after: after.cpu(),
        rflags_before: before.rflags(),
        rflags_after: after.rflags(),
        virtual_irq_before: before.virtual_irq_enabled(),
        virtual_irq_after: after.virtual_irq_enabled(),
    }
}

fn write_batch_records(output: &mut impl Write, records: &[BatchRecord]) -> fmt::Result {
    #[cfg(feature = "kernelet")]
    let (mode, cpu_namespace) = ("image", "kernelet_vcpu");
    #[cfg(not(feature = "kernelet"))]
    let (mode, cpu_namespace) = ("native", "asterinas_host_cpu");
    write!(
        output,
        "{{\"version\":1,\"kind\":\"rq1_crossing_batch\",\"mode\":\"{mode}\",\"clock\":\"ordered_elapsed_tsc\",\"iterations\":{BATCH_ITERATIONS},\"warmup_per_batch\":{BATCH_WARMUP_ITERATIONS},\"repetitions\":{BATCH_REPETITIONS},\"disturbance\":\"{DISTURBANCE}\",\"interrupt_coverage\":\"{INTERRUPT_COVERAGE}\",\"cpu_namespace\":\"{cpu_namespace}\",\"batches\":["
    )?;
    for (index, record) in records.iter().enumerate() {
        if index != 0 {
            output.write_str(",")?;
        }
        write!(
            output,
            "{{\"repetition\":{},\"body\":\"{}\",\"phase\":\"{}\",\"iterations\":{},\"t0\":{},\"t1\":{},\"elapsed_tsc_ticks\":",
            record.repetition,
            record.body.name(),
            record.phase.name(),
            record.iterations,
            record.t0,
            record.t1,
        )?;
        match record.t1.checked_sub(record.t0) {
            Some(elapsed) => write!(output, "{elapsed}")?,
            None => output.write_str("null")?,
        }
        write!(
            output,
            ",\"expected_return\":0,\"checksum\":{},\"bad_returns\":{},\"first_bad_return\":{},\"cpu_before\":{},\"cpu_after\":{},\"rflags_before\":{},\"rflags_after\":{},\"virtual_irq_before\":",
            record.checksum,
            record.bad_returns,
            record.first_bad_return,
            record.cpu_before,
            record.cpu_after,
            record.rflags_before,
            record.rflags_after,
        )?;
        write_virtual_irq(output, record.virtual_irq_before)?;
        output.write_str(",\"virtual_irq_after\":")?;
        write_virtual_irq(output, record.virtual_irq_after)?;
        write!(output, ",\"valid\":{}}}", record.is_valid())?;
    }
    output.write_str("]}\n")
}

fn write_virtual_irq(output: &mut impl Write, enabled: Option<bool>) -> fmt::Result {
    match enabled {
        Some(enabled) => write!(output, "{enabled}"),
        None => output.write_str("null"),
    }
}

fn serialize(records: &RawRecords) -> Result<String> {
    let mut output = CrossingJsonBuffer(String::new());
    match records {
        RawRecords::Batch(records) => write_batch_records(&mut output, records),
        #[cfg(all(kernelet_rq1_crossing_diag, feature = "kernelet"))]
        RawRecords::Capture(records) => write_records(&mut output, records),
    }
    .map_err(|_| Error::with_message(Errno::ENOMEM, "cannot format echo records"))?;
    Ok(output.0)
}

#[cfg(all(ktest, kernelet_rq1_crossing_diag, feature = "kernelet"))]
fn serialize_capture(records: &[EchoRecord]) -> Result<String> {
    let mut output = CrossingJsonBuffer(String::new());
    write_records(&mut output, records)
        .map_err(|_| Error::with_message(Errno::ENOMEM, "cannot format echo records"))?;
    Ok(output.0)
}

#[cfg(all(kernelet_rq1_crossing_diag, feature = "kernelet"))]
fn write_records(output: &mut impl Write, records: &[EchoRecord]) -> fmt::Result {
    write!(
        output,
        "{{\"version\":1,\"kind\":\"rq1_crossing_image\",\"clock\":\"elapsed_tsc\",\"disturbance\":\"{DISTURBANCE}\",\"interrupt_coverage\":\"{INTERRUPT_COVERAGE}\",\"records\":["
    )?;
    for (index, record) in records.iter().enumerate() {
        if index != 0 {
            output.write_str(",")?;
        }
        write!(
            output,
            "{{\"token\":{},\"returned_token\":{},\"i0_tsc\":{},\"i1_tsc\":{}}}",
            record.token, record.returned_token, record.i0_tsc, record.i1_tsc,
        )?;
    }
    output.write_str("]}\n")
}

#[cfg(all(ktest, kernelet_rq1_crossing_diag, feature = "kernelet"))]
mod test {
    use super::*;

    fn capture_request(session: &Session) -> CaptureRequest {
        match session.request.unwrap() {
            Request::Capture(request) => request,
            Request::Batch => panic!("expected capture request"),
        }
    }

    fn capture_records(session: &Session) -> &[EchoRecord] {
        match session.records.as_ref().unwrap() {
            RawRecords::Capture(records) => records,
            RawRecords::Batch(_) => panic!("expected capture records"),
        }
    }

    #[ktest]
    fn request_accepts_capacity_and_full_u64_token_range() {
        assert_eq!(
            parse_capture_request("64 18446744073709551552\n").unwrap(),
            CaptureRequest {
                count: 64,
                token_base: u64::MAX - 63,
            }
        );
        assert_eq!(
            parse_capture_request("1 18446744073709551615\n")
                .unwrap()
                .token_base,
            u64::MAX
        );
        assert_eq!(parse_capture_request("1 0\n").unwrap().token_base, 0);
    }

    #[ktest]
    fn request_rejects_missing_extra_fields_invalid_count_and_wrapping_tokens() {
        for text in [
            "",
            "1",
            "1 2 3",
            "count=1 2",
            "1 token_base=2",
            "-1 2",
            "0 2",
            "65 2",
            "2 18446744073709551615",
            "1 18446744073709551616",
            "1 2\0ignored",
        ] {
            assert_eq!(
                parse_capture_request(text).unwrap_err().error(),
                Errno::EINVAL
            );
        }
    }

    #[ktest]
    fn serialization_preserves_mismatches_and_maximum_return_bitpattern() {
        let report = serialize_capture(&[
            EchoRecord {
                token: 9,
                returned_token: 10,
                i0_tsc: 20,
                i1_tsc: 10,
            },
            EchoRecord {
                token: u64::MAX,
                returned_token: (-1i64) as u64,
                i0_tsc: 30,
                i1_tsc: 40,
            },
        ])
        .unwrap();
        assert!(report.contains("\"version\":1,\"kind\":\"rq1_crossing_image\""));
        assert!(
            report.contains("\"disturbance\":\"unknown\",\"interrupt_coverage\":\"incomplete\"")
        );
        assert!(report.contains("{\"token\":9,\"returned_token\":10,\"i0_tsc\":20,\"i1_tsc\":10}"));
        assert!(
            report
                .contains("\"token\":18446744073709551615,\"returned_token\":18446744073709551615")
        );
        assert!(report.ends_with("]}\n"));
    }

    #[ktest]
    fn bad_writes_leave_the_open_session_unarmed() {
        let file = EchoFile {
            session: Mutex::new(Session {
                request: None,
                records: None,
                report: None,
            }),
        };
        for bytes in [
            vec![],
            vec![b'1'; MAX_REQUEST_BYTES + 1],
            b"1 2 3\n".to_vec(),
            vec![0xff],
        ] {
            let mut reader = VmReader::from(bytes.as_slice()).to_fallible();
            let error = file
                .write_at(0, &mut reader, StatusFlags::empty())
                .unwrap_err();
            assert_eq!(error.error(), Errno::EINVAL);
            assert!(file.session.lock().request.is_none());
        }
        let mut reader = VmReader::from(b"1 7\n".as_slice()).to_fallible();
        assert_eq!(
            file.write_at(0, &mut reader, StatusFlags::empty()).unwrap(),
            4
        );
        let session = file.session.lock();
        assert_eq!(capture_request(&session).token_base, 7);
        assert!(session.records.is_none());
        assert!(session.report.is_none());
    }

    #[ktest]
    fn cached_short_reads_keep_the_original_request() {
        // This fixture tests cached-file behavior, not a real Host crossing.
        let records = vec![EchoRecord {
            token: 7,
            returned_token: 7,
            i0_tsc: 10,
            i1_tsc: 20,
        }];
        let expected = serialize_capture(&records).unwrap();
        let file = EchoFile {
            session: Mutex::new(Session {
                request: Some(Request::Capture(CaptureRequest {
                    count: 1,
                    token_base: 7,
                })),
                records: Some(RawRecords::Capture(records)),
                report: None,
            }),
        };
        let mut head = [0; 13];
        let first = file
            .read_at(
                0,
                &mut VmWriter::from(head.as_mut_slice()).to_fallible(),
                StatusFlags::empty(),
            )
            .unwrap();
        let mut tail = vec![0; expected.len()];
        let second = file
            .read_at(
                first,
                &mut VmWriter::from(tail.as_mut_slice()).to_fallible(),
                StatusFlags::empty(),
            )
            .unwrap();
        let mut actual = head[..first].to_vec();
        actual.extend_from_slice(&tail[..second]);
        assert_eq!(actual, expected.as_bytes());
        let mut reader = VmReader::from(b"1 9\n".as_slice()).to_fallible();
        assert_eq!(
            file.write_at(0, &mut reader, StatusFlags::empty())
                .unwrap_err()
                .error(),
            Errno::EBUSY
        );
        let session = file.session.lock();
        assert_eq!(capture_request(&session).token_base, 7);
        assert_eq!(capture_records(&session)[0].token, 7);
    }
}

#[cfg(ktest)]
mod batch_test {
    use alloc::format;

    use ostd::prelude::ktest;

    use super::*;

    // Synthetic records exercise serialization and file ownership, not a real
    // Image-to-Host crossing or measurements of this artificial clock window.
    fn record() -> BatchRecord {
        #[cfg(feature = "kernelet")]
        let virtual_irq = Some(true);
        #[cfg(not(feature = "kernelet"))]
        let virtual_irq = None;
        BatchRecord {
            repetition: 0,
            body: BatchBody::NativeIndirect,
            phase: BatchPhase::ClockControl,
            iterations: 0,
            t0: 10,
            t1: 20,
            checksum: 0,
            bad_returns: 0,
            first_bad_return: 0,
            cpu_before: 0,
            cpu_after: 0,
            rflags_before: PHYSICAL_IRQ_FLAG,
            rflags_after: PHYSICAL_IRQ_FLAG,
            virtual_irq_before: virtual_irq,
            virtual_irq_after: virtual_irq,
        }
    }

    fn batch_records() -> RawRecords {
        RawRecords::Batch(vec![record()])
    }

    fn session() -> Session {
        Session {
            request: Some(Request::Batch),
            records: None,
            report: None,
        }
    }

    #[ktest]
    fn batch_request_requires_exact_bytes() {
        assert_eq!(parse_request("batch\n").unwrap(), Request::Batch);
        for request in [
            "batch",
            " batch\n",
            "batch \n",
            "batch\n\n",
            "batch\0\n",
            "batch 1\n",
        ] {
            assert_eq!(parse_request(request).unwrap_err().error(), Errno::EINVAL);
        }
        #[cfg(not(all(kernelet_rq1_crossing_diag, feature = "kernelet")))]
        for request in ["1 0\n", "64 1\n"] {
            assert_eq!(parse_request(request).unwrap_err().error(), Errno::EINVAL);
        }
        let file = EchoFile {
            session: Mutex::new(Session {
                request: None,
                records: None,
                report: None,
            }),
        };
        let mut bytes = [0; 1];
        let error = file
            .read_at(
                1,
                &mut VmWriter::from(bytes.as_mut_slice()).to_fallible(),
                StatusFlags::empty(),
            )
            .unwrap_err();
        assert_eq!(error.error(), Errno::ENODATA);
        let mut reader = VmReader::from(b"batch\n".as_slice()).to_fallible();
        assert_eq!(
            file.write_at(0, &mut reader, StatusFlags::empty()).unwrap(),
            6
        );
        assert_eq!(file.session.lock().request, Some(Request::Batch));
        assert!(file.session.lock().records.is_none());
    }

    #[ktest]
    fn batch_cache_retries_only_allocation_before_measurement() {
        let mut state = session();
        assert!(
            state
                .measure_once(|_| {
                    Err(Error::with_message(
                        Errno::ENOMEM,
                        "test preallocation failure",
                    ))
                })
                .is_err()
        );
        assert!(state.records.is_none());
        let mut calls = 0;
        let records = state
            .measure_once(|request| {
                assert_eq!(request, Request::Batch);
                calls += 1;
                let mut invalid = record();
                invalid.iterations = 1;
                invalid.bad_returns = 1;
                invalid.first_bad_return = u64::MAX;
                invalid.checksum = u64::MAX;
                Ok(RawRecords::Batch(vec![invalid]))
            })
            .unwrap();
        assert!(serialize(records).unwrap().contains("\"valid\":false"));
        state
            .measure_once(|_| {
                calls += 1;
                panic!("cached invalid measurement was repeated");
            })
            .unwrap();
        assert_eq!(calls, 1);
    }

    #[ktest]
    fn batch_format_failure_retains_measured_records() {
        struct FailedWriter;
        impl Write for FailedWriter {
            fn write_str(&mut self, _text: &str) -> fmt::Result {
                Err(fmt::Error)
            }
        }
        let mut state = session();
        let mut calls = 0;
        let raw = state
            .measure_once(|_| {
                calls += 1;
                Ok(batch_records())
            })
            .unwrap();
        match raw {
            RawRecords::Batch(records) => {
                assert!(write_batch_records(&mut FailedWriter, records).is_err());
            }
            #[cfg(all(kernelet_rq1_crossing_diag, feature = "kernelet"))]
            RawRecords::Capture(_) => panic!("expected batch records"),
        }
        let raw = state
            .measure_once(|_| panic!("format failure repeated the batch"))
            .unwrap();
        assert!(serialize(raw).unwrap().contains("\"t0\":10,\"t1\":20"));
        assert_eq!(calls, 1);
    }

    #[ktest]
    fn batch_serialization_preserves_bad_return_and_backwards_clock() {
        #[inline(never)]
        extern "C" fn bad_return_fn(_: u64) -> i64 {
            -1
        }
        // The actual shared loop checks all 1000 artificial error returns.
        // The operation is a test function, not a Host crossing.
        let mut bad = measure_batch(
            0,
            BatchBody::NativeIndirect,
            BatchPhase::Warmup,
            black_box(bad_return_fn as BatchOperation),
        );
        let expected_checksum = u64::MAX.wrapping_mul(BATCH_WARMUP_ITERATIONS as u64);
        assert_eq!(bad.bad_returns, BATCH_WARMUP_ITERATIONS);
        assert_eq!(bad.first_bad_return, u64::MAX);
        assert_eq!(bad.checksum, expected_checksum);
        bad.t0 = 30;
        bad.t1 = 20;
        assert!(!bad.is_valid());
        let report = serialize(&RawRecords::Batch(vec![bad])).unwrap();
        assert!(report.contains("\"elapsed_tsc_ticks\":null"));
        assert!(report.contains(&format!(
            "\"checksum\":{expected_checksum},\"bad_returns\":{BATCH_WARMUP_ITERATIONS},\"first_bad_return\":18446744073709551615"
        )));
        assert!(report.contains("\"valid\":false"));
    }

    #[ktest]
    fn batch_validity_keeps_cpu_and_irq_failures_visible() {
        let good = record();
        assert!(good.is_valid());
        let mut bad = record();
        bad.cpu_after = 1;
        assert!(!bad.is_valid());
        bad = record();
        bad.rflags_after = 0;
        assert!(!bad.is_valid());
        bad = record();
        bad.t1 = bad.t0;
        assert!(!bad.is_valid());
        bad = record();
        bad.virtual_irq_after = Some(false);
        assert!(!bad.is_valid());
    }

    #[ktest]
    fn batch_short_reads_and_rejected_rewrite_keep_original_records() {
        let raw = batch_records();
        let expected = serialize(&raw).unwrap();
        let file = EchoFile {
            session: Mutex::new(Session {
                request: Some(Request::Batch),
                records: Some(raw),
                report: None,
            }),
        };
        let mut first = [0; 13];
        let bytes = file
            .read_at(
                0,
                &mut VmWriter::from(first.as_mut_slice()).to_fallible(),
                StatusFlags::empty(),
            )
            .unwrap();
        let mut remaining = vec![0; expected.len()];
        let tail = file
            .read_at(
                bytes,
                &mut VmWriter::from(remaining.as_mut_slice()).to_fallible(),
                StatusFlags::empty(),
            )
            .unwrap();
        let mut actual = first[..bytes].to_vec();
        actual.extend_from_slice(&remaining[..tail]);
        assert_eq!(actual, expected.as_bytes());
        let mut reader = VmReader::from(b"batch\n".as_slice()).to_fallible();
        assert_eq!(
            file.write_at(0, &mut reader, StatusFlags::empty())
                .unwrap_err()
                .error(),
            Errno::EBUSY
        );
        let state = file.session.lock();
        assert_eq!(state.request, Some(Request::Batch));
        assert_eq!(
            state.report.as_ref().unwrap().as_bytes(),
            expected.as_bytes()
        );
    }

    #[cfg(not(feature = "kernelet"))]
    #[ktest]
    fn batch_user_fault_retains_cached_report() {
        use ostd::mm::VmSpace;

        // The core ktest runner does not initialize Asterinas's fault resolver.
        // Keep this empty user space unresolved and use OSTD's real fixup.
        let page_faults_before = crate::thread::exception::fault_test::count();

        // This Native-only fixture exercises the real fallible user copy into
        // an unmapped user address. It supplies cached synthetic records, so it
        // does not claim that a Host service ran during this ktest.
        struct RestoreKernelRoot;
        impl Drop for RestoreKernelRoot {
            fn drop(&mut self) {
                VmSpace::deactivate();
            }
        }
        VmSpace::deactivate();
        let restore = RestoreKernelRoot;
        let space = Arc::new(VmSpace::new());
        space.activate();
        let file = EchoFile {
            session: Mutex::new(Session {
                request: Some(Request::Batch),
                records: Some(batch_records()),
                report: None,
            }),
        };
        let expected = serialize(file.session.lock().records.as_ref().unwrap()).unwrap();
        let mut writer = space.writer(0x1000, 64).unwrap();
        let error = file
            .read_at(0, &mut writer, StatusFlags::empty())
            .unwrap_err();
        drop(writer);
        drop(restore);
        assert_eq!(error.error(), Errno::EFAULT);
        assert!(crate::thread::exception::fault_test::count() > page_faults_before);
        assert_eq!(
            file.session.lock().report.as_ref().unwrap().as_bytes(),
            expected.as_bytes()
        );
        let mut bytes = vec![0; expected.len()];
        let copied = file
            .read_at(
                0,
                &mut VmWriter::from(bytes.as_mut_slice()).to_fallible(),
                StatusFlags::empty(),
            )
            .unwrap();
        assert_eq!(&bytes[..copied], expected.as_bytes());
    }
}
