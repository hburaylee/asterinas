// SPDX-License-Identifier: MPL-2.0

//! Checks the linked Host's actual indirect service-call destinations.
//!
//! `ServiceTable` is built by OSTD and embedded in the Host ELF. The Guest
//! calls each table entry indirectly, so every final target must begin with
//! ENDBR64. Checking the linked table catches linker or code-generation
//! changes that cannot be established from source annotations alone.

use std::{collections::HashSet, fs, path::Path};

use super::elf::{EM_X86_64, ElfImage, PF_X, PT_LOAD, Symbol};

const SERVICE_TABLE_SYMBOL: &str = "__ostd_kernelet_service_table";
const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];
// Both forward stop/phase branches in the common return fit an i8. This
// includes its stopped-carrier tail through the final fixed-exit jump.
const SERVICE_RETURN_BYTES: u64 = 115;
const SERVICE_FIELDS: [&str; 18] = [
    "grains_request",
    "pt_root_register",
    "pt_root_unregister",
    "pt_activate",
    "tlb_shootdown",
    "kstack_alloc",
    "kstack_free",
    "vcpu_boot",
    "vcpu_idle",
    "vcpu_kick",
    "vcpu_yield",
    "vcpu_on_spin",
    "user_run",
    "mmio_read",
    "mmio_write",
    "log_write",
    "oops",
    "stop",
];

fn service_fields(table_bytes: u64) -> Result<Vec<&'static str>, String> {
    const NORMAL_BYTES: u64 = 8 + SERVICE_FIELDS.len() as u64 * 8;
    let mut fields = SERVICE_FIELDS.to_vec();
    match table_bytes {
        NORMAL_BYTES => {}
        // KERNELET_RQ1_BENCH appends one diagnostic entry. It must pass the
        // same linked wrapper, stack, phase, stop and return checks below.
        bytes if bytes == NORMAL_BYTES + 8 => fields.push("rq1_echo"),
        _ => {
            return Err(format!(
                "the Host service table is {table_bytes} bytes, expected {NORMAL_BYTES} or {} with the diagnostic echo",
                NORMAL_BYTES + 8
            ));
        }
    }
    Ok(fields)
}

/// Validates every service address from the final unstripped Host ELF.
pub(crate) fn audit_host_services(path: &Path) -> Result<(), String> {
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let elf = ElfImage::parse(&bytes)?;
    if elf.e_machine()? != EM_X86_64 {
        return Err("the Host ELF is not x86-64".to_string());
    }

    let sections = elf.section_headers()?;
    let symbols = elf.symbols(&sections)?;
    let strings = elf.symbol_string_table(&sections)?;
    let mut tables = symbols
        .iter()
        .filter(|symbol| elf.symbol_name(&strings, symbol).ok() == Some(SERVICE_TABLE_SYMBOL));
    let table = tables
        .next()
        .ok_or_else(|| format!("the Host ELF lacks {SERVICE_TABLE_SYMBOL}"))?;
    if tables.next().is_some() {
        return Err(format!(
            "the Host ELF has multiple {SERVICE_TABLE_SYMBOL} symbols"
        ));
    }
    let fields = service_fields(table.size)?;
    let data = elf.bytes_at_vaddr(table.value, table.size)?;
    let declared_size = u64::from_le_bytes(data[..8].try_into().unwrap());
    if declared_size != table.size {
        return Err(format!(
            "the Host service table declares {declared_size} bytes, expected {}",
            table.size
        ));
    }

    let segments = elf.program_headers()?;
    let exit = symbol_address(&elf, &symbols, &strings, "kernelet_host_exit")?;
    audit_host_exit_prefix(&elf, exit)?;
    let mut seen = HashSet::new();
    for (index, field) in fields.iter().enumerate() {
        let offset = 8 + index * 8;
        let address = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        let end = address
            .checked_add(ENDBR64.len() as u64)
            .ok_or_else(|| format!("Host service {field} has an overflowing address"))?;
        if !segments.iter().any(|segment| {
            segment.typ == PT_LOAD
                && segment.flags & PF_X != 0
                && segment.covers_vaddr_range(address, end)
        }) {
            return Err(format!(
                "Host service {field} target {address:#x} is outside executable text"
            ));
        }
        if !seen.insert(address) {
            return Err(format!(
                "Host service {field} duplicates target {address:#x}"
            ));
        }
        let symbol = symbols
            .iter()
            .find(|symbol| symbol.value == address && symbol.info & 0x0f == 2)
            .ok_or_else(|| {
                format!("Host service {field} target {address:#x} has no function symbol")
            })?;
        let name = elf.symbol_name(&strings, symbol)?;
        let prologue = elf.bytes_at_vaddr(address, ENDBR64.len() as u64)?;
        if prologue != ENDBR64 {
            return Err(format!(
                "Host service {field} ({name}) at {address:#x} lacks ENDBR64"
            ));
        }
        let stub_name = format!("kernelet_service_{field}");
        let stub = symbols
            .iter()
            .find(|symbol| elf.symbol_name(&strings, symbol).ok() == Some(stub_name.as_str()))
            .ok_or_else(|| format!("the Host ELF lacks {stub_name}"))?;
        let wrapper = elf.bytes_at_vaddr(address, 9)?;
        if wrapper[4] != 0xe9 {
            return Err(format!(
                "Host service {field} wrapper at {address:#x} does not jump to its fixed stub"
            ));
        }
        let jump = i32::from_le_bytes(wrapper[5..9].try_into().unwrap()) as i64;
        let target = (address + 9)
            .checked_add_signed(jump)
            .ok_or_else(|| format!("Host service {field} has an overflowing stub jump"))?;
        if target != stub.value {
            return Err(format!(
                "Host service {field} wrapper jumps to {target:#x}, expected {} at {:#x}",
                stub_name, stub.value
            ));
        }
        let targets = ServiceStubTargets {
            state_pointer: symbol_address(&elf, &symbols, &strings, "KERNELET_HOST_STATE_PTR")?,
            cpu_local_start: symbol_address(&elf, &symbols, &strings, "__cpu_local_start")?,
            implementation: symbol_address(
                &elf,
                &symbols,
                &strings,
                &format!("kernelet_host_{field}_impl"),
            )?,
            exit,
        };
        audit_service_stub_prefix(&elf, stub.value, stub.size, field, &targets)?;
        info!("Host service {field} ({name}) at {address:#x}: ENDBR64");
    }
    audit_native_trap_prefix(&elf, &symbols, &strings)?;
    Ok(())
}

#[derive(Clone, Copy)]
struct ServiceStubTargets {
    state_pointer: u64,
    cpu_local_start: u64,
    implementation: u64,
    exit: u64,
}

struct ServiceStubPrefix {
    phase_failure: u64,
    stack_failure: Option<u64>,
    continuation: u64,
}

/// Ordinary services validate the Host-owned aligned pool, reserve and live
/// bit before their first stack write or call. Stop switches to the protected
/// Host stack instead. Both authenticate the carrier and phase first.
fn audit_service_stub_prefix(
    elf: &ElfImage<'_>,
    address: u64,
    size: u64,
    field: &str,
    targets: &ServiceStubTargets,
) -> Result<(), String> {
    let code = elf.bytes_at_vaddr(address, size)?;
    let prefix = checked_service_stub(code, address, field == "stop", targets)
        .map_err(|error| format!("Host service {field}: {error}"))?;
    let invalid = prefix.phase_failure;
    let failure = elf.bytes_at_vaddr(invalid, 12)?;
    if !failure.starts_with(&[0x48, 0xc7, 0xc0, 0xfb, 0xff, 0xff, 0xff, 0xe9]) {
        return Err(format!(
            "Host service {field} phase failure does not use the fixed exit"
        ));
    }
    let jump = i32::from_le_bytes(failure[8..12].try_into().unwrap()) as i64;
    if (invalid + 12).checked_add_signed(jump) != Some(targets.exit) {
        return Err(format!(
            "Host service {field} phase failure does not reach kernelet_host_exit"
        ));
    }
    if let Some(stack_failure) = prefix.stack_failure {
        let sections = elf.section_headers()?;
        let symbols = elf.symbols(&sections)?;
        let strings = elf.symbol_string_table(&sections)?;
        let invalid_impl =
            symbol_address(elf, &symbols, &strings, "kernelet_host_stack_invalid_impl")?;
        let mut failure = StubCursor::new(elf.bytes_at_vaddr(stack_failure, 54)?, stack_failure);
        failure.carrier(targets)?;
        failure.bytes(&[0x49, 0x8b, 0x23])?; // switch to fixed Host RSP
        failure.host_environment()?;
        if failure.direct(0xe8)? != invalid_impl {
            return Err("Host invalid-stack exit calls an unexpected target".into());
        }
        failure.bytes(&[0x48, 0xc7, 0xc0, 0xfb, 0xff, 0xff, 0xff])?;
        if failure.direct(0xe9)? != targets.exit {
            return Err("Host invalid-stack path does not reach fixed exit".into());
        }
        let prepare = symbol_address(
            elf,
            &symbols,
            &strings,
            "kernelet_host_prepare_service_return_impl",
        )?;
        let cancel = symbol_address(
            elf,
            &symbols,
            &strings,
            "kernelet_host_cancel_service_return_impl",
        )?;
        checked_service_return(
            elf.bytes_at_vaddr(prefix.continuation, SERVICE_RETURN_BYTES)?,
            prefix.continuation,
            targets,
            prepare,
            cancel,
        )?;
    }
    Ok(())
}

/// Exact allowed instructions, not an instruction scanner: an inserted push,
/// call, arbitrary field load, or bypass branch fails at its byte position.
fn checked_service_stub(
    code: &[u8],
    address: u64,
    stop: bool,
    targets: &ServiceStubTargets,
) -> Result<ServiceStubPrefix, String> {
    let mut cursor = StubCursor::new(code, address);
    cursor.bytes(&[0xfa])?;
    cursor.carrier(targets)?;
    let phase_failure = cursor.phase_commit(1, 2)?;
    cursor.bytes(&[0x49, 0x89, 0x63, 0x08])?; // save only IMAGE_RSP
    let stack_failure = if stop {
        cursor.bytes(&[0x49, 0x8b, 0x23])?;
        cursor.host_environment()?;
        None
    } else {
        // CarrierState has matching const offset assertions in host_run.rs:
        // pool start 64, exclusive end 72, live bitmap pointer 80.
        cursor.bytes(&[0x48, 0x89, 0xe0, 0x48, 0x25, 0, 0, 0xf8, 0xff])?;
        cursor.bytes(&[0x49, 0x3b, 0x43, 0x40])?;
        let failure = cursor.conditional(0x72)?;
        cursor.bytes(&[0x49, 0x3b, 0x43, 0x48])?;
        if cursor.conditional(0x73)? != failure {
            return Err("stack upper bound does not reject through fixed exit".into());
        }
        // usable half starts at 256 KiB; Host reserve is another 64 KiB.
        cursor.bytes(&[0x4c, 0x8d, 0x90, 0, 0, 0x05, 0, 0x4c, 0x39, 0xd4])?;
        if cursor.conditional(0x72)? != failure {
            return Err("stack reserve does not reject through fixed exit".into());
        }
        cursor.bytes(&[
            0x49, 0x2b, 0x43, 0x40, 0x48, 0xc1, 0xe8, 0x13, 0x4d, 0x8b, 0x53, 0x50, 0x49, 0x0f,
            0xa3, 0x02,
        ])?;
        if cursor.conditional(0x73)? != failure {
            return Err("stack live bit does not reject through fixed exit".into());
        }
        cursor.bytes(&[0xfc, 0x48, 0x83, 0xec, 0x08])?;
        Some(failure)
    };
    if cursor.direct(0xe8)? != targets.implementation {
        return Err("service calls an unexpected Rust implementation".into());
    }
    let continuation = cursor.jump()?;
    if stop && continuation != targets.exit {
        return Err("stop does not return through the fixed exit".into());
    }
    Ok(ServiceStubPrefix {
        phase_failure,
        stack_failure,
        continuation,
    })
}

/// Audit the whole common return, including its conditional root write and
/// stopped-carrier branch. No IDT transition or direct upcall is part of it.
fn checked_service_return(
    code: &[u8],
    address: u64,
    targets: &ServiceStubTargets,
    prepare: u64,
    cancel: u64,
) -> Result<(), String> {
    let mut cursor = StubCursor::new(code, address);
    cursor.bytes(&[0x50, 0x52])?; // preserve both ABI result words
    if cursor.direct(0xe8)? != prepare {
        return Err("Host service does not reach the common return helper".into());
    }
    cursor.carrier(targets)?;
    let stopped = cursor.phase_commit(4, 1)?;
    cursor.bytes(&[0x5a, 0x58, 0x4d, 0x8b, 0x53, 0x38, 0x4d, 0x85, 0xd2])?;
    let root_ready = cursor.conditional(0x75)?;
    cursor.bytes(&[0x4d, 0x8b, 0x53, 0x30])?;
    if root_ready != cursor.current_address()? {
        return Err("Host service root selection skips unexpected instructions".into());
    }
    cursor.bytes(&[0x0f, 0x20, 0xd9, 0x49, 0x39, 0xca])?;
    let root_unchanged = cursor.conditional(0x74)?;
    cursor.bytes(&[0x41, 0x0f, 0x22, 0xda])?;
    if root_unchanged != cursor.current_address()? {
        return Err("Host service does not skip CR3 write for an unchanged root".into());
    }
    // STI's interrupt shadow must cover RET, so a pending IRQ sees the image
    // continuation rather than the Host return instruction.
    cursor.bytes(&[0x49, 0x8b, 0x63, 0x08, 0xfb, 0xc3])?;
    if stopped != cursor.current_address()? {
        return Err("Host stopped-service branch does not reach its fixed exit".into());
    }
    cursor.bytes(&[0x48, 0x83, 0xc4, 0x10])?;
    if cursor.direct(0xe8)? != cancel {
        return Err("Host stopped-service branch does not cancel its return".into());
    }
    cursor.bytes(&[0x48, 0xc7, 0xc0, 0xfb, 0xff, 0xff, 0xff])?;
    if cursor.direct(0xe9)? != targets.exit {
        return Err("Host stopped-service branch does not reach kernelet_host_exit".into());
    }
    if cursor.offset != code.len() {
        return Err("Host service return has unexpected trailing instructions".into());
    }
    Ok(())
}

struct StubCursor<'a> {
    code: &'a [u8],
    address: u64,
    offset: usize,
}

impl<'a> StubCursor<'a> {
    fn new(code: &'a [u8], address: u64) -> Self {
        Self {
            code,
            address,
            offset: 0,
        }
    }

    fn bytes(&mut self, expected: &[u8]) -> Result<(), String> {
        if self.code.get(self.offset..self.offset + expected.len()) != Some(expected) {
            return Err(format!(
                "unexpected fixed stub instruction at byte {}",
                self.offset
            ));
        }
        self.offset += expected.len();
        Ok(())
    }

    fn current_address(&self) -> Result<u64, String> {
        self.address
            .checked_add(self.offset as u64)
            .ok_or_else(|| "fixed stub address overflows".to_string())
    }

    fn relative(&mut self, bytes: usize) -> Result<u64, String> {
        let displacement = self
            .code
            .get(self.offset..self.offset + bytes)
            .ok_or_else(|| "truncated fixed stub displacement".to_string())?;
        let displacement = if bytes == 1 {
            displacement[0] as i8 as i64
        } else {
            i32::from_le_bytes(displacement.try_into().unwrap()) as i64
        };
        self.offset += bytes;
        self.address
            .checked_add(self.offset as u64)
            .and_then(|next| next.checked_add_signed(displacement))
            .ok_or_else(|| "fixed stub target overflows".to_string())
    }

    fn direct(&mut self, opcode: u8) -> Result<u64, String> {
        self.bytes(&[opcode])?;
        self.relative(4)
    }

    fn jump(&mut self) -> Result<u64, String> {
        if self.code.get(self.offset) == Some(&0xeb) {
            self.bytes(&[0xeb])?;
            self.relative(1)
        } else {
            self.direct(0xe9)
        }
    }

    fn conditional(&mut self, short_opcode: u8) -> Result<u64, String> {
        if self.code.get(self.offset) == Some(&short_opcode) {
            self.bytes(&[short_opcode])?;
            self.relative(1)
        } else {
            self.bytes(&[0x0f, short_opcode + 0x10])?;
            self.relative(4)
        }
    }

    fn carrier(&mut self, targets: &ServiceStubTargets) -> Result<(), String> {
        self.bytes(&[0x4c, 0x8d, 0x1d])?;
        if self.relative(4)? != targets.state_pointer {
            return Err("carrier load does not address protected CPU-local state".into());
        }
        self.bytes(&[0x4c, 0x8d, 0x15])?;
        if self.relative(4)? != targets.cpu_local_start {
            return Err("carrier load does not subtract the native CPU-local base".into());
        }
        self.bytes(&[0x4d, 0x29, 0xd3, 0x65, 0x4d, 0x8b, 0x1b])
    }

    fn phase_commit(&mut self, previous: u8, next: u8) -> Result<u64, String> {
        // CarrierState asserts stop_state at 344 and run_state at 32. The
        // independently published sticky stop is checked before the phase
        // comparison and single-writer Release store, with physical IRQs off.
        self.bytes(&[
            0x4d, 0x8b, 0x93, 0x58, 0x01, 0, 0, 0x41, 0xf7, 0x02, 0, 0, 0, 0x80,
        ])?;
        let stopped = self.conditional(0x75)?;
        self.bytes(&[0x4d, 0x8b, 0x53, 0x20, 0x41, 0x83, 0x3a, previous])?;
        if self.conditional(0x75)? != stopped {
            return Err("phase mismatch and remote stop use different rejection paths".into());
        }
        self.bytes(&[0x41, 0xc7, 0x02, next, 0, 0, 0])?;
        Ok(stopped)
    }

    fn host_environment(&mut self) -> Result<(), String> {
        self.bytes(&[
            0x4d, 0x8b, 0x53, 0x30, 0x41, 0x0f, 0x22, 0xda, 0xfc, 0x48, 0x83, 0xec, 0x08,
        ])
    }
}

/// The fixed exit path must switch back to the protected Host RSP before its
/// first pop or return, including when reached by a failed service phase claim.
fn audit_host_exit_prefix(elf: &ElfImage<'_>, address: u64) -> Result<(), String> {
    let code = elf.bytes_at_vaddr(address, 33)?;
    let parts: &[(usize, &[u8])] = &[
        (0, &[0xfa]),
        (1, &[0x4c, 0x8d, 0x1d]),
        (8, &[0x4c, 0x8d, 0x15]),
        (15, &[0x4d, 0x29, 0xd3, 0x65, 0x4d, 0x8b, 0x1b]),
        (22, &[0x4d, 0x8b, 0x53, 0x30]),
        (26, &[0x41, 0x0f, 0x22, 0xda]),
        (30, &[0x49, 0x8b, 0x23]),
    ];
    if parts
        .iter()
        .any(|&(offset, part)| code.get(offset..offset + part.len()) != Some(part))
    {
        return Err("Host fixed exit has an unexpected pre-switch prefix".to_string());
    }
    Ok(())
}

fn symbol_address(
    elf: &ElfImage<'_>,
    symbols: &[Symbol],
    strings: &[u8],
    name: &str,
) -> Result<u64, String> {
    symbols
        .iter()
        .find(|symbol| elf.symbol_name(strings, symbol).ok() == Some(name))
        .map(|symbol| symbol.value)
        .ok_or_else(|| format!("the Host ELF lacks {name}"))
}

/// Checks the native kernel trap path in the linked ELF. The vector stubs
/// construct the trap metadata, and the common kernel path saves the general
/// registers, calls `trap_handler` on that same stack, and restores the frame.
/// An image-specific root, stack, or IDT transition cannot precede the handler.
fn audit_native_trap_prefix(
    elf: &ElfImage<'_>,
    symbols: &[Symbol],
    strings: &[u8],
) -> Result<(), String> {
    let common = symbol_address(elf, symbols, strings, "trap_common")?;
    let kernel = symbol_address(elf, symbols, strings, "_trap_from_kernel")?;
    let table = symbol_address(elf, symbols, strings, "trap_handler_table")?;
    let handler = symbol_address(elf, symbols, strings, "trap_handler")?;

    let vectors = elf.bytes_at_vaddr(table, 256 * 8)?;
    for vector in 0..256usize {
        let address = u64::from_le_bytes(vectors[vector * 8..vector * 8 + 8].try_into().unwrap());
        let code = elf.bytes_at_vaddr(address, 16)?;
        let hardware_error = matches!(vector, 8 | 10..=14 | 17);
        let mut offset = 0;
        if !hardware_error {
            offset += checked_push_immediate(&code[offset..], 0, vector)?;
        }
        offset += checked_push_immediate(&code[offset..], vector as i32, vector)?;
        let mut jump = StubCursor::new(&code[offset..], address + offset as u64);
        if jump.jump()? != common {
            return Err(format!(
                "Host trap vector {vector} does not jump to trap_common {common:#x}"
            ));
        }
    }

    let mut prefix = StubCursor::new(elf.bytes_at_vaddr(common, 17)?, common);
    prefix.bytes(&[
        0xfc, 0x50, 0x66, 0x8b, 0x44, 0x24, 0x20, 0x66, 0x83, 0xe0, 0x03,
    ])?;
    if prefix.conditional(0x74)? != kernel {
        return Err("Host trap_common does not select the native kernel trap path".into());
    }
    checked_native_kernel_trap(elf.bytes_at_vaddr(kernel, 61)?, kernel, handler)?;
    info!("Host kernel trap: native saved frame and direct trap_handler call");
    Ok(())
}

fn checked_native_kernel_trap(code: &[u8], address: u64, handler: u64) -> Result<(), String> {
    let mut cursor = StubCursor::new(code, address);
    // Remove the temporary RAX save, then save all fifteen general registers.
    cursor.bytes(&[
        0x58, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x41, 0x53, 0x41, 0x52, 0x41, 0x51,
        0x41, 0x50, 0x55, 0x57, 0x56, 0x52, 0x51, 0x53, 0x50,
    ])?;
    cursor.bytes(&[0x48, 0x89, 0xe7])?; // mov rdi, rsp: borrow the saved frame
    if cursor.direct(0xe8)? != handler {
        return Err("Host native kernel trap does not call trap_handler directly".into());
    }
    cursor.bytes(&[
        0x58, 0x5b, 0x59, 0x5a, 0x5e, 0x5f, 0x5d, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x41, 0x5b,
        0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0x48, 0x83, 0xc4, 0x10, 0x48, 0xcf,
    ])?; // Restore GPRs, discard vector/error code, and IRET.
    Ok(())
}

fn checked_push_immediate(code: &[u8], expected: i32, vector: usize) -> Result<usize, String> {
    let (value, size) = match code.first() {
        Some(0x6a) => (code[1] as i8 as i32, 2),
        Some(0x68) => (i32::from_le_bytes(code[1..5].try_into().unwrap()), 5),
        _ => {
            return Err(format!(
                "Host trap vector {vector} has a non-immediate stack push"
            ));
        }
    };
    if value != expected {
        return Err(format!(
            "Host trap vector {vector} pushes {value}, expected {expected}"
        ));
    }
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::{
        ServiceStubTargets, checked_native_kernel_trap, checked_service_return,
        checked_service_stub,
    };

    #[test]
    fn includes_diagnostic_echo_in_the_full_service_audit() {
        let normal = super::service_fields(152).unwrap();
        let diagnostic = super::service_fields(160).unwrap();
        assert_eq!(normal, super::SERVICE_FIELDS);
        assert_eq!(&diagnostic[..normal.len()], normal);
        assert_eq!(diagnostic.last(), Some(&"rq1_echo"));
        for unknown in [0, 8, 144, 153, 159, 161, 168] {
            assert!(super::service_fields(unknown).is_err());
        }
    }

    // Assembled from the actual host_run.S and trap.S. Pool offsets are
    // 64/72/80 and the independent stop pointer is 344; text starts at
    // 0x10000/0x20000. The service commit preserves r11; the return reads CR3
    // into caller-saved rcx and preserves the rax:rdx results. Dummy Rust destinations
    // resolve direct calls without replacing any audited assembly.
    const SHARED_NEAR: &[u8] = &[
        0xfa, 0x4c, 0x8d, 0x1d, 0x58, 0xff, 0x6e, 0x00, 0x4c, 0x8d, 0x15, 0x51, 0xff, 0x5e, 0x00,
        0x4d, 0x29, 0xd3, 0x65, 0x4d, 0x8b, 0x1b, 0x4d, 0x8b, 0x93, 0x58, 0x01, 0x00, 0x00, 0x41,
        0xf7, 0x02, 0x00, 0x00, 0x00, 0x80, 0x0f, 0x85, 0x71, 0x0b, 0x00, 0x00, 0x4d, 0x8b, 0x53,
        0x20, 0x41, 0x83, 0x3a, 0x01, 0x0f, 0x85, 0x63, 0x0b, 0x00, 0x00, 0x41, 0xc7, 0x02, 0x02,
        0x00, 0x00, 0x00, 0x49, 0x89, 0x63, 0x08, 0x48, 0x89, 0xe0, 0x48, 0x25, 0x00, 0x00, 0xf8,
        0xff, 0x49, 0x3b, 0x43, 0x40, 0x0f, 0x82, 0x0f, 0x0b, 0x00, 0x00, 0x49, 0x3b, 0x43, 0x48,
        0x0f, 0x83, 0x05, 0x0b, 0x00, 0x00, 0x4c, 0x8d, 0x90, 0x00, 0x00, 0x05, 0x00, 0x4c, 0x39,
        0xd4, 0x0f, 0x82, 0xf5, 0x0a, 0x00, 0x00, 0x49, 0x2b, 0x43, 0x40, 0x48, 0xc1, 0xe8, 0x13,
        0x4d, 0x8b, 0x53, 0x50, 0x49, 0x0f, 0xa3, 0x02, 0x0f, 0x83, 0xdf, 0x0a, 0x00, 0x00, 0xfc,
        0x48, 0x83, 0xec, 0x08, 0xe8, 0x41, 0x0b, 0x00, 0x00, 0xe9, 0xfd, 0x09, 0x00, 0x00,
    ];
    const SHARED_SHORT_JUMP: &[u8] = &[
        0xfa, 0x4c, 0x8d, 0x1d, 0x58, 0xf5, 0x6e, 0x00, 0x4c, 0x8d, 0x15, 0x51, 0xf5, 0x5e, 0x00,
        0x4d, 0x29, 0xd3, 0x65, 0x4d, 0x8b, 0x1b, 0x4d, 0x8b, 0x93, 0x58, 0x01, 0x00, 0x00, 0x41,
        0xf7, 0x02, 0x00, 0x00, 0x00, 0x80, 0x0f, 0x85, 0x71, 0x01, 0x00, 0x00, 0x4d, 0x8b, 0x53,
        0x20, 0x41, 0x83, 0x3a, 0x01, 0x0f, 0x85, 0x63, 0x01, 0x00, 0x00, 0x41, 0xc7, 0x02, 0x02,
        0x00, 0x00, 0x00, 0x49, 0x89, 0x63, 0x08, 0x48, 0x89, 0xe0, 0x48, 0x25, 0x00, 0x00, 0xf8,
        0xff, 0x49, 0x3b, 0x43, 0x40, 0x0f, 0x82, 0x0f, 0x01, 0x00, 0x00, 0x49, 0x3b, 0x43, 0x48,
        0x0f, 0x83, 0x05, 0x01, 0x00, 0x00, 0x4c, 0x8d, 0x90, 0x00, 0x00, 0x05, 0x00, 0x4c, 0x39,
        0xd4, 0x0f, 0x82, 0xf5, 0x00, 0x00, 0x00, 0x49, 0x2b, 0x43, 0x40, 0x48, 0xc1, 0xe8, 0x13,
        0x4d, 0x8b, 0x53, 0x50, 0x49, 0x0f, 0xa3, 0x02, 0x0f, 0x83, 0xdf, 0x00, 0x00, 0x00, 0xfc,
        0x48, 0x83, 0xec, 0x08, 0xe8, 0x40, 0x01, 0x00, 0x00, 0xeb, 0x00,
    ];
    const STOP: &[u8] = &[
        0xfa, 0x4c, 0x8d, 0x1d, 0x48, 0xf4, 0x6e, 0x00, 0x4c, 0x8d, 0x15, 0x41, 0xf4, 0x5e, 0x00,
        0x4d, 0x29, 0xd3, 0x65, 0x4d, 0x8b, 0x1b, 0x4d, 0x8b, 0x93, 0x58, 0x01, 0x00, 0x00, 0x41,
        0xf7, 0x02, 0x00, 0x00, 0x00, 0x80, 0x75, 0x65, 0x4d, 0x8b, 0x53, 0x20, 0x41, 0x83, 0x3a,
        0x01, 0x75, 0x5b, 0x41, 0xc7, 0x02, 0x02, 0x00, 0x00, 0x00, 0x49, 0x89, 0x63, 0x08, 0x49,
        0x8b, 0x23, 0x4d, 0x8b, 0x53, 0x30, 0x41, 0x0f, 0x22, 0xda, 0xfc, 0x48, 0x83, 0xec, 0x08,
        0xe8, 0x7a, 0x00, 0x00, 0x00, 0xe9, 0x6b, 0xf4, 0xff, 0xff,
    ];
    const SERVICE_RETURN: &[u8] = &[
        0x50, 0x52, 0xe8, 0x3c, 0x01, 0x00, 0x00, 0x4c, 0x8d, 0x1d, 0xc0, 0xf4, 0x6e, 0x00, 0x4c,
        0x8d, 0x15, 0xb9, 0xf4, 0x5e, 0x00, 0x4d, 0x29, 0xd3, 0x65, 0x4d, 0x8b, 0x1b, 0x4d, 0x8b,
        0x93, 0x58, 0x01, 0x00, 0x00, 0x41, 0xf7, 0x02, 0x00, 0x00, 0x00, 0x80, 0x75, 0x32, 0x4d,
        0x8b, 0x53, 0x20, 0x41, 0x83, 0x3a, 0x04, 0x75, 0x28, 0x41, 0xc7, 0x02, 0x01, 0x00, 0x00,
        0x00, 0x5a, 0x58, 0x4d, 0x8b, 0x53, 0x38, 0x4d, 0x85, 0xd2, 0x75, 0x04, 0x4d, 0x8b, 0x53,
        0x30, 0x0f, 0x20, 0xd9, 0x49, 0x39, 0xca, 0x74, 0x04, 0x41, 0x0f, 0x22, 0xda, 0x49, 0x8b,
        0x63, 0x08, 0xfb, 0xc3, 0x48, 0x83, 0xc4, 0x10, 0xe8, 0xd4, 0x00, 0x00, 0x00, 0x48, 0xc7,
        0xc0, 0xfb, 0xff, 0xff, 0xff, 0xe9, 0xcb, 0xf4, 0xff, 0xff,
    ];
    const NATIVE_TRAP: &[u8] = &[
        0x58, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x41, 0x53, 0x41, 0x52, 0x41, 0x51,
        0x41, 0x50, 0x55, 0x57, 0x56, 0x52, 0x51, 0x53, 0x50, 0x48, 0x89, 0xe7, 0xe8, 0x1d, 0x00,
        0x00, 0x00, 0x58, 0x5b, 0x59, 0x5a, 0x5e, 0x5f, 0x5d, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a,
        0x41, 0x5b, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0x48, 0x83, 0xc4, 0x10, 0x48,
        0xcf,
    ];

    fn service_targets(implementation: u64) -> ServiceStubTargets {
        ServiceStubTargets {
            state_pointer: 0x700000,
            cpu_local_start: 0x600000,
            implementation,
            exit: 0x10070,
        }
    }

    fn service_fixtures() -> [(&'static [u8], u64, u64, bool); 3] {
        [
            (SHARED_NEAR, 0x100a0, 0x10c71, false),
            (SHARED_SHORT_JUMP, 0x10aa0, 0x10c70, false),
            (STOP, 0x10bb0, 0x10c7a, true),
        ]
    }

    #[test]
    fn accepts_checked_shared_stack_and_stop_prefixes() {
        for (code, address, implementation, stop) in service_fixtures() {
            let targets = service_targets(implementation);
            let prefix = checked_service_stub(code, address, stop, &targets).unwrap();
            assert_eq!(prefix.phase_failure, 0x10c3b);
            assert_eq!(prefix.stack_failure, (!stop).then_some(0x10c05));
            assert_eq!(
                prefix.continuation,
                if stop { targets.exit } else { 0x10b32 }
            );
            for length in 0..code.len() {
                assert!(checked_service_stub(&code[..length], address, stop, &targets).is_err());
            }
        }
    }

    #[test]
    fn rejects_changed_stack_checks_carrier_offsets_and_early_calls() {
        for (code, address, implementation, stop) in service_fixtures() {
            let targets = service_targets(implementation);
            for changed_byte in 0..code.len() {
                let mut changed = code.to_vec();
                changed[changed_byte] ^= 1;
                if let Ok(prefix) = checked_service_stub(&changed, address, stop, &targets) {
                    // The ELF-level audit checks these branch destinations
                    // against their fixed rejection and continuation bodies.
                    assert!(
                        prefix.phase_failure != 0x10c3b
                            || prefix.stack_failure != (!stop).then_some(0x10c05)
                            || prefix.continuation != if stop { targets.exit } else { 0x10b32 },
                        "accepted changed instruction at byte {changed_byte}"
                    );
                }
            }
        }
        for early_stack_write in [&[0x50][..], &[0xe8, 0, 0, 0, 0][..]] {
            let mut changed = SHARED_NEAR.to_vec();
            changed.splice(67..67, early_stack_write.iter().copied());
            assert!(
                checked_service_stub(&changed, 0x100a0, false, &service_targets(0x10c71)).is_err()
            );
        }
        let mut changed = SHARED_NEAR.to_vec();
        changed.splice(134..134, [0x41, 0x0f, 0x01, 0x5b, 0x40]); // old native-IDT load
        assert!(checked_service_stub(&changed, 0x100a0, false, &service_targets(0x10c71)).is_err());
    }

    #[test]
    fn rejects_missing_remote_stop_check_and_phase_rmw() {
        for (code, address, implementation, stop) in service_fixtures() {
            let targets = service_targets(implementation);
            let stop_load = code
                .windows(7)
                .position(|w| w == [0x4d, 0x8b, 0x93, 0x58, 0x01, 0, 0])
                .unwrap();
            let phase_load = code
                .windows(4)
                .position(|w| w == [0x4d, 0x8b, 0x53, 0x20])
                .unwrap();
            let mut changed = code.to_vec();
            changed.drain(stop_load..phase_load);
            assert!(checked_service_stub(&changed, address, stop, &targets).is_err());

            let mut changed = code.to_vec();
            // Checking the phase word instead of the independent stop word
            // must not silently remove the remote-stop admission check.
            changed[stop_load + 3..stop_load + 7].copy_from_slice(&32u32.to_le_bytes());
            assert!(checked_service_stub(&changed, address, stop, &targets).is_err());

            let phase_store = code
                .windows(7)
                .position(|w| w == [0x41, 0xc7, 0x02, 2, 0, 0, 0])
                .unwrap();
            let mut changed = code.to_vec();
            // Reject restoring the old merged-word LOCK CMPXCHG transaction.
            changed.splice(
                phase_store..phase_store + 7,
                [
                    0xb8, 1, 0, 0, 0, 0x41, 0xba, 2, 0, 0, 0, 0xf0, 0x45, 0x0f, 0xb1, 0x13,
                ],
            );
            assert!(checked_service_stub(&changed, address, stop, &targets).is_err());
        }
    }

    fn check_return(code: &[u8]) -> Result<(), String> {
        checked_service_return(code, 0x10b32, &service_targets(0), 0x10c75, 0x10c6d)
    }

    #[test]
    fn accepts_service_return_without_an_idt_transition() {
        assert_eq!(SERVICE_RETURN.len() as u64, super::SERVICE_RETURN_BYTES);
        check_return(SERVICE_RETURN).unwrap();
        for length in 0..SERVICE_RETURN.len() {
            assert!(check_return(&SERVICE_RETURN[..length]).is_err());
        }
    }

    #[test]
    fn rejects_changed_service_return_phase_root_and_stop_paths() {
        for changed_byte in 0..SERVICE_RETURN.len() {
            let mut code = SERVICE_RETURN.to_vec();
            code[changed_byte] ^= 1;
            assert!(check_return(&code).is_err(), "accepted byte {changed_byte}");
        }
        let mut code = SERVICE_RETURN.to_vec();
        code.splice(7..7, [0x41, 0x0f, 0x01, 0x5b, 0x40]); // old native-IDT load
        assert!(check_return(&code).is_err());
        let mut code = SERVICE_RETURN.to_vec();
        // Reintroducing a NOP after STI admits an IRQ at the Host RET address.
        let ret = code
            .windows(6)
            .position(|w| w == [0x49, 0x8b, 0x63, 0x08, 0xfb, 0xc3])
            .unwrap();
        code.insert(ret + 5, 0x90);
        assert!(check_return(&code).is_err());
        let mut code = SERVICE_RETURN.to_vec();
        code.push(0x90);
        assert!(check_return(&code).is_err());
    }

    #[test]
    fn accepts_native_kernel_trap_frame_and_direct_handler_call() {
        checked_native_kernel_trap(NATIVE_TRAP, 0x20a8d, 0x20aca).unwrap();
        for length in 0..NATIVE_TRAP.len() {
            assert!(checked_native_kernel_trap(&NATIVE_TRAP[..length], 0x20a8d, 0x20aca).is_err());
        }
    }

    #[test]
    fn rejects_native_trap_adapter_or_changed_saved_frame() {
        for changed_byte in 0..NATIVE_TRAP.len() {
            let mut code = NATIVE_TRAP.to_vec();
            code[changed_byte] ^= 1;
            assert!(
                checked_native_kernel_trap(&code, 0x20a8d, 0x20aca).is_err(),
                "accepted byte {changed_byte}"
            );
        }
        for transition in [
            &[0x41, 0x0f, 0x01, 0x5b, 0x40][..], // lidt [r11 + 64]
            &[0x41, 0x0f, 0x22, 0xda][..],       // mov cr3, r10
            &[0x49, 0x8b, 0x23][..],             // mov rsp, [r11]
        ] {
            let mut code = NATIVE_TRAP.to_vec();
            code.splice(24..24, transition.iter().copied());
            assert!(checked_native_kernel_trap(&code, 0x20a8d, 0x20aca).is_err());
        }
    }
}
