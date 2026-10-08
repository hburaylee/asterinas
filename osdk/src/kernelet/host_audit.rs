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
const SERVICE_FIELDS: [&str; 20] = [
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
    "fpu_save",
    "fpu_load",
    "mmio_read",
    "mmio_write",
    "log_write",
    "oops",
    "stop",
];

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
    const TABLE_BYTES: u64 = 8 + SERVICE_FIELDS.len() as u64 * 8;
    if table.size != TABLE_BYTES {
        return Err(format!(
            "the Host service table is {} bytes, expected {TABLE_BYTES}",
            table.size
        ));
    }
    let data = elf.bytes_at_vaddr(table.value, table.size)?;
    let declared_size = u64::from_le_bytes(data[..8].try_into().unwrap());
    if declared_size != TABLE_BYTES {
        return Err(format!(
            "the Host service table declares {declared_size} bytes, expected {TABLE_BYTES}"
        ));
    }

    let segments = elf.program_headers()?;
    let exit = symbol_address(&elf, &symbols, &strings, "kernelet_host_exit")?;
    audit_host_exit_prefix(&elf, exit)?;
    audit_fixed_yield_stub(&elf, &symbols, &strings)?;
    let mut seen = HashSet::new();
    for (index, field) in SERVICE_FIELDS.iter().enumerate() {
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
        audit_service_stub_prefix(&elf, stub.value, field, exit)?;
        info!("Host service {field} ({name}) at {address:#x}: ENDBR64");
    }
    audit_image_trap_prefix(&elf, &symbols, &strings)?;
    Ok(())
}

/// The fixed stub touches no stack until it saves the image RSP and loads the
/// protected Host RSP. The indirect Guest call has consumed eight bytes on
/// the image stack; this 72- or 76-byte machine prefix consumes no more.
fn audit_service_stub_prefix(
    elf: &ElfImage<'_>,
    address: u64,
    field: &str,
    exit: u64,
) -> Result<(), String> {
    let code = elf.bytes_at_vaddr(address, 76)?;
    const PARTS: &[(usize, &[u8])] = &[
        (0, &[0xfa]),             // cli
        (1, &[0x4c, 0x8d, 0x1d]), // load carrier: lea r11, [rip + ...]
        (8, &[0x4c, 0x8d, 0x15]), // lea r10, [rip + ...]
        (15, &[0x4d, 0x29, 0xd3, 0x65, 0x4d, 0x8b, 0x1b]),
        (22, &[0xb8, 1, 0, 0, 0, 0x41, 0xba, 2, 0, 0, 0]),
        (33, &[0x4d, 0x8b, 0x5b, 0x20, 0xf0, 0x45, 0x0f, 0xb1, 0x13]),
    ];
    let branch_len = match code.get(42..44) {
        Some([0x0f, 0x85]) => 6,
        Some([0x75, _]) => 2,
        _ => {
            return Err(format!(
                "Host service {field} has no pre-switch phase-failure branch"
            ));
        }
    };
    let second_load = 42 + branch_len;
    let tail: &[(usize, &[u8])] = &[
        (second_load, &[0x4c, 0x8d, 0x1d]),
        (second_load + 7, &[0x4c, 0x8d, 0x15]),
        (
            second_load + 14,
            &[0x4d, 0x29, 0xd3, 0x65, 0x4d, 0x8b, 0x1b],
        ),
        (second_load + 21, &[0x49, 0x89, 0x63, 0x08]), // save image RSP
        (second_load + 25, &[0x49, 0x8b, 0x23]),       // load protected Host RSP
    ];
    if PARTS
        .iter()
        .chain(tail)
        .any(|&(offset, part)| code.get(offset..offset + part.len()) != Some(part))
    {
        return Err(format!(
            "Host service {field} stub at {address:#x} has an unexpected pre-switch prefix"
        ));
    }
    let displacement = if branch_len == 2 {
        code[43] as i8 as i64
    } else {
        i32::from_le_bytes(code[44..48].try_into().unwrap()) as i64
    };
    let invalid = (address + 42 + branch_len as u64)
        .checked_add_signed(displacement)
        .ok_or_else(|| format!("Host service {field} phase-failure branch overflows"))?;
    let failure = elf.bytes_at_vaddr(invalid, 12)?;
    if !failure.starts_with(&[0x48, 0xc7, 0xc0, 0xfb, 0xff, 0xff, 0xff, 0xe9]) {
        return Err(format!(
            "Host service {field} phase failure does not use the fixed exit"
        ));
    }
    let jump = i32::from_le_bytes(failure[8..12].try_into().unwrap()) as i64;
    if (invalid + 12).checked_add_signed(jump) != Some(exit) {
        return Err(format!(
            "Host service {field} phase failure does not reach kernelet_host_exit"
        ));
    }
    Ok(())
}

/// The fixed exit path must switch back to the protected Host RSP before its
/// first pop or return, including when reached by a failed service phase claim.
fn audit_host_exit_prefix(elf: &ElfImage<'_>, address: u64) -> Result<(), String> {
    let code = elf.bytes_at_vaddr(address, 38)?;
    let parts: &[(usize, &[u8])] = &[
        (0, &[0xfa]),
        (1, &[0x4c, 0x8d, 0x1d]),
        (8, &[0x4c, 0x8d, 0x15]),
        (15, &[0x4d, 0x29, 0xd3, 0x65, 0x4d, 0x8b, 0x1b]),
        (22, &[0x41, 0x0f, 0x01, 0x5b, 0x40]),
        (27, &[0x4d, 0x8b, 0x53, 0x30]),
        (31, &[0x41, 0x0f, 0x22, 0xda]),
        (35, &[0x49, 0x8b, 0x23]),
    ];
    if parts
        .iter()
        .any(|&(offset, part)| code.get(offset..offset + part.len()) != Some(part))
    {
        return Err("Host fixed exit has an unexpected pre-switch prefix".to_string());
    }
    Ok(())
}

/// The forced-yield IRET arrives with the complete image continuation on its
/// private IST. The fixed stub must touch no image-stack memory before loading
/// the protected Host RSP, then enter only the two audited Host call targets.
fn audit_fixed_yield_stub(
    elf: &ElfImage<'_>,
    symbols: &[Symbol],
    strings: &[u8],
) -> Result<(), String> {
    let address = symbol_address(elf, symbols, strings, "kernelet_host_forced_yield")?;
    let implementation = symbol_address(elf, symbols, strings, "kernelet_host_forced_yield_impl")?;
    let prepare = symbol_address(
        elf,
        symbols,
        strings,
        "kernelet_host_prepare_yield_return_impl",
    )?;
    let resume = symbol_address(elf, symbols, strings, "kernelet_host_resume_image_trap")?;
    let code = elf.bytes_at_vaddr(address, 53)?;
    let parts: &[(usize, &[u8])] = &[
        (0, &[0xfa]),             // cli
        (1, &[0x4c, 0x8d, 0x1d]), // load carrier
        (8, &[0x4c, 0x8d, 0x15]),
        (15, &[0x4d, 0x29, 0xd3, 0x65, 0x4d, 0x8b, 0x1b]),
        (22, &[0x49, 0x8b, 0x23]),             // protected Host RSP
        (25, &[0x41, 0x0f, 0x01, 0x5b, 0x40]), // native IDT
        (30, &[0x4d, 0x8b, 0x53, 0x30]),       // Host CR3
        (34, &[0x41, 0x0f, 0x22, 0xda]),
        (38, &[0xfc, 0x48, 0x83, 0xec, 0x08]), // cld; align RSP
    ];
    if parts
        .iter()
        .any(|&(offset, part)| code.get(offset..offset + part.len()) != Some(part))
    {
        return Err("Host fixed yield has an unexpected pre-switch prefix".to_string());
    }
    for (offset, target) in [(43, implementation), (48, prepare)] {
        if code[offset] != 0xe8 {
            return Err("Host fixed yield lost a required Host call".to_string());
        }
        let displacement = i32::from_le_bytes(code[offset + 1..offset + 5].try_into().unwrap());
        if (address + offset as u64 + 5).checked_add_signed(displacement as i64) != Some(target) {
            return Err("Host fixed yield calls an unexpected target".to_string());
        }
    }
    audit_fixed_yield_redirect(elf, symbols, strings, address, resume)?;
    Ok(())
}

/// Verify both linked transitions around a physical image trap: the initial
/// IMAGE -> ENTERING claim precedes Host handling, and the fixed-yield return
/// claims RETURNING -> ENTERING without exposing IMAGE on the Host stack.
fn audit_fixed_yield_redirect(
    elf: &ElfImage<'_>,
    symbols: &[Symbol],
    strings: &[u8],
    yield_stub: u64,
    resume: u64,
) -> Result<(), String> {
    let kernel = symbol_address(elf, symbols, strings, "_trap_from_kernel")?;
    let cancel = symbol_address(
        elf,
        symbols,
        strings,
        "kernelet_host_cancel_trap_return_impl",
    )?;
    let code = elf.bytes_at_vaddr(kernel, 320)?;
    let entry_claim = checked_image_claim(code)?;
    let redirect = (0..code.len() - 42)
        .find(|&at| {
            code[at..].starts_with(&[0x48, 0x8d, 0x0d])
                && (kernel + at as u64 + 7).checked_add_signed(i32::from_le_bytes(
                    code[at + 3..at + 7].try_into().unwrap(),
                ) as i64)
                    == Some(yield_stub)
        })
        .ok_or_else(|| "Host image trap lacks the fixed yield redirect".to_string())?;
    if entry_claim >= redirect {
        return Err("Host image trap claims ENTERING after Host handling".to_string());
    }
    let mut at = redirect + 7;
    if code.get(at..at + 7) != Some(&[0x48, 0x39, 0x8a, 0x88, 0, 0, 0]) {
        return Err("Host yield redirect does not test the saved image RIP".to_string());
    }
    at += 7;
    if code[at] != 0x75 {
        return Err("Host yield redirect does not preserve ordinary traps".to_string());
    }
    at += 2;
    const CLAIM_YIELD: &[u8] = &[
        0xb8, 4, 0, 0, 0, 0xba, 2, 0, 0, 0, 0xf0, 0x41, 0x0f, 0xb1, 0x12,
    ];
    if code.get(at..at + CLAIM_YIELD.len()) != Some(CLAIM_YIELD) {
        return Err("Host yield redirect lost RETURNING -> ENTERING".to_string());
    }
    at += CLAIM_YIELD.len();
    if code[at] != 0x75 {
        return Err("Host yield redirect lacks its failed-claim exit".to_string());
    }
    let stop = (kernel + at as u64 + 2)
        .checked_add_signed(code[at + 1] as i8 as i64)
        .ok_or_else(|| "Host yield failed-claim branch overflows".to_string())?;
    at += 2;
    if code.get(at..at + 5) != Some(&[0x49, 0x8b, 0x63, 0x08, 0xe9]) {
        return Err("Host yield redirect does not restore the private IST frame".to_string());
    }
    let target = (kernel + at as u64 + 9)
        .checked_add_signed(i32::from_le_bytes(code[at + 5..at + 9].try_into().unwrap()) as i64);
    if target != Some(resume) {
        return Err("Host yield redirect does not reach the fixed IRET epilogue".to_string());
    }
    let stop_code = elf.bytes_at_vaddr(stop, 5)?;
    if stop_code[0] != 0xe8
        || (stop + 5)
            .checked_add_signed(i32::from_le_bytes(stop_code[1..5].try_into().unwrap()) as i64)
            != Some(cancel)
    {
        return Err("Host yield phase failure does not cancel on the Host stack".to_string());
    }
    Ok(())
}

/// Checks the STOP-preserving claim loop emitted by `trap.S`.
fn checked_image_claim(code: &[u8]) -> Result<usize, String> {
    // Load the full word into EAX; mask only EDX for the IMAGE phase check.
    const PHASE_CHECK: &[u8] = &[
        0x41, 0x8b, 0x02, 0x89, 0xc2, 0x81, 0xe2, 0xff, 0xff, 0xff, 0x7f, 0x83, 0xfa, 0x01,
    ];
    let start = code
        .windows(PHASE_CHECK.len())
        .position(|window| window == PHASE_CHECK)
        .ok_or_else(|| "Host image trap does not check IMAGE while preserving STOP".to_string())?;
    let branch = start + PHASE_CHECK.len();
    let branch_len = if code.get(branch..branch + 2) == Some(&[0x0f, 0x85]) {
        6
    } else if code.get(branch) == Some(&0x75) {
        2
    } else {
        return Err("Host image trap lacks its wrong-phase exit".to_string());
    };
    // Copy the original EAX back to EDX, XOR only IMAGE/ENTERING phase bits,
    // then compare and exchange the full word. A racing STOP must retry.
    const CLAIM: &[u8] = &[0x89, 0xc2, 0x83, 0xf2, 0x03, 0xf0, 0x41, 0x0f, 0xb1, 0x12];
    let claim = branch + branch_len;
    if code.get(claim..claim + CLAIM.len()) != Some(CLAIM) {
        return Err("Host image trap lost its STOP-preserving IMAGE -> ENTERING claim".to_string());
    }
    let retry = claim + CLAIM.len();
    if code.get(retry) != Some(&0x75)
        || code.get(retry + 1).is_none_or(|displacement| {
            (retry + 2) as isize + *displacement as i8 as isize != start as isize
        })
    {
        return Err("Host image trap does not retry a raced claim".to_string());
    }
    Ok(start)
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

/// Checks the assembly path that lands a physical image interrupt on a
/// carrier's private IST and switches to the protected Host stack before
/// calling Rust. The linked vector stubs consume at most two words, and the
/// common prefix consumes fifteen saved-register words after its RAX save:
/// 40 bytes of hardware frame + 16 vector bytes + 120 registers = 176 bytes.
fn audit_image_trap_prefix(
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
        let (jump_len, displacement) = match code[offset] {
            0xeb => (2, code[offset + 1] as i8 as i64),
            0xe9 => (
                5,
                i32::from_le_bytes(code[offset + 1..offset + 5].try_into().unwrap()) as i64,
            ),
            _ => {
                return Err(format!(
                    "Host trap vector {vector} does not jump to trap_common"
                ));
            }
        };
        let target = (address + offset as u64 + jump_len)
            .checked_add_signed(displacement)
            .ok_or_else(|| format!("Host trap vector {vector} jump overflows"))?;
        if target != common {
            return Err(format!(
                "Host trap vector {vector} jumps to {target:#x}, expected trap_common {common:#x}"
            ));
        }
    }

    // `trap_common` saves RAX before testing CS; the kernel branch removes
    // that temporary save and stores all fifteen general registers.
    let common_code = elf.bytes_at_vaddr(common, 16)?;
    if !common_code.starts_with(&[
        0xfc, 0x50, 0x66, 0x8b, 0x44, 0x24, 0x20, 0x66, 0x83, 0xe0, 0x03,
    ]) {
        return Err("Host trap_common has an unexpected pre-handler prefix".to_string());
    }
    let kernel_code = elf.bytes_at_vaddr(kernel, 400)?;
    const REGISTER_SAVE: &[u8] = &[
        0x58, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x41, 0x53, 0x41, 0x52, 0x41, 0x51,
        0x41, 0x50, 0x55, 0x57, 0x56, 0x52, 0x51, 0x53, 0x50,
    ];
    if !kernel_code.starts_with(REGISTER_SAVE) {
        return Err("Host image IST register-save prefix changed".to_string());
    }

    // Locate the ordinary-trap image-IST branch by its two carrier landing
    // bounds. Both conditional jumps must bypass the protected-stack path
    // when RSP is outside that area.
    // CarrierState::landing_start/end are checked by const assertions in
    // OSTD. Keep these audit displacements in step with trap.S.
    const LOWER: &[u8] = &[0x49, 0x3b, 0xa3, 0x30, 0x01, 0x00, 0x00];
    const UPPER: &[u8] = &[0x49, 0x3b, 0xa3, 0x38, 0x01, 0x00, 0x00];
    let start = kernel_code
        .windows(LOWER.len())
        .position(|window| window == LOWER)
        .ok_or_else(|| "Host image IST landing-start comparison is missing".to_string())?;
    let branch = &kernel_code[start..];
    let required: &[(usize, &[u8])] = &[
        (0, LOWER),
        (7, &[0x72]), // below landing range: use the ordinary native path
        (9, UPPER),
        (16, &[0x73]),             // at or above landing range: ordinary native path
        (18, &[0x48, 0x89, 0xe7]), // pass the saved landing frame
        (21, &[0x41, 0x0f, 0x20, 0xda]), // save interrupted CR3
        (25, &[0x49, 0x8b, 0x23]), // switch to protected Host RSP
        (28, &[0x41, 0x52, 0x57, 0x48, 0x83, 0xec, 0x08]),
        (35, &[0x4d, 0x8b, 0x53, 0x30]), // load Host root
        (39, &[0x41, 0x0f, 0x22, 0xda]), // switch CR3 before Rust
        (43, &[0xe8]),                   // call trap_handler
        (48, &[0xfa, 0x48, 0x83, 0xc4, 0x08]),
        (53, &[0x41, 0x5b, 0x41, 0x5a]), // restore saved frame and CR3
        (57, &[0x41, 0x0f, 0x22, 0xda]),
        (61, &[0x4c, 0x89, 0xdc]), // resume on original landing frame
        (64, &[0xeb]),
        (66, &[0x48, 0x89, 0xe7, 0xe8]), // ordinary native stack path
    ];
    if required
        .iter()
        .any(|&(offset, part)| branch.get(offset..offset + part.len()) != Some(part))
    {
        return Err("Host image IST linked stack/CR3 switch prefix changed".to_string());
    }
    for &(jump_at, displacement_at) in &[(7usize, 8usize), (16, 17)] {
        let target = (jump_at + 2) as isize + branch[displacement_at] as i8 as isize;
        if target != 66 {
            return Err("Host image IST range branch does not skip to native path".to_string());
        }
    }
    if (64 + 2 + branch[65] as i8 as isize) != 74 {
        return Err("Host image IST path does not rejoin after restoring RSP".to_string());
    }
    for call_at in [43usize, 69] {
        let displacement = i32::from_le_bytes(branch[call_at + 1..call_at + 5].try_into().unwrap());
        let target = (kernel + start as u64 + call_at as u64 + 5)
            .checked_add_signed(displacement as i64)
            .ok_or_else(|| "Host trap handler call overflows".to_string())?;
        if target != handler {
            return Err(format!(
                "Host image IST branch calls {target:#x}, expected trap_handler {handler:#x}"
            ));
        }
    }
    info!("Host image IST linked prefix: 176 bytes before the protected stack switch");
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
    use super::checked_image_claim;

    // The linked trap prefix from objdump, including the full-word CAS retry.
    const CLAIM_LOOP: [u8; 32] = [
        0x41, 0x8b, 0x02, 0x89, 0xc2, 0x81, 0xe2, 0xff, 0xff, 0xff, 0x7f, 0x83, 0xfa, 0x01, 0x0f,
        0x85, 0xaf, 0x00, 0x00, 0x00, 0x89, 0xc2, 0x83, 0xf2, 0x03, 0xf0, 0x41, 0x0f, 0xb1, 0x12,
        0x75, 0xe0,
    ];

    #[test]
    fn accepts_stop_preserving_trap_claim() {
        assert_eq!(checked_image_claim(&CLAIM_LOOP).unwrap(), 0);
    }

    #[test]
    fn rejects_trap_claim_that_loses_stop_or_retry() {
        for changed_byte in [10, 21, 24, 25, 30, 31] {
            let mut code = CLAIM_LOOP;
            code[changed_byte] ^= 1;
            assert!(checked_image_claim(&code).is_err());
        }
        for length in 0..CLAIM_LOOP.len() {
            assert!(checked_image_claim(&CLAIM_LOOP[..length]).is_err());
        }
    }
}
