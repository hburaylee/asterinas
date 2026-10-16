// SPDX-License-Identifier: MPL-2.0

//! Rejects ordinary image instructions that use floating-point/vector state or
//! bypass the Host's interrupt and execution-control boundary.
//!
//! GNU objdump supplies the x86 decoder. The audit verifies its bytes and complete
//! linear coverage, rather than searching raw bytes for opcodes. The fixed entry
//! table is metadata; all other executable bytes are code or zero/NOP padding.
//! This does not prove that control flow cannot enter the middle of an instruction.
//!
//! The user-state wrappers below implement explicit user FPU ownership. Kernel
//! unwinding has no separate FP control-state ownership and receives no exception.

use std::{ffi::OsStr, io::Write, process::Command};

use regex::Regex;
use tempfile::NamedTempFile;

use super::super::{
    abi,
    elf::{PF_X, PT_LOAD, ProgramHeader, SHT_PROGBITS, SectionHeader, Symbol},
};

const XGETBV_FUNCTIONS: &[&str] = &[
    "<aster_core::process::posix_thread::builder::PosixThreadBuilder>::new",
    "aster_core::process::execve::do_execve_no_return",
    "aster_core::syscall::rt_sigreturn::sys_rt_sigreturn",
    // Signal delivery resets its saved user FPU context via FpuContext::new.
    // ThinLTO may inline that constructor through handle_user_signal into
    // handle_pending_signal. Only read-only XGETBV is allowed in these bodies.
    "aster_core::process::signal::handle_user_signal",
    "aster_core::process::signal::handle_pending_signal",
    "<ostd::arch::cpu::context::FpuContext>::new",
    "<ostd::arch::cpu::context::FpuContext as core::clone::Clone>::clone",
];
const FXSAVE_FUNCTIONS: &[&str] = &[
    "<ostd::arch::cpu::context::FpuContext>::save",
    "<aster_core::process::posix_thread::cpu_sync::CpuSync<ostd::arch::cpu::context::FpuContext>>::get",
    "<aster_core::process::posix_thread::cpu_sync::CpuSync<ostd::arch::cpu::context::FpuContext>>::before_schedule",
    "<aster_core::process::posix_thread::thread_local::SuppUserContext>::before_schedule",
    // ThinLTO can inline the same OnCpu user-state save through both lifecycle
    // wrappers into the scheduler hook. Permit only its exact FXSAVE operand.
    "aster_core::thread::pre_schedule_handler",
];
const FXRSTOR_FUNCTIONS: &[&str] = &[
    "<ostd::arch::cpu::context::FpuContext>::load",
    "<aster_core::process::posix_thread::cpu_sync::CpuSync<ostd::arch::cpu::context::FpuContext>>::before_user_exec",
    "<aster_core::process::posix_thread::thread_local::SuppUserContext>::before_user_exec",
];
// ThinLTO may inline the fixed inactive-GS write through the user-state hooks.
// Each exception still requires an immediately preceding MOV of the one MSR
// number; the name alone never authorizes WRMSR.
const GS_BASE_FUNCTIONS: &[&str] = &[
    "<ostd::arch::cpu::context::GsBase>::load",
    "<ostd::arch::cpu::context::GsBase>::load_inactive",
    "<aster_core::process::posix_thread::cpu_sync::CpuSync<ostd::arch::cpu::context::GsBase>>::before_user_exec",
    "<aster_core::process::posix_thread::thread_local::SuppUserContext>::before_user_exec",
    "<aster_core::context::Context as ostd::user::UserModeHooks>::pre_user_run",
];
const XSAVE_FUNCTION: &str = "core::core_arch::x86_64::xsave::_xsave64";
const XRSTOR_FUNCTION: &str = "core::core_arch::x86_64::xsave::_xrstor64";

struct Function {
    start: u64,
    end: u64,
    name: String,
}

struct Instruction<'a> {
    address: u64,
    bytes: Vec<u8>,
    mnemonic: &'a str,
    operands: String,
}

pub(super) fn audit(
    bytes: &[u8],
    program_headers: &[ProgramHeader],
    sections: &[SectionHeader],
    section_names: &[String],
    symbols: &[Symbol],
) -> Result<(), String> {
    audit_with_decoder(
        bytes,
        program_headers,
        sections,
        section_names,
        symbols,
        OsStr::new("objdump"),
    )
}

pub(super) fn audit_with_decoder(
    bytes: &[u8],
    program_headers: &[ProgramHeader],
    sections: &[SectionHeader],
    section_names: &[String],
    symbols: &[Symbol],
    decoder: &OsStr,
) -> Result<(), String> {
    let executable: Vec<_> = program_headers
        .iter()
        .filter(|header| header.typ == PT_LOAD && header.flags & PF_X != 0)
        .collect();
    if executable.len() != 1 {
        return Err("expected exactly one executable PT_LOAD for complete coverage".into());
    }
    let load = executable[0];
    if load.filesz != load.memsz {
        return Err("an executable PT_LOAD has a non-file-backed tail".into());
    }
    let load_end = end(load.vaddr, load.filesz)?;
    let (text_index, text) = unique_section(sections, section_names, ".text")?;
    let (_, table) = unique_section(sections, section_names, ".kernelet_entry_table")?;
    if table.addr != abi::ENTRY_TABLE_OFFSET || table.size != abi::entry_table::SIZE {
        return Err("the executable metadata is not the fixed entry table".into());
    }
    for section in [text, table] {
        if section.typ != SHT_PROGBITS
            || section.size == 0
            || section.addr < load.vaddr
            || end(section.addr, section.size)? > load_end
            || section.offset != end(load.offset, section.addr - load.vaddr)?
        {
            return Err("executable code/metadata has inconsistent file-backed bounds".into());
        }
        file_bytes(bytes, section.offset, section.size)?;
    }
    let table_end = end(table.addr, table.size)?;
    if table_end > text.addr {
        return Err("executable entry-table metadata overlaps or follows .text".into());
    }

    let mut file = NamedTempFile::new().map_err(|err| format!("create decoder input: {err}"))?;
    file.write_all(bytes)
        .map_err(|err| format!("write decoder input: {err}"))?;
    let output = run_objdump(
        decoder,
        &[
            "-D",
            "-t",
            "-C",
            "-z",
            "-w",
            "--insn-width=16",
            "--section=.text",
        ],
        file.path().as_os_str(),
    )?;
    if !output.contains("file format elf64-x86-64") {
        return Err("decoder did not recognize an x86-64 ELF".into());
    }
    let functions = allowed_functions(&output, text_index, text, symbols)?;
    check_instructions(
        &output,
        text.addr,
        file_bytes(bytes, text.offset, text.size)?,
        &functions,
        false,
    )?;
    // These ranges, together with the fixed metadata and decoded .text, cover
    // every byte of every executable PT_LOAD. Never silently skip another section.
    for (start, stop) in [
        (load.vaddr, table.addr),
        (table_end, text.addr),
        (end(text.addr, text.size)?, load_end),
    ] {
        let padding = file_bytes(bytes, end(load.offset, start - load.vaddr)?, stop - start)?;
        if padding.iter().all(|byte| *byte == 0) {
            continue;
        }
        let mut file =
            NamedTempFile::new().map_err(|err| format!("create padding input: {err}"))?;
        file.write_all(padding)
            .map_err(|err| format!("write padding input: {err}"))?;
        let adjust = format!("--adjust-vma={start}");
        let output = run_objdump(
            decoder,
            &[
                "-D",
                "-z",
                "-w",
                "--insn-width=16",
                "-b",
                "binary",
                "-m",
                "i386:x86-64",
                &adjust,
            ],
            file.path().as_os_str(),
        )?;
        check_instructions(&output, start, padding, &[], true)?;
    }
    Ok(())
}

fn end(start: u64, size: u64) -> Result<u64, String> {
    start
        .checked_add(size)
        .ok_or_else(|| "executable range overflows".into())
}

fn file_bytes(bytes: &[u8], offset: u64, size: u64) -> Result<&[u8], String> {
    let stop = usize::try_from(end(offset, size)?).map_err(|_| "file range overflows usize")?;
    let start = usize::try_from(offset).map_err(|_| "file offset overflows usize")?;
    bytes
        .get(start..stop)
        .ok_or_else(|| "executable file range is truncated".into())
}

fn unique_section<'a>(
    sections: &'a [SectionHeader],
    names: &[String],
    wanted: &str,
) -> Result<(usize, &'a SectionHeader), String> {
    let mut matching = sections
        .iter()
        .enumerate()
        .filter(|(index, _)| names[*index] == wanted);
    let section = matching.next().ok_or_else(|| format!("missing {wanted}"))?;
    if matching.next().is_some() {
        return Err(format!(
            "multiple {wanted} sections prevent complete decoding"
        ));
    }
    Ok(section)
}

fn run_objdump(decoder: &OsStr, arguments: &[&str], file: &OsStr) -> Result<String, String> {
    let output = Command::new(decoder)
        .args(arguments)
        .arg(file)
        .env("LC_ALL", "C")
        .output()
        .map_err(|err| format!("cannot run required objdump decoder: {err}"))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(format!(
            "objdump decoder failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|err| format!("decoder output is not UTF-8: {err}"))
}

fn allowed_name(name: &str) -> bool {
    XGETBV_FUNCTIONS.contains(&name)
        || FXSAVE_FUNCTIONS.contains(&name)
        || FXRSTOR_FUNCTIONS.contains(&name)
        || GS_BASE_FUNCTIONS.contains(&name)
        || [XSAVE_FUNCTION, XRSTOR_FUNCTION, "virq_entry", "yield_entry"].contains(&name)
}

fn changes_host_control(instruction: &Instruction<'_>) -> bool {
    matches!(
        instruction.mnemonic,
        "wrmsr"
            | "wrmsrns"
            | "wrmsrlist"
            | "invpcid"
            | "cli"
            | "sti"
            | "hlt"
            | "iret"
            | "iretd"
            | "iretq"
            | "iretw"
            | "sysret"
            | "sysretq"
            | "sysretl"
            | "sysexit"
            | "sysexitq"
            | "sysexitl"
            | "sysenter"
            | "syscall"
            | "popf"
            | "popfd"
            | "popfq"
            | "popfw"
            | "popfl"
            | "lret"
            | "lretq"
            | "lretw"
            | "lretl"
            | "int"
            | "into"
            | "swapgs"
            | "rsm"
            | "lgdt"
            | "lidt"
            | "lldt"
            | "ltr"
            | "lmsw"
            | "clts"
            | "invd"
            | "wbinvd"
            | "wbnoinvd"
            | "stac"
            | "clac"
            | "vmcall"
            | "vmlaunch"
            | "vmresume"
            | "vmxoff"
            | "vmxon"
            | "vmptrld"
            | "vmptrst"
            | "vmclear"
            | "vmread"
            | "vmwrite"
            | "vmfunc"
            | "vmmcall"
            | "vmrun"
            | "vmsave"
            | "vmload"
            | "stgi"
            | "clgi"
            | "invlpga"
    ) || instruction
        .operands
        .split('#')
        .next()
        .unwrap_or_default()
        .contains("%dr")
        || instruction
            .operands
            .split('#')
            .next()
            .unwrap_or_default()
            .rsplit(',')
            .next()
            .is_some_and(|destination| destination.trim().starts_with("%cr"))
}

// The only Image paths that change physical IF/return across a privilege
// boundary are these two fixed OSTD assembly stubs. Validate their complete
// bytes here as well as in prefixes::audit: a caller-supplied symbol name alone
// never grants an exception. The displacement's target is checked by that audit.
fn is_fixed_return_stub(function: &Function, text_start: u64, text: &[u8]) -> bool {
    use super::prefixes::{VIRQ_AFTER_CALL, VIRQ_BEFORE_CALL};
    if !matches!(function.name.as_str(), "virq_entry" | "yield_entry") {
        return false;
    }
    let Some(start) = function
        .start
        .checked_sub(text_start)
        .and_then(|n| usize::try_from(n).ok())
    else {
        return false;
    };
    let Some(stop) = function
        .end
        .checked_sub(text_start)
        .and_then(|n| usize::try_from(n).ok())
    else {
        return false;
    };
    let Some(code) = text.get(start..stop) else {
        return false;
    };
    let call_end = VIRQ_BEFORE_CALL.len() + 4;
    code.len() == call_end + VIRQ_AFTER_CALL.len()
        && code.starts_with(VIRQ_BEFORE_CALL)
        && code[call_end..] == *VIRQ_AFTER_CALL
}

fn allowed_functions(
    output: &str,
    text_index: usize,
    text: &SectionHeader,
    symbols: &[Symbol],
) -> Result<Vec<Function>, String> {
    let mut functions = Vec::new();
    // GNU objdump demangles Rust symbols in its symbol table, including names
    // with spaces. Match the address, size, section and STT_FUNC to our ELF parser.
    for line in output.lines() {
        let Some((prefix, suffix)) = line.split_once(".text\t") else {
            continue;
        };
        let mut fields = prefix.split_whitespace();
        let Some(address) = fields.next().and_then(|s| u64::from_str_radix(s, 16).ok()) else {
            continue;
        };
        if !fields.any(|field| field == "F") {
            continue;
        }
        let Some((size, name)) = suffix.split_once(char::is_whitespace) else {
            continue;
        };
        let name = name.trim().strip_prefix(".hidden ").unwrap_or(name.trim());
        if !allowed_name(name) {
            continue;
        }
        let size = u64::from_str_radix(size, 16).map_err(|_| "unreadable exception symbol size")?;
        let stop = end(address, size)?;
        if size == 0
            || address < text.addr
            || stop > end(text.addr, text.size)?
            || symbols
                .iter()
                .filter(|symbol| {
                    symbol.info & 0xf == 2
                        && usize::from(symbol.shndx) == text_index
                        && symbol.value == address
                        && symbol.size == size
                })
                .count()
                != 1
        {
            return Err(format!(
                "exception {name} lacks matching bounded STT_FUNC metadata"
            ));
        }
        for other in symbols.iter().filter(|symbol| {
            symbol.info & 0xf == 2 && usize::from(symbol.shndx) == text_index && symbol.size != 0
        }) {
            if other.value == address && other.size == size {
                continue;
            }
            if address < end(other.value, other.size)? && other.value < stop {
                return Err(format!(
                    "exception {name} overlaps another STT_FUNC at {:#x}",
                    other.value
                ));
            }
        }
        functions.push(Function {
            start: address,
            end: stop,
            name: name.into(),
        });
    }
    Ok(functions)
}

fn instruction(line: &str) -> Result<Option<Instruction<'_>>, String> {
    let Some((address, body)) = line.trim_start().split_once(':') else {
        return Ok(None);
    };
    if address.is_empty() || !address.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(None);
    }
    let address = u64::from_str_radix(address, 16).map_err(|_| "instruction address overflows")?;
    let mut fields = body.split_whitespace().peekable();
    let mut bytes = Vec::new();
    while fields
        .peek()
        .is_some_and(|field| field.len() == 2 && field.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        bytes.push(u8::from_str_radix(fields.next().unwrap(), 16).unwrap());
    }
    let mut mnemonic = fields
        .next()
        .ok_or_else(|| format!("undecoded bytes at {address:#x}"))?;
    while matches!(
        mnemonic,
        "lock"
            | "rep"
            | "repz"
            | "repnz"
            | "repe"
            | "repne"
            | "data16"
            | "addr32"
            | "bnd"
            | "notrack"
            | "cs"
            | "ds"
            | "es"
            | "fs"
            | "gs"
            | "ss"
    ) || mnemonic.starts_with("rex")
    {
        mnemonic = fields
            .next()
            .ok_or_else(|| format!("incomplete instruction at {address:#x}"))?;
    }
    if bytes.is_empty() || bytes.len() > 15 || mnemonic == "(bad)" || mnemonic.starts_with('.') {
        return Err(format!("invalid instruction at {address:#x}: {body}"));
    }
    Ok(Some(Instruction {
        address,
        bytes,
        mnemonic,
        operands: fields.collect::<Vec<_>>().join(" "),
    }))
}

fn touches_fp(instruction: &Instruction<'_>, registers: &Regex) -> bool {
    let mnemonic = instruction.mnemonic;
    // Segment checks and virtualization instructions use a `v` prefix without
    // accessing vector state. Vector mnemonics include implicit VZERO clobbers.
    let scalar_v = matches!(
        mnemonic,
        "verr"
            | "verw"
            | "vmcall"
            | "vmlaunch"
            | "vmresume"
            | "vmxoff"
            | "vmxon"
            | "vmptrld"
            | "vmptrst"
            | "vmclear"
            | "vmread"
            | "vmwrite"
            | "vmfunc"
            | "vmmcall"
            | "vmrun"
            | "vmsave"
            | "vmload"
    );
    registers.is_match(instruction.operands.split('#').next().unwrap_or_default())
        || matches!(mnemonic.as_bytes().first(), Some(b'f' | b'k'))
        || (mnemonic.starts_with('v') && !scalar_v)
        || matches!(
            mnemonic,
            "wait"
                | "emms"
                | "ldmxcsr"
                | "stmxcsr"
                | "xgetbv"
                | "xsetbv"
                | "ldtilecfg"
                | "sttilecfg"
        )
        || mnemonic.starts_with("xsave")
        || mnemonic.starts_with("xrstor")
        || mnemonic.starts_with("tile")
}

fn check_instructions(
    output: &str,
    start: u64,
    bytes: &[u8],
    functions: &[Function],
    padding: bool,
) -> Result<(), String> {
    let registers = Regex::new(r"%(?:st\b|mm[0-7]\b|[xyz]mm[0-9]+\b|k[0-7]\b|tmm[0-7]\b)").unwrap();
    let mut offset = 0usize;
    let mut previous: Option<(u64, Vec<u8>)> = None;
    for line in output.lines() {
        let Some(instruction) = instruction(line)? else {
            continue;
        };
        let stop = offset
            .checked_add(instruction.bytes.len())
            .ok_or("decoded size overflows")?;
        if instruction.address != end(start, offset as u64)?
            || bytes.get(offset..stop) != Some(instruction.bytes.as_slice())
        {
            return Err(format!(
                "decoder coverage/bytes mismatch at {:#x}",
                instruction.address
            ));
        }
        let preceding = previous.replace((instruction.address, instruction.bytes.clone()));
        offset = stop;
        if padding {
            if !instruction.bytes.iter().all(|byte| *byte == 0)
                && !matches!(instruction.mnemonic, "nop" | "nopl" | "nopw")
            {
                return Err(format!(
                    "executable padding contains {} at {:#x}",
                    instruction.mnemonic, instruction.address
                ));
            }
            continue;
        }
        let operands = instruction
            .operands
            .split('#')
            .next()
            .unwrap_or_default()
            .trim();
        let host_control = changes_host_control(&instruction);
        if !host_control && !touches_fp(&instruction, &registers) {
            continue;
        }
        let mut containing = functions.iter().filter(|function| {
            function.start <= instruction.address
                && end(instruction.address, instruction.bytes.len() as u64)
                    .is_ok_and(|stop| stop <= function.end)
        });
        let Some(function) = containing.next() else {
            return Err(format!(
                "forbidden {} outside a state wrapper at {:#x}",
                instruction.mnemonic, instruction.address
            ));
        };
        if containing.next().is_some() {
            return Err(format!(
                "ambiguous state-wrapper bounds at {:#x}",
                instruction.address
            ));
        }
        let name = function.name.as_str();
        if host_control {
            let fixed_user_gs_write = instruction.mnemonic == "wrmsr"
                && instruction.bytes == [0x0f, 0x30]
                && operands.is_empty()
                && GS_BASE_FUNCTIONS.contains(&name)
                && preceding.as_ref().is_some_and(|(address, bytes)| {
                    *address >= function.start
                        && bytes == &[0xb9, 0x02, 0x01, 0x00, 0xc0]
                        && *address + bytes.len() as u64 == instruction.address
                });
            if fixed_user_gs_write {
                continue;
            }
            if !matches!(instruction.mnemonic, "cli" | "sti" | "iretq")
                || !is_fixed_return_stub(function, start, bytes)
            {
                return Err(format!(
                    "forbidden physical-control {} in {name} at {:#x}",
                    instruction.mnemonic, instruction.address
                ));
            }
            continue;
        }
        let allowed = match instruction.mnemonic {
            "xgetbv" => XGETBV_FUNCTIONS.contains(&name) && operands.is_empty(),
            "fxsave64" => FXSAVE_FUNCTIONS.contains(&name) && operands == "(%rdi)",
            "fxrstor64" => FXRSTOR_FUNCTIONS.contains(&name) && operands == "(%rdi)",
            "xsave64" => name == XSAVE_FUNCTION && operands == "(%rdi)",
            "xrstor64" => name == XRSTOR_FUNCTION && operands == "(%rdi)",
            _ => false,
        };
        if !allowed {
            return Err(format!(
                "forbidden {} in {name} at {:#x}",
                instruction.mnemonic, instruction.address
            ));
        }
    }
    if offset != bytes.len() {
        return Err(format!(
            "incomplete decoder coverage: decoded {offset} of {} bytes",
            bytes.len()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_safe_dependency_code_cannot_change_physical_interrupts() {
        for name in [
            "safe_cli_proof::safe_cli",
            "ostd::unreviewed",
            "virq_entry",
            "yield_entry",
        ] {
            for code in [
                &[0xfa][..],
                &[0xfb][..],
                &[0xf4][..],
                &[0x48, 0xcf][..],
                &[0x0f, 0x01, 0xf8][..],
            ] {
                let error = audit_function(name, code, code.len() as u64).unwrap_err();
                assert!(error.contains("forbidden"), "{error}");
            }
        }
    }

    #[test]
    fn ordinary_code_cannot_write_control_registers_or_msrs() {
        for code in [
            &[0x0f, 0x22, 0xd8][..], // MOV RAX -> CR3
            &[0x0f, 0x30][..],       // WRMSR
            &[0xb9, 0x02, 0x01, 0x00, 0xc0, 0x0f, 0x30][..],
        ] {
            let error = audit_function("ordinary::code", code, code.len() as u64).unwrap_err();
            assert!(error.contains("forbidden"), "{error}");
        }
    }

    #[test]
    fn user_gs_write_requires_the_fixed_msr_and_adjacent_sequence() {
        let accepted = [0xb9, 0x02, 0x01, 0x00, 0xc0, 0x0f, 0x30];
        for name in GS_BASE_FUNCTIONS {
            assert_eq!(
                audit_function(name, &accepted, accepted.len() as u64),
                Ok(())
            );
            for code in [
                &[0x0f, 0x30][..],
                &[0xb9, 0x01, 0x01, 0x00, 0xc0, 0x0f, 0x30][..],
                &[0xb9, 0x02, 0x01, 0x00, 0xc0, 0x31, 0xc9, 0x0f, 0x30][..],
                &[0xb9, 0x02, 0x01, 0x00, 0xc0, 0x90, 0x0f, 0x30][..],
                &[0x0f, 0x22, 0xd8][..],
            ] {
                assert!(audit_function(name, code, code.len() as u64).is_err());
            }
        }
    }

    #[test]
    fn image_local_invlpg_and_fsbase_access_remain_allowed() {
        for code in [
            &[0x0f, 0x01, 0x3f][..],             // INVLPG (%rdi)
            &[0xf3, 0x48, 0x0f, 0xae, 0xc0][..], // RDFSBASE %rax
            &[0xf3, 0x48, 0x0f, 0xae, 0xd0][..], // WRFSBASE %rax
        ] {
            assert_eq!(
                audit_function("ordinary::code", code, code.len() as u64),
                Ok(())
            );
        }
    }

    #[test]
    fn fixed_ostd_return_stubs_keep_their_physical_control_exception() {
        let mut code = super::super::prefixes::VIRQ_BEFORE_CALL.to_vec();
        code.extend_from_slice(&[0; 4]);
        code.extend_from_slice(super::super::prefixes::VIRQ_AFTER_CALL);
        for name in ["virq_entry", "yield_entry"] {
            assert_eq!(audit_function(name, &code, code.len() as u64), Ok(()));
            let mut altered = code.clone();
            altered[4] = 0x90;
            assert!(audit_function(name, &altered, altered.len() as u64).is_err());
        }
    }

    #[test]
    fn signal_delivery_can_read_initial_user_features_without_other_state_access() {
        for name in [
            "aster_core::process::signal::handle_user_signal",
            "aster_core::process::signal::handle_pending_signal",
        ] {
            assert_eq!(audit_function(name, &[0x0f, 0x01, 0xd0], 3), Ok(()));
            for code in [FXSAVE, FXRSTOR, &[0xfa][..], &[0xfb][..]] {
                assert!(audit_function(name, code, code.len() as u64).is_err());
            }
            assert!(audit_function(&format!("{name}_unreviewed"), &[0x0f, 0x01, 0xd0], 3).is_err());
        }
    }

    #[test]
    fn physical_control_width_aliases_cannot_escape_the_decoder_policy() {
        for code in [
            &[0x66, 0xcf][..],       // IRETW
            &[0x0f, 0x07][..],       // SYSRETL
            &[0x48, 0x0f, 0x35][..], // SYSEXITQ
            &[0x66, 0x9d][..],       // POPFW
            &[0x66, 0xcb][..],       // LRETW
        ] {
            let error = audit_function("ordinary::code", code, code.len() as u64).unwrap_err();
            assert!(error.contains("forbidden"), "{error}");
            assert!(audit_function("virq_entry", code, code.len() as u64).is_err());
        }
    }

    const FPU_SAVE: &str = "<ostd::arch::cpu::context::FpuContext>::save";
    const FPU_LOAD: &str = "<ostd::arch::cpu::context::FpuContext>::load";
    const CPU_SYNC_SAVE: &str = "<aster_core::process::posix_thread::cpu_sync::CpuSync<ostd::arch::cpu::context::FpuContext>>::before_schedule";
    const CPU_SYNC_LOAD: &str = "<aster_core::process::posix_thread::cpu_sync::CpuSync<ostd::arch::cpu::context::FpuContext>>::before_user_exec";
    const PRE_SCHEDULE_SAVE: &str = "aster_core::thread::pre_schedule_handler";
    const FXSAVE: &[u8] = &[0x48, 0x0f, 0xae, 0x07];
    const FXRSTOR: &[u8] = &[0x48, 0x0f, 0xae, 0x0f];

    // Exercise the production symbol-bound checks and the real GNU decoder.
    // The full executable-PT_LOAD coverage tests remain in audit::tests.
    fn audit_function(name: &str, code: &[u8], symbol_size: u64) -> Result<(), String> {
        const START: u64 = 0x2000;
        const TEXT_INDEX: usize = 1;
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(code).unwrap();
        let decoded = run_objdump(
            OsStr::new("objdump"),
            &[
                "-D",
                "-z",
                "-w",
                "--insn-width=16",
                "-b",
                "binary",
                "-m",
                "i386:x86-64",
                "--adjust-vma=8192",
            ],
            file.path().as_os_str(),
        )?;
        let output =
            format!("{START:016x} l F .text\t{symbol_size:016x} .hidden {name}\n{decoded}");
        let text = SectionHeader {
            name_offset: 0,
            typ: SHT_PROGBITS,
            addr: START,
            offset: 0,
            size: code.len() as u64,
            link: 0,
            entsize: 0,
        };
        let symbols = [Symbol {
            name_offset: 0,
            info: 0x12,
            shndx: TEXT_INDEX as u16,
            value: START,
            size: symbol_size,
        }];
        let functions = allowed_functions(&output, TEXT_INDEX, &text, &symbols)?;
        check_instructions(&output, START, code, &functions, false)
    }

    #[test]
    fn fpu_state_wrappers_allow_only_their_legacy_state_operation() {
        for (name, accepted, rejected) in [
            (FPU_SAVE, FXSAVE, FXRSTOR),
            (FPU_LOAD, FXRSTOR, FXSAVE),
            (CPU_SYNC_SAVE, FXSAVE, FXRSTOR),
            (CPU_SYNC_LOAD, FXRSTOR, FXSAVE),
            (PRE_SCHEDULE_SAVE, FXSAVE, FXRSTOR),
        ] {
            // Optimization can leave save/load outlined or inline them into
            // the CpuSync lifecycle hooks that own the user FPU state.
            assert_eq!(
                audit_function(name, accepted, accepted.len() as u64),
                Ok(())
            );
            let error = audit_function(name, rejected, rejected.len() as u64).unwrap_err();
            assert!(error.contains("forbidden"), "{error}");
        }
    }

    #[test]
    fn fpu_state_wrappers_reject_ordinary_fp_and_other_state_operations() {
        for name in [
            FPU_SAVE,
            FPU_LOAD,
            CPU_SYNC_SAVE,
            CPU_SYNC_LOAD,
            PRE_SCHEDULE_SAVE,
        ] {
            for code in [
                &[0x0f, 0x57, 0xc0][..],       // XORPS %xmm0,%xmm0
                &[0xd9, 0xe8][..],             // FLD1
                &[0x48, 0x0f, 0xae, 0x27][..], // XSAVE64 (%rdi)
                &[0x48, 0x0f, 0xae, 0x2f][..], // XRSTOR64 (%rdi)
                &[0xfa][..],                   // CLI
            ] {
                let error = audit_function(name, code, code.len() as u64).unwrap_err();
                assert!(error.contains("forbidden"), "{error}");
            }
        }
    }

    #[test]
    fn fpu_state_wrappers_require_exact_operand_and_whole_instruction_bounds() {
        for (name, accepted, wrong_register, displacement) in [
            (
                FPU_SAVE,
                FXSAVE,
                &[0x48, 0x0f, 0xae, 0x06][..],
                &[0x48, 0x0f, 0xae, 0x47, 0x08][..],
            ),
            (
                FPU_LOAD,
                FXRSTOR,
                &[0x48, 0x0f, 0xae, 0x0e][..],
                &[0x48, 0x0f, 0xae, 0x4f, 0x08][..],
            ),
            (
                CPU_SYNC_SAVE,
                FXSAVE,
                &[0x48, 0x0f, 0xae, 0x06][..],
                &[0x48, 0x0f, 0xae, 0x47, 0x08][..],
            ),
            (
                PRE_SCHEDULE_SAVE,
                FXSAVE,
                &[0x48, 0x0f, 0xae, 0x06][..],
                &[0x48, 0x0f, 0xae, 0x47, 0x08][..],
            ),
            (
                CPU_SYNC_LOAD,
                FXRSTOR,
                &[0x48, 0x0f, 0xae, 0x0e][..],
                &[0x48, 0x0f, 0xae, 0x4f, 0x08][..],
            ),
        ] {
            for code in [wrong_register, displacement] {
                let error = audit_function(name, code, code.len() as u64).unwrap_err();
                assert!(error.contains("forbidden"), "{error}");
            }
            let error = audit_function(name, accepted, accepted.len() as u64 - 1).unwrap_err();
            assert!(error.contains("outside a state wrapper"), "{error}");
        }
    }

    #[test]
    fn state_wrapper_names_must_match_exactly() {
        for name in [
            "<ostd::arch::cpu::context::FpuContext>::load_unchecked",
            "unrelated::FpuContext::load",
            "<aster_core::process::posix_thread::cpu_sync::CpuSync<ostd::arch::cpu::context::FpuContext>>::before_user_exec_unchecked",
            "<aster_core::process::posix_thread::cpu_sync::CpuSync<ostd::arch::cpu::context::FsBase>>::before_user_exec",
        ] {
            let error = audit_function(name, FXRSTOR, FXRSTOR.len() as u64).unwrap_err();
            assert!(error.contains("outside a state wrapper"), "{error}");
        }
    }
}
