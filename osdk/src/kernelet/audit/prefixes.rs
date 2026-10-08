// SPDX-License-Identifier: MPL-2.0

//! Linked x86-64 assembly entry and Task-switch contracts.
//!
//! Check the fixed assembly paths separately from compiler-generated Rust
//! function bodies.

use super::super::elf::{ElfImage, Symbol};

const ENTRY_PREFIX_ALLOWANCE: usize = 512;
const ENDBR64: &[u8] = &[0xf3, 0x0f, 0x1e, 0xfa];

pub(super) const CONTEXT_SAVE: &[u8] = &[
    0x48, 0x8b, 0x04, 0x24, 0x48, 0x89, 0x46, 0x38, 0x48, 0x89, 0x26, 0x48, 0x89, 0x5e, 0x08, 0x48,
    0x89, 0x6e, 0x10, 0x4c, 0x89, 0x66, 0x18, 0x4c, 0x89, 0x6e, 0x20, 0x4c, 0x89, 0x76, 0x28, 0x4c,
    0x89, 0x7e, 0x30, 0x48, 0x89, 0xd6, 0x48, 0x89, 0xca, 0x48, 0x8b, 0x27, 0x48, 0x89, 0x72, 0x60,
    0x48, 0x8b, 0x5f, 0x08, 0x48, 0x8b, 0x6f, 0x10, 0x4c, 0x8b, 0x67, 0x18, 0x4c, 0x8b, 0x6f, 0x20,
    0x4c, 0x8b, 0x77, 0x28, 0x4c, 0x8b, 0x7f, 0x30, 0x48, 0x8b, 0x47, 0x38, 0x48, 0x89, 0x04, 0x24,
    0xc3,
];

pub(super) const VIRQ_BEFORE_CALL: &[u8] = &[
    0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x70, 0xf8, 0x48, 0x8b, 0x00, 0xfb, 0x90, 0x9c, 0x50, 0x53, 0x51,
    0x52, 0x56, 0x57, 0x55, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55,
    0x41, 0x56, 0x41, 0x57, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xe4, 0xf0, 0xfc, 0xe8,
];
pub(super) const VIRQ_AFTER_CALL: &[u8] = &[
    0x48, 0x89, 0xdc, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x41, 0x5b, 0x41, 0x5a, 0x41,
    0x59, 0x41, 0x58, 0x5d, 0x5f, 0x5e, 0x5a, 0x59, 0x5b, 0x58, 0x9d, 0xc3,
];

pub(super) fn audit(
    image: &ElfImage<'_>,
    symbols: &[Symbol],
    names: &[String],
    image_entry: u64,
    vcpu_entry: u64,
    virq_entry: u64,
) -> Result<(), String> {
    let symbol = |name| find_symbol(symbols, names, name);
    let entry = symbol("_kernelet_entry")?;
    let vcpu = symbol("vcpu_entry")?;
    let virq = symbol("virq_entry")?;
    let context = symbol("context_switch")?;
    let first_context = symbol("first_context_switch")?;
    let task_wrapper = symbol("kernel_task_entry_wrapper")?;
    let task_entry = symbol("kernel_task_entry")?;

    if entry.value != image_entry || vcpu.value != vcpu_entry || virq.value != virq_entry {
        return Err("audit item 11: a linked entry symbol disagrees with its entry table".into());
    }
    // The virtual upcall's two retired words, 16 pushes, alignment (at most
    // 15 bytes), and direct call use at most 175
    // bytes. The Host validates a 64 KiB upcall range before this redirection.
    const VIRQ_PREFIX_BYTES: usize = 16 + 8 + 16 * 8 + 15 + 8;
    const _: () = assert!(VIRQ_PREFIX_BYTES <= ENTRY_PREFIX_ALLOWANCE);
    let code = symbol_code(
        image,
        virq,
        VIRQ_BEFORE_CALL.len() + 4 + VIRQ_AFTER_CALL.len(),
        "virq_entry",
    )?;
    let call_end = VIRQ_BEFORE_CALL.len() + 4;
    if !code.starts_with(VIRQ_BEFORE_CALL) || code[call_end..] != *VIRQ_AFTER_CALL {
        return Err("audit item 11: linked virtual-interrupt prefix changed".into());
    }
    let dispatch = relative_target(
        virq.value,
        call_end,
        &code[VIRQ_BEFORE_CALL.len()..call_end],
    )?;
    if !symbols
        .iter()
        .any(|symbol| symbol.value == dispatch && symbol.info & 0xf == 2)
        || image.bytes_at_vaddr(dispatch, ENDBR64.len() as u64)? != ENDBR64
    {
        return Err(
            "audit item 11: virtual interrupt dispatcher is not a linked function entry".into(),
        );
    }

    // The new stack bound is published immediately after loading RSP. The
    // whole switch path is fixed machine code, with no push or call before
    // the Rust continuation.
    let code = symbol_code(image, context, CONTEXT_SAVE.len(), "context_switch")?;
    if code != CONTEXT_SAVE
        || first_context.value != context.value + 41
        || first_context.size != (CONTEXT_SAVE.len() - 41) as u64
    {
        return Err("audit item 11: linked Task-switch stack-limit publication changed".into());
    }
    let wrapper = symbol_code(image, task_wrapper, 13, "kernel_task_entry_wrapper")?;
    if wrapper[..9] != [ENDBR64, &[0x48, 0x83, 0xc4, 0x08, 0xe8]].concat()
        || relative_target(task_wrapper.value, 13, &wrapper[9..13])? != task_entry.value
    {
        return Err("audit item 11: linked first-Task continuation changed".into());
    }
    Ok(())
}

fn find_symbol<'a>(
    symbols: &'a [Symbol],
    names: &[String],
    name: &str,
) -> Result<&'a Symbol, String> {
    symbols
        .iter()
        .zip(names)
        .find(|(_, candidate)| candidate.as_str() == name)
        .map(|(symbol, _)| symbol)
        .ok_or_else(|| format!("audit item 11: linked prefix symbol {name} is missing"))
}

fn symbol_code<'a>(
    image: &'a ElfImage<'a>,
    symbol: &Symbol,
    expected_size: usize,
    name: &str,
) -> Result<&'a [u8], String> {
    if symbol.size != expected_size as u64 {
        return Err(format!(
            "audit item 11: linked {name} prefix is {} bytes, expected {expected_size}",
            symbol.size
        ));
    }
    image.bytes_at_vaddr(symbol.value, symbol.size)
}

fn relative_target(
    origin: u64,
    instruction_end: usize,
    displacement: &[u8],
) -> Result<u64, String> {
    let displacement: [u8; 4] = displacement
        .try_into()
        .map_err(|_| "audit item 11: malformed relative branch".to_string())?;
    origin
        .checked_add(instruction_end as u64)
        .and_then(|next| next.checked_add_signed(i32::from_le_bytes(displacement) as i64))
        .ok_or_else(|| "audit item 11: relative branch target overflows".to_string())
}
