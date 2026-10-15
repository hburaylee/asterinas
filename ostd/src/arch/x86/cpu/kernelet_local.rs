// SPDX-License-Identifier: MPL-2.0

//! Accesses the CPU-local replica assigned to the current virtual CPU.

use crate::cpu::local::single_instr::{
    SingleInstructionAddAssign, SingleInstructionBitAndAssign, SingleInstructionBitOrAssign,
    SingleInstructionBitXorAssign, SingleInstructionLoad, SingleInstructionStore,
    SingleInstructionSubAssign,
};

/// Executes a short access without allowing the Host to redirect its middle.
///
/// Inputs must be CPU-independent. The Host may interrupt this sequence, but
/// its CPU-access range gate resumes it on the same carrier instead of
/// delivering an upcall that could migrate the internal Task. Both jumps are
/// direct and the sequence neither calls nor modifies the stack.
macro_rules! record_asm {
    ($($instruction:expr),+; $($operands:tt)*) => {{
        #[cfg(kernelet_getpid_profile)]
        let _lookup_span = {
            use $crate::kernelet::getpid_profile as profile;
            profile::event(profile::event_id::CPU_LOCAL_LOOKUP);
            profile::span(profile::stage::GUEST_CPU_LOCAL)
        };
        core::arch::asm!(
            "jmp 2f",
            ".pushsection .text.kernelet_cpu_access, \"ax\", @progbits",
            "2:",
            "mov {record_base}, [rip + {boot_args}]",
            "mov {slot:e}, dword ptr [{record_base} + {slot_offset}]",
            "mov {slot}, gs:[{slot}]",
            "shr {slot}, 16",
            "movzx {slot:e}, {slot:x}",
            "imul {slot}, {record_bytes}",
            "lea {record_base}, [{record_base} + {slot} + {records_offset}]",
            $($instruction),+,
            "jmp 3f",
            ".popsection",
            "3:",
            record_base = out(reg) _,
            slot = out(reg) _,
            boot_args = sym $crate::kernelet::entry::KERNELET_BOOT_ARGS,
            slot_offset = const core::mem::offset_of!($crate::kernelet::abi::BootArgs, cpu_slot_gs_offset),
            record_bytes = const core::mem::size_of::<$crate::kernelet::abi::VcpuRecord>(),
            records_offset = const $crate::mm::PAGE_SIZE,
            $($operands)*
        );
    }};
}
pub(crate) use record_asm;

/// Returns the current virtual CPU's private CPU-local base.
/// Borrowing through this address still requires the caller's CPU pin.
pub(crate) fn get_base() -> u64 {
    let base;
    // SAFETY: Entry validates the immutable boot page and record layout. The
    // complete record lookup and replica read are in the protected CPU-access range.
    unsafe {
        record_asm!(
            "mov {base}, [{record_base} + {replica_offset}]";
            base = out(reg) base,
            replica_offset = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, cpu_local_base),
            options(nostack, readonly),
        );
    }
    base
}

macro_rules! cpu_local_asm {
    ($instruction:expr, $offset:expr; $($operands:tt)*) => {
        record_asm!(
            "mov {record_base}, [{record_base} + {replica_offset}]",
            $instruction;
            offset = in(reg) $offset,
            replica_offset = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, cpu_local_base),
            $($operands)*
        )
    };
}

macro_rules! impl_numeric_single_instruction_for {
    ($([$typ:ty, $inout_type:ident, $register_format:expr])*) => {$(
        impl SingleInstructionAddAssign<$typ> for $typ {
            unsafe fn add_assign(offset: usize, val: Self) {
                // SAFETY: The caller supplies a scalar CPU-local offset. The
                // replica selection and access cannot be separated by migration.
                unsafe {
                    cpu_local_asm!(
                        concat!("add [{record_base} + {offset}], {value", $register_format, "}"), offset;
                        value = in($inout_type) val,
                        options(nostack),
                    );
                }
            }
        }
        impl SingleInstructionSubAssign<$typ> for $typ {
            unsafe fn sub_assign(offset: usize, val: Self) {
                // SAFETY: Same as add_assign.
                unsafe {
                    cpu_local_asm!(
                        concat!("sub [{record_base} + {offset}], {value", $register_format, "}"), offset;
                        value = in($inout_type) val,
                        options(nostack),
                    );
                }
            }
        }
        impl SingleInstructionBitAndAssign<$typ> for $typ {
            unsafe fn bitand_assign(offset: usize, val: Self) {
                // SAFETY: Same as add_assign.
                unsafe {
                    cpu_local_asm!(
                        concat!("and [{record_base} + {offset}], {value", $register_format, "}"), offset;
                        value = in($inout_type) val,
                        options(nostack),
                    );
                }
            }
        }
        impl SingleInstructionBitOrAssign<$typ> for $typ {
            unsafe fn bitor_assign(offset: usize, val: Self) {
                // SAFETY: Same as add_assign.
                unsafe {
                    cpu_local_asm!(
                        concat!("or [{record_base} + {offset}], {value", $register_format, "}"), offset;
                        value = in($inout_type) val,
                        options(nostack),
                    );
                }
            }
        }
        impl SingleInstructionBitXorAssign<$typ> for $typ {
            unsafe fn bitxor_assign(offset: usize, val: Self) {
                // SAFETY: Same as add_assign.
                unsafe {
                    cpu_local_asm!(
                        concat!("xor [{record_base} + {offset}], {value", $register_format, "}"), offset;
                        value = in($inout_type) val,
                        options(nostack),
                    );
                }
            }
        }
        impl SingleInstructionLoad for $typ {
            unsafe fn load(offset: usize) -> Self {
                let val;
                // SAFETY: Same as add_assign.
                unsafe {
                    cpu_local_asm!(
                        concat!("mov {value", $register_format, "}, [{record_base} + {offset}]"), offset;
                        value = out($inout_type) val,
                        options(nostack, readonly),
                    );
                }
                val
            }
        }
        impl SingleInstructionStore for $typ {
            unsafe fn store(offset: usize, val: Self) {
                // SAFETY: Same as add_assign.
                unsafe {
                    cpu_local_asm!(
                        concat!("mov [{record_base} + {offset}], {value", $register_format, "}"), offset;
                        value = in($inout_type) val,
                        options(nostack),
                    );
                }
            }
        }
    )*};
}

impl_numeric_single_instruction_for!(
    [u64, reg, ":r"] [usize, reg, ":r"] [u32, reg, ":e"]
    [u16, reg, ":x"] [u8, reg_byte, ""]
    [i64, reg, ":r"] [isize, reg, ":r"] [i32, reg, ":e"]
    [i16, reg, ":x"] [i8, reg_byte, ""]
);

macro_rules! impl_generic_single_instruction_for {
    ($([<$gen_type:ident $(, $more_gen_type:ident)*>, $typ:ty])*) => {$(
        impl<$gen_type $(, $more_gen_type)*> SingleInstructionLoad for $typ {
            unsafe fn load(offset: usize) -> Self {
                let val;
                // SAFETY: The caller supplies a scalar CPU-local offset. The
                // replica selection and load cannot be separated by migration.
                unsafe {
                    cpu_local_asm!("mov {value}, [{record_base} + {offset}]", offset;
                        value = out(reg) val,
                        options(nostack, readonly),
                    );
                }
                val
            }
        }
        impl<$gen_type $(, $more_gen_type)*> SingleInstructionStore for $typ {
            unsafe fn store(offset: usize, val: Self) {
                // SAFETY: Same as load.
                unsafe {
                    cpu_local_asm!("mov [{record_base} + {offset}], {value}", offset;
                        value = in(reg) val,
                        options(nostack),
                    );
                }
            }
        }
    )*}
}
impl_generic_single_instruction_for!(
    [<T>, *const T] [<T>, *mut T] [<T, R>, fn(T) -> R]
);

impl SingleInstructionLoad for bool {
    unsafe fn load(offset: usize) -> Self {
        let val: u8;
        // SAFETY: The caller supplies a CPU-local bool offset. The underlying
        // u8 access is one instruction in the nonredirectable sequence.
        unsafe { val = <u8 as SingleInstructionLoad>::load(offset) };
        debug_assert!(val <= 1);
        val != 0
    }
}
impl SingleInstructionStore for bool {
    unsafe fn store(offset: usize, val: Self) {
        // SAFETY: Same as load; converting bool to u8 preserves its layout.
        unsafe { <u8 as SingleInstructionStore>::store(offset, u8::from(val)) };
    }
}
