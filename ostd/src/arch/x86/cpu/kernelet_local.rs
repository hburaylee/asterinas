// SPDX-License-Identifier: MPL-2.0

//! Accesses the CPU-local replica assigned to the current virtual CPU.

use crate::cpu::local::single_instr::{
    SingleInstructionAddAssign, SingleInstructionBitAndAssign, SingleInstructionBitOrAssign,
    SingleInstructionBitXorAssign, SingleInstructionLoad, SingleInstructionStore,
    SingleInstructionSubAssign,
};

/// Returns the current virtual CPU's private CPU-local base.
pub(crate) fn get_base() -> u64 {
    crate::kernelet::entry::vcpu_record().cpu_local_base
}

#[inline(always)]
fn address(offset: usize) -> usize {
    // An interrupt may run between this lookup and the memory instruction.
    // The carrier remains bound to this vCPU, so the replica cannot change.
    get_base() as usize + offset
}

macro_rules! impl_numeric_single_instruction_for {
    ($([$typ: ty, $inout_type: ident, $register_format: expr])*) => {$(

        impl SingleInstructionAddAssign<$typ> for $typ {
            unsafe fn add_assign(offset: usize, val: Self) {
                // SAFETY:
                // 1. The Host pins this carrier to the CPU mapped to its vCPU,
                //    and only this carrier accesses the vCPU's private replica.
                // 2. `offset` represents the offset of a CPU-local variable
                //    (upheld by the caller).
                // 3. The variable is only accessible on the current vCPU, is
                //    a scalar, and is never borrowed, so it is valid to
                //    read/write using a single instruction (upheld by the
                //    caller).
                unsafe {
                    core::arch::asm!(
                        concat!("add [{0}], {1", $register_format, "}"),
                        in(reg) address(offset),
                        in($inout_type) val,
                        options(nostack),
                    );
                }
            }
        }

        impl SingleInstructionSubAssign<$typ> for $typ {
            unsafe fn sub_assign(offset: usize, val: Self) {
                // SAFETY: Same as `add_assign`.
                unsafe {
                    core::arch::asm!(
                        concat!("sub [{0}], {1", $register_format, "}"),
                        in(reg) address(offset),
                        in($inout_type) val,
                        options(nostack),
                    );
                }
            }
        }

        impl SingleInstructionBitAndAssign<$typ> for $typ {
            unsafe fn bitand_assign(offset: usize, val: Self) {
                // SAFETY: Same as `add_assign`.
                unsafe {
                    core::arch::asm!(
                        concat!("and [{0}], {1", $register_format, "}"),
                        in(reg) address(offset),
                        in($inout_type) val,
                        options(nostack),
                    );
                }
            }
        }

        impl SingleInstructionBitOrAssign<$typ> for $typ {
            unsafe fn bitor_assign(offset: usize, val: Self) {
                // SAFETY: Same as `add_assign`.
                unsafe {
                    core::arch::asm!(
                        concat!("or [{0}], {1", $register_format, "}"),
                        in(reg) address(offset),
                        in($inout_type) val,
                        options(nostack),
                    );
                }
            }
        }

        impl SingleInstructionBitXorAssign<$typ> for $typ {
            unsafe fn bitxor_assign(offset: usize, val: Self) {
                // SAFETY: Same as `add_assign`.
                unsafe {
                    core::arch::asm!(
                        concat!("xor [{0}], {1", $register_format, "}"),
                        in(reg) address(offset),
                        in($inout_type) val,
                        options(nostack),
                    );
                }
            }
        }

        impl SingleInstructionLoad for $typ {
            unsafe fn load(offset: usize) -> Self {
                let val: Self;
                // SAFETY: Same as `add_assign`.
                unsafe {
                    core::arch::asm!(
                        concat!("mov {0", $register_format, "}, [{1}]"),
                        out($inout_type) val,
                        in(reg) address(offset),
                        options(nostack, readonly),
                    );
                }
                val
            }
        }

        impl SingleInstructionStore for $typ {
            unsafe fn store(offset: usize, val: Self) {
                // SAFETY: Same as `add_assign`.
                unsafe {
                    core::arch::asm!(
                        concat!("mov [{0}], {1", $register_format, "}"),
                        in(reg) address(offset),
                        in($inout_type) val,
                        options(nostack),
                    );
                }
            }
        }

    )*};
}

impl_numeric_single_instruction_for!(
    [u64,   reg,    ":r"]
    [usize, reg,    ":r"]
    [u32,   reg,    ":e"]
    [u16,   reg,    ":x"]
    [u8,    reg_byte, ""]
    [i64,   reg,    ":r"]
    [isize, reg,    ":r"]
    [i32,   reg,    ":e"]
    [i16,   reg,    ":x"]
    [i8,    reg_byte, ""]
);

macro_rules! impl_generic_single_instruction_for {
    ($([<$gen_type:ident $(, $more_gen_type:ident)*>, $typ:ty])*) => {$(

        impl<$gen_type $(, $more_gen_type)*> SingleInstructionLoad for $typ {
            unsafe fn load(offset: usize) -> Self {
                let val: Self;
                // SAFETY: Same as `add_assign`.
                unsafe {
                    core::arch::asm!(
                        concat!("mov {0}, [{1}]"),
                        out(reg) val,
                        in(reg) address(offset),
                        options(nostack, readonly),
                    );
                }
                val
            }
        }

        impl<$gen_type $(, $more_gen_type)*> SingleInstructionStore for $typ {
            unsafe fn store(offset: usize, val: Self) {
                // SAFETY: Same as `add_assign`.
                unsafe {
                    core::arch::asm!(
                        concat!("mov [{0}], {1}"),
                        in(reg) address(offset),
                        in(reg) val,
                        options(nostack),
                    );
                }
            }
        }
    )*}
}

impl_generic_single_instruction_for!(
    [<T>, *const T]
    [<T>, *mut T]
    [<T, R>, fn(T) -> R]
);

// In this module, booleans are represented by the least significant bit of a
// `u8` type. Other bits must be zero. This definition is compatible with the
// Rust reference: <https://doc.rust-lang.org/reference/types/boolean.html>.

impl SingleInstructionLoad for bool {
    unsafe fn load(offset: usize) -> Self {
        let val: u8;
        // SAFETY: Same as `add_assign`.
        unsafe {
            core::arch::asm!(
                "mov {0}, [{1}]",
                out(reg_byte) val,
                in(reg) address(offset),
                options(nostack, readonly),
            );
        }
        debug_assert!(val == 1 || val == 0);
        val == 1
    }
}

impl SingleInstructionStore for bool {
    unsafe fn store(offset: usize, val: Self) {
        let val: u8 = if val { 1 } else { 0 };
        // SAFETY: Same as `add_assign`.
        unsafe {
            core::arch::asm!(
                "mov [{0}], {1}",
                in(reg) address(offset),
                in(reg_byte) val,
                options(nostack),
            );
        }
    }
}
