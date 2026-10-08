// SPDX-License-Identifier: MPL-2.0

use crate::prelude::Vaddr;

#[repr(C)]
struct ExTableItem {
    #[cfg(target_arch = "x86_64")]
    inst_offset: i64,
    #[cfg(target_arch = "x86_64")]
    recovery_offset: i64,
    #[cfg(not(target_arch = "x86_64"))]
    inst_addr: Vaddr,
    #[cfg(not(target_arch = "x86_64"))]
    recovery_inst_addr: Vaddr,
}

impl ExTableItem {
    #[cfg(target_arch = "x86_64")]
    fn inst_addr(&self) -> Vaddr {
        (&self.inst_offset as *const i64 as usize).wrapping_add_signed(self.inst_offset as isize)
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn inst_addr(&self) -> Vaddr {
        self.inst_addr
    }

    #[cfg(target_arch = "x86_64")]
    fn recovery_inst_addr(&self) -> Vaddr {
        (&self.recovery_offset as *const i64 as usize)
            .wrapping_add_signed(self.recovery_offset as isize)
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn recovery_inst_addr(&self) -> Vaddr {
        self.recovery_inst_addr
    }
}

unsafe extern "C" {
    fn __ex_table();
    fn __ex_table_end();
}

/// A structure representing the usage of exception table (ExTable).
/// This table is used for recovering from specific exception handling faults
/// occurring at known points in the code.
///
/// On x86-64, entries use offsets relative to their own fields so that the
/// table can reside in the relocation-free text segment. To add a recovery
/// instruction, use the following statements:
///
/// ```
/// .pushsection .ex_table, "a"
/// .align 8
/// .quad target_label - .
/// .quad recovery_label - .
/// .popsection
/// ```
///
/// where the `target_label` and `recovery_label` are the labels of the target instruction
/// and the label of recovery instruction respectively.
///
/// For example, we have the following assembly code snippets in an input file:
/// ```
/// .label1:
///     rep movsb
///     mov rax, rcx
/// .label2:
///     ret
/// ```
///
/// We can add the following statements in the same file (`label1` and `label2` are local
/// labels):
///
/// ```
/// .pushsection .ex_table, "a"
/// .align 8
/// .quad .label1 - .
/// .quad .label2 - .
/// .popsection
/// ```
///
/// Other architectures retain absolute address entries. `ExTable` decodes
/// either form before searching for a recovery instruction.
pub(super) struct ExTable;

impl ExTable {
    /// Finds the recovery instruction address for a given instruction address.
    ///
    /// This function is generally used when an exception (such as a page fault) occurs.
    /// if the exception handling fails and there is a predefined recovery action,
    /// then the found recovery action will be taken.
    pub(super) fn find_recovery_inst_addr(inst_addr: Vaddr) -> Option<Vaddr> {
        let table_size = (__ex_table_end as *const () as usize - __ex_table as *const () as usize)
            / size_of::<ExTableItem>();
        // SAFETY: `__ex_table` is a static section consisting of `ExTableItem`.
        let ex_table =
            unsafe { core::slice::from_raw_parts(__ex_table as *const ExTableItem, table_size) };
        for item in ex_table {
            if item.inst_addr() == inst_addr {
                return Some(item.recovery_inst_addr());
            }
        }
        None
    }
}
