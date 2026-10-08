// SPDX-License-Identifier: MPL-2.0

//! The kernelet entry-table ABI that OSDK generates and audits, mirrored from
//! `ostd/src/kernelet/abi.rs`.
//!
//! OSDK owns the emitted offset and size: it bakes them into the generated
//! kernelet linker script and checks them in the artifact audit. The `ostd`
//! crate asserts the same layout with compile-time assertions, so a divergence
//! fails either the kernelet build or the audit.

/// The offset of the entry table from the image base (`ENTRY_TABLE_OFFSET` in
/// the design), at which the Host finds the table without a symbol table.
pub(crate) const ENTRY_TABLE_OFFSET: u64 = 0x1000;

/// The entry table's field layout, in the declared order of
/// `ostd::kernelet::abi::EntryTable`.
pub(crate) mod entry_table {
    /// The table size in bytes that the OSTD ABI fixes.
    pub(crate) const SIZE: u64 = 88;

    /// The byte offset of the `size` field.
    pub(crate) const SIZE_FIELD_OFFSET: usize = 0;
    /// The byte offset of the `vcpu_entry_offset` field.
    pub(crate) const VCPU_ENTRY_OFFSET: usize = 8;
    /// The byte offset of the `virq_entry_offset` field.
    pub(crate) const VIRQ_ENTRY_OFFSET: usize = 16;
    /// The byte offset of the `cpu_local_start_offset` field.
    pub(crate) const CPU_LOCAL_START_OFFSET: usize = 24;
    /// The byte offset of the `cpu_local_end_offset` field.
    pub(crate) const CPU_LOCAL_END_OFFSET: usize = 32;
    /// The byte offset of the `source_hash` field.
    pub(crate) const SOURCE_HASH_OFFSET: usize = 40;
    /// The byte offset of the `ex_table_start_offset` field.
    pub(crate) const EX_TABLE_START_OFFSET: usize = 72;
    /// The byte offset of the `ex_table_end_offset` field.
    pub(crate) const EX_TABLE_END_OFFSET: usize = 80;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The audit reads the fields by their byte offsets; the offsets must
    /// tile the table exactly, with no gap and no overrun.
    #[test]
    fn field_offsets_tile_the_table() {
        let fields = [
            (entry_table::SIZE_FIELD_OFFSET, 8),
            (entry_table::VCPU_ENTRY_OFFSET, 8),
            (entry_table::VIRQ_ENTRY_OFFSET, 8),
            (entry_table::CPU_LOCAL_START_OFFSET, 8),
            (entry_table::CPU_LOCAL_END_OFFSET, 8),
            (entry_table::SOURCE_HASH_OFFSET, 32),
            (entry_table::EX_TABLE_START_OFFSET, 8),
            (entry_table::EX_TABLE_END_OFFSET, 8),
        ];
        for pair in fields.windows(2) {
            assert_eq!(
                pair[0].0 + pair[0].1,
                pair[1].0,
                "fields must be back to back"
            );
        }
        assert_eq!((fields.last().unwrap().0 + 8) as u64, entry_table::SIZE);
    }
}
