// SPDX-License-Identifier: MPL-2.0

use alloc::format;

use device_id::{DeviceId, MinorId};
use ostd::{mm::VmIo, sync::Mutex, warn};
use ostd_pod::Pod;

use crate::{
    BlockDevice, BlockDeviceMeta, DEVICE_MINORS, SECTOR_SIZE,
    bio::{BioEnqueueError, SubmittedBio},
    device_id::EXTENDED_DEVICE_ID_ALLOCATOR,
    prelude::*,
    register, unregister,
};

/// Represents a partition entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PartitionInfo {
    Mbr(MbrEntry),
    Gpt(GptEntry),
}

impl PartitionInfo {
    fn start_sector(&self) -> u64 {
        match self {
            PartitionInfo::Mbr(entry) => entry.start_sector as u64,
            PartitionInfo::Gpt(entry) => entry.start_lba,
        }
    }

    fn total_sectors(&self) -> u64 {
        match self {
            PartitionInfo::Mbr(entry) => entry.total_sectors as u64,
            PartitionInfo::Gpt(entry) => entry.end_lba - entry.start_lba + 1,
        }
    }
}

/// A MBR (Master Boot Record) partition table header.
///
/// See <https://wiki.osdev.org/MBR_(x86)#MBR_Format>.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct MbrHeader {
    bootstrap_code: [u8; 440],
    id: u32,
    reserved: u16,
    entries: [MbrEntry; 4],
    signature: u16,
}

impl MbrHeader {
    fn check_signature(&self) -> bool {
        self.signature == 0xAA55
    }
}

/// A MBR (Master Boot Record) partition entry.
///
/// See <https://wiki.osdev.org/Partition_Table>.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Pod)]
pub(super) struct MbrEntry {
    flag: u8,
    start_chs: ChsAddr,
    type_: u8,
    end_chs: ChsAddr,
    start_sector: u32,
    total_sectors: u32,
}

impl MbrEntry {
    fn is_extended(&self) -> bool {
        self.type_ == 0x05 || self.type_ == 0x0F
    }

    fn is_valid(&self) -> bool {
        // A System ID byte value of 0 is the definitive indicator for an unused entry.
        // Any other illegal value (CHS Sector = 0 or Total Sectors = 0) may also indicate an unused entry.
        self.type_ != 0x00
            && self.start_chs.0[1] != 0
            && self.end_chs.0[1] != 0
            && self.total_sectors != 0
    }
}

/// A CHS (Cylinder-Head-Sector) address.
///
/// In CHS addressing, sector numbers always start at 1; there is no sector 0.
///
/// The CHS address is stored as a 3-byte field:
/// - Byte 0: Head number (8 bits)
/// - Byte 1: Bits 0–5 are the sector number (6 bits, valid values 1–63);
///   bits 6–7 are the upper two bits of the cylinder number
/// - Byte 2: Lower 8 bits of the cylinder number (bits 0–7)
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Pod)]
struct ChsAddr([u8; 3]);

/// A GPT (GUID Partition Table) header.
///
/// See <https://wiki.osdev.org/GPT#LBA_1:_Partition_Table_Header>.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct GptHeader {
    signature: u64,
    revision: u32,
    size: u32,
    crc32: u32,
    reserved: u32,
    current_lba: u64,
    backup_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    guid: [u8; 16],
    partition_entry_lba: u64,
    nr_partition_entries: u32,
    size_of_partition_entry: u32,
    crc32_of_partition_entries: u32,
    _padding: [u8; 420],
}

impl GptHeader {
    fn check_signature(&self) -> bool {
        &self.signature.to_le_bytes() == b"EFI PART"
    }
}

/// A GPT (GUID Partition Table) partition entry.
///
/// See <https://wiki.osdev.org/GPT#LBA_2:_Partition_Entries>.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Pod)]
pub(super) struct GptEntry {
    // Unique ID that defines the purpose and type of this Partition.
    // A value of zero defines that this partition entry is not being used.
    type_guid: [u8; 16],
    // GUID that is unique for every partition entry.
    guid: [u8; 16],
    start_lba: u64,
    end_lba: u64,
    attributes: u64,
    // Null-terminated string containing a human-readable name of the partition.
    name: [u8; 72],
}

impl GptEntry {
    fn is_valid(&self) -> bool {
        self.type_guid != [0; 16]
    }
}

pub(super) fn parse(device: &Arc<dyn BlockDevice>) -> Option<Vec<Option<PartitionInfo>>> {
    let mbr = device.read_val::<MbrHeader>(0).unwrap();

    // 0xEE indicates a GPT Protective MBR, a fake partition covering the entire disk.
    let partitions = if mbr.check_signature() && mbr.entries[0].type_ != 0xEE {
        parse_mbr(device, &mbr)
    } else {
        parse_gpt(device)
    };

    partitions.iter().any(|p| p.is_some()).then_some(partitions)
}

fn parse_mbr(device: &Arc<dyn BlockDevice>, mbr: &MbrHeader) -> Vec<Option<PartitionInfo>> {
    let mut partitions = Vec::new();
    let mut extended_partition = None;
    for entry in mbr.entries {
        if entry.is_extended() {
            extended_partition = Some(entry.start_sector);
        }

        if entry.is_valid() {
            partitions.push(Some(PartitionInfo::Mbr(entry)));
        } else {
            partitions.push(None);
        }
    }

    if let Some(start_sector) = extended_partition {
        parse_ebr(device, &mut partitions, start_sector, 0);
    }

    partitions
}

fn parse_ebr(
    device: &Arc<dyn BlockDevice>,
    partitions: &mut Vec<Option<PartitionInfo>>,
    start_sector: u32,
    offset: u32,
) {
    let ebr_sector = start_sector + offset;
    let mut ebr = device
        .read_val::<MbrHeader>(ebr_sector as usize * SECTOR_SIZE)
        .unwrap();
    if ebr.entries[0].is_valid() {
        ebr.entries[0].start_sector += ebr_sector;
        partitions.push(Some(PartitionInfo::Mbr(ebr.entries[0])));
    }

    if ebr.entries[1].is_extended() {
        parse_ebr(
            device,
            partitions,
            start_sector,
            ebr.entries[1].start_sector,
        );
    }
}

fn parse_gpt(device: &Arc<dyn BlockDevice>) -> Vec<Option<PartitionInfo>> {
    let mut partitions = Vec::new();

    // The primary GPT Header must be located in LBA 1.
    let gpt = device.read_val::<GptHeader>(SECTOR_SIZE).unwrap();

    if !gpt.check_signature() {
        return partitions;
    }

    // TODO: Check the CRC32 of the header and the partition entries, check the backup GPT header.

    let Some((base, count, stride)) = gpt_entry_layout(&gpt, device.metadata().nr_sectors) else {
        warn!("invalid GPT partition-entry layout");
        return partitions;
    };
    let mut buffer = [0u8; SECTOR_SIZE];
    let mut cached_sector = None;
    for index in 0..count {
        let offset = base + index * stride;
        let sector = offset / SECTOR_SIZE;
        if cached_sector != Some(sector) {
            if device
                .read_bytes(sector * SECTOR_SIZE, &mut buffer)
                .is_err()
            {
                warn!("cannot read GPT partition entry");
                return Vec::new();
            }
            cached_sector = Some(sector);
        }
        // The validated power-of-two stride guarantees that the fixed entry
        // prefix fits in one sector. Reuse that sector for smaller entries.
        let entry_offset = offset % SECTOR_SIZE;
        let entry =
            GptEntry::from_first_bytes(&buffer[entry_offset..entry_offset + size_of::<GptEntry>()]);
        if entry.is_valid()
            && entry.start_lba <= entry.end_lba
            && entry.end_lba < device.metadata().nr_sectors as u64
        {
            partitions.push(Some(PartitionInfo::Gpt(entry)));
        } else {
            partitions.push(None);
        }
    }

    partitions
}

/// Checks untrusted GPT table geometry before division, indexing or I/O.
fn gpt_entry_layout(gpt: &GptHeader, disk_sectors: usize) -> Option<(usize, usize, usize)> {
    let stride = gpt.size_of_partition_entry as usize;
    let minimum = size_of::<GptEntry>();
    // GPT entries are 128 * 2^n bytes. Accept large strides without assuming
    // that an integral number of entries fits in one sector.
    if stride < minimum || !stride.is_multiple_of(minimum) || !(stride / minimum).is_power_of_two()
    {
        return None;
    }
    let base = usize::try_from(gpt.partition_entry_lba)
        .ok()?
        .checked_mul(SECTOR_SIZE)?;
    let count = gpt.nr_partition_entries as usize;
    let end = base.checked_add(count.checked_mul(stride)?)?;
    let disk_bytes = disk_sectors.checked_mul(SECTOR_SIZE)?;
    (base >= 2 * SECTOR_SIZE && end <= disk_bytes).then_some((base, count, stride))
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::*;
    use ostd_pod::FromZeros;

    use super::*;

    #[ktest]
    fn malformed_gpt_entry_geometry_is_rejected() {
        let mut header = GptHeader::new_zeroed();
        header.partition_entry_lba = 2;
        header.nr_partition_entries = 5;
        for size in [0, 1, 64, 127, 129, 192, 384, u32::MAX] {
            header.size_of_partition_entry = size;
            assert_eq!(gpt_entry_layout(&header, 32), None);
        }
        header.size_of_partition_entry = 128;
        // The final partial sector still contains the fifth entry.
        assert_eq!(gpt_entry_layout(&header, 32), Some((1024, 5, 128)));
        header.size_of_partition_entry = 1024;
        assert_eq!(gpt_entry_layout(&header, 32), Some((1024, 5, 1024)));
        assert_eq!(gpt_entry_layout(&header, 3), None);
        header.partition_entry_lba = u64::MAX;
        assert_eq!(gpt_entry_layout(&header, 32), None);
    }
}

#[derive(Debug)]
struct PartitionNode {
    id: DeviceId,
    name: String,
    device: Arc<dyn BlockDevice>,
    info: PartitionInfo,
}

impl BlockDevice for PartitionNode {
    fn enqueue(&self, mut bio: SubmittedBio) -> Result<(), BioEnqueueError> {
        bio.set_sid_offset(self.info.start_sector());
        self.device.enqueue(bio)
    }

    fn metadata(&self) -> BlockDeviceMeta {
        let mut metadata = self.device.metadata();
        metadata.nr_sectors = self.info.total_sectors() as usize;
        metadata
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn id(&self) -> DeviceId {
        self.id
    }

    fn is_partition(&self) -> bool {
        true
    }
}

impl PartitionNode {
    fn new(id: DeviceId, name: String, device: Arc<dyn BlockDevice>, info: PartitionInfo) -> Self {
        Self {
            id,
            name,
            device,
            info,
        }
    }
}

/// Manages the partitions of a whole-disk block device.
///
/// The manager owns the device's current partition list and the lock that
/// serializes partition replacement.
#[derive(Debug)]
pub struct PartitionManager {
    inner: Mutex<Option<Vec<Arc<PartitionNode>>>>,
}

impl Default for PartitionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PartitionManager {
    /// Creates an empty partition manager.
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    /// Replaces the managed partitions with the parsed partition information.
    pub(super) fn update(&self, device: &Arc<dyn BlockDevice>, infos: Vec<Option<PartitionInfo>>) {
        // Lock order: partition lock -> `DEVICE_REGISTRY`

        let mut partitions = self.inner.lock();

        if let Some(old_partitions) = partitions.take() {
            for partition in old_partitions {
                let _ = unregister(partition.id());
            }
        }

        let mut new_partitions = Vec::new();
        for (index, info_opt) in infos.iter().enumerate() {
            let Some(info) = info_opt else {
                continue;
            };

            let index = index as u32 + 1;
            let id = if index < DEVICE_MINORS {
                let device_id = device.id();
                DeviceId::new(
                    device_id.major(),
                    MinorId::new(device_id.minor().get() + index),
                )
            } else {
                EXTENDED_DEVICE_ID_ALLOCATOR.get().unwrap().allocate()
            };
            let name = partition_name(device.name(), index);
            let partition = Arc::new(PartitionNode::new(id, name, device.clone(), *info));
            new_partitions.push(partition);
        }

        for partition in new_partitions.iter() {
            let _ = register(partition.clone());
        }

        *partitions = Some(new_partitions);
    }
}

/// Formats the name of a partition.
///
/// We perform the naming similar to the Linux implementation: insert "p" between
/// the disk name and the partition number when the disk name ends with a digit
/// (`nvme0n1p1`), and append the number otherwise (`vda1`).
///
/// Reference: <https://elixir.bootlin.com/linux/v7.2.2/source/block/partitions/core.c#L337>
fn partition_name(disk_name: &str, partno: u32) -> String {
    if disk_name.ends_with(|c: char| c.is_ascii_digit()) {
        format!("{}p{}", disk_name, partno)
    } else {
        format!("{}{}", disk_name, partno)
    }
}
