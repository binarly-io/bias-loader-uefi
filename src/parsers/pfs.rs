// ported from:
// https://github.com/platomav/BIOSUtilities/blob/5f364f4759020b72d8126525eb0f76d27d684735/Dell_PFS_Extract.py

use arrayvec::ArrayVec;
use flate2::read::ZlibDecoder;
use once_cell::sync::Lazy;
use regex::bytes::Regex;
use regex::Regex as SRegex;
use scroll::ctx::SizeWith;
use scroll::{IOread, Pread, SizeWith};
use utf16string::WStr;

use std::borrow::Cow;
use std::io::Read;
use std::path::Path;
use std::str;

use thiserror::Error;

use super::pfat::IntelBiosGuardHeader;
use super::PFS_MAGIC;

static PKG_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?-u)\x72\x13\x55\x00(.|\x0A){45}7zXZ(?u:(.*))").unwrap());
static HDR_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?-u)\xEE\xAA\x76\x1B\xEC\xBB\x20\xF1\xE6\x51(.|\x0A)\x78\x9C(?u:(.*))").unwrap()
});
static FTR_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?-u)\xEE\xAA\xEE\x8F\x49\x1B\xE8\xAE\x14\x37\x90(?u:(.*))").unwrap()
});
static SECTION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?-u)\xEE\xAA\x76\x1B\xEC\xBB\x20\xF1\xE6\x51(.|\x0A)\x78\x9C(?u:(.*))").unwrap()
});

static SAFE_STRING_REGEX: Lazy<SRegex> = Lazy::new(|| SRegex::new(r#"[\\/:"'*?<>|]+"#).unwrap());

const GUID_NAME_INFO1: [u32; 4] = [0xFD041960, 0x4B9F0DC8, 0xA9BB2582, 0xE0717CE3];
const GUID_NAME_INFO2: [u32; 4] = [0x4D583FD3, 0x4055F80E, 0xEC9B45A1, 0xB033CB16];
const GUID_MODEL_INFO: [u32; 4] = [0x233AE3FB, 0x4FD4DA68, 0x22A6CB92, 0x6F1D619A];
const GUID_SIG_INFO: [u32; 4] = [0x3C880BB7, 0x4D5CED58, 0x3ADBAEA9, 0xD086AFEE];
const GUID_NESTED_PFS: [u32; 4] = [0xAC9FDA84, 0x4055F456, 0x437F3AB1, 0x900FAE60];

const BIOS_NAME_PREFIX: [u8; 22] = [
    83, 0, 121, 0, 115, 0, 116, 0, 101, 0, 109, 0, 32, 0, 66, 0, 73, 0, 79, 0, 83, 0,
];

const MAX_FILE_NAME_SIZE: usize = 100;
const INVALID_ENTRY_DATA: &[u8] = b"INVALID";

const SECTION_TYPE_FIRMWARE: u8 = 0xaa;
const SECTION_TYPE_UITLITIES: u8 = 0xbb;

#[derive(Debug, Error)]
pub enum DellPfsError {
    #[error("no BIOS data found")]
    BiosNotFound,
    #[error("invalid checksum")]
    InvalidChecksum,
    #[error("invalid format")]
    InvalidFormat,
    #[error("invalid header version")]
    InvalidHeaderVersion,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid zlib section data")]
    InvalidZlibSectionData,
    #[error("out of bounds read")]
    OutOfBoundsRead,
    #[error(transparent)]
    Parse(#[from] scroll::Error),
    #[error("unsupportedformat")]
    UnsupportedFormat,
    #[error("unsupported section type {0:x}")]
    UnsupportedSectionType(u8),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DellPfsEntry {
    R1,
    R2,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EntryType {
    Other,
    NameInfo,
    ModelInfo,
    SigInfo,
    NestedPfs,
    Pfat,
    Zlib,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EntryItem<'a> {
    entry_index: u32,
    entry_guid: [u32; 4],
    entry_version_type: [u8; 4],
    entry_version: [u16; 4],
    entry_type: EntryType,
    entry_data: Cow<'a, [u8]>,
    entry_data_sig: &'a [u8],
    entry_met: &'a [u8],
    entry_met_sig: &'a [u8],
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct InfoItem {
    entry_guid: [u32; 4],
    entry_name: ArrayVec<u8, MAX_FILE_NAME_SIZE>,
    entry_version_type: [u8; 4],
    entry_version: [u16; 4],
    entry_file_version: ArrayVec<u8, 33>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PfatDataItem<'a> {
    pfat_entry_off: u32,
    pfat_entry_data_raw: &'a [u8],
}

#[derive(Pread, IOread, SizeWith)]
#[repr(C, packed)]
pub struct DellPfsHeader {
    tag: [u8; 8],
    header_version: u32,
    payload_size: u32,
}

#[derive(Pread, IOread, SizeWith)]
#[repr(C, packed)]
pub struct DellPfsFooter {
    payload_size: u32,
    checksum: u32,
    tag: [u8; 8],
}

#[derive(Debug)]
#[allow(unused)]
struct DellPfsEntryBase {
    guid: [u32; 4],
    header_version: u32,
    version_type: [u8; 4],
    version: [u16; 4],
    data_size: u32,
    data_sig_size: u32,
    data_met_size: u32,
    data_met_sig_size: u32,
}

#[derive(Pread, IOread, SizeWith)]
#[repr(C, packed)]
pub struct DellPfsEntryR1 {
    guid: [u32; 4],
    header_version: u32,
    version_type: [u8; 4],
    version: [u16; 4],
    reserved: u64,
    data_size: u32,
    data_sig_size: u32,
    data_met_size: u32,
    data_met_sig_size: u32,
    unknown: [u32; 4],
}

impl From<DellPfsEntryR1> for DellPfsEntryBase {
    fn from(e: DellPfsEntryR1) -> Self {
        Self {
            guid: e.guid,
            header_version: e.header_version,
            version_type: e.version_type,
            version: e.version,
            data_size: e.data_size,
            data_sig_size: e.data_sig_size,
            data_met_size: e.data_met_size,
            data_met_sig_size: e.data_met_sig_size,
        }
    }
}

#[derive(Pread, IOread, SizeWith)]
#[repr(C, packed)]
pub struct DellPfsEntryR2 {
    guid: [u32; 4],
    header_version: u32,
    version_type: [u8; 4],
    version: [u16; 4],
    reserved: u64,
    data_size: u32,
    data_sig_size: u32,
    data_met_size: u32,
    data_met_sig_size: u32,
    unknown: [u32; 8],
}

impl From<DellPfsEntryR2> for DellPfsEntryBase {
    fn from(e: DellPfsEntryR2) -> Self {
        Self {
            guid: e.guid,
            header_version: e.header_version,
            version_type: e.version_type,
            version: e.version,
            data_size: e.data_size,
            data_sig_size: e.data_sig_size,
            data_met_size: e.data_met_size,
            data_met_sig_size: e.data_met_sig_size,
        }
    }
}

#[derive(Pread, IOread, SizeWith)]
#[repr(C, packed)]
pub struct DellPfsInfo {
    header_version: u32,
    guid: [u32; 4],
}

#[derive(Pread, IOread, SizeWith)]
#[repr(C, packed)]
pub struct DellPfsName {
    version: [u16; 4],
    version_type: [u8; 4],
    character_count: u16,
}

#[derive(Pread, IOread, SizeWith)]
#[repr(C, packed)]
pub struct DellPfsMetadata {
    model_ids: [u8; 501],
    file_name: [u8; 100],
    file_version: [u8; 33],
    date: [u8; 33],
    brand: [u8; 80],
    model_file: [u8; 80],
    model_name: [u8; 100],
    model_version: [u8; 33],
}

#[derive(Pread, IOread, SizeWith)]
#[repr(C, packed)]
pub struct DellPfsPfatMetadata {
    offset_top: u32,
    unknown0: u32,
    offset_base: u32,
    block_size: u32,
    unknown1: u32,
    unknown2: u32,
    unknown3: u32,
}

#[derive(Default)]
pub struct DellPfs {
    data: Vec<(Option<String>, Vec<u8>)>,
}

const PFS_HEADER_LEN: usize = std::mem::size_of::<DellPfsHeader>();
const PFAT_HEADER_LEN: usize = std::mem::size_of::<IntelBiosGuardHeader>();

#[inline(always)]
fn read_slice(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], DellPfsError> {
    let end = offset
        .checked_add(length)
        .ok_or(DellPfsError::OutOfBoundsRead)?;
    Ok(bytes
        .get(offset..end)
        .ok_or(DellPfsError::OutOfBoundsRead)?)
}

#[inline]
fn chk_8_xor(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |acc, v| acc ^ v)
}

#[inline]
fn is_pkg(bytes: &[u8]) -> bool {
    PKG_REGEX.is_match(bytes)
}

#[inline]
fn is_hdr(bytes: &[u8]) -> bool {
    HDR_REGEX.is_match(bytes)
}

#[inline]
fn is_ftr(bytes: &[u8]) -> bool {
    FTR_REGEX.is_match(bytes)
}

#[inline]
fn section_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut offsets = SECTION_REGEX
        .find_iter(bytes)
        .filter_map(|m| {
            if m.start() > 0 && bytes[m.start() - 1] != SECTION_TYPE_UITLITIES {
                Some(m.start())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    offsets.sort();
    offsets.dedup();
    offsets
}

#[inline]
fn parse_pfs_entry_size(bytes: &[u8], offset: usize) -> Result<usize, DellPfsError> {
    let version_offset = offset
        .checked_add(0x10)
        .ok_or(DellPfsError::OutOfBoundsRead)?;
    let version = bytes.pread_with::<u32>(version_offset, scroll::LE)?;

    Ok(match version {
        1 => DellPfsEntryR1::size_with(&scroll::LE),
        _ => DellPfsEntryR2::size_with(&scroll::LE),
    })
}

#[inline]
fn parse_pfs_entry(bytes: &[u8], offset: usize) -> Result<(DellPfsEntryBase, usize), DellPfsError> {
    let version_offset = offset
        .checked_add(0x10)
        .ok_or(DellPfsError::OutOfBoundsRead)?;
    let version = bytes.pread_with::<u32>(version_offset, scroll::LE)?;

    match version {
        1 => {
            let entry = bytes.pread_with::<DellPfsEntryR1>(offset, scroll::LE)?;
            Ok((entry.into(), DellPfsEntryR1::size_with(&scroll::LE)))
        }
        2 => {
            let entry = bytes.pread_with::<DellPfsEntryR2>(offset, scroll::LE)?;
            Ok((entry.into(), DellPfsEntryR2::size_with(&scroll::LE)))
        }
        _ => Err(DellPfsError::InvalidHeaderVersion),
    }
}

#[inline]
fn safe_name(name: String) -> String {
    let result = name.trim_start_matches(".").to_string();
    return SAFE_STRING_REGEX
        .replace_all(result.as_str(), "_")
        .to_string();
}

#[inline]
fn get_entry_ver(version_fields: [u16; 4], version_types: [u8; 4]) -> String {
    let mut version = String::new();
    for (index, field) in version_fields.iter().enumerate() {
        let eol = if index == version_fields.len() - 1 {
            ""
        } else {
            "."
        };
        match version_types[index] {
            // 0x41 = ASCII
            65 => version.push_str(&format!("{:X}{}", field, eol)),
            // 0x4E = Number
            78 => version.push_str(&format!("{}{}", field, eol)),
            // 0x00 or 0x20 = Unused
            0 | 32 => version = version.trim_end_matches(".").to_string(),
            // Unknown
            _ => version.push_str(&format!("{:X}{}", field, eol)),
        }
    }
    version
}

fn parse_pfat_pfs(entry_hdr: DellPfsHeader, entry_data: &[u8]) -> Result<Vec<u8>, DellPfsError> {
    let pfs_version = entry_hdr.header_version;
    if pfs_version != 1 && pfs_version != 2 {
        return Err(DellPfsError::InvalidHeaderVersion);
    }

    // Get sub-PFS Payload Data

    let pfat_payload = read_slice(entry_data, PFS_HEADER_LEN, entry_hdr.payload_size as usize)?;

    let mut pfat_entry_start = 0usize;
    let mut pfat_data_all = Vec::new();

    let (_, mut pfs_entry_size) = parse_pfs_entry(pfat_payload, 0)?;

    while matches!(pfat_entry_start.checked_add(pfs_entry_size), Some(len) if len <= pfat_payload.len())
    {
        let (entry, entry_size) = parse_pfs_entry(pfat_payload, pfat_entry_start)?;

        // PFS Entry Data starts after the PFS Entry Structure
        let entry_data_start = pfat_entry_start
            .checked_add(entry_size)
            .ok_or(DellPfsError::OutOfBoundsRead)?;
        let entry_data_end = entry_data_start
            .checked_add(entry.data_size as usize)
            .ok_or(DellPfsError::OutOfBoundsRead)?;

        // PFS Entry Data Signature starts after PFS Entry Data
        let entry_data_sig_start = entry_data_end;
        let entry_data_sig_end = entry_data_sig_start
            .checked_add(entry.data_sig_size as usize)
            .ok_or(DellPfsError::OutOfBoundsRead)?;

        // PFS Entry Metadata starts after PFS Entry Data Signature
        let entry_met_start = entry_data_sig_end;
        let entry_met_end = entry_met_start
            .checked_add(entry.data_met_size as usize)
            .ok_or(DellPfsError::OutOfBoundsRead)?;

        // PFS Entry Metadata Signature starts after PFS Entry Metadata
        let entry_met_sig_start = entry_met_end;
        let entry_met_sig_end = entry_met_sig_start
            .checked_add(entry.data_met_sig_size as usize)
            .ok_or(DellPfsError::OutOfBoundsRead)?;

        let pfat_hdr_off = entry_data_start;
        let pfat_hdr = pfat_payload.pread_with::<IntelBiosGuardHeader>(pfat_hdr_off, scroll::LE)?;

        let pfat_script_start = pfat_hdr_off
            .checked_add(PFAT_HEADER_LEN)
            .ok_or(DellPfsError::OutOfBoundsRead)?;
        let pfat_script_end = pfat_script_start
            .checked_add(pfat_hdr.script_size as usize)
            .ok_or(DellPfsError::OutOfBoundsRead)?;

        let pfat_script_data = read_slice(
            pfat_payload,
            pfat_script_start,
            pfat_hdr.script_size as usize,
        )?;

        let pfat_payload_start = pfat_script_end;

        let pfat_entry_data_raw = read_slice(
            pfat_payload,
            pfat_payload_start,
            pfat_hdr.data_size as usize,
        )?;

        let pfat_entry_off = pfat_script_data.pread_with::<u32>(0xc, scroll::LE)?;

        pfat_data_all.push(PfatDataItem {
            pfat_entry_off,
            pfat_entry_data_raw,
        });

        pfat_entry_start = entry_met_sig_end;
        pfs_entry_size = entry_size;
    }

    pfat_data_all.sort_by_key(|x| x.pfat_entry_off);

    Ok(pfat_data_all
        .into_iter()
        .map(|e| e.pfat_entry_data_raw.iter().map(|b| *b))
        .flatten()
        .collect())
}

impl DellPfs {
    pub(crate) fn is_dell_pfs(bytes: &[u8]) -> bool {
        is_pkg(bytes) || (is_hdr(bytes) && is_ftr(bytes))
    }

    pub fn data(&self) -> &[(Option<String>, Vec<u8>)] {
        &self.data
    }

    pub fn into_data(self) -> Vec<(Option<String>, Vec<u8>)> {
        self.data
    }

    fn pfs_extract(
        &mut self,
        mut pfs_count: usize,
        pfs_name: Option<String>,
        section_data: &[u8],
    ) -> Result<(), DellPfsError> {
        let pfs_header = section_data.pread_with::<DellPfsHeader>(0, scroll::LE)?;

        if pfs_header.tag != *PFS_MAGIC {
            return Err(DellPfsError::InvalidSignature);
        }

        let header_version = pfs_header.header_version as u32;

        if header_version != 1 && header_version != 2 {
            return Err(DellPfsError::InvalidHeaderVersion);
        }

        let pfs_payload = read_slice(
            section_data,
            PFS_HEADER_LEN,
            pfs_header.payload_size as usize,
        )?;

        let (_, mut pfs_entry_size) = parse_pfs_entry(pfs_payload, 0)?;

        let mut entry_index = 1;
        let mut entry_start = 0usize;

        let mut entries_all = Vec::new();
        let mut filename_info = <&[u8]>::default();

        while matches!(entry_start.checked_add(pfs_entry_size), Some(len) if len <= pfs_payload.len())
        {
            let (entry, entry_size) = parse_pfs_entry(pfs_payload, entry_start)?;

            // PFS Entry Data starts after the PFS Entry Structure
            let entry_data_start = entry_start
                .checked_add(entry_size)
                .ok_or(DellPfsError::OutOfBoundsRead)?;

            let entry_data = read_slice(pfs_payload, entry_data_start, entry.data_size as usize)?;

            let entry_data_sig_start = entry_data_start
                .checked_add(entry.data_size as usize)
                .ok_or(DellPfsError::OutOfBoundsRead)?;

            let entry_data_sig = read_slice(
                pfs_payload,
                entry_data_sig_start,
                entry.data_sig_size as usize,
            )?;

            let entry_met_start = entry_data_sig_start
                .checked_add(entry.data_sig_size as usize)
                .ok_or(DellPfsError::OutOfBoundsRead)?;

            let entry_met = read_slice(pfs_payload, entry_met_start, entry.data_met_size as usize)?;

            let entry_met_sig_start = entry_met_start
                .checked_add(entry.data_met_size as usize)
                .ok_or(DellPfsError::OutOfBoundsRead)?;
            let entry_met_sig_end = entry_met_sig_start
                .checked_add(entry.data_met_sig_size as usize)
                .ok_or(DellPfsError::OutOfBoundsRead)?;

            let entry_met_sig = read_slice(
                pfs_payload,
                entry_met_sig_start,
                entry.data_met_sig_size as usize,
            )?;

            let entry_type = match entry.guid {
                GUID_NAME_INFO1 | GUID_NAME_INFO2 => {
                    filename_info = entry_data;
                    EntryType::NameInfo
                }
                GUID_MODEL_INFO => EntryType::ModelInfo,
                GUID_SIG_INFO => EntryType::SigInfo,
                GUID_NESTED_PFS => EntryType::NestedPfs,
                _ => EntryType::Other,
            };

            entries_all.push(EntryItem {
                entry_index,
                entry_guid: entry.guid,
                entry_version_type: entry.version_type,
                entry_version: entry.version,
                entry_type,
                entry_data: Cow::Borrowed(entry_data),
                entry_data_sig,
                entry_met,
                entry_met_sig,
            });

            entry_index += 1;
            entry_start = entry_met_sig_end;
            pfs_entry_size = entry_size;
        }

        let mut info_start = 0usize;
        let pfs_info_size = DellPfsInfo::size_with(&scroll::LE);
        let pfs_name_size = DellPfsName::size_with(&scroll::LE);
        let mut info_all = Vec::new();

        while matches!(info_start.checked_add(pfs_info_size), Some(len) if len <= filename_info.len())
        {
            let entry_info_hdr = filename_info.pread_with::<DellPfsInfo>(info_start, scroll::LE)?;
            if entry_info_hdr.header_version != 1 && entry_info_hdr.header_version != 2 {
                return Err(DellPfsError::InvalidHeaderVersion);
            }

            let entry_info_mod_start = info_start
                .checked_add(pfs_info_size)
                .ok_or(DellPfsError::OutOfBoundsRead)?;

            let entry_info_mod =
                filename_info.pread_with::<DellPfsName>(entry_info_mod_start, scroll::LE)?;

            let name_start = entry_info_mod_start
                .checked_add(pfs_name_size)
                .ok_or(DellPfsError::OutOfBoundsRead)?;
            let name_size = 2usize
                .checked_mul(entry_info_mod.character_count as usize)
                .ok_or(DellPfsError::OutOfBoundsRead)?;

            let name = read_slice(filename_info, name_start, name_size.min(MAX_FILE_NAME_SIZE))?;

            info_all.push(InfoItem {
                entry_guid: entry_info_hdr.guid,
                entry_name: name.try_into().expect("invalid name"),
                entry_version_type: entry_info_mod.version_type,
                entry_version: entry_info_mod.version,
                ..Default::default()
            });

            info_start = info_start
                .checked_add(pfs_info_size)
                .and_then(|v| v.checked_add(pfs_name_size))
                .and_then(|v| v.checked_add(name_size))
                .and_then(|v| v.checked_add(2))
                .ok_or(DellPfsError::OutOfBoundsRead)?;
        }

        // Parse Nested PFS Metadata when its PFS Information Entry is missing
        let pfs_meta_size = DellPfsMetadata::size_with(&scroll::LE);
        for entry in entries_all.iter_mut() {
            if entry.entry_type == EntryType::NestedPfs {
                if !filename_info.is_empty() {
                    continue;
                }

                if entry.entry_met.len() < pfs_meta_size {
                    continue;
                }

                let entry_info = entry
                    .entry_met
                    .pread_with::<DellPfsMetadata>(0, scroll::LE)?;

                let name = entry_info
                    .file_name
                    .split(|c| *c == 0)
                    .next()
                    .unwrap_or(INVALID_ENTRY_DATA);

                let version = entry_info
                    .file_version
                    .split(|c| *c == 0)
                    .next()
                    .unwrap_or(INVALID_ENTRY_DATA);

                info_all.push(InfoItem {
                    entry_guid: entry.entry_guid,
                    entry_name: name.try_into().expect("invalid name"),
                    entry_file_version: version.try_into().expect("invalid version"),
                    ..Default::default()
                });
            }
        }

        // TODO: Parse all PFS Signature Entries/Descriptors

        // Parse each PFS Entry Data for special types (zlib or PFAT)
        for entry in entries_all.iter_mut() {
            if entry.entry_data.len() < PFS_HEADER_LEN {
                continue;
            }

            let mut entry_type = EntryType::Other;
            let mut entry_data = Vec::new();

            let zlib_offsets = section_offsets(entry.entry_data.as_ref());

            let mut is_pfat = false;

            let pfs_entry_size = parse_pfs_entry_size(&entry.entry_data, PFS_HEADER_LEN)?;

            let pfat_hdr_off = PFS_HEADER_LEN
                .checked_add(pfs_entry_size)
                .ok_or(DellPfsError::OutOfBoundsRead)?;

            let pfat_entry_hdr = entry
                .entry_data
                .pread_with::<DellPfsHeader>(0, scroll::LE)?;

            if matches!(entry.entry_data.len().checked_sub(pfat_hdr_off), Some(len) if len >= PFAT_HEADER_LEN)
            {
                let platform_id_sig =
                    str::from_utf8(read_slice(&entry.entry_data, pfat_hdr_off + 4, 4)?);

                if matches!(platform_id_sig, Ok(sig) if sig.eq_ignore_ascii_case("DELL")) {
                    is_pfat = true;
                }
            }

            // Parse PFS Entry which contains sub-PFS Volume with PFAT Payload
            if pfat_entry_hdr.tag == *PFS_MAGIC && is_pfat {
                entry_type = EntryType::Pfat; // Re-set PFS Entry Type from OTHER to PFAT, to use such info afterwards
                entry_data = parse_pfat_pfs(pfat_entry_hdr, &entry.entry_data)?;
            } else if !zlib_offsets.is_empty() {
                entry_type = EntryType::Zlib; // Re-set PFS Entry Type from OTHER to ZLIB, to use such info afterwards
                pfs_count += 1;
                for offset in zlib_offsets.iter() {
                    let section_name = pfs_count
                        .checked_sub(2)
                        .and_then(|i| info_all.get(i))
                        .and_then(|n| {
                            let name = if n.entry_name.len() >= 2 && n.entry_name[1] == 0 {
                                WStr::from_utf16le(&*n.entry_name).ok()?.to_utf8()
                            } else {
                                str::from_utf8(&*n.entry_name).ok()?.to_owned()
                            };

                            let version = if n.entry_file_version.len() >= 2
                                && n.entry_file_version[1] == 0
                            {
                                WStr::from_utf16le(&*n.entry_file_version).ok()?.to_utf8()
                            } else {
                                str::from_utf8(&*n.entry_file_version).ok()?.to_owned()
                            };

                            let mut name = if let Some(base_name) = Path::new(&name).file_name() {
                                base_name.to_string_lossy().into_owned()
                            } else {
                                name
                            };

                            // post process name according to
                            // https://github.com/platomav/BIOSUtilities/blob/71cbfdaf8b2326509a041da5d58cb1d0d05afad7/Dell_PFS_Extract.py#L528
                            name = safe_name(name.trim_end_matches(".exe").to_string());

                            if version.is_empty() {
                                let v = get_entry_ver(n.entry_version, n.entry_version_type);
                                if v.is_empty() {
                                    Some(name)
                                } else {
                                    Some(format!("{name}_v{v}"))
                                }
                            } else {
                                Some(format!("{name}_v{version}"))
                            }
                        });
                    self.pfs_section_parse(pfs_count, section_name, &entry.entry_data, *offset)?;
                }
            }

            if !entry_data.is_empty() {
                entry.entry_data = Cow::Owned(entry_data);
            }

            entry.entry_type = entry_type;
        }

        let system_bios_guid = info_all.iter().find_map(|info| {
            if info
                .entry_name
                .windows(BIOS_NAME_PREFIX.len())
                .position(|sub| sub == BIOS_NAME_PREFIX)
                .is_some()
            {
                Some(info.entry_guid)
            } else {
                None
            }
        });

        if let Some(guid) = system_bios_guid {
            entries_all.into_iter().for_each(|entry| {
                if entry.entry_guid == guid {
                    self.data
                        .push((pfs_name.clone(), entry.entry_data.into_owned()))
                }
            })
        }

        Ok(())
    }

    fn pfs_section_parse(
        &mut self,
        pfs_count: usize,
        pfs_name: Option<String>,
        bytes: &[u8],
        zlib_start: usize,
    ) -> Result<(), DellPfsError> {
        let section_type_off = zlib_start
            .checked_sub(1)
            .ok_or(DellPfsError::OutOfBoundsRead)?;

        let section_type = *bytes
            .get(section_type_off)
            .ok_or(DellPfsError::OutOfBoundsRead)?;

        if section_type != SECTION_TYPE_FIRMWARE {
            return Err(DellPfsError::UnsupportedSectionType(section_type));
        }

        let compressed_start = zlib_start
            .checked_add(0x0b)
            .ok_or(DellPfsError::OutOfBoundsRead)?;
        let header_start = zlib_start
            .checked_sub(0x5)
            .ok_or(DellPfsError::OutOfBoundsRead)?;
        let header_data = read_slice(bytes, header_start, 0x10)?;

        let mut valid_zlib = true;

        valid_zlib &= chk_8_xor(&header_data[..0xf]) == header_data[0xf];

        let compressed_size_hdr = header_data.pread_with::<u32>(0, scroll::LE)?;
        let compressed_data = read_slice(bytes, compressed_start, compressed_size_hdr as usize)?;

        let compressed_end = compressed_start
            .checked_add(compressed_size_hdr as usize)
            .ok_or(DellPfsError::OutOfBoundsRead)?;

        let footer_data = read_slice(bytes, compressed_end, 0x10)?;
        valid_zlib &= is_ftr(footer_data);
        valid_zlib &= chk_8_xor(&footer_data[..0xf]) == footer_data[0xf];

        let compressed_size_ftr = footer_data.pread_with::<u32>(0, scroll::LE)?;

        valid_zlib &= compressed_size_ftr == compressed_size_hdr;

        if valid_zlib {
            let mut section_data: Vec<u8> = Vec::new();
            if ZlibDecoder::new(compressed_data)
                .read_to_end(&mut section_data)
                .is_ok()
            {
                self.pfs_extract(pfs_count, pfs_name, &section_data)
            } else {
                self.pfs_extract(pfs_count, pfs_name, bytes)
            }
        } else {
            self.pfs_extract(pfs_count, pfs_name, bytes)
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, DellPfsError> {
        if !Self::is_dell_pfs(bytes) {
            return Err(DellPfsError::InvalidFormat);
        }

        if is_pkg(bytes) {
            return Err(DellPfsError::UnsupportedFormat);
        }

        let mut parser = Self::default();

        for zlib_offset in section_offsets(bytes) {
            parser.pfs_section_parse(1, None, bytes, zlib_offset)?;
            if !parser.data().is_empty() {
                return Ok(parser);
            }
        }

        Err(DellPfsError::BiosNotFound)
    }

    pub fn parse_many(bytes: &[u8]) -> Result<Self, DellPfsError> {
        if !Self::is_dell_pfs(bytes) {
            return Err(DellPfsError::InvalidFormat);
        }

        if is_pkg(bytes) {
            return Err(DellPfsError::UnsupportedFormat);
        }

        let mut parser = Self::default();

        for offset in section_offsets(bytes) {
            parser.pfs_section_parse(1, None, bytes, offset)?;
        }

        if parser.data().is_empty() {
            Err(DellPfsError::BiosNotFound)
        } else {
            Ok(parser)
        }
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::{BufReader, Read};

    use super::*;

    #[test]
    fn test_unpack() -> Result<(), Box<dyn std::error::Error>> {
        let _ = tracing_subscriber::fmt::try_init();

        let mut f = BufReader::new(File::open("./tests/DellG3_3579_3779_1220.cap")?);
        let mut bytes = Vec::default();
        f.read_to_end(&mut bytes)?;

        let pfs = DellPfs::parse(&bytes)?;
        assert!(pfs.data().len() > 0);

        // unpacked already
        let mut f = BufReader::new(File::open("./tests/DellG3_3579_3779_1220.bin")?);
        bytes.clear();
        f.read_to_end(&mut bytes)?;

        assert_eq!(bytes, pfs.data()[0].1);

        Ok(())
    }

    #[test]
    fn test_unpack_inspiron() -> Result<(), Box<dyn std::error::Error>> {
        let _ = tracing_subscriber::fmt::try_init();

        let mut f = BufReader::new(File::open("./tests/Inspiron-14-3467.bin")?);
        let mut bytes = Vec::default();
        f.read_to_end(&mut bytes)?;

        let pfs = DellPfs::parse(&bytes)?;
        assert!(pfs.data().len() > 0);

        // unpacked already
        let mut f = BufReader::new(File::open("./tests/Inspiron-14-3467-unpacked.bin")?);
        bytes.clear();
        f.read_to_end(&mut bytes)?;

        assert_eq!(bytes, pfs.data()[0].1);

        Ok(())
    }

    #[test]
    fn test_unpack_all() -> Result<(), Box<dyn std::error::Error>> {
        let _ = tracing_subscriber::fmt::try_init();

        let testcases = [
            "./tests/Latitude_5430_1.6.1_v98.5.5.bin",
            "./tests/aaad4d01bbcc86e8248f3ee5a4a6a4a99866998cfee533f2d9513dab27149b7e.bin",
            "./tests/e1232346710e1c81b6870b86d930d5c5947970ec414fd8f16d185ca9baa69eeb.bin",
            "./tests/1e5ef65076906af30ca4def787ab919264abc3c6f958a569657575791bec9391.bin",
            "./tests/4467bfa96ee342b099f7be0685a093425062d19d9475264ff2fb701d350ebfae.bin",
            "./tests/8a2ebfc747c6bb0e83cd4be7e92990cf56b02fb3be0f0b56bba6fda94bb49af0.bin",
            "./tests/c3f6cc3d1691a23eb423ca7f33829f7f15bbdb5c39095b83b88f76827975a25e.bin",
        ];
        for testcase in testcases {
            println!("test: {testcase}");

            let mut f = BufReader::new(File::open(testcase)?);
            let mut bytes = Vec::default();
            f.read_to_end(&mut bytes)?;

            let pfs = DellPfs::parse(&bytes)?;

            for (name, data) in pfs.data() {
                println!(
                    "name: {name:?}, data size: {} MiB",
                    data.len() / 1024 / 1024
                );
            }
        }
        Ok(())
    }
}
