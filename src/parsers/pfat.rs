use std::io::BufRead;

use scroll::ctx::SizeWith;
use scroll::{IOread, Pread, SizeWith};

use thiserror::Error;

use super::PFAT_MAGIC;

#[derive(Debug, Error)]
pub enum PfatError {
    #[error(transparent)]
    Parse(#[from] scroll::Error),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid entry: {0}")]
    InvalidEntry(&'static str),
    #[error("invalid header: {0}")]
    InvalidHeader(&'static str),
    #[error("invalid file index: {0}")]
    InvalidFileIndex(usize),
}

#[derive(Pread, IOread, SizeWith)]
#[repr(C, packed)]
pub struct AmiBiosGuardHeader {
    size: u32,
    checksum: u32,
    tag: [u8; 8],
    flags: u8,
}

impl AmiBiosGuardHeader {
    pub fn size(&self) -> usize {
        self.size as usize
    }
}

#[derive(Pread, IOread, SizeWith)]
#[repr(C, packed)]
pub struct IntelBiosGuardHeader {
    pub bg_ver_major: u16,
    pub bg_ver_minor: u16,
    pub platform_id: [u8; 16],
    pub attributes: u32,
    pub script_ver_major: u16,
    pub script_ver_minor: u16,
    pub script_size: u32,
    pub data_size: u32,
    pub biossvn: u32,
    pub ecsvn: u32,
    pub vendor_info: u32,
}

impl IntelBiosGuardHeader {
    pub fn data_size(&self) -> usize {
        self.data_size as usize
    }

    pub fn script_size(&self) -> usize {
        self.script_size as usize
    }

    pub fn is_sfam(&self) -> bool {
        (self.attributes & 1) != 0
    }
}

#[derive(Pread, IOread, SizeWith)]
#[repr(C, packed)]
pub struct IntelBiosGuardSignature2k {
    unknown0: u32,
    unknown1: u32,
    modulus: [u32; 64],
    exponent: u32,
    signature: [u32; 64],
}

#[derive(Debug, Clone)]
pub struct PfatEntry {
    name: String,
    param: String,
    flags: u32,
    count: usize,
    file_index: usize,
    block_index: usize,
}

impl PfatEntry {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn param(&self) -> &str {
        &self.param
    }

    pub fn flags(&self) -> u32 {
        self.flags
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn file_index(&self) -> usize {
        self.file_index
    }

    pub fn block_index(&self) -> usize {
        self.block_index
    }

    pub fn parse_into(
        index: usize,
        entry: &str,
        entries: &mut Vec<PfatEntry>,
    ) -> Result<(), PfatError> {
        let mut entry_parts = entry.split(";");
        let mut info_parts = entry_parts
            .next()
            .ok_or_else(|| PfatError::InvalidEntry("could not parse information"))?
            .split_whitespace();
        let name = entry_parts
            .next()
            .ok_or_else(|| PfatError::InvalidEntry("could not parse name"))?;
        let flags = info_parts
            .next()
            .and_then(|part| part.parse::<u32>().ok())
            .ok_or_else(|| PfatError::InvalidEntry("could not parse flags"))?;
        let param = info_parts
            .next()
            .ok_or_else(|| PfatError::InvalidEntry("could not parse param"))?;
        let count = info_parts
            .next()
            .and_then(|part| part.parse::<usize>().ok())
            .ok_or_else(|| PfatError::InvalidEntry("could not parse count"))?;

        // set a limit for the number of PfatEntry elements per file to avoid OOM
        if count > 1024 {
            return Err(PfatError::InvalidEntry("too much PfatEntry elements"));
        }

        for i in 0..count {
            entries.push(Self {
                name: name.to_owned(),
                param: param.to_owned(),
                flags,
                count,
                file_index: index,
                block_index: i,
            });
        }

        Ok(())
    }
}

pub struct Pfat {
    bg_header: AmiBiosGuardHeader,
    entries: Vec<PfatEntry>,
    data: Vec<u8>,
}

impl Pfat {
    pub fn header(&self) -> &AmiBiosGuardHeader {
        &self.bg_header
    }

    pub fn entries(&self) -> &[PfatEntry] {
        &self.entries
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, PfatError> {
        let mut offset = 0;
        let bg_header = bytes.gread_with::<AmiBiosGuardHeader>(&mut offset, scroll::LE)?;
        let size = bg_header.size();

        if &bg_header.tag != PFAT_MAGIC {
            return Err(PfatError::InvalidSignature);
        }

        if bytes.len() < size || size <= offset {
            return Err(PfatError::InvalidHeader("buffer is less than size"));
        }

        let data = &bytes[offset..size];
        let meta = data
            .lines()
            .collect::<Result<Vec<String>, _>>()
            .map_err(|_| PfatError::InvalidHeader("could not parse file entries"))?;

        if meta.len() <= 1 {
            return Err(PfatError::InvalidHeader("no file entries"));
        }

        if meta.len() > 1024 {
            return Err(PfatError::InvalidHeader("too much file entries"));
        }

        let files = &meta[1..];
        let mut entries = Vec::new();

        for (i, entry) in files.iter().enumerate() {
            PfatEntry::parse_into(i, entry, &mut entries)?;
        }

        let mut blocks: Vec<Vec<u8>> = Vec::new();
        offset = size;

        for entry in entries.iter() {
            if entry.block_index == 0 {
                if let Some(nindex) = entry.file_index.checked_add(1) {
                    blocks.resize_with(nindex, Vec::default);
                } else {
                    return Err(PfatError::InvalidFileIndex(entry.file_index));
                }
            }

            let header = bytes.gread_with::<IntelBiosGuardHeader>(&mut offset, scroll::LE)?;
            let bg_script_offset = offset;
            let bg_script_end = bg_script_offset
                .checked_add(header.script_size())
                .ok_or_else(|| PfatError::InvalidEntry("invalid script size"))?;

            if bytes.len() < bg_script_end {
                return Err(PfatError::InvalidEntry("invalid script size"));
            }

            // let bg_script_bytes = &bytes[bg_script_offset..bg_script_end];

            let bg_data_offset = bg_script_end;
            let bg_data_end = bg_data_offset
                .checked_add(header.data_size())
                .ok_or_else(|| PfatError::InvalidEntry("invalid data size"))?;

            if bytes.len() < bg_data_end {
                return Err(PfatError::InvalidEntry("invalid data size"));
            }

            let bg_data_bytes = &bytes[bg_data_offset..bg_data_end];

            if header.is_sfam() {
                offset = bg_data_end + IntelBiosGuardSignature2k::size_with(&scroll::LE);
            } else {
                offset = bg_data_end;
            }

            blocks[entry.file_index].extend(bg_data_bytes);
        }

        let oob_data = if offset < bytes.len() {
            &bytes[offset..]
        } else {
            &[]
        };

        let data = blocks
            .iter()
            .map(|bytes| bytes.as_ref())
            .chain(std::iter::once(oob_data))
            .flatten()
            .copied()
            .collect::<Vec<u8>>();

        Ok(Self {
            bg_header,
            entries,
            data,
        })
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::BufReader;
    use std::io::Read;

    use super::*;

    #[test]
    fn test_unpack() -> Result<(), Box<dyn std::error::Error>> {
        let mut f = BufReader::new(File::open("./tests/M2TKT2DA.cap")?);
        let mut bytes = Vec::default();
        f.read_to_end(&mut bytes)?;

        let pfat = Pfat::parse(&bytes)?;

        assert!(pfat.data().len() > 0);

        // unpacked already
        let mut f = BufReader::new(File::open("./tests/M2TKT2DA.bin")?);

        bytes.clear();
        f.read_to_end(&mut bytes)?;

        assert_eq!(bytes, pfat.data());

        Ok(())
    }
}
