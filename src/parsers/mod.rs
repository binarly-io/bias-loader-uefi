use std::borrow::Cow;
use std::ops::Range;

use thiserror::Error;

pub mod pfat;
pub mod pfs;

use super::UefiError;

const MAGIC_SIZE: usize = 8;

const PFS_MAGIC: &'static [u8; MAGIC_SIZE] = b"PFS.HDR.";

const PFAT_MAGIC: &'static [u8; MAGIC_SIZE] = b"_AMIPFAT";
const PFAT_MAGIC_OFFSET: usize = 8;
const PFAT_MAGIC_RANGE: Range<usize> = PFAT_MAGIC_OFFSET..PFAT_MAGIC_OFFSET + MAGIC_SIZE;

#[derive(Debug, Error)]
pub enum UnpackError {
    #[error(transparent)]
    Pfat(#[from] pfat::PfatError),
    #[error(transparent)]
    Pfs(#[from] pfs::DellPfsError),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Hint {
    Pfat,
    Pfs,
    Unknown,
}

impl Hint {
    pub fn parse(bytes: &[u8]) -> Self {
        let size = bytes.len();

        if size >= PFAT_MAGIC_RANGE.end {
            let bytes = &bytes[PFAT_MAGIC_RANGE];
            if bytes == PFAT_MAGIC {
                return Self::Pfat;
            }
        }

        if pfs::DellPfs::is_dell_pfs(bytes) {
            return Self::Pfs;
        }

        Self::Unknown
    }
}

pub fn try_unpack<'a>(bytes: &'a [u8]) -> Result<Cow<'a, [u8]>, UefiError> {
    Ok(match Hint::parse(bytes) {
        Hint::Pfat => Cow::Owned(
            pfat::Pfat::parse(bytes)
                .map_err(UnpackError::from)?
                .into_data(),
        ),
        Hint::Pfs => Cow::Owned(
            pfs::DellPfs::parse(bytes)
                .map_err(UnpackError::from)?
                .into_data()
                .into_iter()
                .next()
                .unwrap()
                .1,
        ),
        Hint::Unknown => Cow::Borrowed(bytes),
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ParsedImage<'a> {
    name: Cow<'a, str>,
    bytes: Cow<'a, [u8]>,
}

impl<'a> From<Cow<'a, [u8]>> for ParsedImage<'a> {
    fn from(bytes: Cow<'a, [u8]>) -> Self {
        Self::new("default", bytes)
    }
}

impl<'a> From<Vec<u8>> for ParsedImage<'a> {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from(Cow::Owned(bytes))
    }
}

impl<'a> From<&'a [u8]> for ParsedImage<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self::from(Cow::Borrowed(bytes))
    }
}

impl<'a> ParsedImage<'a> {
    #[inline]
    pub fn new(name: impl Into<Cow<'a, str>>, bytes: impl Into<Cow<'a, [u8]>>) -> Self {
        Self {
            name: name.into(),
            bytes: bytes.into(),
        }
    }

    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Vec<Self>, UefiError> {
        Self::from_bytes_with(bytes, |i, name, _| {
            if let Some(name) = name {
                name
            } else {
                format!("pfs{i}")
            }
            .into()
        })
    }

    #[inline]
    pub fn from_bytes_with(
        bytes: &'a [u8],
        name_of: impl Fn(usize, Option<String>, &[u8]) -> Cow<'a, str>,
    ) -> Result<Vec<Self>, UefiError> {
        let parsed = match Hint::parse(bytes) {
            Hint::Pfat => vec![pfat::Pfat::parse(bytes)
                .map_err(UnpackError::from)?
                .into_data()
                .into()],
            Hint::Pfs => pfs::DellPfs::parse_many(bytes)
                .map_err(UnpackError::from)?
                .into_data()
                .into_iter()
                .enumerate()
                .map(|(i, (sname, pfs))| Self::new(name_of(i, sname, &pfs), pfs))
                .collect(),
            Hint::Unknown => vec![bytes.into()],
        };

        Ok(parsed)
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::{BufReader, Read};

    use super::*;

    #[test]
    fn test_multiple() -> Result<(), Box<dyn std::error::Error>> {
        let image = "./tests/Latitude_5430_1.6.1_v98.5.5.bin";
        let mut f = BufReader::new(File::open(image)?);
        let mut bytes = Vec::default();
        f.read_to_end(&mut bytes)?;

        let parsed = ParsedImage::from_bytes_with(&bytes, |_, name, _| {
            if let Some(name) = name {
                name.into()
            } else {
                "Lattitude 5430 v1.6.1".into()
            }
        })?;

        assert_eq!(parsed.len(), 2);

        for p in parsed.iter() {
            println!("{}", p.name());
        }

        Ok(())
    }
}
