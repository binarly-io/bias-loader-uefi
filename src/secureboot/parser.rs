use std::fmt;

use scroll::{ctx, Pread};
use uuid::Uuid;

use super::auth::EfiGuid;

pub struct EfiSignatureDatabase<'a> {
    offset: usize,
    bytes: &'a [u8],
}

impl<'a> EfiSignatureDatabase<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { offset: 0, bytes }
    }
}

impl<'a> Iterator for EfiSignatureDatabase<'a> {
    type Item = EfiSignatureList<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let efi_signature_list = EfiSignatureList::new(self.bytes.get(self.offset..)?).ok()?;

        if efi_signature_list.header.signature_header_size != 0 {
            // For now we support only headers with signature_header_size == 0.
            return None;
        }

        self.offset = self
            .offset
            .checked_add(efi_signature_list.header.signature_list_size as usize)?;

        Some(efi_signature_list)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(C)]
pub struct EfiSignatureListHeader {
    pub signature_type: Uuid,
    pub signature_list_size: u32,
    pub signature_header_size: u32,
    pub signature_size: u32,
}

impl<'a> ctx::TryFromCtx<'a, scroll::Endian> for EfiSignatureListHeader {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: scroll::Endian) -> Result<(Self, usize), Self::Error> {
        let mut offset = 0usize;
        let signature_type = from.gread_with::<EfiGuid>(&mut offset, ctx)?;
        let signature_list_size = from.gread_with::<u32>(&mut offset, ctx)?;
        let signature_header_size = from.gread_with::<u32>(&mut offset, ctx)?;
        let signature_size = from.gread_with::<u32>(&mut offset, ctx)?;

        Ok((
            Self {
                signature_type: signature_type.0,
                signature_list_size,
                signature_header_size,
                signature_size,
            },
            offset,
        ))
    }
}

// TODO: Implement FromCtx for EfiSignatureListHeader so to skip the header based on the signature_header_size
const SIZE_OF_EFI_SIGNATURE_LIST: u32 = 28;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct EfiSignatureList<'a> {
    pub offset: usize,
    pub bytes: &'a [u8],
    pub cert_count: u32,
    pub header: EfiSignatureListHeader,
}

impl<'a> EfiSignatureList<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self, scroll::Error> {
        let mut offset = 0;
        let header = bytes.gread_with::<EfiSignatureListHeader>(&mut offset, scroll::LE)?;

        Self::new_with_header(
            bytes
                .get(offset..)
                .ok_or(scroll::Error::BadOffset(offset))?,
            header,
        )
        .ok_or(scroll::Error::BadInput {
            size: bytes.len(),
            msg: "invalid header",
        })
    }

    pub fn new_with_header(bytes: &'a [u8], header: EfiSignatureListHeader) -> Option<Self> {
        let cert_count = (header
            .signature_list_size
            .checked_sub(SIZE_OF_EFI_SIGNATURE_LIST)?
            .checked_sub(header.signature_header_size)?)
        .checked_div(header.signature_size)?;

        Some(EfiSignatureList {
            offset: 0,
            bytes,
            cert_count,
            header,
        })
    }
}

impl<'a> Iterator for EfiSignatureList<'a> {
    type Item = EfiSignatureData<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cert_count == 0 {
            return None;
        }

        // check signature_size to make sure that noffset is greater than offset
        if self.header.signature_size == 0 {
            return None;
        }

        let noffset = self.offset.checked_add(self.header.signature_size as _)?;

        let efi_signature_data =
            EfiSignatureData::new(self.bytes.get(self.offset..noffset)?).ok()?;

        self.offset = noffset;
        self.cert_count -= 1;

        Some(efi_signature_data)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct EfiSignatureData<'a> {
    pub signature_owner: Uuid,
    pub signature_data: &'a [u8],
}

impl<'a> EfiSignatureData<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<EfiSignatureData<'a>, scroll::Error> {
        let mut offset = 0;
        let signature_owner = bytes.gread_with::<EfiGuid>(&mut offset, scroll::LE)?;

        Ok(Self::new_with_owner(
            bytes
                .get(offset..)
                .ok_or(scroll::Error::BadOffset(offset))?,
            signature_owner.0,
        ))
    }

    pub fn new_with_owner(signature_data: &'a [u8], signature_owner: Uuid) -> EfiSignatureData<'a> {
        EfiSignatureData {
            signature_owner,
            signature_data,
        }
    }
}

impl<'a> fmt::Display for EfiSignatureData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{owner: {} data: {:?}...}}",
            self.signature_owner,
            self.signature_data.get(..16)
        )
    }
}
