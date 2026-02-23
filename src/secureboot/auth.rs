use goblin::pe::certificate_table::AttributeCertificateHeader;
use scroll::{ctx, Pread};
use uuid::Uuid;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct EfiGuid(pub(crate) Uuid);

impl<'a> ctx::TryFromCtx<'a, scroll::Endian> for EfiGuid {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: scroll::Endian) -> Result<(Self, usize), Self::Error> {
        let mut offset = 0usize;
        let mut tmp = [0; 16];

        from.gread_inout_with(&mut offset, &mut tmp, ctx)?;

        Ok((Self(Uuid::from_bytes_le(tmp)), offset))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Pread)]
#[repr(C)]
pub struct EfiTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub pad1: u8,
    pub nanosecond: u32,
    pub timezone: u16,
    pub daylight: u8,
    pub pad2: u8,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct EfiVariableAuthentication2<'a> {
    time: EfiTime,
    auth_info: WinCertificateUefiGuid<'a>,
}

impl<'a> ctx::TryFromCtx<'a, scroll::Endian> for EfiVariableAuthentication2<'a> {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: scroll::Endian) -> Result<(Self, usize), Self::Error> {
        let mut offset = 0usize;
        let time = from.gread_with::<EfiTime>(&mut offset, ctx)?;
        let auth_info = from.gread_with::<WinCertificateUefiGuid<'a>>(&mut offset, ctx)?;

        Ok((Self { time, auth_info }, offset))
    }
}

#[derive(Debug, Clone, PartialEq, Pread)]
#[repr(C)]
pub struct HpEfiVariableAuthentication {
    time: EfiTime,
    header: AttributeCertificateHeader,
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct WinCertificateUefiGuid<'a> {
    pub header: AttributeCertificateHeader,
    pub cert_type: Uuid,
    pub bytes: &'a [u8],
}

impl<'a> ctx::TryFromCtx<'a, scroll::Endian> for WinCertificateUefiGuid<'a> {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: scroll::Endian) -> Result<(Self, usize), Self::Error> {
        let mut offset = 0usize;
        let header = from.gread_with::<AttributeCertificateHeader>(&mut offset, ctx)?;
        let cert_type = from.gread_with::<EfiGuid>(&mut offset, ctx)?;

        let noffset = (header.length as usize)
            .checked_sub(offset)
            .ok_or_else(|| {
                scroll::Error::Custom(format!(
                    "dw_length field in certificate header is smaller than header size: {} < {}",
                    header.length, offset
                ))
            })?;

        let bytes = from.gread_with::<&'a [u8]>(&mut offset, noffset)?;
        let cert = Self {
            header,
            cert_type: cert_type.0,
            bytes,
        };
        Ok((cert, offset))
    }
}
