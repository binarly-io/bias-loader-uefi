use std::borrow::Cow;
use std::ffi::CStr;
use std::fmt::Display;
use std::os::raw::c_char;
use std::ptr::slice_from_raw_parts;

use self_cell::self_cell;
use thiserror::Error;
use uuid::Uuid;

use serde_with::{As, BorrowCow};

pub mod depex;
use depex::DepExOpcode;

pub mod secureboot;

pub mod parsers;
pub use parsers::{try_unpack, ParsedImage};

pub const INVALID_GUID: &'static str = "00000000-0000-0000-0000-000000000000";

#[cxx::bridge(namespace = "efiloader")]
mod ffi {
    unsafe extern "C++" {
        include!("bias-loader-uefi/cxx/uefitool.h");

        type Uefitool<'a>;

        unsafe fn uefitool_new<'a>(
            buffer: *const u8,
            size: usize,
        ) -> Result<UniquePtr<Uefitool<'a>>>;

        fn uefitool_dump<'a>(x: &mut UniquePtr<Uefitool<'a>>) -> Result<()>;

        unsafe fn uefitool_for_each_module<'a>(
            x: &UniquePtr<Uefitool<'a>>,
            cb: *mut c_char,
            ud: *mut c_char,
        );
        unsafe fn uefitool_count_modules<'a>(x: &UniquePtr<Uefitool<'a>>) -> usize;

        unsafe fn uefitool_for_each_raw_section<'a>(
            x: &UniquePtr<Uefitool<'a>>,
            cb: *mut c_char,
            ud: *mut c_char,
        );
        unsafe fn uefitool_count_raw_sections<'a>(x: &UniquePtr<Uefitool<'a>>) -> usize;

        unsafe fn uefitool_for_each_nvram<'a>(
            x: &UniquePtr<Uefitool<'a>>,
            cb: *mut c_char,
            ud: *mut c_char,
        );
        unsafe fn uefitool_count_nvram<'a>(x: &UniquePtr<Uefitool<'a>>) -> usize;

        unsafe fn uefitool_for_each_microcode<'a>(
            x: &UniquePtr<Uefitool<'a>>,
            cb: *mut c_char,
            ud: *mut c_char,
        );
        unsafe fn uefitool_count_microcode<'a>(x: &UniquePtr<Uefitool<'a>>) -> usize;

        unsafe fn uefitool_for_each_guid_defined_section<'a>(
            x: &UniquePtr<Uefitool<'a>>,
            cb: *mut c_char,
            ud: *mut c_char,
        );
        unsafe fn uefitool_count_guid_defined_sections<'a>(x: &UniquePtr<Uefitool<'a>>) -> usize;
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub enum UefiModuleType {
    #[serde(alias = "raw")]
    Raw,
    #[serde(alias = "freeform")]
    Freeform,
    #[serde(alias = "sec.core", alias = "sec-core")]
    SecCore,
    #[serde(alias = "pei.core", alias = "pei-core")]
    PeiCore,
    #[serde(alias = "dxe.core", alias = "dxe-core")]
    DxeCore,
    #[serde(alias = "pei.module", alias = "pei-module")]
    PeiModule,
    #[serde(
        alias = "dxe.driver",
        alias = "dxe-driver",
        alias = "dxe.module",
        alias = "dxe-module"
    )]
    DxeDriver,
    #[serde(alias = "combined.pei.dxe", alias = "combined-pei-dxe")]
    CombinedPeiDxe,
    #[serde(alias = "application")]
    Application,
    #[serde(alias = "smm.module", alias = "smm-module")]
    SmmModule,
    #[serde(alias = "volume.image", alias = "volume-image")]
    VolumeImage,
    #[serde(alias = "combined.smm.dxe", alias = "combined-smm-dxe")]
    CombinedSmmDxe,
    #[serde(alias = "smm.core", alias = "smm-core")]
    SmmCore,
    #[serde(
        alias = "smm.standalone",
        alias = "smm-standalone",
        alias = "smm.standalone.module",
        alias = "smm-standalone-module"
    )]
    SmmStandaloneModule,
    #[serde(alias = "smm.standalone.core", alias = "smm-standalone-core")]
    SmmStandaloneCore,
    #[serde(alias = "oem")]
    Oem(u8),
    #[serde(alias = "debug")]
    Debug(u8),
    #[serde(alias = "pad")]
    Pad,
    #[serde(alias = "ffs")]
    Ffs(u8),
    #[serde(alias = "unknown")]
    Unknown,
}

impl UefiModuleType {
    pub fn is_pei(&self) -> bool {
        matches!(self, Self::PeiCore | Self::PeiModule | Self::CombinedPeiDxe)
    }

    pub fn is_dxe(&self) -> bool {
        matches!(
            self,
            Self::DxeCore
                | Self::CombinedPeiDxe
                | Self::CombinedSmmDxe
                | Self::DxeDriver
                | Self::Application
        )
    }

    pub fn is_smm(&self) -> bool {
        matches!(
            self,
            Self::SmmModule
                | Self::CombinedSmmDxe
                | Self::SmmCore
                | Self::SmmStandaloneModule
                | Self::SmmStandaloneCore
        )
    }
}

impl Default for UefiModuleType {
    fn default() -> Self {
        Self::Unknown
    }
}

impl From<u8> for UefiModuleType {
    fn from(ft: u8) -> Self {
        match ft {
            0x01 => Self::Raw,
            0x02 => Self::Freeform,
            0x03 => Self::SecCore,
            0x04 => Self::PeiCore,
            0x05 => Self::DxeCore,
            0x06 => Self::PeiModule,
            0x07 => Self::DxeDriver,
            0x08 => Self::CombinedPeiDxe,
            0x09 => Self::Application,
            0x0a => Self::SmmModule,
            0x0b => Self::VolumeImage,
            0x0c => Self::CombinedSmmDxe,
            0x0d => Self::SmmCore,
            0x0e => Self::SmmStandaloneModule,
            0x0f => Self::SmmStandaloneCore,
            0xc0..=0xdf => Self::Oem(ft),
            0xe0..=0xef => Self::Debug(ft),
            0xf0 => Self::Pad,
            0xf1..=0xff => Self::Ffs(ft),
            _ => Self::Unknown,
        }
    }
}

impl From<UefiModuleType> for u8 {
    fn from(t: UefiModuleType) -> Self {
        match t {
            UefiModuleType::Raw => 0x01,
            UefiModuleType::Freeform => 0x02,
            UefiModuleType::SecCore => 0x03,
            UefiModuleType::PeiCore => 0x04,
            UefiModuleType::DxeCore => 0x05,
            UefiModuleType::PeiModule => 0x06,
            UefiModuleType::DxeDriver => 0x07,
            UefiModuleType::CombinedPeiDxe => 0x08,
            UefiModuleType::Application => 0x09,
            UefiModuleType::SmmModule => 0x0a,
            UefiModuleType::VolumeImage => 0x0b,
            UefiModuleType::CombinedSmmDxe => 0x0c,
            UefiModuleType::SmmCore => 0x0d,
            UefiModuleType::SmmStandaloneModule => 0x0e,
            UefiModuleType::SmmStandaloneCore => 0x0f,
            UefiModuleType::Oem(ft) => ft,
            UefiModuleType::Debug(ft) => ft,
            UefiModuleType::Pad => 0xf0,
            UefiModuleType::Ffs(ft) => ft,
            UefiModuleType::Unknown => 0x00,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct UefiModule<'a> {
    #[serde(borrow)]
    #[serde(with = "As::<BorrowCow>")]
    name: Cow<'a, str>,
    #[serde(borrow)]
    #[serde(with = "As::<BorrowCow>")]
    real_name: Cow<'a, str>,
    #[serde(borrow)]
    #[serde(with = "As::<Option<BorrowCow>>")]
    guid: Option<Cow<'a, str>>,
    module_type: UefiModuleType,
    is_pe: bool,
    is_te: bool,
    has_ui: bool,
    is_duplicate: bool,
    depex: Vec<DepExOpcode>,
    #[serde(borrow)]
    #[serde(with = "As::<BorrowCow>")]
    bytes: Cow<'a, [u8]>,
}

pub type UefiData<'a> = UefiModule<'a>;
pub type UefiSectionType = UefiModuleType;

impl<'a> UefiModule<'a> {
    pub fn new(
        name: impl Into<Cow<'a, str>>,
        guid: Option<impl Into<Cow<'a, str>>>,
        module_type: impl Into<UefiModuleType>,
        is_pe: bool,
        is_te: bool,
        has_ui: bool,
        depex: Vec<DepExOpcode>,
        bytes: impl Into<Cow<'a, [u8]>>,
    ) -> Self {
        let name = name.into();
        Self::new_with(
            name.clone(),
            name,
            guid,
            module_type,
            is_pe,
            is_te,
            has_ui,
            false,
            depex,
            bytes,
        )
    }

    pub fn new_with(
        name: impl Into<Cow<'a, str>>,
        real_name: impl Into<Cow<'a, str>>,
        guid: Option<impl Into<Cow<'a, str>>>,
        module_type: impl Into<UefiModuleType>,
        is_pe: bool,
        is_te: bool,
        has_ui: bool,
        is_duplicate: bool,
        depex: Vec<DepExOpcode>,
        bytes: impl Into<Cow<'a, [u8]>>,
    ) -> Self {
        Self {
            name: name.into(),
            real_name: real_name.into(),
            guid: guid.map(|g| g.into()),
            module_type: module_type.into(),
            is_pe,
            is_te,
            has_ui,
            is_duplicate,
            depex,
            bytes: bytes.into(),
        }
    }

    pub fn name(&self) -> &str {
        &*self.name
    }

    pub fn real_name(&self) -> &str {
        &*self.real_name
    }

    pub fn guid(&self) -> &str {
        self.guid.as_deref().unwrap_or(INVALID_GUID)
    }

    pub fn has_valid_guid(&self) -> bool {
        self.guid.is_some()
    }

    pub fn module_type(&self) -> UefiModuleType {
        self.module_type
    }

    pub fn section_type(&self) -> UefiSectionType {
        self.module_type
    }

    pub fn is_pe(&self) -> bool {
        self.is_pe
    }

    pub fn is_te(&self) -> bool {
        self.is_te
    }

    pub fn has_ui(&self) -> bool {
        self.has_ui
    }

    pub fn is_duplicate(&self) -> bool {
        self.is_duplicate
    }

    pub fn depex(&self) -> &[DepExOpcode] {
        &*self.depex
    }

    pub fn bytes(&self) -> &[u8] {
        &*self.bytes
    }

    pub fn into_owned(self) -> UefiModule<'static> {
        UefiModule {
            name: self.name.into_owned().into(),
            real_name: self.real_name.into_owned().into(),
            guid: self.guid.map(|g| g.into_owned().into()),
            module_type: self.module_type,
            is_pe: self.is_pe,
            is_te: self.is_te,
            has_ui: self.has_ui,
            is_duplicate: self.is_duplicate,
            depex: self.depex,
            bytes: self.bytes.into_owned().into(),
        }
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum UefiNvramVarType {
    Nvar,
    Vss,
    Evsa,
    Unknown,
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum UefiNvramVarSubType {
    InvalidNvar,
    InvalidNvarLink,
    LinkNvar,
    DataNvar,
    FullNvar,

    InvalidVss,
    StandardVss,
    AppleVss,
    AuthVss,
    IntelVss,

    InvalidEvsa,
    UnknownEvsa,
    GuidEvsa,
    NameEvsa,
    DataEvsa,

    Unknown,
}

impl From<u8> for UefiNvramVarType {
    fn from(t: u8) -> Self {
        match t {
            0x00 => Self::Nvar,
            0x01 => Self::Vss,
            0x02 => Self::Evsa,
            _ => Self::Unknown,
        }
    }
}

impl From<u8> for UefiNvramVarSubType {
    fn from(t: u8) -> Self {
        match t {
            130 => Self::InvalidNvar,
            131 => Self::InvalidNvarLink,
            132 => Self::LinkNvar,
            133 => Self::DataNvar,
            134 => Self::FullNvar,

            140 => Self::InvalidVss,
            141 => Self::StandardVss,
            142 => Self::AppleVss,
            143 => Self::AuthVss,
            144 => Self::IntelVss,

            160 => Self::InvalidEvsa,
            161 => Self::UnknownEvsa,
            162 => Self::GuidEvsa,
            163 => Self::NameEvsa,
            164 => Self::DataEvsa,

            _ => Self::Unknown,
        }
    }
}

impl From<UefiNvramVarType> for u8 {
    fn from(t: UefiNvramVarType) -> u8 {
        match t {
            UefiNvramVarType::Nvar => 0x00,
            UefiNvramVarType::Vss => 0x01,
            UefiNvramVarType::Evsa => 0x02,
            UefiNvramVarType::Unknown => 0xff,
        }
    }
}

impl From<UefiNvramVarSubType> for u8 {
    fn from(t: UefiNvramVarSubType) -> u8 {
        match t {
            UefiNvramVarSubType::InvalidNvar => 130,
            UefiNvramVarSubType::InvalidNvarLink => 131,
            UefiNvramVarSubType::LinkNvar => 132,
            UefiNvramVarSubType::DataNvar => 133,
            UefiNvramVarSubType::FullNvar => 134,

            UefiNvramVarSubType::InvalidVss => 140,
            UefiNvramVarSubType::StandardVss => 141,
            UefiNvramVarSubType::AppleVss => 142,
            UefiNvramVarSubType::AuthVss => 143,
            UefiNvramVarSubType::IntelVss => 144,

            UefiNvramVarSubType::InvalidEvsa => 160,
            UefiNvramVarSubType::UnknownEvsa => 161,
            UefiNvramVarSubType::GuidEvsa => 162,
            UefiNvramVarSubType::NameEvsa => 163,
            UefiNvramVarSubType::DataEvsa => 164,

            UefiNvramVarSubType::Unknown => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct UefiNvramVar<'a> {
    #[serde(borrow)]
    #[serde(with = "As::<BorrowCow>")]
    name: Cow<'a, str>,
    #[serde(borrow)]
    #[serde(with = "As::<Option<BorrowCow>>")]
    guid: Option<Cow<'a, str>>,
    var_type: UefiNvramVarType,
    var_subtype: UefiNvramVarSubType,
    attrs: u32,
    ext_attrs: u8,
    state: u8,
    #[serde(borrow)]
    #[serde(with = "As::<BorrowCow>")]
    data: Cow<'a, [u8]>,
}

impl<'a> UefiNvramVar<'a> {
    pub fn new(
        name: impl Into<Cow<'a, str>>,
        guid: Option<impl Into<Cow<'a, str>>>,
        var_type: impl Into<UefiNvramVarType>,
        var_subtype: u8,
        attrs: u32,
        ext_attrs: u8,
        state: u8,
        data: impl Into<Cow<'a, [u8]>>,
    ) -> Self {
        Self {
            name: name.into(),
            guid: guid.map(|g| g.into()),
            var_type: var_type.into(),
            var_subtype: var_subtype.into(),
            attrs,
            ext_attrs,
            state,
            data: data.into(),
        }
    }

    pub fn name(&self) -> &str {
        &*self.name
    }

    pub fn guid(&self) -> &str {
        self.guid.as_deref().unwrap_or(INVALID_GUID)
    }

    pub fn has_valid_guid(&self) -> bool {
        self.guid.is_some()
    }

    pub fn var_type(&self) -> UefiNvramVarType {
        self.var_type
    }

    pub fn var_subtype(&self) -> UefiNvramVarSubType {
        self.var_subtype
    }

    pub fn attributes(&self) -> u32 {
        self.attrs
    }

    pub fn is_runtime(&self) -> bool {
        match self.var_type {
            UefiNvramVarType::Nvar => (self.attrs & 0x01) != 0,
            UefiNvramVarType::Vss => (self.attrs & 0x04) != 0,
            UefiNvramVarType::Evsa => (self.attrs & 0x04) != 0,
            _ => false,
        }
    }

    pub fn is_boot_service(&self) -> bool {
        match self.var_type {
            UefiNvramVarType::Vss => (self.attrs & 0x02) != 0,
            UefiNvramVarType::Evsa => (self.attrs & 0x02) != 0,
            _ => false,
        }
    }

    pub fn is_non_volatile(&self) -> bool {
        match self.var_type {
            UefiNvramVarType::Vss => (self.attrs & 0x01) != 0,
            UefiNvramVarType::Evsa => (self.attrs & 0x01) != 0,
            _ => false,
        }
    }

    pub fn is_auth_write(&self) -> bool {
        match self.var_type {
            UefiNvramVarType::Nvar => (self.attrs & 0x40) != 0 || (self.ext_attrs & 0x10) != 0,
            UefiNvramVarType::Vss => (self.attrs & 0x10) != 0,
            UefiNvramVarType::Evsa => (self.attrs & 0x10) != 0,
            _ => false,
        }
    }

    pub fn is_time_based_auth_write(&self) -> bool {
        match self.var_type {
            UefiNvramVarType::Nvar => (self.ext_attrs & 0x20) != 0,
            UefiNvramVarType::Vss => (self.attrs & 0x20) != 0,
            UefiNvramVarType::Evsa => (self.attrs & 0x20) != 0,
            _ => false,
        }
    }

    pub fn is_invalid(&self) -> bool {
        match self.var_subtype {
            UefiNvramVarSubType::InvalidNvar
            | UefiNvramVarSubType::InvalidNvarLink
            | UefiNvramVarSubType::InvalidVss
            | UefiNvramVarSubType::InvalidEvsa => true,
            _ => false,
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.is_invalid()
    }

    pub fn is_added(&self) -> bool {
        self.var_type == UefiNvramVarType::Vss && (self.state & 0x3f) != 0
    }

    pub fn is_deleted(&self) -> bool {
        self.var_type == UefiNvramVarType::Vss && (self.state & 0xfd) != 0
    }

    pub fn is_in_deleted_transition(&self) -> bool {
        self.var_type == UefiNvramVarType::Vss && (self.state & 0xfe) != 0
    }

    pub fn data(&self) -> &[u8] {
        &*self.data
    }

    pub fn into_owned(self) -> UefiNvramVar<'static> {
        UefiNvramVar {
            name: self.name.into_owned().into(),
            guid: self.guid.map(|g| g.into_owned().into()),
            var_type: self.var_type,
            var_subtype: self.var_subtype,
            attrs: self.attrs,
            ext_attrs: self.ext_attrs,
            state: self.state,
            data: self.data.into_owned().into(),
        }
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[non_exhaustive]
pub enum UefiMicrocodeVendor {
    Intel,
    Amd,
}

impl UefiMicrocodeVendor {
    pub fn is_intel(&self) -> bool {
        matches!(self, Self::Intel)
    }

    pub fn is_amd(&self) -> bool {
        matches!(self, Self::Amd)
    }
}

impl TryFrom<u8> for UefiMicrocodeVendor {
    type Error = UefiError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x00 => Ok(Self::Intel),
            0x01 => Ok(Self::Amd),
            _ => Err(UefiError::Parse),
        }
    }
}

impl Display for UefiMicrocodeVendor {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            UefiMicrocodeVendor::Intel => write!(f, "Intel"),
            UefiMicrocodeVendor::Amd => write!(f, "AMD"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MicrocodeInfo<'a> {
    #[serde(borrow)]
    #[serde(with = "As::<BorrowCow>")]
    date: Cow<'a, str>,
    cpu_signature: u32,
    update_revision: u32,
    processor_flags: u8,
    vendor: UefiMicrocodeVendor,
}

impl<'a> MicrocodeInfo<'a> {
    fn new(
        date: impl Into<Cow<'a, str>>,
        cpu_signature: u32,
        update_revision: u32,
        processor_flags: u8,
        vendor: UefiMicrocodeVendor,
    ) -> Self {
        Self {
            date: date.into(),
            cpu_signature,
            update_revision,
            processor_flags,
            vendor,
        }
    }

    pub fn new_amd(
        date: impl Into<Cow<'a, str>>,
        cpu_signature: u32,
        update_revision: u32,
    ) -> Self {
        Self::new(
            date,
            cpu_signature,
            update_revision,
            0,
            UefiMicrocodeVendor::Amd,
        )
    }

    pub fn new_intel(
        date: impl Into<Cow<'a, str>>,
        cpu_signature: u32,
        update_revision: u32,
        processor_flags: u8,
    ) -> Self {
        Self::new(
            date,
            cpu_signature,
            update_revision,
            processor_flags,
            UefiMicrocodeVendor::Intel,
        )
    }

    pub fn vendor(&self) -> UefiMicrocodeVendor {
        self.vendor
    }

    pub fn date(&self) -> &str {
        &*self.date
    }

    pub fn cpu_signature(&self) -> u32 {
        self.cpu_signature
    }

    pub fn update_revision(&self) -> u32 {
        self.update_revision
    }

    pub fn processor_flags(&self) -> u8 {
        self.processor_flags
    }

    pub fn into_owned(self) -> MicrocodeInfo<'static> {
        MicrocodeInfo {
            date: self.date.into_owned().into(),
            cpu_signature: self.cpu_signature,
            update_revision: self.update_revision,
            processor_flags: self.processor_flags,
            vendor: self.vendor,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct UefiSection<'a> {
    #[serde(borrow)]
    #[serde(with = "As::<Option<BorrowCow>>")]
    guid: Option<Cow<'a, str>>,
}

impl<'a> UefiSection<'a> {
    pub fn new(guid: Option<impl Into<Cow<'a, str>>>) -> Self {
        Self {
            guid: guid.map(|g| g.into()),
        }
    }

    pub fn guid(&self) -> &str {
        self.guid.as_deref().unwrap_or(INVALID_GUID)
    }

    pub fn has_valid_guid(&self) -> bool {
        self.guid.is_some()
    }

    pub fn into_owned(self) -> UefiSection<'static> {
        UefiSection {
            guid: self.guid.map(|g| g.into_owned().into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub enum ContinueOrStop {
    Continue = 0,
    Stop = 1,
}

unsafe fn guid_from_ptr<'a>(guid: *const c_char) -> Option<Cow<'a, str>> {
    let guid = CStr::from_ptr(guid).to_string_lossy();
    if Uuid::parse_str(&guid).is_ok() {
        Some(guid)
    } else {
        None
    }
}

unsafe extern "C" fn module_trampoline<F>(
    closure: *mut c_char,
    name: *const c_char,
    real_name: *const c_char,
    guid: *const c_char,
    module_type: u8,
    is_pe: bool,
    is_te: bool,
    has_ui: bool,
    is_duplicate: bool,
    depex: *const u8,
    depex_size: usize,
    buffer: *const u8,
    buffer_size: usize,
) -> ContinueOrStop
where
    F: FnMut(UefiModule) -> ContinueOrStop,
{
    let name = CStr::from_ptr(name);
    let real_name = CStr::from_ptr(real_name);
    let guid = guid_from_ptr(guid);
    let bytes = slice_from_raw_parts(buffer, buffer_size).as_ref().unwrap();

    let depex_bytes = slice_from_raw_parts(depex, depex_size).as_ref().unwrap();
    let depex = DepExOpcode::parse_all(&depex_bytes).unwrap_or_default();

    let closure = &mut *(closure as *mut F);

    closure(UefiModule::new_with(
        name.to_string_lossy(),
        real_name.to_string_lossy(),
        guid,
        module_type,
        is_pe,
        is_te,
        has_ui,
        is_duplicate,
        depex,
        bytes,
    ))
}

fn get_module_trampoline<F>(
    _closure: &F,
) -> unsafe extern "C" fn(
    *mut c_char,
    *const c_char,
    *const c_char,
    *const c_char,
    u8,
    bool,
    bool,
    bool,
    bool,
    *const u8,
    usize,
    *const u8,
    usize,
) -> ContinueOrStop
where
    F: FnMut(UefiModule) -> ContinueOrStop,
{
    module_trampoline::<F>
}

unsafe extern "C" fn var_trampoline<F>(
    closure: *mut c_char,
    var_type: u8,
    var_subtype: u8,
    attrs: u32,
    ext_attrs: u8,
    state: u8,
    guid: *const c_char,
    name: *const c_char,
    data: *const u8,
    data_size: usize,
) -> ContinueOrStop
where
    F: FnMut(UefiNvramVar) -> ContinueOrStop,
{
    let name = CStr::from_ptr(name);
    let guid = guid_from_ptr(guid);
    let bytes = slice_from_raw_parts(data, data_size).as_ref().unwrap();
    let closure = &mut *(closure as *mut F);

    closure(UefiNvramVar::new(
        name.to_string_lossy(),
        guid,
        var_type,
        var_subtype,
        attrs,
        ext_attrs,
        state,
        bytes,
    ))
}

fn get_var_trampoline<F>(
    _closure: &F,
) -> unsafe extern "C" fn(
    *mut c_char,
    u8,
    u8,
    u32,
    u8,
    u8,
    *const c_char,
    *const c_char,
    *const u8,
    usize,
) -> ContinueOrStop
where
    F: FnMut(UefiNvramVar) -> ContinueOrStop,
{
    var_trampoline::<F>
}

unsafe extern "C" fn microcode_trampoline<F>(
    closure: *mut c_char,
    date: *const c_char,
    cpu_signature: u32,
    update_revision: u32,
    processor_flags: u8,
    vendor: u8,
) -> ContinueOrStop
where
    F: FnMut(MicrocodeInfo) -> ContinueOrStop,
{
    let date = CStr::from_ptr(date);
    let closure = &mut *(closure as *mut F);

    match UefiMicrocodeVendor::try_from(vendor) {
        Ok(UefiMicrocodeVendor::Amd) => closure(MicrocodeInfo::new_amd(
            date.to_string_lossy(),
            cpu_signature,
            update_revision,
        )),
        Ok(UefiMicrocodeVendor::Intel) => closure(MicrocodeInfo::new_intel(
            date.to_string_lossy(),
            cpu_signature,
            update_revision,
            processor_flags,
        )),
        _ => unreachable!(),
    }
}

fn get_microcode_trampoline<F>(
    _closure: &F,
) -> unsafe extern "C" fn(*mut c_char, *const c_char, u32, u32, u8, u8) -> ContinueOrStop
where
    F: FnMut(MicrocodeInfo) -> ContinueOrStop,
{
    microcode_trampoline::<F>
}

unsafe extern "C" fn guid_defined_section_trampoline<F>(
    closure: *mut c_char,
    guid: *const c_char,
) -> ContinueOrStop
where
    F: FnMut(UefiSection) -> ContinueOrStop,
{
    let guid = guid_from_ptr(guid);
    let closure = &mut *(closure as *mut F);

    closure(UefiSection::new(guid))
}

fn get_guid_defined_section_tampiline<F>(
    _closure: &F,
) -> unsafe extern "C" fn(*mut c_char, guid: *const c_char) -> ContinueOrStop
where
    F: FnMut(UefiSection) -> ContinueOrStop,
{
    guid_defined_section_trampoline::<F>
}

#[derive(Debug, Error)]
pub enum UefiError {
    #[error("cannot dump firmware buffer")]
    Dump,
    #[error("cannot parse firmware buffer")]
    Parse,
    #[error("cannot unpack firmware buffer")]
    Unpack(#[from] parsers::UnpackError),
}

pub type Error = UefiError;

pub struct Uefi<'a> {
    inner: cxx::UniquePtr<ffi::Uefitool<'a>>,
}

impl<'a> Uefi<'a> {
    pub fn new(buffer: &'a [u8]) -> Result<Self, Error> {
        let inner = unsafe {
            let bptr = buffer.as_ptr();
            let size = buffer.len();

            ffi::uefitool_new(bptr, size)
        }
        .map_err(|_| Error::Parse)?;

        let mut slf = Self { inner };

        slf.dump()?;

        Ok(slf)
    }

    fn dump(&mut self) -> Result<(), Error> {
        ffi::uefitool_dump(&mut self.inner).map_err(|_| Error::Dump)
    }

    pub fn for_each<F>(&self, mut f: F)
    where
        F: for<'m> FnMut(UefiModule<'m>),
    {
        self.for_each_until(move |v| {
            f(v);
            ContinueOrStop::Continue
        })
    }

    pub fn for_each_until<F>(&self, f: F)
    where
        F: for<'m> FnMut(UefiModule<'m>) -> ContinueOrStop,
    {
        unsafe {
            let mut closure = f;
            let callback = get_module_trampoline(&closure);

            ffi::uefitool_for_each_module(
                &self.inner,
                callback as *mut c_char,
                &mut closure as *mut _ as *mut c_char,
            )
        }
    }

    pub fn for_each_raw_section<F>(&self, mut f: F)
    where
        F: for<'m> FnMut(UefiData<'m>),
    {
        self.for_each_raw_section_until(move |v| {
            f(v);
            ContinueOrStop::Continue
        })
    }

    pub fn for_each_raw_section_until<F>(&self, f: F)
    where
        F: for<'m> FnMut(UefiData<'m>) -> ContinueOrStop,
    {
        unsafe {
            let mut closure = f;
            let callback = get_module_trampoline(&closure);

            ffi::uefitool_for_each_raw_section(
                &self.inner,
                callback as *mut c_char,
                &mut closure as *mut _ as *mut c_char,
            )
        }
    }

    pub fn for_each_var<F>(&self, mut f: F)
    where
        F: for<'v> FnMut(UefiNvramVar<'v>),
    {
        self.for_each_var_until(move |v| {
            f(v);
            ContinueOrStop::Continue
        })
    }

    pub fn for_each_var_until<F>(&self, f: F)
    where
        F: for<'v> FnMut(UefiNvramVar<'v>) -> ContinueOrStop,
    {
        unsafe {
            let mut closure = f;
            let callback = get_var_trampoline(&closure);

            ffi::uefitool_for_each_nvram(
                &self.inner,
                callback as *mut c_char,
                &mut closure as *mut _ as *mut c_char,
            )
        }
    }

    pub fn for_each_microcode<F>(&self, mut f: F)
    where
        F: for<'v> FnMut(MicrocodeInfo<'v>),
    {
        self.for_each_microcode_until(move |v| {
            f(v);
            ContinueOrStop::Continue
        })
    }

    pub fn for_each_microcode_until<F>(&self, f: F)
    where
        F: for<'v> FnMut(MicrocodeInfo<'v>) -> ContinueOrStop,
    {
        unsafe {
            let mut closure = f;
            let callback = get_microcode_trampoline(&closure);

            ffi::uefitool_for_each_microcode(
                &self.inner,
                callback as *mut c_char,
                &mut closure as *mut _ as *mut c_char,
            )
        }
    }

    pub fn for_each_guid_defined_section<F>(&self, mut f: F)
    where
        F: for<'v> FnMut(UefiSection<'v>),
    {
        self.for_each_guid_defined_section_until(move |v| {
            f(v);
            ContinueOrStop::Continue
        })
    }

    pub fn for_each_guid_defined_section_until<F>(&self, f: F)
    where
        F: for<'v> FnMut(UefiSection<'v>) -> ContinueOrStop,
    {
        unsafe {
            let mut closure = f;
            let callback = get_guid_defined_section_tampiline(&closure);

            ffi::uefitool_for_each_guid_defined_section(
                &self.inner,
                callback as *mut c_char,
                &mut closure as *mut _ as *mut c_char,
            )
        }
    }

    pub fn count_modules(&self) -> usize {
        unsafe { ffi::uefitool_count_modules(&self.inner) }
    }

    pub fn count_vars(&self) -> usize {
        unsafe { ffi::uefitool_count_nvram(&self.inner) }
    }

    pub fn count_raw_sections(&self) -> usize {
        unsafe { ffi::uefitool_count_raw_sections(&self.inner) }
    }

    pub fn count_microcode(&self) -> usize {
        unsafe { ffi::uefitool_count_microcode(&self.inner) }
    }

    pub fn count_guid_defined_sections(&self) -> usize {
        unsafe { ffi::uefitool_count_guid_defined_sections(&self.inner) }
    }
}

type UefiVec<'a> = Vec<Uefi<'a>>;

self_cell! {
    struct UefiMultiInner<'a> {
        owner: Vec<ParsedImage<'a>>,

        #[covariant]
        dependent: UefiVec,
    }
}

pub struct UefiMulti<'a> {
    inner: UefiMultiInner<'a>,
}

impl<'a> UefiMulti<'a> {
    pub fn new(buffer: &'a [u8]) -> Result<Self, Error> {
        let parsed = ParsedImage::from_bytes(buffer)?;

        Ok(Self {
            inner: UefiMultiInner::try_new(parsed, |loaded| {
                loaded
                    .iter()
                    .map(|image| Uefi::new(image.bytes()))
                    .collect::<Result<Vec<_>, _>>()
            })?,
        })
    }

    #[inline]
    pub fn loaded(&self) -> &[Uefi] {
        &self.inner.borrow_dependent()
    }

    #[inline]
    pub fn parsed(&self) -> &[ParsedImage] {
        &self.inner.borrow_owner()
    }

    #[inline]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Uefi> {
        self.inner.borrow_dependent().iter()
    }

    #[inline]
    pub fn iter_full(&self) -> impl ExactSizeIterator<Item = (&Uefi, &ParsedImage)> {
        self.inner
            .borrow_dependent()
            .iter()
            .zip(self.inner.borrow_owner().iter())
    }
}

#[cfg(test)]
mod test {
    use std::fs::{self, File};
    use std::io::{BufReader, BufWriter, Read, Write};
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_intel_ami() -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes = Vec::default();
        let mut f = BufReader::new(File::open("./tests/fw71.bin")?);
        f.read_to_end(&mut bytes)?;

        let fw = Uefi::new(&bytes)?;
        let mut found1 = false;
        let mut found2 = false;

        fw.for_each(|m| {
            found1 |= m.name() == "AMITSE" && m.guid() == "B1DA0ADF-4F77-4070-A88E-BFFE1C60529A";
            found2 |= m.guid() == "A2DF5376-C2ED-49C0-90FF-8B173B0FD066";
        });

        assert_eq!(found1, true);
        assert_eq!(found2, true);

        Ok(())
    }

    #[test]
    fn test_names() -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes = Vec::default();
        let mut f = BufReader::new(File::open("./tests/fw71.bin")?);
        f.read_to_end(&mut bytes)?;

        let fw = Uefi::new(&bytes)?;
        let mut found = false;
        let mut count = 0;

        fw.for_each(|m| {
            found |= m.name() == "RamDiskDxe";
            count += 1;
        });

        assert_eq!(count, 511);
        assert_eq!(found, true);

        Ok(())
    }

    #[test]
    fn test_unpack() -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes = Vec::default();
        let mut f = BufReader::new(File::open("./tests/M2TKT2DA.cap")?);
        f.read_to_end(&mut bytes)?;

        let pfat_bytes = try_unpack(&bytes)?.into_owned();

        // unpacked already
        let mut f = BufReader::new(File::open("./tests/M2TKT2DA.bin")?);

        bytes.clear();
        f.read_to_end(&mut bytes)?;

        assert_eq!(bytes, pfat_bytes);

        let mut f = BufReader::new(File::open("./tests/DellG3_3579_3779_1220.cap")?);
        let mut bytes = Vec::default();
        f.read_to_end(&mut bytes)?;

        let pfs_bytes = try_unpack(&bytes)?.into_owned();

        // unpacked already
        let mut f = BufReader::new(File::open("./tests/DellG3_3579_3779_1220.bin")?);

        bytes.clear();
        f.read_to_end(&mut bytes)?;

        let dell = Uefi::new(&bytes)?;
        let mut count = 0;

        dell.for_each(|_| count += 1);

        assert_eq!(count, dell.count_modules());
        // assert_eq!(count, 1033);
        assert_eq!(count, 524);

        assert_eq!(bytes, pfs_bytes);

        let mut f = BufReader::new(File::open("./tests/fw.bin")?);
        let mut bytes = Vec::default();
        f.read_to_end(&mut bytes)?;

        let unk_bytes = try_unpack(&bytes)?;

        assert_eq!(bytes, &*unk_bytes);

        let mut f = BufReader::new(File::open("./tests/jscn23ww.cap")?);
        let mut bytes = Vec::default();
        f.read_to_end(&mut bytes)?;

        let arm_bytes = try_unpack(&bytes)?;

        assert_eq!(bytes, &*arm_bytes);

        let arm = Uefi::new(&arm_bytes)?;
        let mut count = 0;

        fs::create_dir_all("/tmp/extracted")?;

        arm.for_each(|m| {
            let mut out = BufWriter::new(
                File::create(PathBuf::from_iter(["/tmp", "extracted", m.name()])).unwrap(),
            );
            out.write_all(m.bytes()).ok();
            count += 1;
        });

        // assert_eq!(count, 371);
        assert_eq!(count, 186);

        let mut f = BufReader::new(File::open(
            "./tests/d4d7014f4b0c4b1c3d34c18e8b92205a35b47aed87af359a068957da423053ff.bin",
        )?);
        let mut bytes = Vec::default();
        f.read_to_end(&mut bytes)?;

        let mut count = 0;
        let load = Uefi::new(&bytes)?;

        load.for_each(|_| count += 1);

        assert_eq!(count, 2);

        Ok(())
    }

    #[test]
    fn test_serde() -> Result<(), Box<dyn std::error::Error>> {
        let t1 = "\"dxe.driver\"";
        let t2 = "\"DxeDriver\"";
        let t3 = "{\"ffs\": 16}";
        let t4 = "{\"Ffs\": 16}";

        assert_eq!(
            serde_json::from_str::<UefiModuleType>(t1)?,
            UefiModuleType::DxeDriver
        );

        assert_eq!(
            serde_json::from_str::<UefiModuleType>(t2)?,
            UefiModuleType::DxeDriver
        );

        assert_eq!(
            serde_json::from_str::<UefiModuleType>(t3)?,
            UefiModuleType::Ffs(16)
        );

        assert_eq!(
            serde_json::from_str::<UefiModuleType>(t4)?,
            UefiModuleType::Ffs(16)
        );

        Ok(())
    }
}
