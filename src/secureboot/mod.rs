use std::borrow::Cow;
use std::fmt::{self, Display, Formatter};

use hex_display::HexDisplayExt;
use scroll::Pread;
use serde::{Deserialize, Serialize};
use uuid::{uuid, Uuid};

pub mod auth;
pub mod constants;
pub mod parser;

use auth::*;
use constants::*;
use parser::*;

const MAX_CERT_X509_DATA_DISPLAY_SIZE: usize = 32;
const MIN_SIGNATURE_DATA_SIZE: usize = 16 + 1;
const OPTIONAL_ZERO_PADDING_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub enum DatabaseType {
    PK,
    KEK,
    DB,
    DBX,
    UNKNOWN,
}

impl From<&'_ str> for DatabaseType {
    fn from(variable_name: &str) -> Self {
        match variable_name {
            EDK2_PK_NAME => DatabaseType::PK,
            EDK2_KEK_NAME => DatabaseType::KEK,
            EDK2_DB_NAME | LENOVO_DB_MSKEY_NAME => DatabaseType::DB,
            EDK2_DBX_NAME => DatabaseType::DBX,
            _ => {
                tracing::error!("cannot convert variable name to database type");
                DatabaseType::UNKNOWN
            }
        }
    }
}

impl From<Uuid> for DatabaseType {
    fn from(section_guid: Uuid) -> Self {
        match section_guid {
            AMI_PK_RAW_SECTION_GUID
            | DELL_PK_RAW_SECTION_GUID
            | HP_PK_RAW_SECTION_GUID
            | HP_PK_RAW_SECTION_V2_GUID
            | LENOVO_ARM_PK_RAW_SECTION_GUID
            | LENOVO_ARM_PK2_RAW_SECTION_GUID => DatabaseType::PK,
            AMI_KEK_RAW_SECTION_GUID
            | DELL_KEK_RAW_SECTION_GUID
            | HP_KEK1_RAW_SECTION_GUID
            | HP_KEK2_RAW_SECTION_GUID
            | HP_KEK_RAW_SECTION_V2_GUID
            | LENOVO_ARM_KEK_RAW_SECTION_GUID
            | LENOVO_ARM_KEK2_RAW_SECTION_GUID => DatabaseType::KEK,
            AMI_DB_RAW_SECTION_GUID
            | DELL_DB1_RAW_SECTION_GUID
            | DELL_DB2_RAW_SECTION_GUID
            | DELL_DB3_RAW_SECTION_GUID
            | HP_DB1_RAW_SECTION_GUID
            | HP_DB2_RAW_SECTION_GUID
            | HP_DB3_RAW_SECTION_GUID
            | HP_DB4_RAW_SECTION_GUID
            | HP_DB_RAW_SECTION_V2_GUID
            | LENOVO_ARM_DB_RAW_SECTION_GUID
            | LENOVO_ARM_DB2_RAW_SECTION_GUID => DatabaseType::DB,
            AMI_DBX_RAW_SECTION_GUID
            | DELL_DBX_RAW_SECTION_GUID
            | HP_DBX_RAW_SECTION_GUID
            | LENOVO_ARM_DBX_RAW_SECTION_GUID
            | LENOVO_ARM_DBX2_RAW_SECTION_GUID => DatabaseType::DBX,
            _ => {
                tracing::trace!("cannot convert section guid to database type");
                DatabaseType::UNKNOWN
            }
        }
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Deserialize, Serialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub struct ParsedSignature<'a> {
    pub database_type: DatabaseType,
    pub signature_type: Uuid,
    pub signature_owner: Uuid,
    pub signature_data: Cow<'a, [u8]>,
}

impl Display for ParsedSignature<'_> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let signature_type = &self.signature_type.to_string();
        let signature_type = match self.signature_type {
            G_EFI_CERT_X509_GUID => "EFI_CERT_X509_GUID",
            G_EFI_CERT_SHA256_GUID => "EFI_CERT_SHA256_GUID",
            _ => signature_type,
        };

        let signature_owner = &self.signature_owner.to_string();
        let signature_owner = match self.signature_owner {
            MICROSOFT_SIGNATURE_OWNER_GUID => "Microsoft",
            _ => signature_owner,
        };

        let signature_data = if self.signature_type == G_EFI_CERT_X509_GUID {
            &self.signature_data[..self
                .signature_data
                .len()
                .min(MAX_CERT_X509_DATA_DISPLAY_SIZE)]
        } else {
            &self.signature_data
        };

        write!(
            f,
            "{{db: {:?} type: {} owner: {} data: {}}}",
            self.database_type,
            signature_type,
            signature_owner,
            signature_data.hex()
        )
    }
}

pub fn extract_sb_signatures_from_nvram<'a>(
    variable_name: &str,
    mut bytes: &'a [u8],
) -> Vec<ParsedSignature<'a>> {
    let mut parsed_vec = Vec::new();

    if bytes.len() < MIN_SIGNATURE_DATA_SIZE {
        return parsed_vec;
    }

    if EDK2_VARIABLE_NAMES.contains(&variable_name) {
        tracing::info!(
            "Parsing database stored in NVRAM variable {:?}",
            variable_name
        );

        // Some firmware have 16 zeros before the database (e.g. 8c72ddd6670f25) so strip them.
        if bytes
            .iter()
            .take(OPTIONAL_ZERO_PADDING_SIZE)
            .all(|b| *b == 0)
        {
            bytes = &bytes[OPTIONAL_ZERO_PADDING_SIZE..];
        }

        let database = EfiSignatureDatabase::new(&bytes);
        for list in database {
            for data in list.clone() {
                parsed_vec.push(ParsedSignature {
                    database_type: variable_name.into(),
                    signature_type: list.header.signature_type,
                    signature_owner: data.signature_owner,
                    signature_data: Cow::Borrowed(data.signature_data),
                });
            }
        }
    }

    if THIRD_PARTY_VARIABLE_NAMES.contains(&variable_name) {
        return process_raw_signature_data(variable_name, bytes);
    }

    parsed_vec
}

fn process_raw_signature_data<'a>(
    source: impl Into<DatabaseType>,
    bytes: &[u8],
) -> Vec<ParsedSignature> {
    let parsed = ParsedSignature {
        database_type: source.into(),
        signature_type: G_EFI_CERT_X509_GUID,
        signature_owner: uuid!("00112233-4455-6677-8899-AABBCCDDEEFF"),
        signature_data: Cow::Borrowed(&bytes),
    };

    vec![parsed]
}

pub fn process_authenticated_database(
    source: impl Into<DatabaseType>,
    bytes: &[u8],
) -> Vec<ParsedSignature> {
    let mut offset = 0usize;
    let mut parsed_vec = Vec::new();

    if bytes
        .gread::<EfiVariableAuthentication2>(&mut offset)
        .is_ok()
    {
        let Some(bytes) = bytes.get(offset..) else {
            return Vec::with_capacity(0);
        };

        let database = EfiSignatureDatabase::new(&bytes);

        let database_type = source.into();
        for list in database {
            for data in list {
                parsed_vec.push(ParsedSignature {
                    database_type,
                    signature_type: list.header.signature_type,
                    signature_owner: data.signature_owner,
                    signature_data: Cow::Borrowed(data.signature_data),
                });
            }
        }
    }

    parsed_vec
}

// Some HP firmware store Secure Boot variable lists along with a custom authentication header.
fn process_hp_authenticated_list(section_guid: Uuid, bytes: &[u8]) -> Vec<ParsedSignature> {
    let mut offset = 0usize;

    if bytes
        .gread::<HpEfiVariableAuthentication>(&mut offset)
        .is_err()
    {
        return Vec::with_capacity(0);
    }

    let Some(bytes) = bytes.get(offset..) else {
        return Vec::with_capacity(0);
    };

    let Ok(list) = EfiSignatureList::new(&bytes) else {
        return Vec::with_capacity(0);
    };

    list.into_iter()
        .map(|data| ParsedSignature {
            database_type: section_guid.into(),
            signature_type: list.header.signature_type,
            signature_owner: data.signature_owner,
            signature_data: Cow::Borrowed(data.signature_data),
        })
        .collect()
}

pub fn extract_sb_signatures_from_raw_section(
    section_guid: Uuid,
    bytes: &[u8],
) -> Vec<ParsedSignature> {
    let mut parsed_vec = if AUTHENTICATED_DB_RAW_SECTION_GUIDS.contains(&section_guid) {
        tracing::debug!(
            "parsing authenticated database from raw section {}",
            section_guid,
        );
        process_authenticated_database(section_guid, bytes)
    } else if AUTHENTICATED_LIST_RAW_SECTION_GUIDS.contains(&section_guid) {
        tracing::debug!(
            "parsing authenticated list from raw section {}",
            section_guid
        );
        process_hp_authenticated_list(section_guid, bytes)
    } else if SIGNATURE_DATA_RAW_SECTION_GUIDS.contains(&section_guid) {
        tracing::debug!("parsing signature data from raw section {}", section_guid);
        process_raw_signature_data(section_guid, bytes)
    } else {
        Vec::with_capacity(0)
    };

    // Some Lenovo ARM firmware store in raw sections the signature database.
    if parsed_vec.is_empty()
        && [
            LENOVO_ARM_PK_RAW_SECTION_GUID,
            LENOVO_ARM_KEK_RAW_SECTION_GUID,
            LENOVO_ARM_DB_RAW_SECTION_GUID,
            LENOVO_ARM_DBX_RAW_SECTION_GUID,
        ]
        .contains(&section_guid)
    {
        let database = EfiSignatureDatabase::new(&bytes);
        for list in database {
            for data in list {
                parsed_vec.push(ParsedSignature {
                    database_type: section_guid.into(),
                    signature_type: list.header.signature_type,
                    signature_owner: data.signature_owner,
                    signature_data: Cow::Borrowed(data.signature_data),
                });
            }
        }
    }

    parsed_vec
}
