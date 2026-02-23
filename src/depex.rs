use thiserror::Error;

#[derive(Debug, Error)]
pub enum DepExError {
    #[error("incomplete opcode: not enough input")]
    Incomplete,
    #[error("invalid opcode {0:x}")]
    InvalidOpcode(u8),
}

pub const OP_SIZE: usize = 1;

pub const OP_WITH_GUID_START: usize = 1;
pub const OP_WITH_GUID_END: usize = 17;
pub const OP_WITH_GUID_ARG_SIZE: usize = 16;

pub const OP_BEFORE: u8 = 0x00;
pub const OP_AFTER: u8 = 0x01;
pub const OP_PUSH: u8 = 0x02;
pub const OP_AND: u8 = 0x03;
pub const OP_OR: u8 = 0x04;
pub const OP_NOT: u8 = 0x05;
pub const OP_TRUE: u8 = 0x06;
pub const OP_FALSE: u8 = 0x07;
pub const OP_END: u8 = 0x08;
pub const OP_SOR: u8 = 0x09;

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum DepExOpcode {
    Before([u8; 16]),
    After([u8; 16]),
    Push([u8; 16]),
    And,
    Or,
    Not,
    True,
    False,
    End,
    Sor,
}

impl DepExOpcode {
    pub fn guid(&self) -> Option<[u8; 16]> {
        match self {
            Self::Before(guid) | Self::After(guid) | Self::Push(guid) => Some(*guid),
            _ => None,
        }
    }

    pub fn file_guid(&self) -> Option<[u8; 16]> {
        match self {
            Self::Before(guid) | Self::After(guid) => Some(*guid),
            _ => None,
        }
    }

    pub fn protocol_guid(&self) -> Option<[u8; 16]> {
        if let Self::Push(guid) = self {
            Some(*guid)
        } else {
            None
        }
    }
}

impl DepExOpcode {
    #[inline]
    fn parse_guid(bytes: &[u8]) -> Result<[u8; 16], DepExError> {
        if bytes.len() >= OP_WITH_GUID_END {
            let mut guid = [0u8; OP_WITH_GUID_ARG_SIZE];
            guid.copy_from_slice(&bytes[OP_WITH_GUID_START..OP_WITH_GUID_END]);
            Ok(guid)
        } else {
            Err(DepExError::Incomplete)
        }
    }

    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), DepExError> {
        if bytes.is_empty() {
            return Err(DepExError::Incomplete);
        }

        match bytes[0] {
            OP_BEFORE => {
                let guid = Self::parse_guid(bytes)?;
                Ok((Self::Before(guid), OP_SIZE + OP_WITH_GUID_ARG_SIZE))
            }
            OP_AFTER => {
                let guid = Self::parse_guid(bytes)?;
                Ok((Self::After(guid), OP_SIZE + OP_WITH_GUID_ARG_SIZE))
            }
            OP_PUSH => {
                let guid = Self::parse_guid(bytes)?;
                Ok((Self::Push(guid), OP_SIZE + OP_WITH_GUID_ARG_SIZE))
            }
            OP_AND => Ok((Self::And, OP_SIZE)),
            OP_OR => Ok((Self::Or, OP_SIZE)),
            OP_NOT => Ok((Self::Not, OP_SIZE)),
            OP_TRUE => Ok((Self::True, OP_SIZE)),
            OP_FALSE => Ok((Self::False, OP_SIZE)),
            OP_END => Ok((Self::End, OP_SIZE)),
            OP_SOR => Ok((Self::Sor, OP_SIZE)),
            opcode => Err(DepExError::InvalidOpcode(opcode)),
        }
    }

    pub fn parse_all(bytes: &[u8]) -> Result<Vec<Self>, DepExError> {
        let mut offset = 0;
        let mut opcodes = Vec::with_capacity(0);

        while offset < bytes.len() {
            let (opcode, length) = Self::parse(&bytes[offset..])?;

            opcodes.push(opcode);
            offset += length;
        }

        Ok(opcodes)
    }
}
