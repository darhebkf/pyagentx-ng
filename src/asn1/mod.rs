pub mod ber;

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Tag {
    // Universal
    Integer = 0x02,
    OctetString = 0x04,
    Null = 0x05,
    ObjectIdentifier = 0x06,
    Sequence = 0x30,

    // Application (SNMP)
    IpAddress = 0x40,
    Counter32 = 0x41,
    Gauge32 = 0x42,
    TimeTicks = 0x43,
    Opaque = 0x44,
    Counter64 = 0x46,

    // Context-specific (exceptions)
    NoSuchObject = 0x80,
    NoSuchInstance = 0x81,
    EndOfMibView = 0x82,

    // Context-specific (PDUs)
    GetRequest = 0xA0,
    GetNextRequest = 0xA1,
    Response = 0xA2,
    SetRequest = 0xA3,
    GetBulkRequest = 0xA5,
    InformRequest = 0xA6,
    TrapV2 = 0xA7,
}

impl TryFrom<u8> for Tag {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x02 => Ok(Tag::Integer),
            0x04 => Ok(Tag::OctetString),
            0x05 => Ok(Tag::Null),
            0x06 => Ok(Tag::ObjectIdentifier),
            0x30 => Ok(Tag::Sequence),
            0x40 => Ok(Tag::IpAddress),
            0x41 => Ok(Tag::Counter32),
            0x42 => Ok(Tag::Gauge32),
            0x43 => Ok(Tag::TimeTicks),
            0x44 => Ok(Tag::Opaque),
            0x46 => Ok(Tag::Counter64),
            0x80 => Ok(Tag::NoSuchObject),
            0x81 => Ok(Tag::NoSuchInstance),
            0x82 => Ok(Tag::EndOfMibView),
            0xA0 => Ok(Tag::GetRequest),
            0xA1 => Ok(Tag::GetNextRequest),
            0xA2 => Ok(Tag::Response),
            0xA3 => Ok(Tag::SetRequest),
            0xA5 => Ok(Tag::GetBulkRequest),
            0xA6 => Ok(Tag::InformRequest),
            0xA7 => Ok(Tag::TrapV2),
            _ => Err(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BerError {
    BufferTooShort,
    InvalidTag(u8),
    InvalidLength,
    InvalidOid,
    Overflow,
}

impl fmt::Display for BerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BerError::BufferTooShort => write!(f, "buffer too short"),
            BerError::InvalidTag(t) => write!(f, "invalid tag: 0x{t:02X}"),
            BerError::InvalidLength => write!(f, "invalid length encoding"),
            BerError::InvalidOid => write!(f, "invalid OID encoding"),
            BerError::Overflow => write!(f, "integer overflow"),
        }
    }
}

impl std::error::Error for BerError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_conversion() {
        assert_eq!(Tag::try_from(0x02), Ok(Tag::Integer));
        assert_eq!(Tag::try_from(0x30), Ok(Tag::Sequence));
        assert_eq!(Tag::try_from(0xA0), Ok(Tag::GetRequest));
        assert!(Tag::try_from(0xFF).is_err());
    }
}
