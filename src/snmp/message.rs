use std::io::{self, Write};

use crate::asn1::BerError;
use crate::asn1::ber::{
    decode_integer, decode_octet_string, decode_sequence, encode_integer, encode_octet_string,
    encode_sequence,
};

use super::pdu::{BulkPdu, Pdu, PduType};

// SNMP versions (wire format values per RFCs)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Version {
    V1 = 0,  // RFC 1157
    V2c = 1, // RFC 3416
    V3 = 3,  // RFC 3412 (2 was reserved for SNMPv2p, never used)
}

impl TryFrom<i64> for Version {
    type Error = i64;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Version::V1),
            1 => Ok(Version::V2c),
            3 => Ok(Version::V3),
            _ => Err(value),
        }
    }
}

// SNMPv1 message (RFC 1157)
#[derive(Debug, Clone, PartialEq)]
pub struct MessageV1 {
    pub community: Vec<u8>,
    pub pdu: Pdu,
}

impl MessageV1 {
    pub fn new(community: impl Into<Vec<u8>>, pdu: Pdu) -> Self {
        Self {
            community: community.into(),
            pdu,
        }
    }

    pub fn get_request(
        community: impl Into<Vec<u8>>,
        request_id: i32,
        oids: Vec<crate::oid::Oid>,
    ) -> Self {
        Self::new(community, Pdu::get_request(request_id, oids))
    }

    pub fn get_next_request(
        community: impl Into<Vec<u8>>,
        request_id: i32,
        oids: Vec<crate::oid::Oid>,
    ) -> Self {
        Self::new(community, Pdu::get_next_request(request_id, oids))
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut inner = Vec::new();
        encode_integer(&mut inner, Version::V1 as i64)?;
        encode_octet_string(&mut inner, &self.community)?;
        self.pdu.encode(&mut inner)?;

        encode_sequence(writer, &inner)
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), BerError> {
        let (inner, total) = decode_sequence(data)?;

        let (version, ver_len) = decode_integer(inner)?;
        if version != Version::V1 as i64 {
            return Err(BerError::InvalidTag(version as u8));
        }

        let (community, comm_len) = decode_octet_string(&inner[ver_len..])?;
        let (pdu, _) = Pdu::decode(&inner[ver_len + comm_len..])?;

        Ok((Self { community, pdu }, total))
    }
}

// SNMPv2c message (RFC 3416)
#[derive(Debug, Clone, PartialEq)]
pub enum MessageV2c {
    Standard { community: Vec<u8>, pdu: Pdu },
    Bulk { community: Vec<u8>, pdu: BulkPdu },
}

impl MessageV2c {
    pub fn new(community: impl Into<Vec<u8>>, pdu: Pdu) -> Self {
        MessageV2c::Standard {
            community: community.into(),
            pdu,
        }
    }

    pub fn bulk(community: impl Into<Vec<u8>>, pdu: BulkPdu) -> Self {
        MessageV2c::Bulk {
            community: community.into(),
            pdu,
        }
    }

    pub fn get_request(
        community: impl Into<Vec<u8>>,
        request_id: i32,
        oids: Vec<crate::oid::Oid>,
    ) -> Self {
        MessageV2c::Standard {
            community: community.into(),
            pdu: Pdu::get_request(request_id, oids),
        }
    }

    pub fn get_next_request(
        community: impl Into<Vec<u8>>,
        request_id: i32,
        oids: Vec<crate::oid::Oid>,
    ) -> Self {
        MessageV2c::Standard {
            community: community.into(),
            pdu: Pdu::get_next_request(request_id, oids),
        }
    }

    pub fn get_bulk_request(
        community: impl Into<Vec<u8>>,
        request_id: i32,
        non_repeaters: i32,
        max_repetitions: i32,
        oids: Vec<crate::oid::Oid>,
    ) -> Self {
        MessageV2c::Bulk {
            community: community.into(),
            pdu: BulkPdu::new(request_id, non_repeaters, max_repetitions, oids),
        }
    }

    pub fn set_request(
        community: impl Into<Vec<u8>>,
        request_id: i32,
        varbinds: Vec<super::pdu::VarBind>,
    ) -> Self {
        MessageV2c::Standard {
            community: community.into(),
            pdu: Pdu::set_request(request_id, varbinds),
        }
    }

    pub fn trap_v2(
        community: impl Into<Vec<u8>>,
        request_id: i32,
        varbinds: Vec<super::pdu::VarBind>,
    ) -> Self {
        MessageV2c::Standard {
            community: community.into(),
            pdu: Pdu::trap_v2(request_id, varbinds),
        }
    }

    pub fn inform_request(
        community: impl Into<Vec<u8>>,
        request_id: i32,
        varbinds: Vec<super::pdu::VarBind>,
    ) -> Self {
        MessageV2c::Standard {
            community: community.into(),
            pdu: Pdu::inform_request(request_id, varbinds),
        }
    }

    pub fn response(
        community: impl Into<Vec<u8>>,
        request_id: i32,
        error_status: super::pdu::ErrorStatus,
        error_index: i32,
        varbinds: Vec<super::pdu::VarBind>,
    ) -> Self {
        MessageV2c::Standard {
            community: community.into(),
            pdu: Pdu::response(request_id, error_status, error_index, varbinds),
        }
    }

    pub fn community(&self) -> &[u8] {
        match self {
            MessageV2c::Standard { community, .. } => community,
            MessageV2c::Bulk { community, .. } => community,
        }
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut inner = Vec::new();
        encode_integer(&mut inner, Version::V2c as i64)?;

        match self {
            MessageV2c::Standard { community, pdu } => {
                encode_octet_string(&mut inner, community)?;
                pdu.encode(&mut inner)?;
            }
            MessageV2c::Bulk { community, pdu } => {
                encode_octet_string(&mut inner, community)?;
                pdu.encode(&mut inner)?;
            }
        }

        encode_sequence(writer, &inner)
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), BerError> {
        let (inner, total) = decode_sequence(data)?;

        let (version, ver_len) = decode_integer(inner)?;
        if version != Version::V2c as i64 {
            return Err(BerError::InvalidTag(version as u8));
        }

        let (community, comm_len) = decode_octet_string(&inner[ver_len..])?;
        let pdu_data = &inner[ver_len + comm_len..];

        if pdu_data.is_empty() {
            return Err(BerError::BufferTooShort);
        }

        let msg = if pdu_data[0] == PduType::GetBulkRequest as u8 {
            let (pdu, _) = BulkPdu::decode(pdu_data)?;
            MessageV2c::Bulk { community, pdu }
        } else {
            let (pdu, _) = Pdu::decode(pdu_data)?;
            MessageV2c::Standard { community, pdu }
        };

        Ok((msg, total))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid::Oid;

    #[test]
    fn test_version_conversion() {
        assert_eq!(Version::try_from(0i64), Ok(Version::V1));
        assert_eq!(Version::try_from(1i64), Ok(Version::V2c));
        assert_eq!(Version::try_from(3i64), Ok(Version::V3));
        assert!(Version::try_from(2i64).is_err());
    }

    #[test]
    fn test_message_v1_roundtrip() {
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let pdu = Pdu::get_request(12345, vec![oid]);
        let msg = MessageV1::new(b"public".to_vec(), pdu);

        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();

        let (decoded, _) = MessageV1::decode(&buf).unwrap();
        assert_eq!(decoded.community, b"public");
        assert_eq!(decoded.pdu.request_id, 12345);
    }

    #[test]
    fn test_message_v1_convenience() {
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let msg = MessageV1::get_request(b"public", 42, vec![oid]);

        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();

        let (decoded, _) = MessageV1::decode(&buf).unwrap();
        assert_eq!(decoded.pdu.pdu_type, PduType::GetRequest);
        assert_eq!(decoded.pdu.request_id, 42);
    }

    #[test]
    fn test_message_v2c_get_request_roundtrip() {
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let msg = MessageV2c::get_request(b"public".to_vec(), 12345, vec![oid]);

        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();

        let (decoded, _) = MessageV2c::decode(&buf).unwrap();
        assert_eq!(decoded.community(), b"public");
        match decoded {
            MessageV2c::Standard { pdu, .. } => {
                assert_eq!(pdu.pdu_type, PduType::GetRequest);
                assert_eq!(pdu.request_id, 12345);
            }
            _ => panic!("expected Standard"),
        }
    }

    #[test]
    fn test_message_v2c_bulk_roundtrip() {
        let oid: Oid = "1.3.6.1.2.1.2.2".parse().unwrap();
        let msg = MessageV2c::get_bulk_request(b"public".to_vec(), 12345, 0, 10, vec![oid]);

        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();

        let (decoded, _) = MessageV2c::decode(&buf).unwrap();
        match decoded {
            MessageV2c::Bulk { pdu, .. } => {
                assert_eq!(pdu.request_id, 12345);
                assert_eq!(pdu.non_repeaters, 0);
                assert_eq!(pdu.max_repetitions, 10);
            }
            _ => panic!("expected Bulk"),
        }
    }

    #[test]
    fn test_message_v2c_trap_v2_roundtrip() {
        let oid: Oid = "1.3.6.1.6.3.1.1.4.1.0".parse().unwrap();
        let vb = super::super::pdu::VarBind::new(
            oid,
            crate::types::Value::ObjectIdentifier("1.3.6.1.4.1.99".parse().unwrap()),
        );
        let msg = MessageV2c::trap_v2(b"public", 42, vec![vb]);

        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();

        let (decoded, _) = MessageV2c::decode(&buf).unwrap();
        match decoded {
            MessageV2c::Standard { pdu, .. } => {
                assert_eq!(pdu.pdu_type, PduType::TrapV2);
                assert_eq!(pdu.request_id, 42);
                assert_eq!(pdu.varbinds.len(), 1);
            }
            _ => panic!("expected Standard"),
        }
    }

    #[test]
    fn test_message_v2c_inform_roundtrip() {
        let oid: Oid = "1.3.6.1.6.3.1.1.4.1.0".parse().unwrap();
        let vb = super::super::pdu::VarBind::new(
            oid,
            crate::types::Value::ObjectIdentifier("1.3.6.1.4.1.99".parse().unwrap()),
        );
        let msg = MessageV2c::inform_request(b"public", 99, vec![vb]);

        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();

        let (decoded, _) = MessageV2c::decode(&buf).unwrap();
        match decoded {
            MessageV2c::Standard { pdu, .. } => {
                assert_eq!(pdu.pdu_type, PduType::InformRequest);
                assert_eq!(pdu.request_id, 99);
            }
            _ => panic!("expected Standard"),
        }
    }

    #[test]
    fn test_message_v2c_response_roundtrip() {
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let vb = super::super::pdu::VarBind::new(
            oid,
            crate::types::Value::OctetString(b"Linux".to_vec()),
        );
        let msg = MessageV2c::response(
            b"public",
            12345,
            super::super::pdu::ErrorStatus::NoError,
            0,
            vec![vb],
        );

        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();

        let (decoded, _) = MessageV2c::decode(&buf).unwrap();
        match decoded {
            MessageV2c::Standard { pdu, .. } => {
                assert_eq!(pdu.pdu_type, PduType::Response);
                assert_eq!(pdu.request_id, 12345);
                assert_eq!(pdu.error_status, super::super::pdu::ErrorStatus::NoError);
            }
            _ => panic!("expected Standard"),
        }
    }

    #[test]
    fn test_message_v2c_multiple_oids() {
        let oids: Vec<Oid> = vec![
            "1.3.6.1.2.1.1.1.0".parse().unwrap(),
            "1.3.6.1.2.1.1.3.0".parse().unwrap(),
            "1.3.6.1.2.1.1.5.0".parse().unwrap(),
        ];
        let msg = MessageV2c::get_request(b"public", 999, oids);

        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();

        let (decoded, _) = MessageV2c::decode(&buf).unwrap();
        match decoded {
            MessageV2c::Standard { pdu, .. } => {
                assert_eq!(pdu.varbinds.len(), 3);
            }
            _ => panic!("expected Standard"),
        }
    }
}
