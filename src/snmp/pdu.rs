use std::io::{self, Write};

use crate::asn1::ber::{
    decode_integer, decode_length, decode_null, decode_oid, decode_sequence, decode_tagged,
    encode_integer, encode_null, encode_oid, encode_sequence, encode_tagged,
};
use crate::asn1::{BerError, Tag};
use crate::oid::Oid;
use crate::types::Value;

// PDU type tags (RFC 3416)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PduType {
    GetRequest = 0xA0,
    GetNextRequest = 0xA1,
    Response = 0xA2,
    SetRequest = 0xA3,
    // 0xA4 is obsolete (TrapV1)
    GetBulkRequest = 0xA5,
    InformRequest = 0xA6,
    TrapV2 = 0xA7,
    Report = 0xA8,
}

impl TryFrom<u8> for PduType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0xA0 => Ok(PduType::GetRequest),
            0xA1 => Ok(PduType::GetNextRequest),
            0xA2 => Ok(PduType::Response),
            0xA3 => Ok(PduType::SetRequest),
            0xA5 => Ok(PduType::GetBulkRequest),
            0xA6 => Ok(PduType::InformRequest),
            0xA7 => Ok(PduType::TrapV2),
            0xA8 => Ok(PduType::Report),
            _ => Err(value),
        }
    }
}

// Error status codes (RFC 3416)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum ErrorStatus {
    #[default]
    NoError = 0,
    TooBig = 1,
    NoSuchName = 2,
    BadValue = 3,
    ReadOnly = 4,
    GenErr = 5,
    NoAccess = 6,
    WrongType = 7,
    WrongLength = 8,
    WrongEncoding = 9,
    WrongValue = 10,
    NoCreation = 11,
    InconsistentValue = 12,
    ResourceUnavailable = 13,
    CommitFailed = 14,
    UndoFailed = 15,
    AuthorizationError = 16,
    NotWritable = 17,
    InconsistentName = 18,
}

impl TryFrom<i32> for ErrorStatus {
    type Error = i32;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ErrorStatus::NoError),
            1 => Ok(ErrorStatus::TooBig),
            2 => Ok(ErrorStatus::NoSuchName),
            3 => Ok(ErrorStatus::BadValue),
            4 => Ok(ErrorStatus::ReadOnly),
            5 => Ok(ErrorStatus::GenErr),
            6 => Ok(ErrorStatus::NoAccess),
            7 => Ok(ErrorStatus::WrongType),
            8 => Ok(ErrorStatus::WrongLength),
            9 => Ok(ErrorStatus::WrongEncoding),
            10 => Ok(ErrorStatus::WrongValue),
            11 => Ok(ErrorStatus::NoCreation),
            12 => Ok(ErrorStatus::InconsistentValue),
            13 => Ok(ErrorStatus::ResourceUnavailable),
            14 => Ok(ErrorStatus::CommitFailed),
            15 => Ok(ErrorStatus::UndoFailed),
            16 => Ok(ErrorStatus::AuthorizationError),
            17 => Ok(ErrorStatus::NotWritable),
            18 => Ok(ErrorStatus::InconsistentName),
            _ => Err(value),
        }
    }
}

impl From<ErrorStatus> for i32 {
    fn from(e: ErrorStatus) -> i32 {
        e as i32
    }
}

// VarBind value (RFC 3416 section 3)
#[derive(Debug, Clone, PartialEq, Default)]
pub enum VarBindValue {
    Value(Value),
    #[default]
    Unspecified,
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

impl From<Value> for VarBindValue {
    fn from(v: Value) -> Self {
        VarBindValue::Value(v)
    }
}

// VarBind (RFC 3416 section 3)
#[derive(Debug, Clone, PartialEq)]
pub struct VarBind {
    pub name: Oid,
    pub value: VarBindValue,
}

impl VarBind {
    pub fn new(name: Oid, value: impl Into<VarBindValue>) -> Self {
        Self {
            name,
            value: value.into(),
        }
    }

    pub fn unspecified(name: Oid) -> Self {
        Self {
            name,
            value: VarBindValue::Unspecified,
        }
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut inner = Vec::new();
        encode_oid(&mut inner, &self.name)?;

        match &self.value {
            VarBindValue::Value(v) => encode_value(&mut inner, v)?,
            VarBindValue::Unspecified => encode_null(&mut inner)?,
            VarBindValue::NoSuchObject => inner.write_all(&[0x80, 0x00])?,
            VarBindValue::NoSuchInstance => inner.write_all(&[0x81, 0x00])?,
            VarBindValue::EndOfMibView => inner.write_all(&[0x82, 0x00])?,
        }

        encode_sequence(writer, &inner)
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), BerError> {
        let (inner, total) = decode_sequence(data)?;

        let (name, name_len) = decode_oid(inner)?;
        let value_data = &inner[name_len..];

        let value = if value_data.is_empty() {
            return Err(BerError::BufferTooShort);
        } else {
            match value_data[0] {
                0x05 => {
                    decode_null(value_data)?;
                    VarBindValue::Unspecified
                }
                0x80 => VarBindValue::NoSuchObject,
                0x81 => VarBindValue::NoSuchInstance,
                0x82 => VarBindValue::EndOfMibView,
                _ => VarBindValue::Value(decode_value(value_data)?.0),
            }
        };

        Ok((Self { name, value }, total))
    }
}

// VarBindList encoding/decoding
pub fn encode_varbind_list<W: Write>(writer: &mut W, varbinds: &[VarBind]) -> io::Result<()> {
    let mut inner = Vec::new();
    for vb in varbinds {
        vb.encode(&mut inner)?;
    }
    encode_sequence(writer, &inner)
}

pub fn decode_varbind_list(data: &[u8]) -> Result<(Vec<VarBind>, usize), BerError> {
    let (inner, total) = decode_sequence(data)?;

    let mut varbinds = Vec::new();
    let mut pos = 0;

    while pos < inner.len() {
        let (vb, consumed) = VarBind::decode(&inner[pos..])?;
        varbinds.push(vb);
        pos += consumed;
    }

    Ok((varbinds, total))
}

// Standard PDU (GetRequest, GetNextRequest, Response, SetRequest, InformRequest, TrapV2, Report)
#[derive(Debug, Clone, PartialEq)]
pub struct Pdu {
    pub pdu_type: PduType,
    pub request_id: i32,
    pub error_status: ErrorStatus,
    pub error_index: i32,
    pub varbinds: Vec<VarBind>,
}

impl Pdu {
    pub fn new(pdu_type: PduType, request_id: i32) -> Self {
        Self {
            pdu_type,
            request_id,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds: Vec::new(),
        }
    }

    pub fn get_request(request_id: i32, oids: Vec<Oid>) -> Self {
        let varbinds = oids.into_iter().map(VarBind::unspecified).collect();
        Self {
            pdu_type: PduType::GetRequest,
            request_id,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds,
        }
    }

    pub fn get_next_request(request_id: i32, oids: Vec<Oid>) -> Self {
        let varbinds = oids.into_iter().map(VarBind::unspecified).collect();
        Self {
            pdu_type: PduType::GetNextRequest,
            request_id,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds,
        }
    }

    pub fn set_request(request_id: i32, varbinds: Vec<VarBind>) -> Self {
        Self {
            pdu_type: PduType::SetRequest,
            request_id,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds,
        }
    }

    pub fn response(
        request_id: i32,
        error_status: ErrorStatus,
        error_index: i32,
        varbinds: Vec<VarBind>,
    ) -> Self {
        Self {
            pdu_type: PduType::Response,
            request_id,
            error_status,
            error_index,
            varbinds,
        }
    }

    pub fn inform_request(request_id: i32, varbinds: Vec<VarBind>) -> Self {
        Self {
            pdu_type: PduType::InformRequest,
            request_id,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds,
        }
    }

    pub fn trap_v2(request_id: i32, varbinds: Vec<VarBind>) -> Self {
        Self {
            pdu_type: PduType::TrapV2,
            request_id,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds,
        }
    }

    pub fn report(request_id: i32, varbinds: Vec<VarBind>) -> Self {
        Self {
            pdu_type: PduType::Report,
            request_id,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds,
        }
    }

    pub fn with_varbind(mut self, vb: VarBind) -> Self {
        self.varbinds.push(vb);
        self
    }

    pub fn with_varbinds(mut self, vbs: Vec<VarBind>) -> Self {
        self.varbinds = vbs;
        self
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut inner = Vec::new();
        encode_integer(&mut inner, self.request_id as i64)?;
        encode_integer(&mut inner, self.error_status as i64)?;
        encode_integer(&mut inner, self.error_index as i64)?;
        encode_varbind_list(&mut inner, &self.varbinds)?;

        encode_tagged(writer, self.pdu_type as u8, &inner)
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), BerError> {
        if data.is_empty() {
            return Err(BerError::BufferTooShort);
        }

        let pdu_type = PduType::try_from(data[0]).map_err(BerError::InvalidTag)?;

        // GetBulkRequest has different structure
        if pdu_type == PduType::GetBulkRequest {
            return Err(BerError::InvalidTag(data[0]));
        }

        let (inner, total) = decode_tagged(data, data[0])?;

        let (request_id, rid_len) = decode_integer(inner)?;
        let (error_status_raw, es_len) = decode_integer(&inner[rid_len..])?;
        let (error_index, ei_len) = decode_integer(&inner[rid_len + es_len..])?;
        let (varbinds, _) = decode_varbind_list(&inner[rid_len + es_len + ei_len..])?;

        let error_status =
            ErrorStatus::try_from(error_status_raw as i32).unwrap_or(ErrorStatus::GenErr);

        Ok((
            Self {
                pdu_type,
                request_id: request_id as i32,
                error_status,
                error_index: error_index as i32,
                varbinds,
            },
            total,
        ))
    }
}

// GetBulkRequest PDU (different structure: non-repeaters + max-repetitions instead of error fields)
#[derive(Debug, Clone, PartialEq)]
pub struct BulkPdu {
    pub request_id: i32,
    pub non_repeaters: i32,
    pub max_repetitions: i32,
    pub varbinds: Vec<VarBind>,
}

impl BulkPdu {
    pub fn new(request_id: i32, non_repeaters: i32, max_repetitions: i32, oids: Vec<Oid>) -> Self {
        let varbinds = oids.into_iter().map(VarBind::unspecified).collect();
        Self {
            request_id,
            non_repeaters,
            max_repetitions,
            varbinds,
        }
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut inner = Vec::new();
        encode_integer(&mut inner, self.request_id as i64)?;
        encode_integer(&mut inner, self.non_repeaters as i64)?;
        encode_integer(&mut inner, self.max_repetitions as i64)?;
        encode_varbind_list(&mut inner, &self.varbinds)?;

        encode_tagged(writer, PduType::GetBulkRequest as u8, &inner)
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), BerError> {
        let (inner, total) = decode_tagged(data, PduType::GetBulkRequest as u8)?;

        let (request_id, rid_len) = decode_integer(inner)?;
        let (non_repeaters, nr_len) = decode_integer(&inner[rid_len..])?;
        let (max_repetitions, mr_len) = decode_integer(&inner[rid_len + nr_len..])?;
        let (varbinds, _) = decode_varbind_list(&inner[rid_len + nr_len + mr_len..])?;

        Ok((
            Self {
                request_id: request_id as i32,
                non_repeaters: non_repeaters as i32,
                max_repetitions: max_repetitions as i32,
                varbinds,
            },
            total,
        ))
    }
}

// Value encoding for SNMP (uses BER, different tags than AgentX)
fn encode_value<W: Write>(writer: &mut W, value: &Value) -> io::Result<()> {
    use crate::asn1::ber::{
        encode_counter64, encode_ip_address, encode_octet_string, encode_unsigned,
    };

    match value {
        Value::Integer(v) => encode_integer(writer, *v as i64),
        Value::OctetString(v) => encode_octet_string(writer, v),
        Value::Null() => encode_null(writer),
        Value::ObjectIdentifier(oid) => encode_oid(writer, oid),
        Value::IpAddress(a, b, c, d) => encode_ip_address(writer, *a, *b, *c, *d),
        Value::Counter32(v) => encode_unsigned(writer, Tag::Counter32 as u8, *v),
        Value::Gauge32(v) => encode_unsigned(writer, Tag::Gauge32 as u8, *v),
        Value::TimeTicks(v) => encode_unsigned(writer, Tag::TimeTicks as u8, *v),
        Value::Opaque(v) => {
            writer.write_all(&[Tag::Opaque as u8])?;
            crate::asn1::ber::encode_length(writer, v.len())?;
            writer.write_all(v)
        }
        Value::Counter64(v) => encode_counter64(writer, *v),
        Value::NoSuchObject() => writer.write_all(&[0x80, 0x00]),
        Value::NoSuchInstance() => writer.write_all(&[0x81, 0x00]),
        Value::EndOfMibView() => writer.write_all(&[0x82, 0x00]),
    }
}

fn decode_value(data: &[u8]) -> Result<(Value, usize), BerError> {
    use crate::asn1::ber::{
        decode_counter64, decode_ip_address, decode_octet_string, decode_unsigned,
    };

    if data.is_empty() {
        return Err(BerError::BufferTooShort);
    }

    match data[0] {
        0x02 => {
            let (v, len) = decode_integer(data)?;
            Ok((Value::Integer(v as i32), len))
        }
        0x04 => {
            let (v, len) = decode_octet_string(data)?;
            Ok((Value::OctetString(v), len))
        }
        0x05 => {
            let len = decode_null(data)?;
            Ok((Value::Null(), len))
        }
        0x06 => {
            let (oid, len) = decode_oid(data)?;
            Ok((Value::ObjectIdentifier(oid), len))
        }
        0x40 => {
            let (addr, len) = decode_ip_address(data)?;
            Ok((Value::IpAddress(addr[0], addr[1], addr[2], addr[3]), len))
        }
        0x41 => {
            let (v, len) = decode_unsigned(data, 0x41)?;
            Ok((Value::Counter32(v), len))
        }
        0x42 => {
            let (v, len) = decode_unsigned(data, 0x42)?;
            Ok((Value::Gauge32(v), len))
        }
        0x43 => {
            let (v, len) = decode_unsigned(data, 0x43)?;
            Ok((Value::TimeTicks(v), len))
        }
        0x44 => {
            let (len, len_bytes) = decode_length(&data[1..])?;
            let total = 1 + len_bytes + len;
            if data.len() < total {
                return Err(BerError::BufferTooShort);
            }
            Ok((Value::Opaque(data[1 + len_bytes..total].to_vec()), total))
        }
        0x46 => {
            let (v, len) = decode_counter64(data)?;
            Ok((Value::Counter64(v), len))
        }
        0x80 => Ok((Value::NoSuchObject(), 2)),
        0x81 => Ok((Value::NoSuchInstance(), 2)),
        0x82 => Ok((Value::EndOfMibView(), 2)),
        tag => Err(BerError::InvalidTag(tag)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pdu_type_conversion() {
        assert_eq!(PduType::try_from(0xA0), Ok(PduType::GetRequest));
        assert_eq!(PduType::try_from(0xA2), Ok(PduType::Response));
        assert_eq!(PduType::try_from(0xA5), Ok(PduType::GetBulkRequest));
        assert!(PduType::try_from(0xA4).is_err()); // obsolete TrapV1
    }

    #[test]
    fn test_error_status_conversion() {
        assert_eq!(ErrorStatus::try_from(0), Ok(ErrorStatus::NoError));
        assert_eq!(ErrorStatus::try_from(5), Ok(ErrorStatus::GenErr));
        assert_eq!(ErrorStatus::try_from(18), Ok(ErrorStatus::InconsistentName));
        assert!(ErrorStatus::try_from(19).is_err());
    }

    #[test]
    fn test_varbind_roundtrip() {
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let vb = VarBind::new(oid.clone(), Value::Integer(42));

        let mut buf = Vec::new();
        vb.encode(&mut buf).unwrap();

        let (decoded, _) = VarBind::decode(&buf).unwrap();
        assert_eq!(decoded.name.to_string(), oid.to_string());
        match decoded.value {
            VarBindValue::Value(Value::Integer(v)) => assert_eq!(v, 42),
            _ => panic!("unexpected value"),
        }
    }

    #[test]
    fn test_varbind_unspecified() {
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let vb = VarBind::unspecified(oid);

        let mut buf = Vec::new();
        vb.encode(&mut buf).unwrap();

        let (decoded, _) = VarBind::decode(&buf).unwrap();
        assert_eq!(decoded.value, VarBindValue::Unspecified);
    }

    #[test]
    fn test_varbind_exceptions() {
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();

        for value in [
            VarBindValue::NoSuchObject,
            VarBindValue::NoSuchInstance,
            VarBindValue::EndOfMibView,
        ] {
            let vb = VarBind {
                name: oid.clone(),
                value: value.clone(),
            };

            let mut buf = Vec::new();
            vb.encode(&mut buf).unwrap();

            let (decoded, _) = VarBind::decode(&buf).unwrap();
            assert_eq!(decoded.value, value);
        }
    }

    #[test]
    fn test_pdu_get_request_roundtrip() {
        let oid1: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let oid2: Oid = "1.3.6.1.2.1.1.3.0".parse().unwrap();
        let pdu = Pdu::get_request(12345, vec![oid1, oid2]);

        let mut buf = Vec::new();
        pdu.encode(&mut buf).unwrap();

        let (decoded, _) = Pdu::decode(&buf).unwrap();
        assert_eq!(decoded.pdu_type, PduType::GetRequest);
        assert_eq!(decoded.request_id, 12345);
        assert_eq!(decoded.error_status, ErrorStatus::NoError);
        assert_eq!(decoded.varbinds.len(), 2);
    }

    #[test]
    fn test_pdu_response_roundtrip() {
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let vb = VarBind::new(oid, Value::OctetString(b"Linux".to_vec()));
        let pdu = Pdu::response(12345, ErrorStatus::NoError, 0, vec![vb]);

        let mut buf = Vec::new();
        pdu.encode(&mut buf).unwrap();

        let (decoded, _) = Pdu::decode(&buf).unwrap();
        assert_eq!(decoded.pdu_type, PduType::Response);
        assert_eq!(decoded.request_id, 12345);
    }

    #[test]
    fn test_bulk_pdu_roundtrip() {
        let oid: Oid = "1.3.6.1.2.1.2.2".parse().unwrap();
        let pdu = BulkPdu::new(12345, 0, 10, vec![oid]);

        let mut buf = Vec::new();
        pdu.encode(&mut buf).unwrap();

        let (decoded, _) = BulkPdu::decode(&buf).unwrap();
        assert_eq!(decoded.request_id, 12345);
        assert_eq!(decoded.non_repeaters, 0);
        assert_eq!(decoded.max_repetitions, 10);
        assert_eq!(decoded.varbinds.len(), 1);
    }

    #[test]
    fn test_all_value_types() {
        // Note: Null is not included because in VarBind context it means "unspecified"
        let test_cases: Vec<Value> = vec![
            Value::Integer(-42),
            Value::OctetString(b"test".to_vec()),
            Value::ObjectIdentifier("1.3.6.1".parse().unwrap()),
            Value::IpAddress(192, 168, 1, 1),
            Value::Counter32(4294967295),
            Value::Gauge32(100),
            Value::TimeTicks(123456),
            Value::Opaque(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            Value::Counter64(u64::MAX),
        ];

        for value in test_cases {
            let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
            let vb = VarBind::new(oid, value.clone());

            let mut buf = Vec::new();
            vb.encode(&mut buf).unwrap();

            let (decoded, _) = VarBind::decode(&buf).unwrap();
            match decoded.value {
                VarBindValue::Value(v) => assert_eq!(v, value),
                _ => panic!("expected Value"),
            }
        }
    }
}
