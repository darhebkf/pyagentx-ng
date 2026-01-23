use std::io::{self, Write};

use crate::asn1::BerError;
use crate::asn1::ber::{
    decode_integer, decode_octet_string, decode_sequence, encode_integer, encode_octet_string,
    encode_sequence,
};

use super::pdu::{BulkPdu, Pdu, PduType};

// SNMPv3 message (RFC 3412)
#[derive(Debug, Clone, PartialEq)]
pub struct MessageV3 {
    pub msg_id: i32,
    pub msg_max_size: i32,
    pub msg_flags: MsgFlags,
    pub msg_security_model: SecurityModel,
    pub security_parameters: Vec<u8>,
    pub scoped_pdu: ScopedPdu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MsgFlags {
    pub auth: bool,
    pub priv_: bool,
    pub reportable: bool,
}

impl MsgFlags {
    pub fn new(auth: bool, priv_: bool, reportable: bool) -> Self {
        Self {
            auth,
            priv_,
            reportable,
        }
    }

    pub fn auth_priv() -> Self {
        Self {
            auth: true,
            priv_: true,
            reportable: true,
        }
    }

    pub fn auth_no_priv() -> Self {
        Self {
            auth: true,
            priv_: false,
            reportable: true,
        }
    }

    pub fn no_auth_no_priv() -> Self {
        Self {
            auth: false,
            priv_: false,
            reportable: true,
        }
    }

    pub fn to_byte(&self) -> u8 {
        let mut flags = 0u8;
        if self.auth {
            flags |= 0x01;
        }
        if self.priv_ {
            flags |= 0x02;
        }
        if self.reportable {
            flags |= 0x04;
        }
        flags
    }

    pub fn from_byte(b: u8) -> Self {
        Self {
            auth: (b & 0x01) != 0,
            priv_: (b & 0x02) != 0,
            reportable: (b & 0x04) != 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SecurityModel {
    Any = 0,
    V1 = 1,
    V2c = 2,
    Usm = 3,
}

impl TryFrom<i64> for SecurityModel {
    type Error = i64;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SecurityModel::Any),
            1 => Ok(SecurityModel::V1),
            2 => Ok(SecurityModel::V2c),
            3 => Ok(SecurityModel::Usm),
            _ => Err(value),
        }
    }
}

// Scoped PDU for SNMPv3 (contains context + PDU)
#[derive(Debug, Clone, PartialEq)]
pub enum ScopedPdu {
    Plaintext {
        context_engine_id: Vec<u8>,
        context_name: Vec<u8>,
        pdu: ScopedPduData,
    },
    Encrypted(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScopedPduData {
    Standard(Pdu),
    Bulk(BulkPdu),
}

impl MessageV3 {
    pub fn new(
        msg_id: i32,
        msg_flags: MsgFlags,
        security_parameters: Vec<u8>,
        context_engine_id: Vec<u8>,
        context_name: Vec<u8>,
        pdu: Pdu,
    ) -> Self {
        Self {
            msg_id,
            msg_max_size: 65507, // max UDP payload
            msg_flags,
            msg_security_model: SecurityModel::Usm,
            security_parameters,
            scoped_pdu: ScopedPdu::Plaintext {
                context_engine_id,
                context_name,
                pdu: ScopedPduData::Standard(pdu),
            },
        }
    }

    pub fn with_bulk(
        msg_id: i32,
        msg_flags: MsgFlags,
        security_parameters: Vec<u8>,
        context_engine_id: Vec<u8>,
        context_name: Vec<u8>,
        pdu: BulkPdu,
    ) -> Self {
        Self {
            msg_id,
            msg_max_size: 65507,
            msg_flags,
            msg_security_model: SecurityModel::Usm,
            security_parameters,
            scoped_pdu: ScopedPdu::Plaintext {
                context_engine_id,
                context_name,
                pdu: ScopedPduData::Bulk(pdu),
            },
        }
    }

    pub fn encrypted(
        msg_id: i32,
        msg_flags: MsgFlags,
        security_parameters: Vec<u8>,
        encrypted_pdu: Vec<u8>,
    ) -> Self {
        Self {
            msg_id,
            msg_max_size: 65507,
            msg_flags,
            msg_security_model: SecurityModel::Usm,
            security_parameters,
            scoped_pdu: ScopedPdu::Encrypted(encrypted_pdu),
        }
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut inner = Vec::new();

        // version (3)
        encode_integer(&mut inner, 3)?;

        // msgGlobalData (SEQUENCE)
        let mut global_data = Vec::new();
        encode_integer(&mut global_data, self.msg_id as i64)?;
        encode_integer(&mut global_data, self.msg_max_size as i64)?;
        // msgFlags as OCTET STRING of length 1
        global_data.write_all(&[0x04, 0x01, self.msg_flags.to_byte()])?;
        encode_integer(&mut global_data, self.msg_security_model as i64)?;
        encode_sequence(&mut inner, &global_data)?;

        // msgSecurityParameters (OCTET STRING wrapping USM data)
        encode_octet_string(&mut inner, &self.security_parameters)?;

        // msgData (ScopedPDU or encrypted)
        match &self.scoped_pdu {
            ScopedPdu::Plaintext {
                context_engine_id,
                context_name,
                pdu,
            } => {
                let mut scoped = Vec::new();
                encode_octet_string(&mut scoped, context_engine_id)?;
                encode_octet_string(&mut scoped, context_name)?;
                match pdu {
                    ScopedPduData::Standard(p) => p.encode(&mut scoped)?,
                    ScopedPduData::Bulk(p) => p.encode(&mut scoped)?,
                }
                encode_sequence(&mut inner, &scoped)?;
            }
            ScopedPdu::Encrypted(data) => {
                // Encrypted ScopedPDU as OCTET STRING
                encode_octet_string(&mut inner, data)?;
            }
        }

        encode_sequence(writer, &inner)
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), BerError> {
        let (inner, total) = decode_sequence(data)?;
        let mut pos = 0;

        // version
        let (version, ver_len) = decode_integer(inner)?;
        if version != 3 {
            return Err(BerError::InvalidTag(version as u8));
        }
        pos += ver_len;

        // msgGlobalData
        let (global_data, gd_len) = decode_sequence(&inner[pos..])?;
        pos += gd_len;

        let mut gd_pos = 0;
        let (msg_id, mid_len) = decode_integer(global_data)?;
        gd_pos += mid_len;
        let (msg_max_size, mms_len) = decode_integer(&global_data[gd_pos..])?;
        gd_pos += mms_len;

        // msgFlags (OCTET STRING of length 1)
        if global_data.len() < gd_pos + 3
            || global_data[gd_pos] != 0x04
            || global_data[gd_pos + 1] != 0x01
        {
            return Err(BerError::InvalidLength);
        }
        let msg_flags = MsgFlags::from_byte(global_data[gd_pos + 2]);
        gd_pos += 3;

        let (security_model_raw, _) = decode_integer(&global_data[gd_pos..])?;
        let msg_security_model =
            SecurityModel::try_from(security_model_raw).unwrap_or(SecurityModel::Usm);

        // msgSecurityParameters
        let (security_parameters, sp_len) = decode_octet_string(&inner[pos..])?;
        pos += sp_len;

        // msgData
        if pos >= inner.len() {
            return Err(BerError::BufferTooShort);
        }

        let scoped_pdu = if inner[pos] == 0x30 {
            // Plaintext ScopedPDU (SEQUENCE)
            let (scoped_inner, _) = decode_sequence(&inner[pos..])?;
            let mut sp_pos = 0;

            let (context_engine_id, cei_len) = decode_octet_string(scoped_inner)?;
            sp_pos += cei_len;
            let (context_name, cn_len) = decode_octet_string(&scoped_inner[sp_pos..])?;
            sp_pos += cn_len;

            let pdu_data = &scoped_inner[sp_pos..];
            let pdu = if !pdu_data.is_empty() && pdu_data[0] == PduType::GetBulkRequest as u8 {
                let (p, _) = BulkPdu::decode(pdu_data)?;
                ScopedPduData::Bulk(p)
            } else {
                let (p, _) = Pdu::decode(pdu_data)?;
                ScopedPduData::Standard(p)
            };

            ScopedPdu::Plaintext {
                context_engine_id,
                context_name,
                pdu,
            }
        } else {
            // Encrypted ScopedPDU (OCTET STRING)
            let (encrypted, _) = decode_octet_string(&inner[pos..])?;
            ScopedPdu::Encrypted(encrypted)
        };

        Ok((
            Self {
                msg_id: msg_id as i32,
                msg_max_size: msg_max_size as i32,
                msg_flags,
                msg_security_model,
                security_parameters,
                scoped_pdu,
            },
            total,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid::Oid;

    #[test]
    fn test_msg_flags() {
        let flags = MsgFlags::auth_priv();
        assert!(flags.auth);
        assert!(flags.priv_);
        assert!(flags.reportable);
        assert_eq!(flags.to_byte(), 0x07);

        let decoded = MsgFlags::from_byte(0x07);
        assert_eq!(decoded, flags);
    }

    #[test]
    fn test_msg_flags_variants() {
        assert_eq!(MsgFlags::no_auth_no_priv().to_byte(), 0x04);
        assert_eq!(MsgFlags::auth_no_priv().to_byte(), 0x05);
        assert_eq!(MsgFlags::auth_priv().to_byte(), 0x07);
    }

    #[test]
    fn test_security_model_conversion() {
        assert_eq!(SecurityModel::try_from(0i64), Ok(SecurityModel::Any));
        assert_eq!(SecurityModel::try_from(3i64), Ok(SecurityModel::Usm));
        assert!(SecurityModel::try_from(99i64).is_err());
    }

    #[test]
    fn test_message_v3_roundtrip() {
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let pdu = Pdu::get_request(12345, vec![oid]);
        let msg = MessageV3::new(
            1,
            MsgFlags::no_auth_no_priv(),
            vec![],
            vec![0x80, 0x00, 0x01, 0x02],
            vec![],
            pdu,
        );

        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();

        let (decoded, _) = MessageV3::decode(&buf).unwrap();
        assert_eq!(decoded.msg_id, 1);
        assert_eq!(decoded.msg_flags, MsgFlags::no_auth_no_priv());
        match decoded.scoped_pdu {
            ScopedPdu::Plaintext {
                context_engine_id,
                pdu,
                ..
            } => {
                assert_eq!(context_engine_id, vec![0x80, 0x00, 0x01, 0x02]);
                match pdu {
                    ScopedPduData::Standard(p) => assert_eq!(p.request_id, 12345),
                    _ => panic!("expected Standard"),
                }
            }
            _ => panic!("expected Plaintext"),
        }
    }

    #[test]
    fn test_message_v3_with_bulk() {
        let oid: Oid = "1.3.6.1.2.1.2.2".parse().unwrap();
        let pdu = BulkPdu::new(99999, 0, 25, vec![oid]);
        let msg = MessageV3::with_bulk(
            42,
            MsgFlags::auth_no_priv(),
            vec![0xAA, 0xBB],
            vec![0x80, 0x00],
            b"context".to_vec(),
            pdu,
        );

        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();

        let (decoded, _) = MessageV3::decode(&buf).unwrap();
        assert_eq!(decoded.msg_id, 42);
        assert_eq!(decoded.msg_flags, MsgFlags::auth_no_priv());
        match decoded.scoped_pdu {
            ScopedPdu::Plaintext { pdu, .. } => match pdu {
                ScopedPduData::Bulk(p) => {
                    assert_eq!(p.request_id, 99999);
                    assert_eq!(p.max_repetitions, 25);
                }
                _ => panic!("expected Bulk"),
            },
            _ => panic!("expected Plaintext"),
        }
    }

    #[test]
    fn test_message_v3_encrypted() {
        let encrypted_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let msg = MessageV3::encrypted(
            123,
            MsgFlags::auth_priv(),
            vec![0x11, 0x22, 0x33],
            encrypted_data.clone(),
        );

        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();

        let (decoded, _) = MessageV3::decode(&buf).unwrap();
        assert_eq!(decoded.msg_id, 123);
        match decoded.scoped_pdu {
            ScopedPdu::Encrypted(data) => assert_eq!(data, encrypted_data),
            _ => panic!("expected Encrypted"),
        }
    }
}
