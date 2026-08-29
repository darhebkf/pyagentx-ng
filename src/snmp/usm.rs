use std::io::{self, Write};

use crate::asn1::BerError;
use crate::asn1::ber::{
    decode_integer, decode_octet_string, decode_sequence, encode_integer, encode_octet_string,
    encode_sequence,
};

// Authentication protocols (RFC 3414, RFC 7860)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProtocol {
    None,
    Md5,    // HMAC-MD5-96 (RFC 3414)
    Sha,    // HMAC-SHA-96 (RFC 3414)
    Sha224, // HMAC-SHA-224 (RFC 7860)
    Sha256, // HMAC-SHA-256 (RFC 7860)
    Sha384, // HMAC-SHA-384 (RFC 7860)
    Sha512, // HMAC-SHA-512 (RFC 7860)
}

impl AuthProtocol {
    pub fn digest_length(&self) -> usize {
        match self {
            AuthProtocol::None => 0,
            AuthProtocol::Md5 => 12,    // truncated to 96 bits
            AuthProtocol::Sha => 12,    // truncated to 96 bits
            AuthProtocol::Sha224 => 16, // truncated to 128 bits
            AuthProtocol::Sha256 => 24, // truncated to 192 bits
            AuthProtocol::Sha384 => 32, // truncated to 256 bits
            AuthProtocol::Sha512 => 48, // truncated to 384 bits
        }
    }

    pub fn key_length(&self) -> usize {
        match self {
            AuthProtocol::None => 0,
            AuthProtocol::Md5 => 16,
            AuthProtocol::Sha => 20,
            AuthProtocol::Sha224 => 28,
            AuthProtocol::Sha256 => 32,
            AuthProtocol::Sha384 => 48,
            AuthProtocol::Sha512 => 64,
        }
    }
}

// Privacy protocols (RFC 3414, RFC 3826)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivProtocol {
    None,
    Des,    // CBC-DES (RFC 3414)
    Aes128, // CFB128-AES-128 (RFC 3826)
    Aes192, // CFB128-AES-192 (RFC 3826)
    Aes256, // CFB128-AES-256 (RFC 3826)
}

impl PrivProtocol {
    pub fn key_length(&self) -> usize {
        match self {
            PrivProtocol::None => 0,
            PrivProtocol::Des => 8,
            PrivProtocol::Aes128 => 16,
            PrivProtocol::Aes192 => 24,
            PrivProtocol::Aes256 => 32,
        }
    }

    // Key material USM derives before the cipher takes its key
    //
    // DES needs 16 bytes, 8 for the key and 8 for the pre-IV (RFC 3414 8.1.1.1).
    // AES takes the first key_length() bytes (draft-blumenthal-aes-usm-04 3.1.2.1).
    pub fn derived_key_length(&self) -> usize {
        match self {
            PrivProtocol::None => 0,
            PrivProtocol::Des => 16,
            PrivProtocol::Aes128 => 16,
            PrivProtocol::Aes192 => 24,
            PrivProtocol::Aes256 => 32,
        }
    }

    pub fn iv_length(&self) -> usize {
        match self {
            PrivProtocol::None => 0,
            PrivProtocol::Des => 8,
            PrivProtocol::Aes128 | PrivProtocol::Aes192 | PrivProtocol::Aes256 => 16,
        }
    }
}

// USM security parameters (RFC 3414 section 2.4)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UsmSecurityParameters {
    pub authoritative_engine_id: Vec<u8>,
    pub authoritative_engine_boots: i32,
    pub authoritative_engine_time: i32,
    pub user_name: Vec<u8>,
    pub auth_parameters: Vec<u8>,
    pub priv_parameters: Vec<u8>,
}

impl UsmSecurityParameters {
    pub fn new(
        engine_id: Vec<u8>,
        engine_boots: i32,
        engine_time: i32,
        user_name: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            authoritative_engine_id: engine_id,
            authoritative_engine_boots: engine_boots,
            authoritative_engine_time: engine_time,
            user_name: user_name.into(),
            auth_parameters: Vec::new(),
            priv_parameters: Vec::new(),
        }
    }

    pub fn with_auth(mut self, auth_params: Vec<u8>) -> Self {
        self.auth_parameters = auth_params;
        self
    }

    pub fn with_priv(mut self, priv_params: Vec<u8>) -> Self {
        self.priv_parameters = priv_params;
        self
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut inner = Vec::new();

        encode_octet_string(&mut inner, &self.authoritative_engine_id)?;
        encode_integer(&mut inner, self.authoritative_engine_boots as i64)?;
        encode_integer(&mut inner, self.authoritative_engine_time as i64)?;
        encode_octet_string(&mut inner, &self.user_name)?;
        encode_octet_string(&mut inner, &self.auth_parameters)?;
        encode_octet_string(&mut inner, &self.priv_parameters)?;

        encode_sequence(writer, &inner)
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), BerError> {
        let (inner, total) = decode_sequence(data)?;
        let mut pos = 0;

        let (authoritative_engine_id, len) = decode_octet_string(inner)?;
        pos += len;

        let (authoritative_engine_boots, len) = decode_integer(&inner[pos..])?;
        pos += len;

        let (authoritative_engine_time, len) = decode_integer(&inner[pos..])?;
        pos += len;

        let (user_name, len) = decode_octet_string(&inner[pos..])?;
        pos += len;

        let (auth_parameters, len) = decode_octet_string(&inner[pos..])?;
        pos += len;

        let (priv_parameters, _) = decode_octet_string(&inner[pos..])?;

        Ok((
            Self {
                authoritative_engine_id,
                authoritative_engine_boots: authoritative_engine_boots as i32,
                authoritative_engine_time: authoritative_engine_time as i32,
                user_name,
                auth_parameters,
                priv_parameters,
            },
            total,
        ))
    }

    // Encode to bytes (for use in msgSecurityParameters field)
    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.encode(&mut buf)?;
        Ok(buf)
    }
}

// User credentials for SNMPv3
#[derive(Debug, Clone)]
pub struct UsmUser {
    pub user_name: Vec<u8>,
    pub auth_protocol: AuthProtocol,
    pub auth_key: Vec<u8>,
    pub priv_protocol: PrivProtocol,
    pub priv_key: Vec<u8>,
}

impl UsmUser {
    pub fn new(user_name: impl Into<Vec<u8>>) -> Self {
        Self {
            user_name: user_name.into(),
            auth_protocol: AuthProtocol::None,
            auth_key: Vec::new(),
            priv_protocol: PrivProtocol::None,
            priv_key: Vec::new(),
        }
    }

    pub fn with_auth(mut self, protocol: AuthProtocol, key: Vec<u8>) -> Self {
        self.auth_protocol = protocol;
        self.auth_key = key;
        self
    }

    pub fn with_priv(mut self, protocol: PrivProtocol, key: Vec<u8>) -> Self {
        self.priv_protocol = protocol;
        self.priv_key = key;
        self
    }

    pub fn has_auth(&self) -> bool {
        self.auth_protocol != AuthProtocol::None && !self.auth_key.is_empty()
    }

    pub fn has_priv(&self) -> bool {
        self.priv_protocol != PrivProtocol::None && !self.priv_key.is_empty()
    }
}

// Engine ID (RFC 3411 section 5)
#[derive(Debug, Clone, PartialEq)]
pub struct EngineId(pub Vec<u8>);

impl EngineId {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    // Create from enterprise number and format (RFC 3411 section 5)
    pub fn from_enterprise(enterprise: u32, format: u8, data: &[u8]) -> Self {
        let mut engine_id = Vec::with_capacity(5 + data.len());
        // First 4 bytes: enterprise number with high bit set
        let ent = enterprise | 0x80000000;
        engine_id.extend_from_slice(&ent.to_be_bytes());
        // Format byte
        engine_id.push(format);
        // Format-specific data
        engine_id.extend_from_slice(data);
        Self(engine_id)
    }

    // Create from IPv4 address (format 1)
    pub fn from_ipv4(enterprise: u32, addr: [u8; 4]) -> Self {
        Self::from_enterprise(enterprise, 1, &addr)
    }

    // Create from IPv6 address (format 2)
    pub fn from_ipv6(enterprise: u32, addr: [u8; 16]) -> Self {
        Self::from_enterprise(enterprise, 2, &addr)
    }

    // Create from MAC address (format 3)
    pub fn from_mac(enterprise: u32, mac: [u8; 6]) -> Self {
        Self::from_enterprise(enterprise, 3, &mac)
    }

    // Create from text (format 4)
    pub fn from_text(enterprise: u32, text: &[u8]) -> Self {
        let truncated: Vec<u8> = text.iter().take(27).copied().collect();
        Self::from_enterprise(enterprise, 4, &truncated)
    }

    // Create from octets (format 5)
    pub fn from_octets(enterprise: u32, octets: &[u8]) -> Self {
        let truncated: Vec<u8> = octets.iter().take(27).copied().collect();
        Self::from_enterprise(enterprise, 5, &truncated)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_protocol_lengths() {
        assert_eq!(AuthProtocol::Md5.digest_length(), 12);
        assert_eq!(AuthProtocol::Sha.digest_length(), 12);
        assert_eq!(AuthProtocol::Sha256.digest_length(), 24);
        assert_eq!(AuthProtocol::Sha512.digest_length(), 48);
    }

    #[test]
    fn test_priv_protocol_lengths() {
        assert_eq!(PrivProtocol::Des.key_length(), 8);
        assert_eq!(PrivProtocol::Aes128.key_length(), 16);
        assert_eq!(PrivProtocol::Aes256.key_length(), 32);
        assert_eq!(PrivProtocol::Des.derived_key_length(), 16);
        assert_eq!(PrivProtocol::Aes192.derived_key_length(), 24);
        assert_eq!(PrivProtocol::Aes256.derived_key_length(), 32);
    }

    #[test]
    fn test_usm_security_parameters_roundtrip() {
        let params =
            UsmSecurityParameters::new(vec![0x80, 0x00, 0x01, 0x02], 100, 12345, b"testuser")
                .with_auth(vec![0; 12])
                .with_priv(vec![0; 8]);

        let mut buf = Vec::new();
        params.encode(&mut buf).unwrap();

        let (decoded, _) = UsmSecurityParameters::decode(&buf).unwrap();
        assert_eq!(
            decoded.authoritative_engine_id,
            vec![0x80, 0x00, 0x01, 0x02]
        );
        assert_eq!(decoded.authoritative_engine_boots, 100);
        assert_eq!(decoded.authoritative_engine_time, 12345);
        assert_eq!(decoded.user_name, b"testuser");
        assert_eq!(decoded.auth_parameters.len(), 12);
        assert_eq!(decoded.priv_parameters.len(), 8);
    }

    #[test]
    fn test_usm_user() {
        let user = UsmUser::new(b"admin")
            .with_auth(AuthProtocol::Sha256, vec![0; 32])
            .with_priv(PrivProtocol::Aes128, vec![0; 16]);

        assert!(user.has_auth());
        assert!(user.has_priv());
        assert_eq!(user.user_name, b"admin");
    }

    #[test]
    fn test_engine_id_from_ipv4() {
        let engine_id = EngineId::from_ipv4(12345, [192, 168, 1, 1]);
        let bytes = engine_id.as_bytes();

        // First 4 bytes: enterprise with high bit set
        let ent = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(ent, 12345 | 0x80000000);
        // Format byte
        assert_eq!(bytes[4], 1);
        // IPv4 address
        assert_eq!(&bytes[5..], &[192, 168, 1, 1]);
    }

    #[test]
    fn test_engine_id_from_mac() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let engine_id = EngineId::from_mac(9999, mac);
        let bytes = engine_id.as_bytes();

        assert_eq!(bytes[4], 3); // format 3 = MAC
        assert_eq!(&bytes[5..], &mac);
    }
}
