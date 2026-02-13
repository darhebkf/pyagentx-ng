use std::fmt;

use digest::Digest;
use hmac::{Hmac, Mac};

use super::usm::AuthProtocol;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    InvalidKeyLength,
    VerificationFailed,
    UnsupportedProtocol,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::InvalidKeyLength => write!(f, "invalid key length"),
            AuthError::VerificationFailed => write!(f, "authentication verification failed"),
            AuthError::UnsupportedProtocol => write!(f, "unsupported auth protocol"),
        }
    }
}

impl std::error::Error for AuthError {}

// Password to key using hash algorithm (RFC 3414 A.2.1)
//
// Repeats password to fill 1MB (1,048,576 bytes), then hashes.
pub fn password_to_key(password: &[u8], protocol: AuthProtocol) -> Result<Vec<u8>, AuthError> {
    if protocol == AuthProtocol::None {
        return Err(AuthError::UnsupportedProtocol);
    }

    const COUNT: usize = 1_048_576;

    match protocol {
        AuthProtocol::Md5 => Ok(password_to_key_hash::<md5::Md5>(password, COUNT)),
        AuthProtocol::Sha => Ok(password_to_key_hash::<sha1::Sha1>(password, COUNT)),
        AuthProtocol::Sha224 => Ok(password_to_key_hash::<sha2::Sha224>(password, COUNT)),
        AuthProtocol::Sha256 => Ok(password_to_key_hash::<sha2::Sha256>(password, COUNT)),
        AuthProtocol::Sha384 => Ok(password_to_key_hash::<sha2::Sha384>(password, COUNT)),
        AuthProtocol::Sha512 => Ok(password_to_key_hash::<sha2::Sha512>(password, COUNT)),
        AuthProtocol::None => unreachable!(),
    }
}

fn password_to_key_hash<D: Digest>(password: &[u8], count: usize) -> Vec<u8> {
    let mut hasher = D::new();
    let password_len = password.len();
    let mut remaining = count;
    let mut index = 0;

    // Feed password bytes repeatedly until count bytes processed
    while remaining > 0 {
        let mut buf = [0u8; 64];
        for b in &mut buf {
            *b = password[index % password_len];
            index += 1;
        }
        let chunk = buf.len().min(remaining);
        hasher.update(&buf[..chunk]);
        remaining -= chunk;
    }

    hasher.finalize().to_vec()
}

// Localize key with engine ID (RFC 3414 A.2.2)
//
// Hash(key || engine_id || key)
pub fn localize_key(
    key: &[u8],
    engine_id: &[u8],
    protocol: AuthProtocol,
) -> Result<Vec<u8>, AuthError> {
    if protocol == AuthProtocol::None {
        return Err(AuthError::UnsupportedProtocol);
    }

    match protocol {
        AuthProtocol::Md5 => Ok(localize_hash::<md5::Md5>(key, engine_id)),
        AuthProtocol::Sha => Ok(localize_hash::<sha1::Sha1>(key, engine_id)),
        AuthProtocol::Sha224 => Ok(localize_hash::<sha2::Sha224>(key, engine_id)),
        AuthProtocol::Sha256 => Ok(localize_hash::<sha2::Sha256>(key, engine_id)),
        AuthProtocol::Sha384 => Ok(localize_hash::<sha2::Sha384>(key, engine_id)),
        AuthProtocol::Sha512 => Ok(localize_hash::<sha2::Sha512>(key, engine_id)),
        AuthProtocol::None => unreachable!(),
    }
}

fn localize_hash<D: Digest>(key: &[u8], engine_id: &[u8]) -> Vec<u8> {
    let mut hasher = D::new();
    hasher.update(key);
    hasher.update(engine_id);
    hasher.update(key);
    hasher.finalize().to_vec()
}

// Combined: password to localized key
pub fn password_to_localized_key(
    password: &[u8],
    engine_id: &[u8],
    protocol: AuthProtocol,
) -> Result<Vec<u8>, AuthError> {
    let key = password_to_key(password, protocol)?;
    localize_key(&key, engine_id, protocol)
}

// Authenticate outgoing message (RFC 3414 Section 6)
//
// 1. Zero out auth_parameters field
// 2. Calculate HMAC over entire message
// 3. Truncate to protocol-specific length
// 4. Write truncated HMAC to auth_parameters field
pub fn authenticate_message(
    message: &mut [u8],
    auth_params_offset: usize,
    key: &[u8],
    protocol: AuthProtocol,
) -> Result<(), AuthError> {
    if protocol == AuthProtocol::None {
        return Err(AuthError::UnsupportedProtocol);
    }

    let digest_len = protocol.digest_length();

    // Zero out auth_parameters
    for byte in &mut message[auth_params_offset..auth_params_offset + digest_len] {
        *byte = 0;
    }

    let mac = compute_hmac(key, message, protocol)?;

    message[auth_params_offset..auth_params_offset + digest_len]
        .copy_from_slice(&mac[..digest_len]);

    Ok(())
}

// Verify incoming message authentication (RFC 3414 Section 6)
//
// 1. Extract auth_parameters
// 2. Zero out auth_parameters in copy
// 3. Calculate HMAC
// 4. Compare with extracted value
pub fn verify_authentication(
    message: &[u8],
    auth_params_offset: usize,
    key: &[u8],
    protocol: AuthProtocol,
) -> Result<(), AuthError> {
    if protocol == AuthProtocol::None {
        return Err(AuthError::UnsupportedProtocol);
    }

    let digest_len = protocol.digest_length();

    let received = message[auth_params_offset..auth_params_offset + digest_len].to_vec();

    let mut msg_copy = message.to_vec();
    for byte in &mut msg_copy[auth_params_offset..auth_params_offset + digest_len] {
        *byte = 0;
    }

    let mac = compute_hmac(key, &msg_copy, protocol)?;

    if received[..] != mac[..digest_len] {
        return Err(AuthError::VerificationFailed);
    }

    Ok(())
}

fn compute_hmac(key: &[u8], data: &[u8], protocol: AuthProtocol) -> Result<Vec<u8>, AuthError> {
    macro_rules! hmac_compute {
        ($hasher:ty, $key:expr, $data:expr) => {{
            let mut mac =
                Hmac::<$hasher>::new_from_slice($key).map_err(|_| AuthError::InvalidKeyLength)?;
            mac.update($data);
            Ok(mac.finalize().into_bytes().to_vec())
        }};
    }

    match protocol {
        AuthProtocol::Md5 => hmac_compute!(md5::Md5, key, data),
        AuthProtocol::Sha => hmac_compute!(sha1::Sha1, key, data),
        AuthProtocol::Sha224 => hmac_compute!(sha2::Sha224, key, data),
        AuthProtocol::Sha256 => hmac_compute!(sha2::Sha256, key, data),
        AuthProtocol::Sha384 => hmac_compute!(sha2::Sha384, key, data),
        AuthProtocol::Sha512 => hmac_compute!(sha2::Sha512, key, data),
        AuthProtocol::None => Err(AuthError::UnsupportedProtocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // RFC 3414 A.3.1 - Password to key for MD5
    #[test]
    fn test_password_to_key_md5() {
        let key = password_to_key(b"maplesyrup", AuthProtocol::Md5).unwrap();
        assert_eq!(key, hex!("9faf3283884e92834ebc9847d8edd963"));
    }

    // RFC 3414 A.3.1 - Password to key for SHA
    #[test]
    fn test_password_to_key_sha() {
        let key = password_to_key(b"maplesyrup", AuthProtocol::Sha).unwrap();
        assert_eq!(key, hex!("9fb5cc0381497b3793528939ff788d5d79145211"));
    }

    // RFC 3414 A.3.2 - Key localization for MD5
    #[test]
    fn test_localize_key_md5() {
        let key = hex!("9faf3283884e92834ebc9847d8edd963");
        let engine_id = hex!("000000000000000000000002");
        let localized = localize_key(&key, &engine_id, AuthProtocol::Md5).unwrap();
        assert_eq!(localized, hex!("526f5eed9fcce26f8964c2930787d82b"));
    }

    // RFC 3414 A.3.2 - Key localization for SHA
    #[test]
    fn test_localize_key_sha() {
        let key = hex!("9fb5cc0381497b3793528939ff788d5d79145211");
        let engine_id = hex!("000000000000000000000002");
        let localized = localize_key(&key, &engine_id, AuthProtocol::Sha).unwrap();
        assert_eq!(localized, hex!("6695febc9288e36282235fc7151f128497b38f3f"));
    }

    // Combined password to localized key for MD5
    #[test]
    fn test_password_to_localized_key_md5() {
        let engine_id = hex!("000000000000000000000002");
        let localized =
            password_to_localized_key(b"maplesyrup", &engine_id, AuthProtocol::Md5).unwrap();
        assert_eq!(localized, hex!("526f5eed9fcce26f8964c2930787d82b"));
    }

    // Combined password to localized key for SHA
    #[test]
    fn test_password_to_localized_key_sha() {
        let engine_id = hex!("000000000000000000000002");
        let localized =
            password_to_localized_key(b"maplesyrup", &engine_id, AuthProtocol::Sha).unwrap();
        assert_eq!(localized, hex!("6695febc9288e36282235fc7151f128497b38f3f"));
    }

    #[test]
    fn test_authenticate_and_verify_md5() {
        let key = hex!("526f5eed9fcce26f8964c2930787d82b");
        let mut message = vec![0u8; 64];
        message[0..4].copy_from_slice(&[0x30, 0x3E, 0x02, 0x01]);
        let auth_offset = 20;

        authenticate_message(&mut message, auth_offset, &key, AuthProtocol::Md5).unwrap();

        // Auth params should be filled
        assert_ne!(&message[auth_offset..auth_offset + 12], &[0u8; 12]);

        // Verify should pass
        verify_authentication(&message, auth_offset, &key, AuthProtocol::Md5).unwrap();

        // Tamper and verify should fail
        message[0] ^= 0xFF;
        assert!(verify_authentication(&message, auth_offset, &key, AuthProtocol::Md5).is_err());
    }

    #[test]
    fn test_authenticate_and_verify_sha256() {
        let key = vec![0x42u8; 32];
        let mut message = vec![0u8; 128];
        message[0..4].copy_from_slice(&[0x30, 0x7E, 0x02, 0x01]);
        let auth_offset = 40;

        authenticate_message(&mut message, auth_offset, &key, AuthProtocol::Sha256).unwrap();

        assert_ne!(&message[auth_offset..auth_offset + 24], &[0u8; 24]);

        verify_authentication(&message, auth_offset, &key, AuthProtocol::Sha256).unwrap();
    }

    #[test]
    fn test_none_protocol_returns_error() {
        assert!(password_to_key(b"test", AuthProtocol::None).is_err());
        assert!(localize_key(&[0; 16], &[0; 12], AuthProtocol::None).is_err());
    }
}
