use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use aes::{Aes128, Aes192, Aes256};
use cipher::block_padding::NoPadding;
use cipher::{
    AsyncStreamCipher, BlockCipher, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit,
};

use super::usm::PrivProtocol;

static SALT_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivError {
    InvalidKeyLength,
    InvalidData,
    UnsupportedProtocol,
    EncryptionFailed,
    DecryptionFailed,
}

impl fmt::Display for PrivError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivError::InvalidKeyLength => write!(f, "invalid key length"),
            PrivError::InvalidData => write!(f, "invalid data"),
            PrivError::UnsupportedProtocol => write!(f, "unsupported priv protocol"),
            PrivError::EncryptionFailed => write!(f, "encryption failed"),
            PrivError::DecryptionFailed => write!(f, "decryption failed"),
        }
    }
}

impl std::error::Error for PrivError {}

// Encrypt scoped PDU
//
// Returns (ciphertext, priv_parameters)
pub fn encrypt_scoped_pdu(
    plaintext: &[u8],
    key: &[u8],
    engine_boots: i32,
    engine_time: i32,
    protocol: PrivProtocol,
) -> Result<(Vec<u8>, Vec<u8>), PrivError> {
    match protocol {
        PrivProtocol::Des => encrypt_des_cbc(plaintext, key, engine_boots),
        PrivProtocol::Aes128 => {
            encrypt_aes_cfb::<Aes128>(plaintext, key, engine_boots, engine_time)
        }
        PrivProtocol::Aes192 => {
            encrypt_aes_cfb::<Aes192>(plaintext, key, engine_boots, engine_time)
        }
        PrivProtocol::Aes256 => {
            encrypt_aes_cfb::<Aes256>(plaintext, key, engine_boots, engine_time)
        }
        PrivProtocol::None => Ok((plaintext.to_vec(), vec![])),
    }
}

// Decrypt scoped PDU
pub fn decrypt_scoped_pdu(
    ciphertext: &[u8],
    key: &[u8],
    priv_parameters: &[u8],
    engine_boots: i32,
    engine_time: i32,
    protocol: PrivProtocol,
) -> Result<Vec<u8>, PrivError> {
    match protocol {
        PrivProtocol::Des => decrypt_des_cbc(ciphertext, key, priv_parameters),
        PrivProtocol::Aes128 => {
            decrypt_aes_cfb::<Aes128>(ciphertext, key, priv_parameters, engine_boots, engine_time)
        }
        PrivProtocol::Aes192 => {
            decrypt_aes_cfb::<Aes192>(ciphertext, key, priv_parameters, engine_boots, engine_time)
        }
        PrivProtocol::Aes256 => {
            decrypt_aes_cfb::<Aes256>(ciphertext, key, priv_parameters, engine_boots, engine_time)
        }
        PrivProtocol::None => Ok(ciphertext.to_vec()),
    }
}

// DES-CBC encryption (RFC 3414 Section 8.1)
//
// key: 16 bytes - first 8 = DES key, last 8 = pre-IV
// priv_parameters = salt (8 bytes)
// IV = pre-IV XOR salt
fn encrypt_des_cbc(
    plaintext: &[u8],
    key: &[u8],
    engine_boots: i32,
) -> Result<(Vec<u8>, Vec<u8>), PrivError> {
    if key.len() < 16 {
        return Err(PrivError::InvalidKeyLength);
    }

    let des_key = &key[..8];
    let pre_iv = &key[8..16];

    // Generate salt: engine_boots (4 bytes) || counter (4 bytes)
    let counter = SALT_COUNTER.fetch_add(1, Ordering::Relaxed) as u32;
    let mut salt = [0u8; 8];
    salt[..4].copy_from_slice(&engine_boots.to_be_bytes());
    salt[4..].copy_from_slice(&counter.to_be_bytes());

    // IV = pre-IV XOR salt
    let mut iv = [0u8; 8];
    for i in 0..8 {
        iv[i] = pre_iv[i] ^ salt[i];
    }

    // Pad plaintext to 8-byte boundary
    let padded = pad_to_block_size(plaintext, 8);

    // Encrypt with DES-CBC
    type DesCbcEnc = cbc::Encryptor<des::Des>;
    let encryptor =
        DesCbcEnc::new_from_slices(des_key, &iv).map_err(|_| PrivError::InvalidKeyLength)?;

    let mut buf = padded.clone();
    let ciphertext = encryptor
        .encrypt_padded_mut::<NoPadding>(&mut buf, padded.len())
        .map_err(|_| PrivError::EncryptionFailed)?
        .to_vec();

    Ok((ciphertext, salt.to_vec()))
}

// DES-CBC decryption (RFC 3414 Section 8.1)
fn decrypt_des_cbc(
    ciphertext: &[u8],
    key: &[u8],
    priv_parameters: &[u8],
) -> Result<Vec<u8>, PrivError> {
    if key.len() < 16 {
        return Err(PrivError::InvalidKeyLength);
    }
    if priv_parameters.len() != 8 {
        return Err(PrivError::InvalidData);
    }

    let des_key = &key[..8];
    let pre_iv = &key[8..16];

    // IV = pre-IV XOR salt
    let mut iv = [0u8; 8];
    for i in 0..8 {
        iv[i] = pre_iv[i] ^ priv_parameters[i];
    }

    type DesCbcDec = cbc::Decryptor<des::Des>;
    let decryptor =
        DesCbcDec::new_from_slices(des_key, &iv).map_err(|_| PrivError::InvalidKeyLength)?;

    let mut buf = ciphertext.to_vec();
    let plaintext = decryptor
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| PrivError::DecryptionFailed)?
        .to_vec();

    Ok(plaintext)
}

// AES-CFB encryption (RFC 3826)
//
// IV = engine_boots (4 bytes) || engine_time (4 bytes) || local (8 bytes)
// priv_parameters = local (8 bytes)
fn encrypt_aes_cfb<C>(
    plaintext: &[u8],
    key: &[u8],
    engine_boots: i32,
    engine_time: i32,
) -> Result<(Vec<u8>, Vec<u8>), PrivError>
where
    C: BlockEncryptMut + BlockCipher + KeyInit,
{
    let key_length = C::key_size();
    if key.len() < key_length {
        return Err(PrivError::InvalidKeyLength);
    }

    // Generate 64-bit local integer (counter)
    let local = SALT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let local_bytes = local.to_be_bytes();

    // IV = engine_boots (4) || engine_time (4) || local (8)
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&engine_boots.to_be_bytes());
    iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
    iv[8..].copy_from_slice(&local_bytes);

    let mut ciphertext = plaintext.to_vec();
    cfb_mode::Encryptor::<C>::new_from_slices(&key[..key_length], &iv)
        .map_err(|_| PrivError::InvalidKeyLength)?
        .encrypt_b2b(plaintext, &mut ciphertext)
        .map_err(|_| PrivError::EncryptionFailed)?;

    Ok((ciphertext, local_bytes.to_vec()))
}

// AES-CFB decryption (RFC 3826)
fn decrypt_aes_cfb<C>(
    ciphertext: &[u8],
    key: &[u8],
    priv_parameters: &[u8],
    engine_boots: i32,
    engine_time: i32,
) -> Result<Vec<u8>, PrivError>
where
    C: BlockEncryptMut + BlockCipher + KeyInit,
{
    let key_length = C::key_size();
    if key.len() < key_length {
        return Err(PrivError::InvalidKeyLength);
    }
    if priv_parameters.len() != 8 {
        return Err(PrivError::InvalidData);
    }

    // IV = engine_boots (4) || engine_time (4) || local (8)
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&engine_boots.to_be_bytes());
    iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
    iv[8..].copy_from_slice(priv_parameters);

    let mut plaintext = ciphertext.to_vec();
    cfb_mode::Decryptor::<C>::new_from_slices(&key[..key_length], &iv)
        .map_err(|_| PrivError::InvalidKeyLength)?
        .decrypt_b2b(ciphertext, &mut plaintext)
        .map_err(|_| PrivError::DecryptionFailed)?;

    Ok(plaintext)
}

fn pad_to_block_size(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding = if data.len().is_multiple_of(block_size) {
        0
    } else {
        block_size - (data.len() % block_size)
    };
    let mut padded = data.to_vec();
    padded.resize(data.len() + padding, 0);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_des_cbc_roundtrip() {
        let key = [0x42u8; 16]; // first 8 = DES key, last 8 = pre-IV
        let plaintext = b"Hello SNMP World!"; // 17 bytes, will be padded

        let (ciphertext, salt) = encrypt_des_cbc(plaintext, &key, 100).unwrap();
        assert_eq!(salt.len(), 8);
        assert_ne!(ciphertext, plaintext);

        let decrypted = decrypt_des_cbc(&ciphertext, &key, &salt).unwrap();
        // Decrypted has padding, check prefix matches
        assert_eq!(&decrypted[..plaintext.len()], &plaintext[..]);
    }

    #[test]
    fn test_aes_cfb_roundtrip() {
        let key = [0x42u8; 16];
        let plaintext = b"Hello SNMP World!";

        let (ciphertext, priv_params) =
            encrypt_aes_cfb::<Aes128>(plaintext, &key, 100, 200).unwrap();
        assert_eq!(priv_params.len(), 8);
        assert_ne!(ciphertext, plaintext);

        let decrypted =
            decrypt_aes_cfb::<Aes128>(&ciphertext, &key, &priv_params, 100, 200).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_scoped_pdu_des() {
        let key = [0x42u8; 16];
        let plaintext = vec![0x30, 0x0E, 0x04, 0x00, 0x04, 0x00, 0xA0, 0x08];

        let (ciphertext, priv_params) =
            encrypt_scoped_pdu(&plaintext, &key, 1, 100, PrivProtocol::Des).unwrap();
        let decrypted =
            decrypt_scoped_pdu(&ciphertext, &key, &priv_params, 1, 100, PrivProtocol::Des).unwrap();
        assert_eq!(&decrypted[..plaintext.len()], &plaintext[..]);
    }

    #[test]
    fn test_encrypt_decrypt_scoped_pdu_aes128() {
        let key = [0x42u8; 16];
        let plaintext = vec![0x30, 0x0E, 0x04, 0x00, 0x04, 0x00, 0xA0, 0x08];

        let (ciphertext, priv_params) =
            encrypt_scoped_pdu(&plaintext, &key, 1, 100, PrivProtocol::Aes128).unwrap();
        let decrypted = decrypt_scoped_pdu(
            &ciphertext,
            &key,
            &priv_params,
            1,
            100,
            PrivProtocol::Aes128,
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_scoped_pdu_aes192() {
        let plaintext = b"scoped pdu contents".to_vec();
        let key = vec![0x42u8; 24];

        let (ciphertext, priv_params) =
            encrypt_scoped_pdu(&plaintext, &key, 1, 100, PrivProtocol::Aes192).unwrap();
        let decrypted = decrypt_scoped_pdu(
            &ciphertext,
            &key,
            &priv_params,
            1,
            100,
            PrivProtocol::Aes192,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_scoped_pdu_aes256() {
        let plaintext = b"scoped pdu contents".to_vec();
        let key = vec![0x42u8; 32];

        let (ciphertext, priv_params) =
            encrypt_scoped_pdu(&plaintext, &key, 1, 100, PrivProtocol::Aes256).unwrap();
        let decrypted = decrypt_scoped_pdu(
            &ciphertext,
            &key,
            &priv_params,
            1,
            100,
            PrivProtocol::Aes256,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    // AES-192 and AES-256 must use the whole key, not the first 16 bytes
    #[test]
    fn test_longer_keys_are_not_truncated_to_aes128() {
        let plaintext = b"scoped pdu contents".to_vec();
        let mut key = vec![0x42u8; 32];

        let (ciphertext, priv_params) =
            encrypt_scoped_pdu(&plaintext, &key, 1, 100, PrivProtocol::Aes256).unwrap();

        key[16..].fill(0x43);
        let decrypted = decrypt_scoped_pdu(
            &ciphertext,
            &key,
            &priv_params,
            1,
            100,
            PrivProtocol::Aes256,
        )
        .unwrap();

        assert_ne!(decrypted, plaintext);
    }

    #[test]
    fn test_aes192_and_aes256_reject_short_keys() {
        assert!(encrypt_scoped_pdu(b"test", &[0u8; 16], 0, 0, PrivProtocol::Aes192).is_err());
        assert!(encrypt_scoped_pdu(b"test", &[0u8; 24], 0, 0, PrivProtocol::Aes256).is_err());
    }

    #[test]
    fn test_none_protocol_passthrough() {
        let plaintext = b"no encryption";
        let (ciphertext, params) =
            encrypt_scoped_pdu(plaintext, &[], 0, 0, PrivProtocol::None).unwrap();
        assert_eq!(ciphertext, plaintext);
        assert!(params.is_empty());
    }

    #[test]
    fn test_des_invalid_key_length() {
        assert!(encrypt_des_cbc(b"test", &[0u8; 8], 0).is_err());
    }

    #[test]
    fn test_aes_invalid_key_length() {
        assert!(encrypt_aes_cfb::<Aes128>(b"test", &[0u8; 8], 0, 0).is_err());
    }

    #[test]
    fn test_des_invalid_priv_parameters() {
        assert!(decrypt_des_cbc(b"test", &[0u8; 16], &[0u8; 4]).is_err());
    }

    #[test]
    fn test_pad_to_block_size() {
        assert_eq!(pad_to_block_size(b"12345678", 8).len(), 8);
        assert_eq!(pad_to_block_size(b"123456789", 8).len(), 16);
        assert_eq!(pad_to_block_size(b"", 8).len(), 0);
    }
}
