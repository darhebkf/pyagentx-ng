use std::io::{self, Write};

use crate::oid::Oid;

use super::BerError;

// Length encoding

pub fn encode_length<W: Write>(writer: &mut W, len: usize) -> io::Result<()> {
    if len < 128 {
        writer.write_all(&[len as u8])
    } else if len <= 0xFF {
        writer.write_all(&[0x81, len as u8])
    } else if len <= 0xFFFF {
        writer.write_all(&[0x82, (len >> 8) as u8, len as u8])
    } else if len <= 0xFFFFFF {
        writer.write_all(&[0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8])
    } else {
        writer.write_all(&[
            0x84,
            (len >> 24) as u8,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ])
    }
}

pub fn decode_length(data: &[u8]) -> Result<(usize, usize), BerError> {
    if data.is_empty() {
        return Err(BerError::BufferTooShort);
    }

    let first = data[0];
    if first < 128 {
        Ok((first as usize, 1))
    } else {
        let num_octets = (first & 0x7F) as usize;
        if num_octets == 0 || num_octets > 4 {
            return Err(BerError::InvalidLength);
        }
        if data.len() < 1 + num_octets {
            return Err(BerError::BufferTooShort);
        }

        let mut len = 0usize;
        for i in 0..num_octets {
            len = len.checked_shl(8).ok_or(BerError::Overflow)?;
            len |= data[1 + i] as usize;
        }
        Ok((len, 1 + num_octets))
    }
}

// Integer encoding (two's complement, minimal bytes)

pub fn encode_integer<W: Write>(writer: &mut W, value: i64) -> io::Result<()> {
    let bytes = value.to_be_bytes();

    // Find first significant byte
    let start = if value >= 0 {
        let mut i = 0;
        while i < 7 && bytes[i] == 0 && (bytes[i + 1] & 0x80) == 0 {
            i += 1;
        }
        i
    } else {
        let mut i = 0;
        while i < 7 && bytes[i] == 0xFF && (bytes[i + 1] & 0x80) != 0 {
            i += 1;
        }
        i
    };

    let data = &bytes[start..];
    writer.write_all(&[0x02])?; // INTEGER tag
    encode_length(writer, data.len())?;
    writer.write_all(data)
}

pub fn decode_integer(data: &[u8]) -> Result<(i64, usize), BerError> {
    if data.is_empty() {
        return Err(BerError::BufferTooShort);
    }
    if data[0] != 0x02 {
        return Err(BerError::InvalidTag(data[0]));
    }

    let (len, len_bytes) = decode_length(&data[1..])?;
    let start = 1 + len_bytes;
    let end = start + len;

    if data.len() < end {
        return Err(BerError::BufferTooShort);
    }
    if len == 0 || len > 8 {
        return Err(BerError::Overflow);
    }

    let int_bytes = &data[start..end];
    let negative = (int_bytes[0] & 0x80) != 0;

    let mut result: i64 = if negative { -1 } else { 0 };
    for &b in int_bytes {
        result = result.checked_shl(8).ok_or(BerError::Overflow)?;
        result |= b as i64;
    }

    Ok((result, end))
}

// Unsigned integer encoding (for Counter32, Gauge32, TimeTicks)

pub fn encode_unsigned<W: Write>(writer: &mut W, tag: u8, value: u32) -> io::Result<()> {
    let bytes = value.to_be_bytes();

    // Find first significant byte, but ensure high bit doesn't make it look negative
    let mut start = 0;
    while start < 3 && bytes[start] == 0 {
        start += 1;
    }

    // If high bit is set, prepend a zero byte
    let needs_padding = (bytes[start] & 0x80) != 0;

    writer.write_all(&[tag])?;
    if needs_padding {
        encode_length(writer, 4 - start + 1)?;
        writer.write_all(&[0])?;
    } else {
        encode_length(writer, 4 - start)?;
    }
    writer.write_all(&bytes[start..])
}

pub fn decode_unsigned(data: &[u8], expected_tag: u8) -> Result<(u32, usize), BerError> {
    if data.is_empty() {
        return Err(BerError::BufferTooShort);
    }
    if data[0] != expected_tag {
        return Err(BerError::InvalidTag(data[0]));
    }

    let (len, len_bytes) = decode_length(&data[1..])?;
    let start = 1 + len_bytes;
    let end = start + len;

    if data.len() < end {
        return Err(BerError::BufferTooShort);
    }
    if len == 0 || len > 5 {
        return Err(BerError::Overflow);
    }

    let int_bytes = &data[start..end];
    let mut result: u32 = 0;

    for &b in int_bytes {
        result = result.checked_shl(8).ok_or(BerError::Overflow)?;
        result |= b as u32;
    }

    Ok((result, end))
}

// Counter64 encoding

pub fn encode_counter64<W: Write>(writer: &mut W, value: u64) -> io::Result<()> {
    let bytes = value.to_be_bytes();

    let mut start = 0;
    while start < 7 && bytes[start] == 0 {
        start += 1;
    }

    let needs_padding = (bytes[start] & 0x80) != 0;

    writer.write_all(&[0x46])?; // Counter64 tag
    if needs_padding {
        encode_length(writer, 8 - start + 1)?;
        writer.write_all(&[0])?;
    } else {
        encode_length(writer, 8 - start)?;
    }
    writer.write_all(&bytes[start..])
}

pub fn decode_counter64(data: &[u8]) -> Result<(u64, usize), BerError> {
    if data.is_empty() {
        return Err(BerError::BufferTooShort);
    }
    if data[0] != 0x46 {
        return Err(BerError::InvalidTag(data[0]));
    }

    let (len, len_bytes) = decode_length(&data[1..])?;
    let start = 1 + len_bytes;
    let end = start + len;

    if data.len() < end {
        return Err(BerError::BufferTooShort);
    }
    if len == 0 || len > 9 {
        return Err(BerError::Overflow);
    }

    let int_bytes = &data[start..end];
    let mut result: u64 = 0;

    for &b in int_bytes {
        result = result.checked_shl(8).ok_or(BerError::Overflow)?;
        result |= b as u64;
    }

    Ok((result, end))
}

// Octet string encoding

pub fn encode_octet_string<W: Write>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    writer.write_all(&[0x04])?;
    encode_length(writer, data.len())?;
    writer.write_all(data)
}

pub fn decode_octet_string(data: &[u8]) -> Result<(Vec<u8>, usize), BerError> {
    if data.is_empty() {
        return Err(BerError::BufferTooShort);
    }
    if data[0] != 0x04 {
        return Err(BerError::InvalidTag(data[0]));
    }

    let (len, len_bytes) = decode_length(&data[1..])?;
    let start = 1 + len_bytes;
    let end = start + len;

    if data.len() < end {
        return Err(BerError::BufferTooShort);
    }

    Ok((data[start..end].to_vec(), end))
}

// Null encoding

pub fn encode_null<W: Write>(writer: &mut W) -> io::Result<()> {
    writer.write_all(&[0x05, 0x00])
}

pub fn decode_null(data: &[u8]) -> Result<usize, BerError> {
    if data.len() < 2 {
        return Err(BerError::BufferTooShort);
    }
    if data[0] != 0x05 {
        return Err(BerError::InvalidTag(data[0]));
    }
    if data[1] != 0x00 {
        return Err(BerError::InvalidLength);
    }
    Ok(2)
}

// OID encoding (BER format: first two components merged as 40*x + y)

pub fn encode_oid<W: Write>(writer: &mut W, oid: &Oid) -> io::Result<()> {
    let parts = oid.parts();
    if parts.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty OID"));
    }

    let mut content = Vec::new();

    // First two components: 40 * parts[0] + parts[1]
    if parts.len() >= 2 {
        content.push((40 * parts[0] + parts[1]) as u8);
    } else {
        content.push((40 * parts[0]) as u8);
    }

    // Remaining components in base-128
    for &part in parts.iter().skip(2) {
        encode_subid(&mut content, part)?;
    }

    writer.write_all(&[0x06])?;
    encode_length(writer, content.len())?;
    writer.write_all(&content)
}

fn encode_subid<W: Write>(writer: &mut W, value: u32) -> io::Result<()> {
    if value < 128 {
        writer.write_all(&[value as u8])
    } else {
        let mut bytes = Vec::with_capacity(5);
        let mut v = value;

        bytes.push((v & 0x7F) as u8);
        v >>= 7;

        while v > 0 {
            bytes.push((v & 0x7F) as u8 | 0x80);
            v >>= 7;
        }

        bytes.reverse();
        writer.write_all(&bytes)
    }
}

pub fn decode_oid(data: &[u8]) -> Result<(Oid, usize), BerError> {
    if data.is_empty() {
        return Err(BerError::BufferTooShort);
    }
    if data[0] != 0x06 {
        return Err(BerError::InvalidTag(data[0]));
    }

    let (len, len_bytes) = decode_length(&data[1..])?;
    let start = 1 + len_bytes;
    let end = start + len;

    if data.len() < end {
        return Err(BerError::BufferTooShort);
    }
    if len == 0 {
        return Err(BerError::InvalidOid);
    }

    let content = &data[start..end];
    let mut parts = Vec::new();

    // First byte encodes first two components
    let first = content[0] as u32;
    parts.push(first / 40);
    parts.push(first % 40);

    // Decode remaining sub-identifiers
    let mut i = 1;
    while i < content.len() {
        let (subid, consumed) = decode_subid(&content[i..])?;
        parts.push(subid);
        i += consumed;
    }

    let oid = Oid::new(parts).map_err(|_| BerError::InvalidOid)?;
    Ok((oid, end))
}

fn decode_subid(data: &[u8]) -> Result<(u32, usize), BerError> {
    let mut value: u32 = 0;
    let mut i = 0;

    loop {
        if i >= data.len() {
            return Err(BerError::BufferTooShort);
        }

        let b = data[i];
        value = value.checked_shl(7).ok_or(BerError::Overflow)?;
        value |= (b & 0x7F) as u32;
        i += 1;

        if (b & 0x80) == 0 {
            break;
        }
    }

    Ok((value, i))
}

// Sequence encoding

pub fn encode_sequence<W: Write>(writer: &mut W, contents: &[u8]) -> io::Result<()> {
    writer.write_all(&[0x30])?;
    encode_length(writer, contents.len())?;
    writer.write_all(contents)
}

pub fn decode_sequence(data: &[u8]) -> Result<(&[u8], usize), BerError> {
    if data.is_empty() {
        return Err(BerError::BufferTooShort);
    }
    if data[0] != 0x30 {
        return Err(BerError::InvalidTag(data[0]));
    }

    let (len, len_bytes) = decode_length(&data[1..])?;
    let start = 1 + len_bytes;
    let end = start + len;

    if data.len() < end {
        return Err(BerError::BufferTooShort);
    }

    Ok((&data[start..end], end))
}

// Tagged encoding (for PDUs and other context-specific types)

pub fn encode_tagged<W: Write>(writer: &mut W, tag: u8, contents: &[u8]) -> io::Result<()> {
    writer.write_all(&[tag])?;
    encode_length(writer, contents.len())?;
    writer.write_all(contents)
}

pub fn decode_tagged(data: &[u8], expected_tag: u8) -> Result<(&[u8], usize), BerError> {
    if data.is_empty() {
        return Err(BerError::BufferTooShort);
    }
    if data[0] != expected_tag {
        return Err(BerError::InvalidTag(data[0]));
    }

    let (len, len_bytes) = decode_length(&data[1..])?;
    let start = 1 + len_bytes;
    let end = start + len;

    if data.len() < end {
        return Err(BerError::BufferTooShort);
    }

    Ok((&data[start..end], end))
}

// IpAddress encoding (4 bytes, application tag 0x40)

pub fn encode_ip_address<W: Write>(writer: &mut W, a: u8, b: u8, c: u8, d: u8) -> io::Result<()> {
    writer.write_all(&[0x40, 0x04, a, b, c, d])
}

pub fn decode_ip_address(data: &[u8]) -> Result<([u8; 4], usize), BerError> {
    if data.len() < 6 {
        return Err(BerError::BufferTooShort);
    }
    if data[0] != 0x40 {
        return Err(BerError::InvalidTag(data[0]));
    }
    if data[1] != 0x04 {
        return Err(BerError::InvalidLength);
    }

    Ok(([data[2], data[3], data[4], data[5]], 6))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_length_short() {
        let mut buf = Vec::new();
        encode_length(&mut buf, 50).unwrap();
        assert_eq!(buf, vec![50]);

        let (len, consumed) = decode_length(&buf).unwrap();
        assert_eq!(len, 50);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_length_long_1() {
        let mut buf = Vec::new();
        encode_length(&mut buf, 200).unwrap();
        assert_eq!(buf, vec![0x81, 200]);

        let (len, consumed) = decode_length(&buf).unwrap();
        assert_eq!(len, 200);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_length_long_2() {
        let mut buf = Vec::new();
        encode_length(&mut buf, 1000).unwrap();
        assert_eq!(buf, vec![0x82, 0x03, 0xE8]);

        let (len, consumed) = decode_length(&buf).unwrap();
        assert_eq!(len, 1000);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn test_integer_positive() {
        let mut buf = Vec::new();
        encode_integer(&mut buf, 42).unwrap();
        assert_eq!(buf, vec![0x02, 0x01, 42]);

        let (val, consumed) = decode_integer(&buf).unwrap();
        assert_eq!(val, 42);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn test_integer_negative() {
        let mut buf = Vec::new();
        encode_integer(&mut buf, -1).unwrap();
        assert_eq!(buf, vec![0x02, 0x01, 0xFF]);

        let (val, _) = decode_integer(&buf).unwrap();
        assert_eq!(val, -1);
    }

    #[test]
    fn test_integer_zero() {
        let mut buf = Vec::new();
        encode_integer(&mut buf, 0).unwrap();
        assert_eq!(buf, vec![0x02, 0x01, 0x00]);

        let (val, _) = decode_integer(&buf).unwrap();
        assert_eq!(val, 0);
    }

    #[test]
    fn test_integer_large() {
        let mut buf = Vec::new();
        encode_integer(&mut buf, 0x7FFFFFFF).unwrap();

        let (val, _) = decode_integer(&buf).unwrap();
        assert_eq!(val, 0x7FFFFFFF);
    }

    #[test]
    fn test_integer_large_negative() {
        let mut buf = Vec::new();
        encode_integer(&mut buf, -128).unwrap();

        let (val, _) = decode_integer(&buf).unwrap();
        assert_eq!(val, -128);
    }

    #[test]
    fn test_octet_string() {
        let mut buf = Vec::new();
        encode_octet_string(&mut buf, b"hello").unwrap();
        assert_eq!(buf, vec![0x04, 0x05, b'h', b'e', b'l', b'l', b'o']);

        let (val, consumed) = decode_octet_string(&buf).unwrap();
        assert_eq!(val, b"hello");
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_null() {
        let mut buf = Vec::new();
        encode_null(&mut buf).unwrap();
        assert_eq!(buf, vec![0x05, 0x00]);

        let consumed = decode_null(&buf).unwrap();
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_oid_simple() {
        let oid: Oid = "1.3.6.1".parse().unwrap();
        let mut buf = Vec::new();
        encode_oid(&mut buf, &oid).unwrap();
        // 1.3 -> 40*1 + 3 = 43 (0x2B), then 6, 1
        assert_eq!(buf, vec![0x06, 0x03, 0x2B, 0x06, 0x01]);

        let (decoded, consumed) = decode_oid(&buf).unwrap();
        assert_eq!(decoded.to_string(), "1.3.6.1");
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_oid_large_subid() {
        let oid: Oid = "1.3.6.1.4.1.12345".parse().unwrap();
        let mut buf = Vec::new();
        encode_oid(&mut buf, &oid).unwrap();

        let (decoded, _) = decode_oid(&buf).unwrap();
        assert_eq!(decoded.to_string(), "1.3.6.1.4.1.12345");
    }

    #[test]
    fn test_oid_very_large_subid() {
        let oid: Oid = "1.3.6.1.4.1.311.21.20".parse().unwrap();
        let mut buf = Vec::new();
        encode_oid(&mut buf, &oid).unwrap();

        let (decoded, _) = decode_oid(&buf).unwrap();
        assert_eq!(decoded.to_string(), oid.to_string());
    }

    #[test]
    fn test_sequence() {
        let inner = vec![0x02, 0x01, 0x2A]; // INTEGER 42
        let mut buf = Vec::new();
        encode_sequence(&mut buf, &inner).unwrap();
        assert_eq!(buf, vec![0x30, 0x03, 0x02, 0x01, 0x2A]);

        let (contents, consumed) = decode_sequence(&buf).unwrap();
        assert_eq!(contents, &[0x02, 0x01, 0x2A]);
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_tagged() {
        let inner = vec![0x02, 0x01, 0x00];
        let mut buf = Vec::new();
        encode_tagged(&mut buf, 0xA0, &inner).unwrap();

        let (contents, consumed) = decode_tagged(&buf, 0xA0).unwrap();
        assert_eq!(contents, &inner[..]);
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_unsigned_counter32() {
        let mut buf = Vec::new();
        encode_unsigned(&mut buf, 0x41, 4294967295).unwrap();

        let (val, _) = decode_unsigned(&buf, 0x41).unwrap();
        assert_eq!(val, 4294967295);
    }

    #[test]
    fn test_counter64() {
        let mut buf = Vec::new();
        encode_counter64(&mut buf, u64::MAX).unwrap();

        let (val, _) = decode_counter64(&buf).unwrap();
        assert_eq!(val, u64::MAX);
    }

    #[test]
    fn test_ip_address() {
        let mut buf = Vec::new();
        encode_ip_address(&mut buf, 192, 168, 1, 1).unwrap();

        let (addr, consumed) = decode_ip_address(&buf).unwrap();
        assert_eq!(addr, [192, 168, 1, 1]);
        assert_eq!(consumed, 6);
    }
}
