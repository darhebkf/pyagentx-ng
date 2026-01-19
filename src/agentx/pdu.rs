use pyo3::prelude::*;
use std::io::{self, Read, Write};

use crate::oid::Oid;
use crate::types::Value;

fn pad_to_4(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

pub fn encode_oid<W: Write>(writer: &mut W, oid: &Oid, include: bool) -> io::Result<()> {
    let parts = oid.parts();

    // Check for internet prefix optimization (1.3.6.1)
    let (prefix, start_idx) = if parts.len() >= 5
        && parts[0] == 1
        && parts[1] == 3
        && parts[2] == 6
        && parts[3] == 1
        && parts[4] <= 255
    {
        (parts[4] as u8, 5)
    } else {
        (0u8, 0)
    };

    let actual_n_subid = (parts.len() - start_idx) as u8;
    writer.write_all(&[actual_n_subid])?;
    writer.write_all(&[prefix])?;
    writer.write_all(&[include as u8])?;
    writer.write_all(&[0u8])?; // reserved

    for &part in &parts[start_idx..] {
        writer.write_all(&part.to_be_bytes())?;
    }

    Ok(())
}

pub fn decode_oid<R: Read>(reader: &mut R) -> io::Result<(Oid, bool)> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header)?;

    let n_subid = header[0] as usize;
    let prefix = header[1];
    let include = header[2] != 0;

    let mut parts = Vec::with_capacity(n_subid + 5);

    if prefix != 0 {
        parts.extend_from_slice(&[1, 3, 6, 1, prefix as u32]);
    }

    for _ in 0..n_subid {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        parts.push(u32::from_be_bytes(buf));
    }

    let oid = if parts.is_empty() {
        // Null OID - use a placeholder
        Oid::from_slice(&[0])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
    } else {
        Oid::from_slice(&parts)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
    };

    Ok((oid, include))
}

pub fn encode_octet_string<W: Write>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(data)?;

    // Pad to 4-byte boundary
    let padding = pad_to_4(data.len());
    for _ in 0..padding {
        writer.write_all(&[0u8])?;
    }

    Ok(())
}

pub fn decode_octet_string<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut data = vec![0u8; len];
    reader.read_exact(&mut data)?;

    // Skip padding
    let padding = pad_to_4(len);
    if padding > 0 {
        let mut pad = vec![0u8; padding];
        reader.read_exact(&mut pad)?;
    }

    Ok(data)
}

#[derive(Debug, Clone, PartialEq)]
pub struct SearchRange {
    pub start: Oid,
    pub end: Oid,
    pub include: bool,
}

impl SearchRange {
    pub fn new(start: Oid, end: Oid, include: bool) -> Self {
        Self {
            start,
            end,
            include,
        }
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        encode_oid(writer, &self.start, self.include)?;
        encode_oid(writer, &self.end, false)?;
        Ok(())
    }

    pub fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let (start, include) = decode_oid(reader)?;
        let (end, _) = decode_oid(reader)?;
        Ok(Self {
            start,
            end,
            include,
        })
    }
}

// AgentX value type codes (RFC 2741 section 5.4)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ValueType {
    Integer = 2,
    OctetString = 4,
    Null = 5,
    ObjectIdentifier = 6,
    IpAddress = 64,
    Counter32 = 65,
    Gauge32 = 66,
    TimeTicks = 67,
    Opaque = 68,
    Counter64 = 70,
    NoSuchObject = 128,
    NoSuchInstance = 129,
    EndOfMibView = 130,
}

pub fn encode_value<W: Write>(writer: &mut W, value: &Value) -> io::Result<()> {
    let (type_code, data): (u16, Option<Vec<u8>>) = match value {
        Value::Integer(v) => (ValueType::Integer as u16, Some(v.to_be_bytes().to_vec())),
        Value::OctetString(v) => {
            let mut buf = Vec::new();
            encode_octet_string(&mut buf, v)?;
            (ValueType::OctetString as u16, Some(buf))
        }
        Value::Null() => (ValueType::Null as u16, None),
        Value::ObjectIdentifier(oid) => {
            let mut buf = Vec::new();
            encode_oid(&mut buf, oid, false)?;
            (ValueType::ObjectIdentifier as u16, Some(buf))
        }
        Value::IpAddress(a, b, c, d) => (ValueType::IpAddress as u16, Some(vec![*a, *b, *c, *d])),
        Value::Counter32(v) => (ValueType::Counter32 as u16, Some(v.to_be_bytes().to_vec())),
        Value::Gauge32(v) => (ValueType::Gauge32 as u16, Some(v.to_be_bytes().to_vec())),
        Value::TimeTicks(v) => (ValueType::TimeTicks as u16, Some(v.to_be_bytes().to_vec())),
        Value::Opaque(v) => {
            let mut buf = Vec::new();
            encode_octet_string(&mut buf, v)?;
            (ValueType::Opaque as u16, Some(buf))
        }
        Value::Counter64(v) => (ValueType::Counter64 as u16, Some(v.to_be_bytes().to_vec())),
        Value::NoSuchObject() => (ValueType::NoSuchObject as u16, None),
        Value::NoSuchInstance() => (ValueType::NoSuchInstance as u16, None),
        Value::EndOfMibView() => (ValueType::EndOfMibView as u16, None),
    };

    writer.write_all(&type_code.to_be_bytes())?;
    writer.write_all(&[0u8; 2])?; // reserved

    if let Some(d) = data {
        writer.write_all(&d)?;
    }

    Ok(())
}

pub fn decode_value<R: Read>(reader: &mut R) -> io::Result<Value> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header)?;

    let type_code = u16::from_be_bytes([header[0], header[1]]);

    let value = match type_code {
        2 => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            Value::Integer(i32::from_be_bytes(buf))
        }
        4 => {
            let data = decode_octet_string(reader)?;
            Value::OctetString(data)
        }
        5 => Value::Null(),
        6 => {
            let (oid, _) = decode_oid(reader)?;
            Value::ObjectIdentifier(oid)
        }
        64 => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            Value::IpAddress(buf[0], buf[1], buf[2], buf[3])
        }
        65 => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            Value::Counter32(u32::from_be_bytes(buf))
        }
        66 => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            Value::Gauge32(u32::from_be_bytes(buf))
        }
        67 => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            Value::TimeTicks(u32::from_be_bytes(buf))
        }
        68 => {
            let data = decode_octet_string(reader)?;
            Value::Opaque(data)
        }
        70 => {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
            Value::Counter64(u64::from_be_bytes(buf))
        }
        128 => Value::NoSuchObject(),
        129 => Value::NoSuchInstance(),
        130 => Value::EndOfMibView(),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown value type: {type_code}"),
            ));
        }
    };

    Ok(value)
}

#[derive(Debug, Clone, PartialEq)]
#[pyclass]
pub struct VarBind {
    #[pyo3(get)]
    pub oid: Oid,
    #[pyo3(get)]
    pub value: Value,
}

#[pymethods]
impl VarBind {
    #[new]
    pub fn py_new(oid: Oid, value: Value) -> Self {
        Self { oid, value }
    }

    fn __repr__(&self) -> String {
        format!("VarBind({}, {})", self.oid, self.value)
    }
}

impl VarBind {
    pub fn new(oid: Oid, value: Value) -> Self {
        Self { oid, value }
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        encode_oid(writer, &self.oid, false)?;
        encode_value(writer, &self.value)?;
        Ok(())
    }

    pub fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let (oid, _) = decode_oid(reader)?;
        let value = decode_value(reader)?;
        Ok(Self { oid, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oid_encode_decode() {
        let oid: Oid = "1.3.6.1.4.1.12345".parse().unwrap();

        let mut buf = Vec::new();
        encode_oid(&mut buf, &oid, true).unwrap();

        let (decoded, include) = decode_oid(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.to_string(), oid.to_string());
        assert!(include);
    }

    #[test]
    fn test_oid_prefix_optimization() {
        // OID starting with 1.3.6.1.X should use prefix optimization
        let oid: Oid = "1.3.6.1.4.1.12345".parse().unwrap();

        let mut buf = Vec::new();
        encode_oid(&mut buf, &oid, false).unwrap();

        // n_subid=2 (only .1.12345 after prefix), prefix=4, include=0, reserved=0
        assert_eq!(buf[0], 2); // n_subid
        assert_eq!(buf[1], 4); // prefix (the 4 from 1.3.6.1.4)
    }

    #[test]
    fn test_octet_string_roundtrip() {
        let data = b"hello world";

        let mut buf = Vec::new();
        encode_octet_string(&mut buf, data).unwrap();

        let decoded = decode_octet_string(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_octet_string_padding() {
        // 5 bytes should be padded to 8 (4 len + 5 data + 3 pad)
        let data = b"hello";

        let mut buf = Vec::new();
        encode_octet_string(&mut buf, data).unwrap();

        // 4 bytes length + 5 bytes data + 3 bytes padding = 12
        assert_eq!(buf.len(), 12);
    }

    #[test]
    fn test_search_range() {
        let start: Oid = "1.3.6.1.2.1".parse().unwrap();
        let end: Oid = "1.3.6.1.2.2".parse().unwrap();
        let range = SearchRange::new(start.clone(), end.clone(), true);

        let mut buf = Vec::new();
        range.encode(&mut buf).unwrap();

        let decoded = SearchRange::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.start.to_string(), start.to_string());
        assert_eq!(decoded.end.to_string(), end.to_string());
        assert!(decoded.include);
    }

    #[test]
    fn test_value_integer_roundtrip() {
        let value = Value::Integer(-12345);

        let mut buf = Vec::new();
        encode_value(&mut buf, &value).unwrap();

        let decoded = decode_value(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_value_string_roundtrip() {
        let value = Value::OctetString(b"hello world".to_vec());

        let mut buf = Vec::new();
        encode_value(&mut buf, &value).unwrap();

        let decoded = decode_value(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_value_counter64_roundtrip() {
        let value = Value::Counter64(u64::MAX);

        let mut buf = Vec::new();
        encode_value(&mut buf, &value).unwrap();

        let decoded = decode_value(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_varbind_roundtrip() {
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let varbind = VarBind::new(oid, Value::Integer(42));

        let mut buf = Vec::new();
        varbind.encode(&mut buf).unwrap();

        let decoded = VarBind::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.oid.to_string(), varbind.oid.to_string());
        assert_eq!(decoded.value, varbind.value);
    }
}
