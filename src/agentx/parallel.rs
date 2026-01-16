use std::io;

use crate::oid::Oid;
use crate::types::Value;

use super::pdu::{SearchRange, VarBind, encode_oid, encode_value};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[cfg(feature = "parallel")]
pub fn encode_varbinds_batch(varbinds: &[VarBind]) -> io::Result<Vec<Vec<u8>>> {
    varbinds
        .par_iter()
        .map(|vb| {
            let mut buf = Vec::new();
            vb.encode(&mut buf)?;
            Ok(buf)
        })
        .collect()
}

#[cfg(not(feature = "parallel"))]
pub fn encode_varbinds_batch(varbinds: &[VarBind]) -> io::Result<Vec<Vec<u8>>> {
    varbinds
        .iter()
        .map(|vb| {
            let mut buf = Vec::new();
            vb.encode(&mut buf)?;
            Ok(buf)
        })
        .collect()
}

#[cfg(feature = "parallel")]
pub fn encode_search_ranges_batch(ranges: &[SearchRange]) -> io::Result<Vec<Vec<u8>>> {
    ranges
        .par_iter()
        .map(|r| {
            let mut buf = Vec::new();
            r.encode(&mut buf)?;
            Ok(buf)
        })
        .collect()
}

#[cfg(not(feature = "parallel"))]
pub fn encode_search_ranges_batch(ranges: &[SearchRange]) -> io::Result<Vec<Vec<u8>>> {
    ranges
        .iter()
        .map(|r| {
            let mut buf = Vec::new();
            r.encode(&mut buf)?;
            Ok(buf)
        })
        .collect()
}

#[cfg(feature = "parallel")]
pub fn encode_oids_batch(oids: &[Oid], include: bool) -> io::Result<Vec<Vec<u8>>> {
    oids.par_iter()
        .map(|oid| {
            let mut buf = Vec::new();
            encode_oid(&mut buf, oid, include)?;
            Ok(buf)
        })
        .collect()
}

#[cfg(not(feature = "parallel"))]
pub fn encode_oids_batch(oids: &[Oid], include: bool) -> io::Result<Vec<Vec<u8>>> {
    oids.iter()
        .map(|oid| {
            let mut buf = Vec::new();
            encode_oid(&mut buf, oid, include)?;
            Ok(buf)
        })
        .collect()
}

#[cfg(feature = "parallel")]
pub fn encode_values_batch(values: &[Value]) -> io::Result<Vec<Vec<u8>>> {
    values
        .par_iter()
        .map(|v| {
            let mut buf = Vec::new();
            encode_value(&mut buf, v)?;
            Ok(buf)
        })
        .collect()
}

#[cfg(not(feature = "parallel"))]
pub fn encode_values_batch(values: &[Value]) -> io::Result<Vec<Vec<u8>>> {
    values
        .iter()
        .map(|v| {
            let mut buf = Vec::new();
            encode_value(&mut buf, v)?;
            Ok(buf)
        })
        .collect()
}

pub fn concat_buffers(buffers: Vec<Vec<u8>>) -> Vec<u8> {
    let total_len: usize = buffers.iter().map(|b| b.len()).sum();
    let mut result = Vec::with_capacity(total_len);
    for buf in buffers {
        result.extend(buf);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_varbinds_batch() {
        let varbinds: Vec<VarBind> = (0..100)
            .map(|i| {
                let oid: Oid = format!("1.3.6.1.2.1.1.{i}").parse().unwrap();
                VarBind::new(oid, Value::Integer(i))
            })
            .collect();

        let encoded = encode_varbinds_batch(&varbinds).unwrap();
        assert_eq!(encoded.len(), 100);

        for buf in &encoded {
            assert!(!buf.is_empty());
        }
    }

    #[test]
    fn test_encode_search_ranges_batch() {
        let ranges: Vec<SearchRange> = (0..100)
            .map(|i| {
                let start: Oid = format!("1.3.6.1.2.1.{i}").parse().unwrap();
                let end: Oid = format!("1.3.6.1.2.1.{}", i + 1).parse().unwrap();
                SearchRange::new(start, end, false)
            })
            .collect();

        let encoded = encode_search_ranges_batch(&ranges).unwrap();
        assert_eq!(encoded.len(), 100);
    }

    #[test]
    fn test_encode_oids_batch() {
        let oids: Vec<Oid> = (0..100)
            .map(|i| format!("1.3.6.1.4.1.{i}").parse().unwrap())
            .collect();

        let encoded = encode_oids_batch(&oids, false).unwrap();
        assert_eq!(encoded.len(), 100);
    }

    #[test]
    fn test_encode_values_batch() {
        let values: Vec<Value> = (0..100).map(Value::Integer).collect();

        let encoded = encode_values_batch(&values).unwrap();
        assert_eq!(encoded.len(), 100);
    }

    #[test]
    fn test_concat_buffers() {
        let buffers = vec![vec![1, 2, 3], vec![4, 5], vec![6, 7, 8, 9]];

        let result = concat_buffers(buffers);
        assert_eq!(result, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }
}
