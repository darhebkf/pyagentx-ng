use std::io::{self, Read, Write};

use crate::oid::Oid;

use super::pdu::{
    SearchRange, VarBind, decode_octet_string, decode_oid, encode_octet_string, encode_oid,
};

// Helper to read VarBinds until payload exhausted
fn decode_varbinds<R: Read>(reader: &mut R, payload_len: usize) -> io::Result<Vec<VarBind>> {
    let mut varbinds = Vec::new();
    let mut bytes_read = 0;

    while bytes_read < payload_len {
        let vb = VarBind::decode(reader)?;
        // Approximate size: 4 (oid header) + oid.len()*4 + 4 (value header) + value data
        bytes_read += 8 + vb.oid.len() * 4 + 8; // Conservative estimate
        varbinds.push(vb);
    }

    Ok(varbinds)
}

// Open PDU body
#[derive(Debug, Clone)]
pub struct OpenPdu {
    pub timeout: u8,
    pub id: Oid,
    pub description: Vec<u8>,
}

impl OpenPdu {
    pub fn new(timeout: u8, id: Oid, description: impl Into<Vec<u8>>) -> Self {
        Self {
            timeout,
            id,
            description: description.into(),
        }
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&[self.timeout])?;
        writer.write_all(&[0u8; 3])?; // reserved
        encode_oid(writer, &self.id, false)?;
        encode_octet_string(writer, &self.description)?;
        Ok(())
    }

    pub fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut header = [0u8; 4];
        reader.read_exact(&mut header)?;
        let timeout = header[0];

        let (id, _) = decode_oid(reader)?;
        let description = decode_octet_string(reader)?;

        Ok(Self {
            timeout,
            id,
            description,
        })
    }
}

// Close PDU body
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CloseReason {
    Other = 1,
    ParseError = 2,
    ProtocolError = 3,
    Timeouts = 4,
    Shutdown = 5,
    ByManager = 6,
}

#[derive(Debug, Clone)]
pub struct ClosePdu {
    pub reason: CloseReason,
}

impl ClosePdu {
    pub fn new(reason: CloseReason) -> Self {
        Self { reason }
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&[self.reason as u8])?;
        writer.write_all(&[0u8; 3])?; // reserved
        Ok(())
    }

    pub fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        let reason = match buf[0] {
            1 => CloseReason::Other,
            2 => CloseReason::ParseError,
            3 => CloseReason::ProtocolError,
            4 => CloseReason::Timeouts,
            5 => CloseReason::Shutdown,
            6 => CloseReason::ByManager,
            _ => CloseReason::Other,
        };
        Ok(Self { reason })
    }
}

// Register PDU body
#[derive(Debug, Clone)]
pub struct RegisterPdu {
    pub timeout: u8,
    pub priority: u8,
    pub range_subid: u8,
    pub subtree: Oid,
    pub upper_bound: Option<u32>,
}

impl RegisterPdu {
    pub fn new(subtree: Oid, priority: u8, timeout: u8) -> Self {
        Self {
            timeout,
            priority,
            range_subid: 0,
            subtree,
            upper_bound: None,
        }
    }

    pub fn with_range(mut self, range_subid: u8, upper_bound: u32) -> Self {
        self.range_subid = range_subid;
        self.upper_bound = Some(upper_bound);
        self
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&[self.timeout])?;
        writer.write_all(&[self.priority])?;
        writer.write_all(&[self.range_subid])?;
        writer.write_all(&[0u8])?; // reserved
        encode_oid(writer, &self.subtree, false)?;

        if let Some(ub) = self.upper_bound {
            writer.write_all(&ub.to_be_bytes())?;
        }

        Ok(())
    }

    pub fn decode<R: Read>(reader: &mut R, has_upper_bound: bool) -> io::Result<Self> {
        let mut header = [0u8; 4];
        reader.read_exact(&mut header)?;

        let timeout = header[0];
        let priority = header[1];
        let range_subid = header[2];

        let (subtree, _) = decode_oid(reader)?;

        let upper_bound = if has_upper_bound {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            Some(u32::from_be_bytes(buf))
        } else {
            None
        };

        Ok(Self {
            timeout,
            priority,
            range_subid,
            subtree,
            upper_bound,
        })
    }
}

// Unregister PDU body (similar to Register)
#[derive(Debug, Clone)]
pub struct UnregisterPdu {
    pub priority: u8,
    pub range_subid: u8,
    pub subtree: Oid,
    pub upper_bound: Option<u32>,
}

impl UnregisterPdu {
    pub fn new(subtree: Oid, priority: u8) -> Self {
        Self {
            priority,
            range_subid: 0,
            subtree,
            upper_bound: None,
        }
    }

    pub fn with_range(mut self, range_subid: u8, upper_bound: u32) -> Self {
        self.range_subid = range_subid;
        self.upper_bound = Some(upper_bound);
        self
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&[0u8])?; // reserved (no timeout for unregister)
        writer.write_all(&[self.priority])?;
        writer.write_all(&[self.range_subid])?;
        writer.write_all(&[0u8])?; // reserved
        encode_oid(writer, &self.subtree, false)?;

        if let Some(ub) = self.upper_bound {
            writer.write_all(&ub.to_be_bytes())?;
        }

        Ok(())
    }

    pub fn decode<R: Read>(reader: &mut R, has_upper_bound: bool) -> io::Result<Self> {
        let mut header = [0u8; 4];
        reader.read_exact(&mut header)?;

        let priority = header[1];
        let range_subid = header[2];

        let (subtree, _) = decode_oid(reader)?;

        let upper_bound = if has_upper_bound {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            Some(u32::from_be_bytes(buf))
        } else {
            None
        };

        Ok(Self {
            priority,
            range_subid,
            subtree,
            upper_bound,
        })
    }
}

// Get/GetNext PDU body (list of SearchRanges)
#[derive(Debug, Clone)]
pub struct GetPdu {
    pub ranges: Vec<SearchRange>,
}

impl GetPdu {
    pub fn new(ranges: Vec<SearchRange>) -> Self {
        Self { ranges }
    }

    pub fn single(oid: Oid) -> Self {
        let end = oid.child(0); // null terminator
        Self {
            ranges: vec![SearchRange::new(oid, end, false)],
        }
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        for range in &self.ranges {
            range.encode(writer)?;
        }
        Ok(())
    }

    pub fn decode<R: Read>(reader: &mut R, payload_len: usize) -> io::Result<Self> {
        let mut ranges = Vec::new();
        let mut bytes_read = 0;

        while bytes_read < payload_len {
            let start_pos = bytes_read;
            let range = SearchRange::decode(reader)?;
            // Estimate bytes read (this is approximate, actual tracking would need cursor)
            bytes_read += 8 + (range.start.len() + range.end.len()) * 4;
            ranges.push(range);

            if bytes_read == start_pos {
                break; // No progress, avoid infinite loop
            }
        }

        Ok(Self { ranges })
    }
}

// GetBulk PDU body (RFC 2741 section 6.2.7)
#[derive(Debug, Clone)]
pub struct GetBulkPdu {
    pub non_repeaters: u16,
    pub max_repetitions: u16,
    pub ranges: Vec<SearchRange>,
}

impl GetBulkPdu {
    pub fn new(non_repeaters: u16, max_repetitions: u16, ranges: Vec<SearchRange>) -> Self {
        Self {
            non_repeaters,
            max_repetitions,
            ranges,
        }
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.non_repeaters.to_be_bytes())?;
        writer.write_all(&self.max_repetitions.to_be_bytes())?;

        for range in &self.ranges {
            range.encode(writer)?;
        }

        Ok(())
    }

    pub fn decode<R: Read>(reader: &mut R, payload_len: usize) -> io::Result<Self> {
        let mut header = [0u8; 4];
        reader.read_exact(&mut header)?;

        let non_repeaters = u16::from_be_bytes([header[0], header[1]]);
        let max_repetitions = u16::from_be_bytes([header[2], header[3]]);

        // Remaining payload is SearchRanges
        let remaining = payload_len.saturating_sub(4);
        let mut ranges = Vec::new();
        let mut bytes_read = 0;

        while bytes_read < remaining {
            let range = SearchRange::decode(reader)?;
            bytes_read += 8 + (range.start.len() + range.end.len()) * 4;
            ranges.push(range);
        }

        Ok(Self {
            non_repeaters,
            max_repetitions,
            ranges,
        })
    }
}

// TestSet PDU body (contains VarBindList for SET phase 1)
#[derive(Debug, Clone)]
pub struct TestSetPdu {
    pub varbinds: Vec<VarBind>,
}

impl TestSetPdu {
    pub fn new(varbinds: Vec<VarBind>) -> Self {
        Self { varbinds }
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        for vb in &self.varbinds {
            vb.encode(writer)?;
        }
        Ok(())
    }

    pub fn decode<R: Read>(reader: &mut R, payload_len: usize) -> io::Result<Self> {
        let varbinds = decode_varbinds(reader, payload_len)?;
        Ok(Self { varbinds })
    }
}

// CommitSet PDU body (empty - just acknowledges TestSet)
#[derive(Debug, Clone, Default)]
pub struct CommitSetPdu;

impl CommitSetPdu {
    pub fn new() -> Self {
        Self
    }

    pub fn encode<W: Write>(&self, _writer: &mut W) -> io::Result<()> {
        Ok(())
    }

    pub fn decode<R: Read>(_reader: &mut R) -> io::Result<Self> {
        Ok(Self)
    }
}

// UndoSet PDU body (empty - requests rollback)
#[derive(Debug, Clone, Default)]
pub struct UndoSetPdu;

impl UndoSetPdu {
    pub fn new() -> Self {
        Self
    }

    pub fn encode<W: Write>(&self, _writer: &mut W) -> io::Result<()> {
        Ok(())
    }

    pub fn decode<R: Read>(_reader: &mut R) -> io::Result<Self> {
        Ok(Self)
    }
}

// CleanupSet PDU body (empty - signals end of SET transaction)
#[derive(Debug, Clone, Default)]
pub struct CleanupSetPdu;

impl CleanupSetPdu {
    pub fn new() -> Self {
        Self
    }

    pub fn encode<W: Write>(&self, _writer: &mut W) -> io::Result<()> {
        Ok(())
    }

    pub fn decode<R: Read>(_reader: &mut R) -> io::Result<Self> {
        Ok(Self)
    }
}

// Notify PDU body (trap/notification - contains VarBindList)
#[derive(Debug, Clone)]
pub struct NotifyPdu {
    pub varbinds: Vec<VarBind>,
}

impl NotifyPdu {
    pub fn new(varbinds: Vec<VarBind>) -> Self {
        Self { varbinds }
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        for vb in &self.varbinds {
            vb.encode(writer)?;
        }
        Ok(())
    }

    pub fn decode<R: Read>(reader: &mut R, payload_len: usize) -> io::Result<Self> {
        let varbinds = decode_varbinds(reader, payload_len)?;
        Ok(Self { varbinds })
    }
}

// Ping PDU body (empty - keepalive)
#[derive(Debug, Clone, Default)]
pub struct PingPdu;

impl PingPdu {
    pub fn new() -> Self {
        Self
    }

    pub fn encode<W: Write>(&self, _writer: &mut W) -> io::Result<()> {
        Ok(())
    }

    pub fn decode<R: Read>(_reader: &mut R) -> io::Result<Self> {
        Ok(Self)
    }
}

// Response PDU body
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ResponseError {
    NoError = 0,
    OpenFailed = 256,
    NotOpen = 257,
    IndexWrongType = 258,
    IndexAlreadyAllocated = 259,
    IndexNoneAvailable = 260,
    IndexNotAllocated = 261,
    UnsupportedContext = 262,
    DuplicateRegistration = 263,
    UnknownRegistration = 264,
    UnknownAgentCaps = 265,
    ParseError = 266,
    RequestDenied = 267,
    ProcessingError = 268,
}

impl From<u16> for ResponseError {
    fn from(v: u16) -> Self {
        match v {
            0 => ResponseError::NoError,
            256 => ResponseError::OpenFailed,
            257 => ResponseError::NotOpen,
            258 => ResponseError::IndexWrongType,
            259 => ResponseError::IndexAlreadyAllocated,
            260 => ResponseError::IndexNoneAvailable,
            261 => ResponseError::IndexNotAllocated,
            262 => ResponseError::UnsupportedContext,
            263 => ResponseError::DuplicateRegistration,
            264 => ResponseError::UnknownRegistration,
            265 => ResponseError::UnknownAgentCaps,
            266 => ResponseError::ParseError,
            267 => ResponseError::RequestDenied,
            268 => ResponseError::ProcessingError,
            _ => ResponseError::ProcessingError,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResponsePdu {
    pub sys_uptime: u32,
    pub error: ResponseError,
    pub index: u16,
    pub varbinds: Vec<VarBind>,
}

impl ResponsePdu {
    pub fn new(sys_uptime: u32, varbinds: Vec<VarBind>) -> Self {
        Self {
            sys_uptime,
            error: ResponseError::NoError,
            index: 0,
            varbinds,
        }
    }

    pub fn error(sys_uptime: u32, error: ResponseError, index: u16) -> Self {
        Self {
            sys_uptime,
            error,
            index,
            varbinds: Vec::new(),
        }
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.sys_uptime.to_be_bytes())?;
        writer.write_all(&(self.error as u16).to_be_bytes())?;
        writer.write_all(&self.index.to_be_bytes())?;

        for vb in &self.varbinds {
            vb.encode(writer)?;
        }

        Ok(())
    }

    pub fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut header = [0u8; 8];
        reader.read_exact(&mut header)?;

        let sys_uptime = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        let error = ResponseError::from(u16::from_be_bytes([header[4], header[5]]));
        let index = u16::from_be_bytes([header[6], header[7]]);

        // VarBinds would need payload length to know when to stop
        let varbinds = Vec::new();

        Ok(Self {
            sys_uptime,
            error,
            index,
            varbinds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_pdu_roundtrip() {
        let pdu = OpenPdu::new(
            30,
            "1.3.6.1.4.1.12345".parse().unwrap(),
            b"test agent".to_vec(),
        );

        let mut buf = Vec::new();
        pdu.encode(&mut buf).unwrap();

        let decoded = OpenPdu::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.timeout, 30);
        assert_eq!(decoded.description, b"test agent");
    }

    #[test]
    fn test_close_pdu_roundtrip() {
        let pdu = ClosePdu::new(CloseReason::Shutdown);

        let mut buf = Vec::new();
        pdu.encode(&mut buf).unwrap();

        let decoded = ClosePdu::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.reason, CloseReason::Shutdown);
    }

    #[test]
    fn test_register_pdu_roundtrip() {
        let pdu = RegisterPdu::new("1.3.6.1.4.1.12345".parse().unwrap(), 127, 30);

        let mut buf = Vec::new();
        pdu.encode(&mut buf).unwrap();

        let decoded = RegisterPdu::decode(&mut buf.as_slice(), false).unwrap();
        assert_eq!(decoded.timeout, 30);
        assert_eq!(decoded.priority, 127);
    }

    #[test]
    fn test_response_pdu_encode() {
        let pdu = ResponsePdu::new(1000, vec![]);

        let mut buf = Vec::new();
        pdu.encode(&mut buf).unwrap();

        assert_eq!(buf.len(), 8); // 4 + 2 + 2
    }

    #[test]
    fn test_unregister_pdu_roundtrip() {
        let pdu = UnregisterPdu::new("1.3.6.1.4.1.12345".parse().unwrap(), 127);

        let mut buf = Vec::new();
        pdu.encode(&mut buf).unwrap();

        let decoded = UnregisterPdu::decode(&mut buf.as_slice(), false).unwrap();
        assert_eq!(decoded.priority, 127);
    }

    #[test]
    fn test_getbulk_pdu_roundtrip() {
        let start: Oid = "1.3.6.1.2.1".parse().unwrap();
        let end: Oid = "1.3.6.1.2.2".parse().unwrap();
        let range = SearchRange::new(start, end, false);
        let pdu = GetBulkPdu::new(0, 10, vec![range]);

        let mut buf = Vec::new();
        pdu.encode(&mut buf).unwrap();

        let decoded = GetBulkPdu::decode(&mut buf.as_slice(), buf.len()).unwrap();
        assert_eq!(decoded.non_repeaters, 0);
        assert_eq!(decoded.max_repetitions, 10);
        assert_eq!(decoded.ranges.len(), 1);
    }

    #[test]
    fn test_testset_pdu_roundtrip() {
        use crate::types::Value;

        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let vb = VarBind::new(oid, Value::Integer(42));
        let pdu = TestSetPdu::new(vec![vb]);

        let mut buf = Vec::new();
        pdu.encode(&mut buf).unwrap();

        let decoded = TestSetPdu::decode(&mut buf.as_slice(), buf.len()).unwrap();
        assert_eq!(decoded.varbinds.len(), 1);
    }

    #[test]
    fn test_empty_pdus() {
        // CommitSet
        let commit = CommitSetPdu::new();
        let mut buf = Vec::new();
        commit.encode(&mut buf).unwrap();
        assert!(buf.is_empty());

        // UndoSet
        let undo = UndoSetPdu::new();
        let mut buf = Vec::new();
        undo.encode(&mut buf).unwrap();
        assert!(buf.is_empty());

        // CleanupSet
        let cleanup = CleanupSetPdu::new();
        let mut buf = Vec::new();
        cleanup.encode(&mut buf).unwrap();
        assert!(buf.is_empty());

        // Ping
        let ping = PingPdu::new();
        let mut buf = Vec::new();
        ping.encode(&mut buf).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn test_notify_pdu_roundtrip() {
        use crate::types::Value;

        let oid: Oid = "1.3.6.1.6.3.1.1.4.1.0".parse().unwrap();
        let vb = VarBind::new(
            oid,
            Value::ObjectIdentifier("1.3.6.1.4.1.12345.1".parse().unwrap()),
        );
        let pdu = NotifyPdu::new(vec![vb]);

        let mut buf = Vec::new();
        pdu.encode(&mut buf).unwrap();

        let decoded = NotifyPdu::decode(&mut buf.as_slice(), buf.len()).unwrap();
        assert_eq!(decoded.varbinds.len(), 1);
    }
}
