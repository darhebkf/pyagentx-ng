use std::io::{self, Read, Write};

pub const HEADER_SIZE: usize = 20;
pub const AGENTX_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PduType {
    Open = 1,
    Close = 2,
    Register = 3,
    Unregister = 4,
    Get = 5,
    GetNext = 6,
    GetBulk = 7,
    TestSet = 8,
    CommitSet = 9,
    UndoSet = 10,
    CleanupSet = 11,
    Notify = 12,
    Ping = 13,
    IndexAllocate = 14,
    IndexDeallocate = 15,
    AddAgentCaps = 16,
    RemoveAgentCaps = 17,
    Response = 18,
}

impl TryFrom<u8> for PduType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PduType::Open),
            2 => Ok(PduType::Close),
            3 => Ok(PduType::Register),
            4 => Ok(PduType::Unregister),
            5 => Ok(PduType::Get),
            6 => Ok(PduType::GetNext),
            7 => Ok(PduType::GetBulk),
            8 => Ok(PduType::TestSet),
            9 => Ok(PduType::CommitSet),
            10 => Ok(PduType::UndoSet),
            11 => Ok(PduType::CleanupSet),
            12 => Ok(PduType::Notify),
            13 => Ok(PduType::Ping),
            14 => Ok(PduType::IndexAllocate),
            15 => Ok(PduType::IndexDeallocate),
            16 => Ok(PduType::AddAgentCaps),
            17 => Ok(PduType::RemoveAgentCaps),
            18 => Ok(PduType::Response),
            _ => Err(value),
        }
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Flags: u8 {
        const INSTANCE_REGISTRATION = 0x01;
        const NEW_INDEX = 0x02;
        const ANY_INDEX = 0x04;
        const NON_DEFAULT_CONTEXT = 0x08;
        const NETWORK_BYTE_ORDER = 0x10;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub pdu_type: PduType,
    pub flags: Flags,
    pub session_id: u32,
    pub transaction_id: u32,
    pub packet_id: u32,
    pub payload_length: u32,
}

impl Header {
    pub fn new(pdu_type: PduType, session_id: u32, transaction_id: u32, packet_id: u32) -> Self {
        Self {
            version: AGENTX_VERSION,
            pdu_type,
            flags: Flags::NETWORK_BYTE_ORDER,
            session_id,
            transaction_id,
            packet_id,
            payload_length: 0,
        }
    }

    pub fn with_payload_length(mut self, len: u32) -> Self {
        self.payload_length = len;
        self
    }

    pub fn with_flags(mut self, flags: Flags) -> Self {
        self.flags = flags;
        self
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&[self.version])?;
        writer.write_all(&[self.pdu_type as u8])?;
        writer.write_all(&[self.flags.bits()])?;
        writer.write_all(&[0u8])?; // reserved

        if self.flags.contains(Flags::NETWORK_BYTE_ORDER) {
            writer.write_all(&self.session_id.to_be_bytes())?;
            writer.write_all(&self.transaction_id.to_be_bytes())?;
            writer.write_all(&self.packet_id.to_be_bytes())?;
            writer.write_all(&self.payload_length.to_be_bytes())?;
        } else {
            writer.write_all(&self.session_id.to_le_bytes())?;
            writer.write_all(&self.transaction_id.to_le_bytes())?;
            writer.write_all(&self.packet_id.to_le_bytes())?;
            writer.write_all(&self.payload_length.to_le_bytes())?;
        }

        Ok(())
    }

    pub fn decode<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut buf)?;

        let version = buf[0];
        let pdu_type = PduType::try_from(buf[1]).map_err(|v| {
            io::Error::new(io::ErrorKind::InvalidData, format!("unknown PDU type: {v}"))
        })?;
        let flags = Flags::from_bits_truncate(buf[2]);

        let network_order = flags.contains(Flags::NETWORK_BYTE_ORDER);
        let (session_id, transaction_id, packet_id, payload_length) = if network_order {
            (
                u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
                u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
                u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
                u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]),
            )
        } else {
            (
                u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
                u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
                u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
                u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
            )
        };

        Ok(Self {
            version,
            pdu_type,
            flags,
            session_id,
            transaction_id,
            packet_id,
            payload_length,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let header = Header::new(PduType::Open, 1, 2, 3).with_payload_length(100);

        let mut buf = Vec::new();
        header.encode(&mut buf).unwrap();

        assert_eq!(buf.len(), HEADER_SIZE);

        let decoded = Header::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_header_fields() {
        let header = Header::new(PduType::Register, 42, 100, 200)
            .with_payload_length(50)
            .with_flags(Flags::NETWORK_BYTE_ORDER | Flags::INSTANCE_REGISTRATION);

        assert_eq!(header.version, AGENTX_VERSION);
        assert_eq!(header.pdu_type, PduType::Register);
        assert_eq!(header.session_id, 42);
        assert_eq!(header.transaction_id, 100);
        assert_eq!(header.packet_id, 200);
        assert_eq!(header.payload_length, 50);
    }

    #[test]
    fn test_pdu_type_conversion() {
        assert_eq!(PduType::try_from(1), Ok(PduType::Open));
        assert_eq!(PduType::try_from(18), Ok(PduType::Response));
        assert!(PduType::try_from(0).is_err());
        assert!(PduType::try_from(19).is_err());
    }
}
