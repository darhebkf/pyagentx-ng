use snmpkit::agentx::{Flags, HEADER_SIZE, Header, PduType};

#[test]
fn test_header_encode_decode() {
    let header = Header::new(PduType::Open, 1, 2, 3)
        .with_payload_length(100)
        .with_flags(Flags::NETWORK_BYTE_ORDER);

    let mut buf = Vec::new();
    header.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), HEADER_SIZE);

    let decoded = Header::decode(&mut buf.as_slice()).unwrap();
    assert_eq!(decoded.pdu_type, PduType::Open);
    assert_eq!(decoded.session_id, 1);
    assert_eq!(decoded.transaction_id, 2);
    assert_eq!(decoded.packet_id, 3);
    assert_eq!(decoded.payload_length, 100);
}

#[test]
fn test_all_pdu_types() {
    let types = [
        PduType::Open,
        PduType::Close,
        PduType::Register,
        PduType::Unregister,
        PduType::Get,
        PduType::GetNext,
        PduType::GetBulk,
        PduType::Response,
    ];

    for pdu_type in types {
        let header = Header::new(pdu_type, 0, 0, 0);
        let mut buf = Vec::new();
        header.encode(&mut buf).unwrap();

        let decoded = Header::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.pdu_type, pdu_type);
    }
}
