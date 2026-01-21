"""Unit Tests for AgentX PDU encoding/decoding via Rust bindings."""

import pytest
from snmpkit.core import (
    HEADER_SIZE,
    CloseReasons,
    Oid,
    PduTypes,
    ResponseErrors,
    Value,
    VarBind,
    decode_get_pdu,
    decode_getbulk_pdu,
    decode_header,
    decode_response_pdu,
    decode_testset_pdu,
    encode_close_pdu,
    encode_notify_pdu,
    encode_open_pdu,
    encode_ping_pdu,
    encode_register_pdu,
    encode_response_pdu,
    encode_unregister_pdu,
)

# Common test data
TEST_OID = Oid("1.3.6.1.4.1.12345")
SYSNAME_OID = Oid("1.3.6.1.2.1.1.5.0")


@pytest.fixture
def sample_varbinds():
    """Common varbinds for testing."""
    return [
        VarBind(Oid("1.3.6.1.2.1.1.1.0"), Value.OctetString(b"Linux")),
        VarBind(Oid("1.3.6.1.2.1.1.3.0"), Value.TimeTicks(123456)),
        VarBind(Oid("1.3.6.1.2.1.1.5.0"), Value.OctetString(b"hostname")),
    ]


def make_response_pdu(varbinds, error=0, index=0):
    """Helper to create response PDU with defaults."""
    return encode_response_pdu(
        session_id=1,
        transaction_id=1,
        packet_id=1,
        sys_uptime=1000,
        error=error,
        index=index,
        varbinds=varbinds,
    )


def decode_response(pdu):
    """Helper to decode a response PDU."""
    header = decode_header(pdu[:HEADER_SIZE])
    return decode_response_pdu(pdu[HEADER_SIZE:], header.payload_length)


class TestConstants:
    """Tests for PDU constants."""

    def test_header_size(self):
        """Header size is 20 bytes per RFC 2741."""
        assert HEADER_SIZE == 20

    def test_pdu_types(self):
        """PDU type constants match RFC 2741."""
        expected = {
            "OPEN": 1,
            "CLOSE": 2,
            "REGISTER": 3,
            "UNREGISTER": 4,
            "GET": 5,
            "GET_NEXT": 6,
            "GET_BULK": 7,
            "TEST_SET": 8,
            "COMMIT_SET": 9,
            "UNDO_SET": 10,
            "CLEANUP_SET": 11,
            "NOTIFY": 12,
            "PING": 13,
            "RESPONSE": 18,
        }
        for name, val in expected.items():
            assert getattr(PduTypes, name) == val

    def test_close_reasons(self):
        """Close reason constants match RFC 2741."""
        expected = {
            "OTHER": 1,
            "PARSE_ERROR": 2,
            "PROTOCOL_ERROR": 3,
            "TIMEOUTS": 4,
            "SHUTDOWN": 5,
            "BY_MANAGER": 6,
        }
        for name, val in expected.items():
            assert getattr(CloseReasons, name) == val

    def test_response_errors(self):
        """Response error constants match RFC 2741."""
        assert ResponseErrors.NO_ERROR == 0
        assert ResponseErrors.OPEN_FAILED == 256
        assert ResponseErrors.DUPLICATE_REGISTRATION == 263


class TestVarBind:
    """Tests for VarBind class."""

    @pytest.mark.parametrize(
        "value",
        [
            Value.Integer(42),
            Value.OctetString(b"test"),
            Value.Counter64(2**63),
            Value.IpAddress(192, 168, 1, 1),
            Value.NoSuchObject(),
        ],
    )
    def test_create_varbind(self, value):
        """Create VarBind with various value types."""
        vb = VarBind(TEST_OID, value)
        assert vb.value == value
        assert str(vb.oid) == str(TEST_OID)

    def test_varbind_repr(self):
        """VarBind has readable repr."""
        vb = VarBind(Oid("1.3.6.1"), Value.Integer(123))
        assert "1.3.6.1" in repr(vb) and "123" in repr(vb)


class TestValueTypes:
    """Tests for SNMP Value types."""

    @pytest.mark.parametrize(
        "value,expected",
        [
            (Value.Integer(42), Value.Integer(42)),
            (Value.Integer(-12345), Value.Integer(-12345)),
            (Value.OctetString(b"hello"), Value.OctetString(b"hello")),
            (Value.Null(), Value.Null()),
            (Value.Counter32(4294967295), Value.Counter32(4294967295)),
            (Value.Gauge32(1000000), Value.Gauge32(1000000)),
            (Value.TimeTicks(123456789), Value.TimeTicks(123456789)),
            (Value.Counter64(2**64 - 1), Value.Counter64(2**64 - 1)),
            (Value.Opaque(b"\x00\x01\x02"), Value.Opaque(b"\x00\x01\x02")),
            (Value.NoSuchObject(), Value.NoSuchObject()),
            (Value.NoSuchInstance(), Value.NoSuchInstance()),
            (Value.EndOfMibView(), Value.EndOfMibView()),
        ],
    )
    def test_value_equality(self, value, expected):
        """Value types compare equal correctly."""
        assert value == expected

    def test_ip_address(self):
        """IpAddress value with octets."""
        v = Value.IpAddress(192, 168, 1, 1)
        assert v == Value.IpAddress(192, 168, 1, 1)

    def test_object_identifier(self):
        """ObjectIdentifier value."""
        v = Value.ObjectIdentifier(TEST_OID)
        assert v == Value.ObjectIdentifier(TEST_OID)


class TestEncodePdu:
    """Tests for PDU encoding functions."""

    def test_encode_open_pdu(self):
        """Encode Open PDU."""
        pdu = encode_open_pdu(0, 1, 1, 5, TEST_OID, "test-agent")
        header = decode_header(pdu[:HEADER_SIZE])
        assert header.pdu_type == PduTypes.OPEN
        assert len(pdu) >= HEADER_SIZE

    def test_encode_close_pdu(self):
        """Encode Close PDU."""
        pdu = encode_close_pdu(123, 1, 1, CloseReasons.SHUTDOWN)
        header = decode_header(pdu[:HEADER_SIZE])
        assert header.pdu_type == PduTypes.CLOSE
        assert header.session_id == 123

    def test_encode_register_pdu(self):
        """Encode Register PDU."""
        pdu = encode_register_pdu(123, 1, 1, TEST_OID, 127, 5)
        header = decode_header(pdu[:HEADER_SIZE])
        assert header.pdu_type == PduTypes.REGISTER

    def test_encode_register_pdu_with_context(self):
        """Encode Register PDU with context sets flag."""
        pdu = encode_register_pdu(123, 1, 1, TEST_OID, 127, 5, context="ctx")
        header = decode_header(pdu[:HEADER_SIZE])
        assert header.flags & 0x08

    def test_encode_unregister_pdu(self):
        """Encode Unregister PDU."""
        pdu = encode_unregister_pdu(123, 1, 1, TEST_OID, 127)
        header = decode_header(pdu[:HEADER_SIZE])
        assert header.pdu_type == PduTypes.UNREGISTER

    def test_encode_ping_pdu(self):
        """Encode Ping PDU."""
        pdu = encode_ping_pdu(123, 5, 10)
        header = decode_header(pdu[:HEADER_SIZE])
        assert header.pdu_type == PduTypes.PING
        assert header.session_id == 123
        assert header.transaction_id == 5
        assert header.packet_id == 10

    def test_encode_response_pdu(self, sample_varbinds):
        """Encode Response PDU."""
        pdu = make_response_pdu(sample_varbinds)
        header = decode_header(pdu[:HEADER_SIZE])
        assert header.pdu_type == PduTypes.RESPONSE

    def test_encode_response_pdu_with_error(self):
        """Encode Response PDU with error."""
        pdu = make_response_pdu([], error=17, index=1)
        header = decode_header(pdu[:HEADER_SIZE])
        assert header.pdu_type == PduTypes.RESPONSE

    def test_encode_notify_pdu(self):
        """Encode Notify PDU."""
        varbinds = [VarBind(TEST_OID, Value.Integer(1))]
        pdu = encode_notify_pdu(123, 1, 1, varbinds)
        header = decode_header(pdu[:HEADER_SIZE])
        assert header.pdu_type == PduTypes.NOTIFY

    def test_encode_notify_pdu_with_context(self):
        """Encode Notify PDU with context."""
        varbinds = [VarBind(TEST_OID, Value.Integer(1))]
        pdu = encode_notify_pdu(123, 1, 1, varbinds, context="ctx")
        header = decode_header(pdu[:HEADER_SIZE])
        assert header.flags & 0x08


class TestDecodeHeader:
    """Tests for header decoding."""

    def test_decode_header_fields(self):
        """Decode header extracts all fields."""
        pdu = encode_open_pdu(42, 7, 99, 5, TEST_OID, "test")
        header = decode_header(pdu[:HEADER_SIZE])
        assert header.pdu_type == PduTypes.OPEN
        assert header.session_id == 42
        assert header.transaction_id == 7
        assert header.packet_id == 99
        assert header.payload_length > 0

    def test_decode_header_flags(self):
        """Decode header includes flags."""
        pdu = encode_register_pdu(1, 1, 1, TEST_OID, 127, 5, context="ctx")
        header = decode_header(pdu[:HEADER_SIZE])
        assert header.flags & 0x10  # NETWORK_BYTE_ORDER


class TestDecodeResponsePdu:
    """Tests for Response PDU decoding."""

    def test_decode_response_no_error(self):
        """Decode Response PDU without error."""
        pdu = make_response_pdu([])
        response = decode_response(pdu)
        assert response.error == 0
        assert not response.is_error

    def test_decode_response_with_error(self):
        """Decode Response PDU with error."""
        pdu = make_response_pdu([], error=17, index=2)
        response = decode_response(pdu)
        assert response.error == 17
        assert response.index == 2
        assert response.is_error

    def test_decode_response_uptime(self):
        """Decode Response PDU preserves uptime."""
        pdu = encode_response_pdu(1, 1, 1, sys_uptime=5000, error=0, index=0, varbinds=[])
        response = decode_response(pdu)
        assert response.sys_uptime == 5000


class TestDecodePduCallables:
    """Verify decode functions exist and are callable."""

    def test_decode_get_pdu_exists(self):
        assert callable(decode_get_pdu)

    def test_decode_getbulk_pdu_exists(self):
        assert callable(decode_getbulk_pdu)

    def test_decode_testset_pdu_exists(self):
        assert callable(decode_testset_pdu)


class TestRoundTrip:
    """End-to-end roundtrip tests."""

    @pytest.mark.parametrize(
        "value",
        [
            Value.Integer(42),
            Value.Integer(-12345),
            Value.OctetString(b"test string"),
            Value.Counter64(2**63 + 12345),
            Value.TimeTicks(123456),
            Value.IpAddress(192, 168, 1, 1),
            Value.Counter32(4294967295),
            Value.Gauge32(1000000),
            Value.NoSuchObject(),
            Value.NoSuchInstance(),
            Value.EndOfMibView(),
        ],
    )
    def test_response_roundtrip_value(self, value):
        """Response PDU value roundtrips correctly."""
        varbinds = [VarBind(SYSNAME_OID, value)]
        pdu = make_response_pdu(varbinds)
        response = decode_response(pdu)

        assert len(response.varbinds) == 1
        assert response.varbinds[0].value == value

    def test_response_roundtrip_multiple_varbinds(self, sample_varbinds):
        """Response PDU with multiple varbinds roundtrips correctly."""
        pdu = make_response_pdu(sample_varbinds)
        response = decode_response(pdu)

        assert len(response.varbinds) == 3
        assert response.varbinds[0].value == Value.OctetString(b"Linux")
        assert response.varbinds[1].value == Value.TimeTicks(123456)
        assert response.varbinds[2].value == Value.OctetString(b"hostname")

    def test_response_roundtrip_preserves_oid(self):
        """Response PDU preserves OID."""
        oid = Oid("1.3.6.1.2.1.1.1.0")
        varbinds = [VarBind(oid, Value.Integer(1))]
        pdu = make_response_pdu(varbinds)
        response = decode_response(pdu)

        assert str(response.varbinds[0].oid) == str(oid)
