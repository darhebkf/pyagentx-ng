"""Unit Tests for the Manager class."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from snmpkit.core import Oid, Value
from snmpkit.manager import Manager
from snmpkit.manager.exceptions import (
    EndOfMibViewError,
    GenericError,
    NoSuchInstanceError,
    NoSuchObjectError,
)


class MockVarBind:
    """Mock VarBind for SNMP responses."""

    def __init__(self, oid: str, value: Value):
        self.oid = Oid(oid)
        self.value = value


class MockResponse:
    """Mock SNMP response."""

    def __init__(self, varbinds=None, error_status=0, error_index=0):
        self.varbinds = varbinds or []
        self.error_status = error_status
        self.error_index = error_index


@pytest.fixture
def manager():
    """Create a fresh Manager for each test."""
    return Manager("192.168.1.1")


@pytest.fixture
def connected_manager(manager):
    """Create a Manager with mocked transport."""
    manager.transport = MagicMock()
    manager.transport.send_request = AsyncMock(return_value=b"\x30\x00")
    return manager


class TestManagerInit:
    """Tests for Manager initialization."""

    def test_default_values(self):
        """Manager initializes with default values."""
        mgr = Manager("10.0.0.1")
        assert mgr.host == "10.0.0.1"
        assert mgr.port == 161
        assert mgr.community == "public"
        assert mgr.version == 2
        assert mgr.timeout == 5.0
        assert mgr.retries == 3
        assert mgr.transport is None

    def test_custom_values(self):
        """Manager accepts custom initialization values."""
        mgr = Manager(
            "10.0.0.1",
            port=1161,
            community="private",
            version=1,
            timeout=10.0,
            retries=5,
        )
        assert mgr.host == "10.0.0.1"
        assert mgr.port == 1161
        assert mgr.community == "private"
        assert mgr.version == 1
        assert mgr.timeout == 10.0
        assert mgr.retries == 5


class TestManagerRequestId:
    """Tests for request ID generation."""

    def test_next_request_id_increments(self, manager):
        """_next_request_id increments and returns."""
        first = manager._next_request_id()
        second = manager._next_request_id()
        third = manager._next_request_id()
        assert second == first + 1
        assert third == second + 1


class TestManagerGet:
    """Tests for GET operations."""

    async def test_get_not_connected_raises(self, manager):
        """GET on unconnected manager raises RuntimeError."""
        with pytest.raises(RuntimeError, match="Not connected"):
            await manager.get("1.3.6.1.2.1.1.1.0")

    async def test_get_returns_value(self, connected_manager):
        """GET returns the value from response."""
        with patch("snmpkit.manager.manager.decode_snmp_response") as mock_decode:
            mock_decode.return_value = MockResponse(
                varbinds=[MockVarBind("1.3.6.1.2.1.1.1.0", Value.OctetString(b"Linux"))]
            )

            result = await connected_manager.get("1.3.6.1.2.1.1.1.0")
            assert result == Value.OctetString(b"Linux")

    async def test_get_many_returns_multiple_values(self, connected_manager):
        """GET with multiple OIDs returns list of values."""
        with patch("snmpkit.manager.manager.decode_snmp_response") as mock_decode:
            mock_decode.return_value = MockResponse(
                varbinds=[
                    MockVarBind("1.3.6.1.2.1.1.1.0", Value.OctetString(b"Linux")),
                    MockVarBind("1.3.6.1.2.1.1.3.0", Value.TimeTicks(12345)),
                ]
            )

            results = await connected_manager.get_many(
                "1.3.6.1.2.1.1.1.0",
                "1.3.6.1.2.1.1.3.0",
            )
            assert len(results) == 2
            assert results[0] == Value.OctetString(b"Linux")
            assert results[1] == Value.TimeTicks(12345)

    async def test_get_nosuchobject_raises(self, connected_manager):
        """GET on non-existent OID raises NoSuchObjectError."""
        with patch("snmpkit.manager.manager.decode_snmp_response") as mock_decode:
            mock_decode.return_value = MockResponse(
                varbinds=[MockVarBind("1.3.6.1.2.1.1.99.0", Value.NoSuchObject())]
            )

            with pytest.raises(NoSuchObjectError):
                await connected_manager.get("1.3.6.1.2.1.1.99.0")

    async def test_get_nosuchinstance_raises(self, connected_manager):
        """GET on non-existent instance raises NoSuchInstanceError."""
        with patch("snmpkit.manager.manager.decode_snmp_response") as mock_decode:
            mock_decode.return_value = MockResponse(
                varbinds=[MockVarBind("1.3.6.1.2.1.1.1.99", Value.NoSuchInstance())]
            )

            with pytest.raises(NoSuchInstanceError):
                await connected_manager.get("1.3.6.1.2.1.1.1.99")

    async def test_get_error_status_raises(self, connected_manager):
        """GET with error status raises GenericError."""
        with patch("snmpkit.manager.manager.decode_snmp_response") as mock_decode:
            mock_decode.return_value = MockResponse(error_status=2, error_index=1)

            with pytest.raises(GenericError) as exc_info:
                await connected_manager.get("1.3.6.1.2.1.1.1.0")
            assert exc_info.value.status == 2
            assert exc_info.value.index == 1


class TestManagerGetNext:
    """Tests for GETNEXT operations."""

    async def test_getnext_returns_next_oid_and_value(self, connected_manager):
        """GETNEXT returns the next OID and its value."""
        with patch("snmpkit.manager.manager.decode_snmp_response") as mock_decode:
            mock_decode.return_value = MockResponse(
                varbinds=[
                    MockVarBind(
                        "1.3.6.1.2.1.1.2.0",
                        Value.ObjectIdentifier(Oid("1.3.6.1.4.1.8072.3.2.10")),
                    )
                ]
            )

            oid, value = await connected_manager.get_next("1.3.6.1.2.1.1.1.0")
            assert oid == "1.3.6.1.2.1.1.2.0"
            assert value == Value.ObjectIdentifier(Oid("1.3.6.1.4.1.8072.3.2.10"))

    async def test_getnext_endofmibview_raises(self, connected_manager):
        """GETNEXT at end of MIB raises EndOfMibViewError."""
        with patch("snmpkit.manager.manager.decode_snmp_response") as mock_decode:
            mock_decode.return_value = MockResponse(
                varbinds=[MockVarBind("1.3.6.1.2.1.1.9.1.4.9", Value.EndOfMibView())]
            )

            with pytest.raises(EndOfMibViewError):
                await connected_manager.get_next("1.3.6.1.2.1.1.9.1.4.9")

    async def test_getnext_empty_response_raises(self, connected_manager):
        """GETNEXT with empty response raises EndOfMibViewError."""
        with patch("snmpkit.manager.manager.decode_snmp_response") as mock_decode:
            mock_decode.return_value = MockResponse(varbinds=[])

            with pytest.raises(EndOfMibViewError, match="No varbinds"):
                await connected_manager.get_next("1.3.6.1.2.1.1.1.0")


class TestManagerGetBulk:
    """Tests for GETBULK operations."""

    async def test_getbulk_v1_raises(self):
        """GETBULK on SNMPv1 raises ValueError."""
        mgr = Manager("10.0.0.1", version=1)
        mgr.transport = MagicMock()

        with pytest.raises(ValueError, match="not supported in SNMPv1"):
            await mgr.get_bulk("1.3.6.1.2.1.2.2")

    async def test_getbulk_returns_multiple_results(self, connected_manager):
        """GETBULK returns multiple OID/value pairs."""
        with patch("snmpkit.manager.manager.decode_snmp_response") as mock_decode:
            mock_decode.return_value = MockResponse(
                varbinds=[
                    MockVarBind("1.3.6.1.2.1.2.2.1.1.1", Value.Integer(1)),
                    MockVarBind("1.3.6.1.2.1.2.2.1.1.2", Value.Integer(2)),
                    MockVarBind("1.3.6.1.2.1.2.2.1.1.3", Value.Integer(3)),
                ]
            )

            results = await connected_manager.get_bulk(
                "1.3.6.1.2.1.2.2.1.1",
                max_repetitions=10,
            )
            assert len(results) == 3
            assert results[0] == ("1.3.6.1.2.1.2.2.1.1.1", Value.Integer(1))
            assert results[1] == ("1.3.6.1.2.1.2.2.1.1.2", Value.Integer(2))
            assert results[2] == ("1.3.6.1.2.1.2.2.1.1.3", Value.Integer(3))

    async def test_getbulk_filters_exception_values(self, connected_manager):
        """GETBULK filters out exception values."""
        with patch("snmpkit.manager.manager.decode_snmp_response") as mock_decode:
            mock_decode.return_value = MockResponse(
                varbinds=[
                    MockVarBind("1.3.6.1.2.1.2.2.1.1.1", Value.Integer(1)),
                    MockVarBind("1.3.6.1.2.1.2.2.1.1.2", Value.EndOfMibView()),
                ]
            )

            results = await connected_manager.get_bulk(
                "1.3.6.1.2.1.2.2.1.1",
                max_repetitions=10,
            )
            assert len(results) == 1
            assert results[0] == ("1.3.6.1.2.1.2.2.1.1.1", Value.Integer(1))


class TestManagerWalk:
    """Tests for WALK operations."""

    async def test_walk_iterates_subtree(self, connected_manager):
        """WALK iterates through OID subtree."""
        call_count = [0]
        responses = [
            MockResponse(varbinds=[MockVarBind("1.3.6.1.2.1.1.1.0", Value.OctetString(b"desc"))]),
            MockResponse(
                varbinds=[
                    MockVarBind(
                        "1.3.6.1.2.1.1.2.0",
                        Value.ObjectIdentifier(Oid("1.3.6.1")),
                    )
                ]
            ),
            MockResponse(varbinds=[MockVarBind("1.3.6.1.2.1.2.1.0", Value.Integer(1))]),
        ]

        def mock_decode(data):
            idx = call_count[0]
            call_count[0] += 1
            return responses[idx]

        with patch(
            "snmpkit.manager.manager.decode_snmp_response",
            side_effect=mock_decode,
        ):
            results = []
            async for oid, value in connected_manager.walk("1.3.6.1.2.1.1"):
                results.append((oid, value))

            assert len(results) == 2
            assert results[0][0] == "1.3.6.1.2.1.1.1.0"
            assert results[1][0] == "1.3.6.1.2.1.1.2.0"

    async def test_walk_stops_at_endofmibview(self, connected_manager):
        """WALK stops when EndOfMibView is returned."""
        with patch("snmpkit.manager.manager.decode_snmp_response") as mock_decode:
            mock_decode.return_value = MockResponse(
                varbinds=[MockVarBind("1.3.6.1.2.1.1.1.0", Value.EndOfMibView())]
            )

            results = []
            async for oid, value in connected_manager.walk("1.3.6.1.2.1.1"):
                results.append((oid, value))

            assert len(results) == 0


class TestManagerSet:
    """Tests for SET operations."""

    async def test_set_not_connected_raises(self, manager):
        """SET on unconnected manager raises RuntimeError."""
        with pytest.raises(RuntimeError, match="Not connected"):
            await manager.set("1.3.6.1.2.1.1.5.0", Value.OctetString(b"newname"))

    async def test_set_v1_raises(self):
        """SET on SNMPv1 raises ValueError."""
        mgr = Manager("10.0.0.1", version=1)
        mgr.transport = MagicMock()

        with pytest.raises(ValueError, match="not implemented for SNMPv1"):
            await mgr.set("1.3.6.1.2.1.1.5.0", Value.OctetString(b"newname"))

    async def test_set_success(self, connected_manager):
        """SET successfully sets a value."""
        with patch("snmpkit.manager.manager.decode_snmp_response") as mock_decode:
            mock_decode.return_value = MockResponse(
                varbinds=[MockVarBind("1.3.6.1.2.1.1.5.0", Value.OctetString(b"newname"))]
            )

            await connected_manager.set(
                "1.3.6.1.2.1.1.5.0",
                Value.OctetString(b"newname"),
            )


class TestManagerContextManager:
    """Tests for async context manager."""

    async def test_context_manager_connects_and_closes(self):
        """Context manager calls connect and close."""
        with patch.object(Manager, "connect", new_callable=AsyncMock) as mock_connect:
            with patch.object(Manager, "close", new_callable=AsyncMock) as mock_close:
                async with Manager("10.0.0.1") as mgr:
                    mock_connect.assert_called_once()
                    assert mgr is not None
                mock_close.assert_called_once()
