"""Tests for Manager.get_table()."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from snmpkit.core import Oid, Value
from snmpkit.manager import Manager


class MockVarBind:
    def __init__(self, oid: str, value: Value):
        self.oid = Oid(oid)
        self.value = value


class MockResponse:
    def __init__(self, varbinds=None, error_status=0, error_index=0):
        self.varbinds = varbinds or []
        self.error_status = error_status
        self.error_index = error_index


@pytest.fixture
def connected_manager():
    mgr = Manager("192.168.1.1")
    mgr.transport = MagicMock()
    mgr.transport.send_request = AsyncMock(return_value=b"\x30\x00")
    return mgr


class TestGetTable:
    """Tests for get_table() method."""

    async def test_basic_table(self, connected_manager):
        """get_table parses OID suffixes into {index: {column: value}}."""
        # ifTable: base = 1.3.6.1.2.1.2.2.1
        # OID format: base.column.index
        call_count = [0]
        responses = [
            # First bulk response: some rows
            MockResponse(
                varbinds=[
                    MockVarBind("1.3.6.1.2.1.2.2.1.1.1", Value.Integer(1)),  # col=1, idx=(1,)
                    MockVarBind("1.3.6.1.2.1.2.2.1.1.2", Value.Integer(2)),  # col=1, idx=(2,)
                    MockVarBind(
                        "1.3.6.1.2.1.2.2.1.2.1", Value.OctetString(b"lo")
                    ),  # col=2, idx=(1,)
                    MockVarBind(
                        "1.3.6.1.2.1.2.2.1.2.2", Value.OctetString(b"eth0")
                    ),  # col=2, idx=(2,)
                ]
            ),
            # Second bulk response: out of subtree -> end
            MockResponse(
                varbinds=[
                    MockVarBind("1.3.6.1.2.1.3.1.0", Value.Integer(0)),
                ]
            ),
        ]

        def mock_decode(data):
            idx = call_count[0]
            call_count[0] += 1
            return responses[idx]

        with patch("snmpkit.manager.manager.decode_snmp_response", side_effect=mock_decode):
            table = await connected_manager.get_table("1.3.6.1.2.1.2.2.1", bulk_size=10)

        assert (1,) in table
        assert (2,) in table
        assert table[(1,)][1] == Value.Integer(1)
        assert table[(1,)][2] == Value.OctetString(b"lo")
        assert table[(2,)][1] == Value.Integer(2)
        assert table[(2,)][2] == Value.OctetString(b"eth0")

    async def test_column_filtering(self, connected_manager):
        """get_table filters columns when specified."""
        call_count = [0]
        responses = [
            MockResponse(
                varbinds=[
                    MockVarBind("1.3.6.1.2.1.2.2.1.1.1", Value.Integer(1)),
                    MockVarBind("1.3.6.1.2.1.2.2.1.2.1", Value.OctetString(b"lo")),
                    MockVarBind("1.3.6.1.2.1.2.2.1.3.1", Value.Integer(24)),
                ]
            ),
            MockResponse(
                varbinds=[
                    MockVarBind("1.3.6.1.2.1.3.1.0", Value.Integer(0)),
                ]
            ),
        ]

        def mock_decode(data):
            idx = call_count[0]
            call_count[0] += 1
            return responses[idx]

        with patch("snmpkit.manager.manager.decode_snmp_response", side_effect=mock_decode):
            table = await connected_manager.get_table("1.3.6.1.2.1.2.2.1", columns=[1, 2])

        assert (1,) in table
        assert 1 in table[(1,)]
        assert 2 in table[(1,)]
        assert 3 not in table[(1,)]  # filtered out

    async def test_multi_index(self, connected_manager):
        """get_table handles multi-component index tuples."""
        call_count = [0]
        # ipNetToMediaTable uses index = (ifIndex, ipAddress parts)
        # base.column.ifIndex.a.b.c.d
        responses = [
            MockResponse(
                varbinds=[
                    MockVarBind("1.3.6.1.2.1.4.22.1.1.1.10.0.0.1", Value.Integer(1)),
                    MockVarBind("1.3.6.1.2.1.4.22.1.1.2.192.168.1.1", Value.Integer(2)),
                ]
            ),
            MockResponse(
                varbinds=[
                    MockVarBind("1.3.6.1.2.1.5.0", Value.Integer(0)),
                ]
            ),
        ]

        def mock_decode(data):
            idx = call_count[0]
            call_count[0] += 1
            return responses[idx]

        with patch("snmpkit.manager.manager.decode_snmp_response", side_effect=mock_decode):
            table = await connected_manager.get_table("1.3.6.1.2.1.4.22.1")

        assert (1, 10, 0, 0, 1) in table
        assert (2, 192, 168, 1, 1) in table

    async def test_empty_table(self, connected_manager):
        """get_table returns empty dict when no rows match."""
        with patch("snmpkit.manager.manager.decode_snmp_response") as mock_decode:
            mock_decode.return_value = MockResponse(varbinds=[])

            table = await connected_manager.get_table("1.3.6.1.2.1.99.1")

        assert table == {}

    async def test_skips_short_oids(self, connected_manager):
        """get_table skips OIDs that are too short for base.column.index."""
        call_count = [0]
        responses = [
            MockResponse(
                varbinds=[
                    # This OID is base + just 1 component (column only, no index)
                    MockVarBind("1.3.6.1.2.1.2.2.1.1", Value.Integer(1)),
                    # This one is valid: base.column.index
                    MockVarBind("1.3.6.1.2.1.2.2.1.1.1", Value.Integer(1)),
                ]
            ),
            MockResponse(
                varbinds=[
                    MockVarBind("1.3.6.1.2.1.3.1.0", Value.Integer(0)),
                ]
            ),
        ]

        def mock_decode(data):
            idx = call_count[0]
            call_count[0] += 1
            return responses[idx]

        with patch("snmpkit.manager.manager.decode_snmp_response", side_effect=mock_decode):
            table = await connected_manager.get_table("1.3.6.1.2.1.2.2.1")

        # Only the valid row should be in the table
        assert len(table) == 1
        assert (1,) in table
