"""Tests for Manager.send_trap() and Manager.send_inform()."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from snmpkit.core import Oid, Value
from snmpkit.manager import Manager


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
    mgr.transport.send_only = AsyncMock()
    return mgr


class TestBuildTrapVarbinds:
    """Tests for _build_trap_varbinds helper."""

    def test_builds_standard_varbinds(self):
        mgr = Manager("10.0.0.1")
        vbs = mgr._build_trap_varbinds("1.3.6.1.4.1.99.0.1")

        assert len(vbs) == 2
        assert str(vbs[0].oid) == "1.3.6.1.2.1.1.3.0"
        assert vbs[0].value == Value.TimeTicks(0)
        assert str(vbs[1].oid) == "1.3.6.1.6.3.1.1.4.1.0"
        assert vbs[1].value == Value.ObjectIdentifier(Oid("1.3.6.1.4.1.99.0.1"))

    def test_custom_uptime(self):
        mgr = Manager("10.0.0.1")
        vbs = mgr._build_trap_varbinds("1.3.6.1.4.1.99.0.1", uptime=54321)

        assert vbs[0].value == Value.TimeTicks(54321)

    def test_user_varbinds_appended(self):
        mgr = Manager("10.0.0.1")
        user_vbs = [
            ("1.3.6.1.4.1.99.1.1.0", Value.Integer(42)),
            ("1.3.6.1.4.1.99.1.2.0", Value.OctetString(b"hello")),
        ]
        vbs = mgr._build_trap_varbinds("1.3.6.1.4.1.99.0.1", varbinds=user_vbs)

        assert len(vbs) == 4
        assert str(vbs[2].oid) == "1.3.6.1.4.1.99.1.1.0"
        assert vbs[2].value == Value.Integer(42)
        assert str(vbs[3].oid) == "1.3.6.1.4.1.99.1.2.0"
        assert vbs[3].value == Value.OctetString(b"hello")


class TestSendTrap:
    """Tests for Manager.send_trap()."""

    async def test_send_trap_not_connected_raises(self):
        mgr = Manager("10.0.0.1")
        with pytest.raises(RuntimeError, match="Not connected"):
            await mgr.send_trap("1.3.6.1.4.1.99.0.1")

    async def test_send_trap_v1_calls_send_only(self):
        """v1 traps are fire-and-forget via send_only."""
        mgr = Manager("10.0.0.1", version=1)
        mgr.transport = MagicMock()
        mgr.transport.send_only = AsyncMock()
        await mgr.send_trap("1.3.6.1.4.1.99.0.1", agent_addr=(10, 0, 0, 1))
        mgr.transport.send_only.assert_called_once()

    async def test_send_trap_calls_send_only(self, connected_manager):
        """send_trap is fire-and-forget (uses send_only, not send_request)."""
        await connected_manager.send_trap("1.3.6.1.4.1.99.0.1")

        connected_manager.transport.send_only.assert_called_once()
        connected_manager.transport.send_request.assert_not_called()

    async def test_send_trap_encodes_v2c(self, connected_manager):
        """send_trap encodes using v2c for version 2."""
        with patch("snmpkit.manager.manager.encode_snmp_trap_v2c") as mock_encode:
            mock_encode.return_value = b"\x30\x00"
            await connected_manager.send_trap("1.3.6.1.4.1.99.0.1")
            mock_encode.assert_called_once()
            args = mock_encode.call_args
            assert args[0][0] == "public"  # community

    async def test_send_trap_with_varbinds(self, connected_manager):
        """send_trap includes user varbinds."""
        with patch("snmpkit.manager.manager.encode_snmp_trap_v2c") as mock_encode:
            mock_encode.return_value = b"\x30\x00"
            user_vbs = [("1.3.6.1.4.1.99.1.0", Value.Integer(100))]
            await connected_manager.send_trap("1.3.6.1.4.1.99.0.1", varbinds=user_vbs, uptime=5000)
            mock_encode.assert_called_once()
            varbinds = mock_encode.call_args[0][2]
            assert len(varbinds) == 3  # sysUpTime + trapOID + user


class TestSendInform:
    """Tests for Manager.send_inform()."""

    async def test_send_inform_not_connected_raises(self):
        mgr = Manager("10.0.0.1")
        with pytest.raises(RuntimeError, match="Not connected"):
            await mgr.send_inform("1.3.6.1.4.1.99.0.1")

    async def test_send_inform_v1_raises(self):
        mgr = Manager("10.0.0.1", version=1)
        mgr.transport = MagicMock()
        with pytest.raises(ValueError, match="SNMPv1"):
            await mgr.send_inform("1.3.6.1.4.1.99.0.1")

    async def test_send_inform_waits_for_ack(self, connected_manager):
        """send_inform uses send_request (waits for Response ACK)."""
        with patch("snmpkit.manager.manager.decode_snmp_response") as mock_decode:
            mock_decode.return_value = MockResponse()
            await connected_manager.send_inform("1.3.6.1.4.1.99.0.1")

        connected_manager.transport.send_request.assert_called_once()
        connected_manager.transport.send_only.assert_not_called()

    async def test_send_inform_encodes_v2c(self, connected_manager):
        """send_inform encodes using v2c for version 2."""
        with patch("snmpkit.manager.manager.decode_snmp_response") as mock_decode:
            mock_decode.return_value = MockResponse()
            with patch("snmpkit.manager.manager.encode_snmp_inform_v2c") as mock_encode:
                mock_encode.return_value = b"\x30\x00"
                await connected_manager.send_inform("1.3.6.1.4.1.99.0.1")
                mock_encode.assert_called_once()
