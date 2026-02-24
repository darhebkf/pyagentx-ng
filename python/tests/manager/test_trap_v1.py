"""Tests for SNMPv1 Trap support."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from snmpkit.core import Oid, SnmpVarBind, Value, decode_snmp_message, encode_snmp_trap_v1
from snmpkit.manager import Manager
from snmpkit.manager.trap_receiver import (
    _PDU_TRAPV1,
    TrapReceiver,
)

# Helpers


def _make_v1_trap_bytes(
    community: str = "public",
    enterprise: str = "1.3.6.1.4.1.99",
    agent_addr: tuple[int, int, int, int] = (192, 168, 1, 1),
    generic_trap: int = 6,
    specific_trap: int = 1,
    timestamp: int = 54321,
    varbinds: list | None = None,
) -> bytes:
    vbs = varbinds or []
    return encode_snmp_trap_v1(
        community, enterprise, agent_addr, generic_trap, specific_trap, timestamp, vbs
    )


class TestEncodeDecodeV1Trap:
    """Tests for v1 trap encoding and decoding via Rust bindings."""

    def test_encode_v1_trap(self):
        data = _make_v1_trap_bytes()
        assert isinstance(data, bytes)
        assert len(data) > 0

    def test_decode_v1_trap(self):
        data = _make_v1_trap_bytes()
        msg = decode_snmp_message(data)
        assert msg.version == 0
        assert msg.pdu_type == _PDU_TRAPV1
        assert msg.enterprise == "1.3.6.1.4.1.99"
        assert msg.agent_addr == (192, 168, 1, 1)
        assert msg.generic_trap == 6
        assert msg.specific_trap == 1
        assert msg.timestamp == 54321

    def test_decode_v1_trap_with_varbinds(self):
        vbs = [
            SnmpVarBind(Oid("1.3.6.1.4.1.99.1.1.0"), Value.Integer(42)),
            SnmpVarBind(Oid("1.3.6.1.4.1.99.1.2.0"), Value.OctetString(b"hello")),
        ]
        data = _make_v1_trap_bytes(varbinds=vbs)
        msg = decode_snmp_message(data)
        assert len(msg.varbinds) == 2
        assert msg.varbinds[0].value == Value.Integer(42)
        assert msg.varbinds[1].value == Value.OctetString(b"hello")

    def test_decode_v1_cold_start(self):
        data = _make_v1_trap_bytes(
            enterprise="1.3.6.1.6.3.1.1.5",
            agent_addr=(10, 0, 0, 1),
            generic_trap=0,
            specific_trap=0,
            timestamp=0,
        )
        msg = decode_snmp_message(data)
        assert msg.generic_trap == 0
        assert msg.specific_trap == 0
        assert msg.timestamp == 0

    def test_v1_trap_community(self):
        data = _make_v1_trap_bytes(community="private")
        msg = decode_snmp_message(data)
        assert bytes(msg.community) == b"private"


class TestTrapReceiverV1:
    """Tests for TrapReceiver handling v1 traps."""

    def test_receiver_accepts_v1_trap(self):
        data = _make_v1_trap_bytes()
        receiver = TrapReceiver()
        receiver._handle_datagram(data, ("10.0.0.1", 5000))
        assert not receiver._queue.empty()

    def test_receiver_parses_v1_fields(self):
        data = _make_v1_trap_bytes(
            enterprise="1.3.6.1.4.1.99",
            agent_addr=(192, 168, 1, 1),
            generic_trap=6,
            specific_trap=3,
            timestamp=12345,
        )
        receiver = TrapReceiver()
        receiver._handle_datagram(data, ("10.0.0.1", 5000))
        msg = receiver._queue.get_nowait()

        assert msg.version == 0
        assert msg.pdu_type == _PDU_TRAPV1
        assert msg.enterprise == "1.3.6.1.4.1.99"
        assert msg.agent_addr == (192, 168, 1, 1)
        assert msg.generic_trap == 6
        assert msg.specific_trap == 3
        assert msg.uptime == 12345
        assert msg.trap_oid == "1.3.6.1.4.1.99"
        assert msg.source == ("10.0.0.1", 5000)

    def test_receiver_v1_trap_varbinds(self):
        vbs = [SnmpVarBind(Oid("1.3.6.1.4.1.99.1.0"), Value.Integer(100))]
        data = _make_v1_trap_bytes(varbinds=vbs)
        receiver = TrapReceiver()
        receiver._handle_datagram(data, ("10.0.0.1", 5000))
        msg = receiver._queue.get_nowait()

        assert len(msg.varbinds) == 1
        assert msg.varbinds[0][0] == "1.3.6.1.4.1.99.1.0"
        assert msg.varbinds[0][1] == Value.Integer(100)

    def test_receiver_v1_no_ack(self):
        """v1 traps should NOT get an ACK (only Informs do)."""
        data = _make_v1_trap_bytes()
        receiver = TrapReceiver()
        mock_transport = MagicMock()
        receiver._transport = mock_transport
        receiver._handle_datagram(data, ("10.0.0.1", 5000))
        mock_transport.sendto.assert_not_called()

    def test_mixed_v1_v2c_traps(self):
        """Receiver handles both v1 and v2c traps."""
        from snmpkit.core import encode_snmp_trap_v2c

        v1_data = _make_v1_trap_bytes()
        v2c_vbs = [
            SnmpVarBind(Oid("1.3.6.1.2.1.1.3.0"), Value.TimeTicks(100)),
            SnmpVarBind(
                Oid("1.3.6.1.6.3.1.1.4.1.0"),
                Value.ObjectIdentifier(Oid("1.3.6.1.4.1.99.0.1")),
            ),
        ]
        v2c_data = encode_snmp_trap_v2c("public", 1, v2c_vbs)

        receiver = TrapReceiver()
        receiver._handle_datagram(v1_data, ("10.0.0.1", 5000))
        receiver._handle_datagram(v2c_data, ("10.0.0.2", 5000))

        assert receiver._queue.qsize() == 2

        msg1 = receiver._queue.get_nowait()
        msg2 = receiver._queue.get_nowait()

        assert msg1.version == 0
        assert msg1.pdu_type == _PDU_TRAPV1
        assert msg2.version == 1
        assert msg2.pdu_type == 0xA7


class TestManagerSendTrapV1:
    """Tests for Manager.send_trap() with version=1."""

    async def test_send_v1_trap_not_connected_raises(self):
        mgr = Manager("10.0.0.1", version=1)
        with pytest.raises(RuntimeError, match="Not connected"):
            await mgr.send_trap("1.3.6.1.4.1.99.0.1")

    async def test_send_v1_trap_encodes(self):
        mgr = Manager("10.0.0.1", version=1)
        mgr.transport = MagicMock()
        mgr.transport.send_only = AsyncMock()
        await mgr.send_trap(
            "1.3.6.1.4.1.99.0.1",
            agent_addr=(10, 0, 0, 1),
            generic_trap=6,
            specific_trap=1,
            uptime=5000,
        )
        mgr.transport.send_only.assert_called_once()
        sent_data = mgr.transport.send_only.call_args[0][0]
        assert isinstance(sent_data, bytes)

        # Verify the encoded data decodes correctly
        msg = decode_snmp_message(sent_data)
        assert msg.version == 0
        assert msg.pdu_type == _PDU_TRAPV1
        assert msg.enterprise == "1.3.6.1.4.1.99.0.1"
        assert msg.agent_addr == (10, 0, 0, 1)
        assert msg.generic_trap == 6
        assert msg.specific_trap == 1
        assert msg.timestamp == 5000

    async def test_send_v1_trap_with_varbinds(self):
        mgr = Manager("10.0.0.1", version=1)
        mgr.transport = MagicMock()
        mgr.transport.send_only = AsyncMock()
        user_vbs = [("1.3.6.1.4.1.99.1.0", Value.Integer(42))]
        await mgr.send_trap("1.3.6.1.4.1.99.0.1", varbinds=user_vbs)
        sent_data = mgr.transport.send_only.call_args[0][0]
        msg = decode_snmp_message(sent_data)
        assert len(msg.varbinds) == 1
        assert msg.varbinds[0].value == Value.Integer(42)

    async def test_send_v1_trap_enterprise_defaults_to_trap_oid(self):
        mgr = Manager("10.0.0.1", version=1)
        mgr.transport = MagicMock()
        mgr.transport.send_only = AsyncMock()
        await mgr.send_trap("1.3.6.1.4.1.99.0.1")
        sent_data = mgr.transport.send_only.call_args[0][0]
        msg = decode_snmp_message(sent_data)
        assert msg.enterprise == "1.3.6.1.4.1.99.0.1"
