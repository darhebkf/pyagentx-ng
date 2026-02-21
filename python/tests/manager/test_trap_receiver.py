"""Tests for TrapReceiver."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from snmpkit.core import Oid, SnmpVarBind, Value, encode_snmp_inform_v2c, encode_snmp_trap_v2c
from snmpkit.manager.trap_receiver import _PDU_INFORM, _PDU_TRAPV2, TrapMessage, TrapReceiver

# Helpers


def _make_trap_bytes(
    community: str = "public",
    request_id: int = 1,
    trap_oid: str = "1.3.6.1.4.1.99.0.1",
    uptime: int = 12345,
    extra_varbinds: list | None = None,
) -> bytes:
    vbs = [
        SnmpVarBind(Oid("1.3.6.1.2.1.1.3.0"), Value.TimeTicks(uptime)),
        SnmpVarBind(Oid("1.3.6.1.6.3.1.1.4.1.0"), Value.ObjectIdentifier(Oid(trap_oid))),
    ]
    if extra_varbinds:
        vbs.extend(extra_varbinds)
    return encode_snmp_trap_v2c(community, request_id, vbs)


def _make_inform_bytes(
    community: str = "public",
    request_id: int = 42,
    trap_oid: str = "1.3.6.1.4.1.99.0.2",
    uptime: int = 99999,
) -> bytes:
    vbs = [
        SnmpVarBind(Oid("1.3.6.1.2.1.1.3.0"), Value.TimeTicks(uptime)),
        SnmpVarBind(Oid("1.3.6.1.6.3.1.1.4.1.0"), Value.ObjectIdentifier(Oid(trap_oid))),
    ]
    return encode_snmp_inform_v2c(community, request_id, vbs)


class TestTrapMessageDataclass:
    """Tests for TrapMessage fields."""

    def test_fields(self):
        msg = TrapMessage(
            source=("10.0.0.1", 9999),
            version=1,
            community="public",
            pdu_type=_PDU_TRAPV2,
            request_id=1,
            trap_oid="1.3.6.1.4.1.99.0.1",
            uptime=100,
            varbinds=[],
        )
        assert msg.source == ("10.0.0.1", 9999)
        assert msg.trap_oid == "1.3.6.1.4.1.99.0.1"
        assert msg.uptime == 100
        assert msg.raw_varbinds == []


class TestTrapReceiverInit:
    """Tests for TrapReceiver initialization."""

    def test_defaults(self):
        r = TrapReceiver()
        assert r.host == "0.0.0.0"
        assert r.port == 162
        assert r._running is False
        assert r._transport is None

    def test_custom(self):
        r = TrapReceiver(host="127.0.0.1", port=1162)
        assert r.host == "127.0.0.1"
        assert r.port == 1162


class TestParseTrapMessage:
    """Tests for _parse_trap_message parsing logic."""

    def test_parses_trap_oid_and_uptime(self):
        data = _make_trap_bytes(trap_oid="1.3.6.1.4.1.99.0.1", uptime=54321)
        receiver = TrapReceiver()
        receiver._handle_datagram(data, ("10.0.0.1", 5000))

        msg = receiver._queue.get_nowait()
        assert msg.trap_oid == "1.3.6.1.4.1.99.0.1"
        assert msg.uptime == 54321
        assert msg.source == ("10.0.0.1", 5000)
        assert msg.community == "public"

    def test_parses_user_varbinds(self):
        extra = [
            SnmpVarBind(Oid("1.3.6.1.4.1.99.1.1.0"), Value.Integer(42)),
            SnmpVarBind(Oid("1.3.6.1.4.1.99.1.2.0"), Value.OctetString(b"test")),
        ]
        data = _make_trap_bytes(extra_varbinds=extra)
        receiver = TrapReceiver()
        receiver._handle_datagram(data, ("10.0.0.1", 5000))

        msg = receiver._queue.get_nowait()
        assert len(msg.varbinds) == 2
        assert msg.varbinds[0][0] == "1.3.6.1.4.1.99.1.1.0"
        assert msg.varbinds[0][1] == Value.Integer(42)
        assert msg.varbinds[1][0] == "1.3.6.1.4.1.99.1.2.0"
        assert msg.varbinds[1][1] == Value.OctetString(b"test")

    def test_raw_varbinds_include_all(self):
        extra = [SnmpVarBind(Oid("1.3.6.1.4.1.99.1.1.0"), Value.Integer(1))]
        data = _make_trap_bytes(extra_varbinds=extra)
        receiver = TrapReceiver()
        receiver._handle_datagram(data, ("10.0.0.1", 5000))

        msg = receiver._queue.get_nowait()
        # raw_varbinds has sysUpTime + trapOID + user = 3
        assert len(msg.raw_varbinds) == 3
        # user varbinds only has user = 1
        assert len(msg.varbinds) == 1

    def test_pdu_type_set_for_trapv2(self):
        data = _make_trap_bytes()
        receiver = TrapReceiver()
        receiver._handle_datagram(data, ("10.0.0.1", 5000))

        msg = receiver._queue.get_nowait()
        assert msg.pdu_type == _PDU_TRAPV2


class TestHandleDatagram:
    """Tests for _handle_datagram filtering."""

    def test_ignores_invalid_data(self):
        receiver = TrapReceiver()
        receiver._handle_datagram(b"\xff\xff\xff", ("10.0.0.1", 5000))
        assert receiver._queue.empty()

    def test_ignores_non_trap_pdu(self):
        # A GET request is not a trap — encode a simple get and feed it in
        from snmpkit.core import encode_snmp_get_v2c

        data = encode_snmp_get_v2c("public", 1, [Oid("1.3.6.1.2.1.1.1.0")])
        receiver = TrapReceiver()
        receiver._handle_datagram(data, ("10.0.0.1", 5000))
        assert receiver._queue.empty()


class TestInformAutoAck:
    """Tests for auto-acknowledging InformRequests."""

    def test_inform_sends_ack(self):
        data = _make_inform_bytes(request_id=42)
        receiver = TrapReceiver()
        mock_transport = MagicMock()
        receiver._transport = mock_transport

        receiver._handle_datagram(data, ("10.0.0.1", 5000))

        # Should have queued the inform as a trap message
        assert not receiver._queue.empty()
        msg = receiver._queue.get_nowait()
        assert msg.pdu_type == _PDU_INFORM
        assert msg.trap_oid == "1.3.6.1.4.1.99.0.2"

        # Should have sent an ACK
        mock_transport.sendto.assert_called_once()
        ack_data, ack_addr = mock_transport.sendto.call_args[0]
        assert ack_addr == ("10.0.0.1", 5000)
        assert isinstance(ack_data, bytes)

    def test_trap_does_not_send_ack(self):
        data = _make_trap_bytes()
        receiver = TrapReceiver()
        mock_transport = MagicMock()
        receiver._transport = mock_transport

        receiver._handle_datagram(data, ("10.0.0.1", 5000))

        mock_transport.sendto.assert_not_called()


class TestTrapReceiverContextManager:
    """Tests for async context manager and iterator."""

    async def test_start_stop(self):
        receiver = TrapReceiver(host="127.0.0.1", port=0)
        await receiver.start()
        assert receiver._running is True
        assert receiver._transport is not None
        await receiver.stop()
        assert receiver._running is False
        assert receiver._transport is None

    async def test_context_manager(self):
        async with TrapReceiver(host="127.0.0.1", port=0) as receiver:
            assert receiver._running is True
        assert receiver._running is False

    async def test_anext_stops_when_not_running(self):
        receiver = TrapReceiver()
        receiver._running = False
        with pytest.raises(StopAsyncIteration):
            await receiver.__anext__()
