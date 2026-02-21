"""SNMP Trap/Inform receiver."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Self

from snmpkit.core import (
    Value,
    decode_snmp_message,
    encode_snmp_response_v2c,
)

logger = logging.getLogger("snmpkit.trap_receiver")

# PDU type constants
_PDU_INFORM = 0xA6
_PDU_TRAPV2 = 0xA7

# Well-known OIDs
_SYSUPTIME_OID = "1.3.6.1.2.1.1.3.0"
_SNMPTRAPOID_OID = "1.3.6.1.6.3.1.1.4.1.0"


@dataclass
class TrapMessage:
    """A received SNMP Trap or Inform notification."""

    source: tuple[str, int]
    version: int
    community: str
    pdu_type: int
    request_id: int
    trap_oid: str
    uptime: int
    varbinds: list[tuple[str, Value]]
    raw_varbinds: list[tuple[str, Value]] = field(default_factory=list)


class TrapReceiver:
    """Async SNMP Trap/Inform receiver.

    Listens on a UDP port for incoming SNMP TrapV2 and InformRequest PDUs.
    InformRequests are automatically acknowledged with a Response PDU.

    Example:
        async with TrapReceiver(port=1162) as receiver:
            async for trap in receiver:
                print(f"Trap from {trap.source}: {trap.trap_oid}")
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 162,
    ) -> None:
        self.host = host
        self.port = port
        self._transport: asyncio.DatagramTransport | None = None
        self._queue: asyncio.Queue[TrapMessage] = asyncio.Queue()
        self._running = False

    async def start(self) -> None:
        """Bind UDP socket and start receiving traps."""
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _TrapProtocol(self),
            local_addr=(self.host, self.port),
        )
        self._transport = transport
        self._running = True
        logger.info("TrapReceiver listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        """Stop the receiver and close the socket."""
        self._running = False
        if self._transport:
            self._transport.close()
            self._transport = None

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.stop()

    def __aiter__(self) -> AsyncIterator[TrapMessage]:
        return self

    async def __anext__(self) -> TrapMessage:
        if not self._running and self._queue.empty():
            raise StopAsyncIteration
        return await self._queue.get()

    def _handle_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        """Decode an incoming SNMP message and queue it."""
        try:
            msg = decode_snmp_message(data)
        except Exception:
            logger.debug("Failed to decode message from %s", addr)
            return

        if msg.pdu_type not in (_PDU_INFORM, _PDU_TRAPV2):
            logger.debug("Ignoring non-trap PDU type 0x%02X from %s", msg.pdu_type, addr)
            return

        trap = self._parse_trap_message(msg, addr)
        self._queue.put_nowait(trap)

        # Auto-ACK InformRequests
        if msg.pdu_type == _PDU_INFORM:
            self._send_inform_ack(msg, addr)

    def _parse_trap_message(self, msg, addr: tuple[str, int]) -> TrapMessage:
        """Extract trap_oid, uptime, and user varbinds from the message."""
        trap_oid = ""
        uptime = 0
        user_varbinds: list[tuple[str, Value]] = []
        raw_varbinds: list[tuple[str, Value]] = []

        for vb in msg.varbinds:
            oid_str = str(vb.oid)
            raw_varbinds.append((oid_str, vb.value))

            if oid_str == _SYSUPTIME_OID:
                try:
                    uptime = int(str(vb.value))
                except (ValueError, TypeError):
                    pass
            elif oid_str == _SNMPTRAPOID_OID:
                trap_oid = str(vb.value)
            else:
                user_varbinds.append((oid_str, vb.value))

        community = bytes(msg.community).decode("ascii", errors="replace") if msg.community else ""

        return TrapMessage(
            source=addr,
            version=msg.version,
            community=community,
            pdu_type=msg.pdu_type,
            request_id=msg.request_id,
            trap_oid=trap_oid,
            uptime=uptime,
            varbinds=user_varbinds,
            raw_varbinds=raw_varbinds,
        )

    def _send_inform_ack(self, msg, addr: tuple[str, int]) -> None:
        """Send a Response PDU to acknowledge an InformRequest."""
        if self._transport is None:
            return

        try:
            community = bytes(msg.community).decode("ascii", errors="replace")
            ack = encode_snmp_response_v2c(community, msg.request_id, 0, 0, [])
            self._transport.sendto(ack, addr)
            logger.debug("Sent Inform ACK to %s (request_id=%d)", addr, msg.request_id)
        except Exception:
            logger.debug("Failed to send Inform ACK to %s", addr)


class _TrapProtocol(asyncio.DatagramProtocol):
    """Internal UDP protocol for TrapReceiver."""

    def __init__(self, receiver: TrapReceiver) -> None:
        self._receiver = receiver

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._receiver._handle_datagram(data, addr)

    def error_received(self, exc: Exception) -> None:
        logger.error("TrapReceiver UDP error: %s", exc)
