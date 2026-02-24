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
    decode_snmp_v3_message,
    encode_snmp_response_v2c,
    encode_snmp_response_v3_secure,
    password_to_localized_key,
)
from snmpkit.manager.trap_filter import TrapFilter
from snmpkit.manager.v3_user import V3User

logger = logging.getLogger("snmpkit.trap_receiver")

# PDU type constants
_PDU_TRAPV1 = 0xA4
_PDU_INFORM = 0xA6
_PDU_TRAPV2 = 0xA7

_TRAP_PDU_TYPES = (_PDU_TRAPV1, _PDU_INFORM, _PDU_TRAPV2)

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
    # v1 trap fields
    enterprise: str = ""
    agent_addr: tuple[int, int, int, int] = (0, 0, 0, 0)
    generic_trap: int = 0
    specific_trap: int = 0
    # v3 fields
    engine_id: bytes = b""
    user_name: str = ""
    context_name: str = ""
    msg_id: int = 0


class TrapReceiver:
    """Async SNMP Trap/Inform receiver.

    Listens on a UDP port for incoming SNMP TrapV2 and InformRequest PDUs.
    InformRequests are automatically acknowledged with a Response PDU.

    Supports v1, v2c, and v3 (with USM authentication/privacy).

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
        self._users: dict[str, V3User] = {}
        # Cache: (engine_id_hex, user_name) -> (auth_key, priv_key)
        self._key_cache: dict[tuple[str, str], tuple[bytes | None, bytes | None]] = {}
        self._filters: list[TrapFilter] = []

    def add_filter(self, filt: TrapFilter) -> None:
        """Add a filter for incoming traps. Multiple filters use OR logic."""
        self._filters.append(filt)

    def _check_filters(self, trap: TrapMessage) -> bool:
        """Check if a trap passes all registered filters. No filters = accept all."""
        if not self._filters:
            return True
        return any(f.matches(trap) for f in self._filters)

    def add_user(self, user: V3User) -> None:
        """Register a v3 user for decoding incoming v3 traps/informs."""
        self._users[user.user_name] = user
        # Clear key cache entries for this user (engine_id may have changed)
        to_remove = [k for k in self._key_cache if k[1] == user.user_name]
        for k in to_remove:
            del self._key_cache[k]

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
        version = self._peek_version(data)
        if version is None:
            logger.debug("Failed to peek version from %s", addr)
            return

        if version == 3:
            self._handle_v3_datagram(data, addr)
            return

        try:
            msg = decode_snmp_message(data)
        except Exception:
            logger.debug("Failed to decode message from %s", addr)
            return

        if msg.pdu_type not in _TRAP_PDU_TYPES:
            logger.debug("Ignoring non-trap PDU type 0x%02X from %s", msg.pdu_type, addr)
            return

        if msg.pdu_type == _PDU_TRAPV1:
            trap = self._parse_v1_trap_message(msg, addr)
        else:
            trap = self._parse_trap_message(msg, addr)

        if not self._check_filters(trap):
            return

        self._queue.put_nowait(trap)

        # Auto-ACK InformRequests
        if msg.pdu_type == _PDU_INFORM:
            self._send_inform_ack(msg, addr)

    def _handle_v3_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        """Decode an incoming v3 message using registered users."""
        user_name = self._peek_v3_user_name(data)
        if user_name is None:
            logger.debug("Failed to extract v3 user_name from %s", addr)
            return

        user = self._users.get(user_name)
        if user is None:
            logger.debug("Unknown v3 user '%s' from %s", user_name, addr)
            return

        engine_id = self._peek_v3_engine_id(data)
        auth_key, priv_key = self._get_keys(user, engine_id)

        try:
            msg = decode_snmp_v3_message(
                data,
                auth_protocol=user.auth_protocol,
                auth_key=auth_key,
                priv_protocol=user.priv_protocol,
                priv_key=priv_key,
                engine_boots=0,
                engine_time=0,
            )
        except Exception:
            logger.debug("Failed to decode v3 message from %s (user=%s)", addr, user_name)
            return

        if msg.pdu_type not in _TRAP_PDU_TYPES:
            logger.debug("Ignoring non-trap v3 PDU type 0x%02X from %s", msg.pdu_type, addr)
            return

        trap = self._parse_trap_message(msg, addr)
        trap.engine_id = bytes(msg.engine_id)
        trap.user_name = bytes(msg.user_name).decode("ascii", errors="replace")
        trap.context_name = bytes(msg.context_name).decode("ascii", errors="replace")
        trap.msg_id = msg.msg_id

        if not self._check_filters(trap):
            return

        self._queue.put_nowait(trap)

        if msg.pdu_type == _PDU_INFORM:
            self._send_v3_inform_ack(msg, user, auth_key, priv_key, addr)

    def _get_keys(self, user: V3User, engine_id: bytes) -> tuple[bytes | None, bytes | None]:
        """Derive and cache localized auth/priv keys for a user + engine."""
        cache_key = (engine_id.hex(), user.user_name)
        if cache_key in self._key_cache:
            return self._key_cache[cache_key]

        auth_key = None
        priv_key = None

        if user.auth_protocol and user.auth_password:
            auth_key = password_to_localized_key(user.auth_password, engine_id, user.auth_protocol)

        if user.priv_protocol and user.priv_password and user.auth_protocol:
            priv_key = password_to_localized_key(user.priv_password, engine_id, user.auth_protocol)

        self._key_cache[cache_key] = (auth_key, priv_key)
        return auth_key, priv_key

    @staticmethod
    def _peek_version(data: bytes) -> int | None:
        """Peek at SNMP version without fully decoding."""
        try:
            if data[0] != 0x30:
                return None
            pos = 1
            # Skip SEQUENCE length
            if data[pos] & 0x80:
                pos += 1 + (data[pos] & 0x7F)
            else:
                pos += 1
            # version INTEGER
            if data[pos] != 0x02:
                return None
            pos += 1
            vlen = data[pos]
            pos += 1
            version = int.from_bytes(data[pos : pos + vlen], "big", signed=True)
            return version
        except (IndexError, ValueError):
            return None

    @staticmethod
    def _peek_v3_user_name(data: bytes) -> str | None:
        """Extract user_name from v3 USM security parameters without full decode."""
        try:
            # SEQUENCE
            pos = 1
            if data[pos] & 0x80:
                pos += 1 + (data[pos] & 0x7F)
            else:
                pos += 1
            # Skip version INTEGER
            tag = data[pos]
            if tag != 0x02:
                return None
            pos += 1
            vlen = data[pos]
            pos += 1 + vlen
            # Skip headerData SEQUENCE
            if data[pos] != 0x30:
                return None
            pos += 1
            if data[pos] & 0x80:
                num = data[pos] & 0x7F
                hlen = int.from_bytes(data[pos + 1 : pos + 1 + num], "big")
                pos += 1 + num + hlen
            else:
                pos += 1 + data[pos]
            # msgSecurityParameters OCTET STRING
            if data[pos] != 0x04:
                return None
            pos += 1
            if data[pos] & 0x80:
                num = data[pos] & 0x7F
                pos += 1 + num
            else:
                pos += 1
            # Inside: USM SEQUENCE
            if data[pos] != 0x30:
                return None
            pos += 1
            if data[pos] & 0x80:
                num = data[pos] & 0x7F
                pos += 1 + num
            else:
                pos += 1
            # engineID OCTET STRING
            if data[pos] != 0x04:
                return None
            pos += 1
            eidlen = data[pos]
            pos += 1 + eidlen
            # engineBoots INTEGER
            if data[pos] != 0x02:
                return None
            pos += 1
            blen = data[pos]
            pos += 1 + blen
            # engineTime INTEGER
            if data[pos] != 0x02:
                return None
            pos += 1
            tlen = data[pos]
            pos += 1 + tlen
            # userName OCTET STRING
            if data[pos] != 0x04:
                return None
            pos += 1
            ulen = data[pos]
            pos += 1
            return data[pos : pos + ulen].decode("ascii", errors="replace")
        except (IndexError, ValueError):
            return None

    @staticmethod
    def _peek_v3_engine_id(data: bytes) -> bytes:
        """Extract engine_id from v3 USM security parameters."""
        try:
            pos = 1
            if data[pos] & 0x80:
                pos += 1 + (data[pos] & 0x7F)
            else:
                pos += 1
            # Skip version
            pos += 1
            vlen = data[pos]
            pos += 1 + vlen
            # Skip headerData
            if data[pos] != 0x30:
                return b""
            pos += 1
            if data[pos] & 0x80:
                num = data[pos] & 0x7F
                hlen = int.from_bytes(data[pos + 1 : pos + 1 + num], "big")
                pos += 1 + num + hlen
            else:
                pos += 1 + data[pos]
            # msgSecurityParameters OCTET STRING
            if data[pos] != 0x04:
                return b""
            pos += 1
            if data[pos] & 0x80:
                num = data[pos] & 0x7F
                pos += 1 + num
            else:
                pos += 1
            # USM SEQUENCE
            if data[pos] != 0x30:
                return b""
            pos += 1
            if data[pos] & 0x80:
                num = data[pos] & 0x7F
                pos += 1 + num
            else:
                pos += 1
            # engineID OCTET STRING
            if data[pos] != 0x04:
                return b""
            pos += 1
            eidlen = data[pos]
            pos += 1
            return bytes(data[pos : pos + eidlen])
        except (IndexError, ValueError):
            return b""

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

    def _parse_v1_trap_message(self, msg, addr: tuple[str, int]) -> TrapMessage:
        """Parse an SNMPv1 Trap PDU into a TrapMessage."""
        community = bytes(msg.community).decode("ascii", errors="replace") if msg.community else ""
        varbinds = [(str(vb.oid), vb.value) for vb in msg.varbinds]

        return TrapMessage(
            source=addr,
            version=0,
            community=community,
            pdu_type=msg.pdu_type,
            request_id=0,
            trap_oid=msg.enterprise,
            uptime=msg.timestamp,
            varbinds=varbinds,
            raw_varbinds=varbinds.copy(),
            enterprise=msg.enterprise,
            agent_addr=msg.agent_addr,
            generic_trap=msg.generic_trap,
            specific_trap=msg.specific_trap,
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

    def _send_v3_inform_ack(
        self,
        msg,
        user: V3User,
        auth_key: bytes | None,
        priv_key: bytes | None,
        addr: tuple[str, int],
    ) -> None:
        """Send a v3 Response PDU to acknowledge an InformRequest."""
        if self._transport is None:
            return

        try:
            kwargs: dict = {
                "engine_id": bytes(msg.engine_id),
                "engine_boots": msg.engine_boots,
                "engine_time": msg.engine_time,
                "user_name": user.user_name,
                "context_name": bytes(msg.context_name),
            }
            if auth_key and user.auth_protocol:
                kwargs["auth_protocol"] = user.auth_protocol
                kwargs["auth_key"] = auth_key
            if priv_key and user.priv_protocol:
                kwargs["priv_protocol"] = user.priv_protocol
                kwargs["priv_key"] = priv_key
            ack = encode_snmp_response_v3_secure(
                msg_id=msg.msg_id,
                request_id=msg.request_id,
                error_status=0,
                error_index=0,
                varbinds=[],
                **kwargs,
            )
            self._transport.sendto(ack, addr)
            logger.debug("Sent v3 Inform ACK to %s (request_id=%d)", addr, msg.request_id)
        except Exception:
            logger.debug("Failed to send v3 Inform ACK to %s", addr)


class _TrapProtocol(asyncio.DatagramProtocol):
    """Internal UDP protocol for TrapReceiver."""

    def __init__(self, receiver: TrapReceiver) -> None:
        self._receiver = receiver

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._receiver._handle_datagram(data, addr)

    def error_received(self, exc: Exception) -> None:
        logger.error("TrapReceiver UDP error: %s", exc)
