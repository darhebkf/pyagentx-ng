"""TCP transport for SNMP (RFC 3430)."""

from __future__ import annotations

import asyncio
import logging
import struct

from snmpkit.manager.exceptions import TimeoutError, UnreachableError

logger = logging.getLogger("snmpkit.manager")

# 4-byte big-endian length prefix per RFC 3430
_LENGTH_PREFIX = struct.Struct("!I")


class TcpTransport:
    """Async TCP transport for SNMP requests.

    Uses 4-byte big-endian length-prefix framing per RFC 3430.
    """

    def __init__(
        self,
        host: str,
        port: int,
        timeout: float,
        retries: int,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def connect(self) -> None:
        """Open TCP connection to target."""
        try:
            self._reader, self._writer = await asyncio.open_connection(self.host, self.port)
        except OSError as e:
            raise UnreachableError(f"{self.host}:{self.port}: {e}") from e
        logger.debug("TCP connected to %s:%d", self.host, self.port)

    async def close(self) -> None:
        """Close the TCP connection."""
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None

    async def send_only(self, data: bytes) -> None:
        """Send data without waiting for a response (fire-and-forget)."""
        if self._writer is None:
            raise RuntimeError("Transport not connected")
        frame = _LENGTH_PREFIX.pack(len(data)) + data
        self._writer.write(frame)
        await self._writer.drain()

    async def send_request(self, data: bytes) -> bytes:
        """Send request and wait for length-prefixed response with retries."""
        if self._writer is None or self._reader is None:
            raise RuntimeError("Transport not connected")

        for attempt in range(self.retries):
            try:
                frame = _LENGTH_PREFIX.pack(len(data)) + data
                self._writer.write(frame)
                await self._writer.drain()

                header = await asyncio.wait_for(
                    self._reader.readexactly(_LENGTH_PREFIX.size),
                    timeout=self.timeout,
                )
                (length,) = _LENGTH_PREFIX.unpack(header)

                response = await asyncio.wait_for(
                    self._reader.readexactly(length),
                    timeout=self.timeout,
                )
                return response

            except asyncio.TimeoutError:
                logger.debug("TCP timeout on attempt %d/%d", attempt + 1, self.retries)
                continue

        raise TimeoutError(f"Request timed out after {self.retries} attempts")
