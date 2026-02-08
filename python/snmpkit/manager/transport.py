"""UDP transport for SNMP."""

from __future__ import annotations

import asyncio
import logging

from snmpkit.manager.exceptions import TimeoutError

logger = logging.getLogger("snmpkit.manager")


class UdpTransport:
    """Async UDP transport for SNMP requests."""

    def __init__(
        self,
        host: str,
        port: int,
        timeout: float,
        retries: int,
    ) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout
        self._retries = retries
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: _UdpProtocol | None = None

    async def connect(self) -> None:
        """Create UDP socket and connect to target."""
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _UdpProtocol(),
            remote_addr=(self._host, self._port),
        )
        self._transport = transport
        self._protocol = protocol
        logger.debug("Connected to %s:%d", self._host, self._port)

    async def close(self) -> None:
        """Close the UDP socket."""
        if self._transport:
            self._transport.close()
            self._transport = None
            self._protocol = None

    async def send_request(self, data: bytes) -> bytes:
        """Send request and wait for response with retries."""
        if self._transport is None or self._protocol is None:
            raise RuntimeError("Transport not connected")

        for attempt in range(self._retries):
            try:
                self._protocol.clear()
                self._transport.sendto(data)

                response = await asyncio.wait_for(
                    self._protocol.wait_response(),
                    timeout=self._timeout,
                )
                return response

            except asyncio.TimeoutError:
                logger.debug("Timeout on attempt %d/%d", attempt + 1, self._retries)
                continue

        raise TimeoutError(f"Request timed out after {self._retries} attempts")


class _UdpProtocol(asyncio.DatagramProtocol):
    """Internal UDP protocol handler."""

    def __init__(self) -> None:
        self._response: bytes | None = None
        self._event: asyncio.Event = asyncio.Event()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._response = data
        self._event.set()

    def error_received(self, exc: Exception) -> None:
        logger.error("UDP error: %s", exc)

    def clear(self) -> None:
        self._response = None
        self._event.clear()

    async def wait_response(self) -> bytes:
        await self._event.wait()
        if self._response is None:
            raise RuntimeError("No response received")
        return self._response
