"""UDP transport for SNMP."""

from __future__ import annotations

import asyncio
import logging

from snmpkit.manager.exceptions import TimeoutError, UnreachableError

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
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.transport: asyncio.DatagramTransport | None = None
        self.protocol: _UdpProtocol | None = None

    async def connect(self) -> None:
        """Create UDP socket and connect to target."""
        loop = asyncio.get_running_loop()
        # remote_addr resolves DNS here, so gaierror surfaces as OSError.
        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: _UdpProtocol(),
                remote_addr=(self.host, self.port),
            )
        except OSError as e:
            raise UnreachableError(f"{self.host}:{self.port}: {e}") from e
        self.transport = transport
        self.protocol = protocol
        logger.debug("Connected to %s:%d", self.host, self.port)

    async def close(self) -> None:
        """Close the UDP socket."""
        if self.transport:
            self.transport.close()
            self.transport = None
            self.protocol = None

    async def send_only(self, data: bytes) -> None:
        """Send data without waiting for a response (fire-and-forget)."""
        if self.transport is None:
            raise RuntimeError("Transport not connected")
        self.transport.sendto(data)

    async def send_request(self, data: bytes) -> bytes:
        """Send request and wait for response with retries."""
        if self.transport is None or self.protocol is None:
            raise RuntimeError("Transport not connected")

        refused: OSError | None = None

        for attempt in range(self.retries):
            try:
                self.protocol.clear()
                try:
                    self.transport.sendto(data)
                except OSError as e:
                    raise UnreachableError(f"{self.host}:{self.port}: {e}") from e

                response = await asyncio.wait_for(
                    self.protocol.wait_response(),
                    timeout=self.timeout,
                )
                return response

            # asyncio.TimeoutError is the builtin, which subclasses OSError,
            # so it has to be caught before the ICMP case below.
            except asyncio.TimeoutError:
                logger.debug("Timeout on attempt %d/%d", attempt + 1, self.retries)
                continue

            except OSError as e:
                refused = e
                logger.debug("Unreachable on attempt %d/%d: %s", attempt + 1, self.retries, e)
                continue

        if refused is not None:
            raise UnreachableError(f"{self.host}:{self.port}: {refused}") from refused
        raise TimeoutError(f"Request timed out after {self.retries} attempts")


class _UdpProtocol(asyncio.DatagramProtocol):
    """Internal UDP protocol handler."""

    def __init__(self) -> None:
        self._response: bytes | None = None
        self._error: OSError | None = None
        self._event: asyncio.Event = asyncio.Event()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._response = data
        self._event.set()

    def error_received(self, exc: Exception) -> None:
        # ICMP port/host unreachable. The OS already knows the reply cannot
        # come, so wake the waiter instead of sitting out the whole timeout.
        self._error = exc if isinstance(exc, OSError) else OSError(str(exc))
        self._event.set()

    def clear(self) -> None:
        self._response = None
        self._error = None
        self._event.clear()

    async def wait_response(self) -> bytes:
        await self._event.wait()
        if self._error is not None:
            raise self._error
        if self._response is None:
            raise RuntimeError("No response received")
        return self._response
