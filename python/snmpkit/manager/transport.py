"""UDP transport for SNMP."""

from __future__ import annotations

import asyncio
import logging

from snmpkit.core import peek_correlation_id
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

        correlation_id = peek_correlation_id(data)
        refused: OSError | None = None

        for attempt in range(self.retries):
            waiter = self.protocol.register(correlation_id)
            try:
                try:
                    self.transport.sendto(data)
                except OSError as e:
                    raise UnreachableError(f"{self.host}:{self.port}: {e}") from e

                return await asyncio.wait_for(waiter, timeout=self.timeout)

            # asyncio.TimeoutError is the builtin, which subclasses OSError,
            # so it has to be caught before the ICMP case below.
            except asyncio.TimeoutError:
                logger.debug("Timeout on attempt %d/%d", attempt + 1, self.retries)
                continue

            except OSError as e:
                refused = e
                logger.debug("Unreachable on attempt %d/%d: %s", attempt + 1, self.retries, e)
                continue

            finally:
                self.protocol.unregister(correlation_id)

        if refused is not None:
            raise UnreachableError(f"{self.host}:{self.port}: {refused}") from refused
        raise TimeoutError(f"Request timed out after {self.retries} attempts")


class Waiters:
    """Requests still in flight, keyed by the id their response will carry."""

    def __init__(self) -> None:
        self._waiters: dict[int, asyncio.Future[bytes]] = {}

    def register(self, correlation_id: int) -> asyncio.Future[bytes]:
        waiter: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
        self._waiters[correlation_id] = waiter
        return waiter

    def unregister(self, correlation_id: int) -> None:
        self._waiters.pop(correlation_id, None)

    def deliver(self, data: bytes) -> None:
        try:
            correlation_id = peek_correlation_id(data)
        except ValueError:
            logger.debug("Dropped a response that is not an SNMP message")
            return

        waiter = self._waiters.pop(correlation_id, None)
        if waiter is None:
            # A retry already took it, or it arrived after the request gave up.
            logger.debug("Dropped response %d, nothing waiting for it", correlation_id)
        elif not waiter.done():
            waiter.set_result(data)

    def fail_all(self, error: BaseException) -> None:
        for waiter in self._waiters.values():
            if not waiter.done():
                waiter.set_exception(error)
        self._waiters.clear()


class _UdpProtocol(asyncio.DatagramProtocol):
    """Internal UDP protocol handler, routing each datagram to its request."""

    def __init__(self) -> None:
        self.waiters = Waiters()

    def register(self, correlation_id: int) -> asyncio.Future[bytes]:
        return self.waiters.register(correlation_id)

    def unregister(self, correlation_id: int) -> None:
        self.waiters.unregister(correlation_id)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.waiters.deliver(data)

    def error_received(self, exc: Exception) -> None:
        # ICMP port/host unreachable. The OS already knows the reply cannot
        # come, so wake the waiters instead of sitting out the whole timeout.
        # It names no request, so everything outstanding fails.
        self.waiters.fail_all(exc if isinstance(exc, OSError) else OSError(str(exc)))
