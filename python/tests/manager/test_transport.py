"""Unit Tests for the UdpTransport class."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from snmpkit.core import Oid, encode_snmp_get_v2c
from snmpkit.manager.exceptions import TimeoutError, UnreachableError
from snmpkit.manager.transport import UdpTransport, _UdpProtocol


def message(request_id: int) -> bytes:
    """A real v2c message, since the transport routes on its request id."""
    return encode_snmp_get_v2c("public", request_id, [Oid("1.3.6.1.2.1.1.1.0")])


@pytest.fixture
def transport():
    """Create a fresh UdpTransport for each test."""
    return UdpTransport("192.168.1.1", 161, 2.0, 3)


class TestTransportInit:
    """Tests for UdpTransport initialization."""

    def test_default_values(self, transport):
        """Transport initializes with correct values."""
        assert transport.host == "192.168.1.1"
        assert transport.port == 161
        assert transport.timeout == 2.0
        assert transport.retries == 3
        assert transport.transport is None
        assert transport.protocol is None


class TestTransportConnect:
    """Tests for connect method."""

    async def test_connect_creates_endpoint(self, transport):
        """connect creates datagram endpoint."""
        mock_transport = MagicMock()
        mock_protocol = MagicMock()

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop.return_value.create_datagram_endpoint = AsyncMock(
                return_value=(mock_transport, mock_protocol)
            )

            await transport.connect()

            assert transport.transport is mock_transport
            assert transport.protocol is mock_protocol


class TestTransportClose:
    """Tests for close method."""

    async def test_close_closes_transport(self, transport):
        """close closes the transport."""
        mock_transport = MagicMock()
        transport.transport = mock_transport
        transport.protocol = MagicMock()

        await transport.close()

        mock_transport.close.assert_called_once()
        assert transport.transport is None
        assert transport.protocol is None

    async def test_close_when_not_connected(self, transport):
        """close does nothing when not connected."""
        await transport.close()
        assert transport.transport is None


class TestTransportSendRequest:
    """Tests for send_request method."""

    async def test_send_request_not_connected_raises(self, transport):
        """send_request raises when not connected."""
        with pytest.raises(RuntimeError, match="not connected"):
            await transport.send_request(b"test")

    async def test_send_request_returns_response(self, transport):
        """send_request sends data and returns the matching response."""
        request = message(42)
        transport.transport = MagicMock()
        transport.protocol = _UdpProtocol()
        transport.transport.sendto.side_effect = lambda _: transport.protocol.datagram_received(
            request, ("192.168.1.1", 161)
        )

        result = await transport.send_request(request)

        transport.transport.sendto.assert_called_once_with(request)
        assert result == request

    async def test_send_request_retries_on_timeout(self, transport):
        """send_request retries, and a late answer still lands."""
        transport.timeout = 0.05
        request = message(42)
        transport.transport = MagicMock()
        transport.protocol = _UdpProtocol()

        attempts = [0]

        def answer_on_second(_data):
            attempts[0] += 1
            if attempts[0] == 2:
                transport.protocol.datagram_received(request, ("192.168.1.1", 161))

        transport.transport.sendto.side_effect = answer_on_second

        assert await transport.send_request(request) == request
        assert attempts[0] == 2

    async def test_send_request_raises_after_all_retries(self, transport):
        """send_request raises TimeoutError after all retries fail."""
        transport.timeout = 0.01
        transport.transport = MagicMock()
        transport.protocol = _UdpProtocol()

        with pytest.raises(TimeoutError, match="timed out after 3 attempts"):
            await transport.send_request(message(42))

    async def test_concurrent_requests_each_get_their_own_response(self, transport):
        """Two requests in flight must not be handed each other's answer."""
        transport.transport = MagicMock()
        transport.protocol = _UdpProtocol()
        sent = []
        transport.transport.sendto.side_effect = sent.append

        first = asyncio.ensure_future(transport.send_request(message(1)))
        second = asyncio.ensure_future(transport.send_request(message(2)))
        await asyncio.sleep(0)

        # Answered out of order, which is what a real agent is free to do.
        transport.protocol.datagram_received(message(2), ("192.168.1.1", 161))
        transport.protocol.datagram_received(message(1), ("192.168.1.1", 161))

        assert await first == message(1)
        assert await second == message(2)
        assert len(sent) == 2


class TestUdpProtocol:
    """Tests for _UdpProtocol class."""

    def test_init(self):
        """Protocol starts with nothing outstanding."""
        proto = _UdpProtocol()
        assert proto.waiters._waiters == {}

    async def test_datagram_received_resolves_the_matching_waiter(self):
        """A datagram completes the request carrying the same id."""
        proto = _UdpProtocol()
        waiter = proto.register(42)
        proto.datagram_received(message(42), ("192.168.1.1", 161))

        assert await waiter == message(42)

    async def test_datagram_for_another_request_is_left_alone(self):
        """A response nobody is waiting for must not complete someone else."""
        proto = _UdpProtocol()
        waiter = proto.register(42)
        proto.datagram_received(message(99), ("192.168.1.1", 161))

        assert not waiter.done()

    async def test_datagram_that_is_not_snmp_is_dropped(self):
        """Garbage on the socket must not raise out of the event loop callback."""
        proto = _UdpProtocol()
        waiter = proto.register(42)
        proto.datagram_received(b"not an snmp message", ("192.168.1.1", 161))

        assert not waiter.done()

    async def test_unregister_stops_delivery(self):
        """A request that gave up does not get resolved later."""
        proto = _UdpProtocol()
        waiter = proto.register(42)
        proto.unregister(42)
        proto.datagram_received(message(42), ("192.168.1.1", 161))

        assert not waiter.done()
        waiter.cancel()


class TestUnreachableClassification:
    """Tests that transport failures land in the SnmpError hierarchy."""

    async def test_dns_failure_raises_unreachable(self):
        """A bad hostname must not escape as socket.gaierror."""
        from snmpkit.manager import Manager, SnmpError

        with pytest.raises(SnmpError) as exc:
            async with Manager("no-such-host.invalid", timeout=0.5, retries=1):
                pass
        assert exc.value.unreachable is True

    async def test_blackhole_host_raises_unreachable(self):
        """A host that never answers times out and reports unreachable."""
        from snmpkit.manager import Manager, SnmpError

        async with Manager("192.0.2.1", timeout=0.5, retries=1) as mgr:
            with pytest.raises(SnmpError) as exc:
                await mgr.get("1.3.6.1.2.1.1.1.0")
        assert exc.value.unreachable is True


class TestIcmpErrorFailsFast:
    """Tests that an ICMP error ends the attempt instead of waiting out the timeout."""

    async def test_error_received_wakes_every_waiter(self):
        """ICMP names no request, so everything in flight fails at once."""
        protocol = _UdpProtocol()
        first = protocol.register(1)
        second = protocol.register(2)
        protocol.error_received(ConnectionRefusedError(111, "Connection refused"))

        for waiter in (first, second):
            with pytest.raises(OSError):
                await asyncio.wait_for(waiter, timeout=0.1)

    async def test_a_stale_error_does_not_poison_the_next_attempt(self):
        """The failed waiters are dropped, so a later request starts clean."""
        protocol = _UdpProtocol()
        stale = protocol.register(1)
        protocol.error_received(ConnectionRefusedError(111, "Connection refused"))
        with pytest.raises(OSError):
            await stale

        waiter = protocol.register(2)
        protocol.datagram_received(message(2), ("127.0.0.1", 161))

        assert await asyncio.wait_for(waiter, timeout=0.1) == message(2)

    async def test_send_request_raises_unreachable_without_burning_the_timeout(self):
        """A refused port reports UnreachableError, not TimeoutError."""
        # A 10s timeout over 3 retries would be 30s if the ICMP error were ignored.
        transport = UdpTransport("192.168.1.1", 161, 10.0, 3)
        transport.transport = MagicMock()
        transport.protocol = _UdpProtocol()

        def refuse(_data):
            transport.protocol.error_received(ConnectionRefusedError(111, "Connection refused"))

        transport.transport.sendto.side_effect = refuse

        with pytest.raises(UnreachableError, match="Connection refused"):
            await asyncio.wait_for(transport.send_request(message(42)), timeout=2.0)

        assert transport.transport.sendto.call_count == 3

    async def test_a_silent_host_still_times_out(self):
        """With no ICMP error there is nothing to shortcut, so it still times out."""
        transport = UdpTransport("192.168.1.1", 161, 0.01, 2)
        transport.transport = MagicMock()
        transport.protocol = _UdpProtocol()

        with pytest.raises(TimeoutError):
            await transport.send_request(message(42))
