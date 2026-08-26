"""Unit Tests for the UdpTransport class."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from snmpkit.manager.exceptions import TimeoutError, UnreachableError
from snmpkit.manager.transport import UdpTransport, _UdpProtocol


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
        """send_request sends data and returns response."""
        mock_transport = MagicMock()
        mock_protocol = MagicMock()
        mock_protocol.clear = MagicMock()
        mock_protocol.wait_response = AsyncMock(return_value=b"\x30\x00response")

        transport.transport = mock_transport
        transport.protocol = mock_protocol

        result = await transport.send_request(b"request")

        mock_protocol.clear.assert_called_once()
        mock_transport.sendto.assert_called_once_with(b"request")
        assert result == b"\x30\x00response"

    async def test_send_request_retries_on_timeout(self, transport):
        """send_request retries on timeout."""
        mock_transport = MagicMock()
        mock_protocol = MagicMock()
        mock_protocol.clear = MagicMock()

        call_count = [0]

        async def mock_wait():
            call_count[0] += 1
            if call_count[0] < 2:
                raise asyncio.TimeoutError()
            return b"\x30\x00response"

        mock_protocol.wait_response = mock_wait

        transport.transport = mock_transport
        transport.protocol = mock_protocol

        result = await transport.send_request(b"request")

        assert call_count[0] == 2
        assert result == b"\x30\x00response"

    async def test_send_request_raises_after_all_retries(self, transport):
        """send_request raises TimeoutError after all retries fail."""
        mock_transport = MagicMock()
        mock_protocol = MagicMock()
        mock_protocol.clear = MagicMock()
        mock_protocol.wait_response = AsyncMock(side_effect=asyncio.TimeoutError())

        transport.transport = mock_transport
        transport.protocol = mock_protocol

        with pytest.raises(TimeoutError, match="timed out after 3 attempts"):
            await transport.send_request(b"request")


class TestUdpProtocol:
    """Tests for _UdpProtocol class."""

    def test_init(self):
        """Protocol initializes correctly."""
        proto = _UdpProtocol()
        assert proto._response is None
        assert not proto._event.is_set()

    def test_datagram_received_sets_response(self):
        """datagram_received stores response and sets event."""
        proto = _UdpProtocol()
        proto.datagram_received(b"response", ("192.168.1.1", 161))

        assert proto._response == b"response"
        assert proto._event.is_set()

    def test_clear_resets_state(self):
        """clear resets response and event."""
        proto = _UdpProtocol()
        proto._response = b"data"
        proto._event.set()

        proto.clear()

        assert proto._response is None
        assert not proto._event.is_set()

    async def test_wait_response_returns_data(self):
        """wait_response returns the response data."""
        proto = _UdpProtocol()
        proto._response = b"response"
        proto._event.set()

        result = await proto.wait_response()

        assert result == b"response"

    async def test_wait_response_no_data_raises(self):
        """wait_response raises when no data received."""
        proto = _UdpProtocol()
        proto._event.set()

        with pytest.raises(RuntimeError, match="No response"):
            await proto.wait_response()


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

    async def test_error_received_wakes_the_waiter(self):
        """error_received raises from wait_response rather than blocking."""
        protocol = _UdpProtocol()
        protocol.clear()
        protocol.error_received(ConnectionRefusedError(111, "Connection refused"))

        with pytest.raises(OSError):
            await asyncio.wait_for(protocol.wait_response(), timeout=0.1)

    async def test_clear_discards_a_previous_error(self):
        """A stale ICMP error must not poison the next attempt."""
        protocol = _UdpProtocol()
        protocol.error_received(ConnectionRefusedError(111, "Connection refused"))
        protocol.clear()
        protocol.datagram_received(b"payload", ("127.0.0.1", 161))

        assert await asyncio.wait_for(protocol.wait_response(), timeout=0.1) == b"payload"

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
            await asyncio.wait_for(transport.send_request(b"req"), timeout=2.0)

        assert transport.transport.sendto.call_count == 3

    async def test_a_silent_host_still_times_out(self):
        """With no ICMP error there is nothing to shortcut, so it still times out."""
        transport = UdpTransport("192.168.1.1", 161, 0.01, 2)
        transport.transport = MagicMock()
        transport.protocol = _UdpProtocol()

        with pytest.raises(TimeoutError):
            await transport.send_request(b"req")
