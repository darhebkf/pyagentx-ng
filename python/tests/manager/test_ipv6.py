"""Tests for IPv6 support in transports and receivers."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from snmpkit.manager import Manager
from snmpkit.manager.tcp_transport import TcpTransport
from snmpkit.manager.transport import UdpTransport


class TestUdpTransportIPv6:
    def test_accepts_ipv6_address(self):
        t = UdpTransport("::1", 161, 2.0, 3)
        assert t.host == "::1"
        assert t.port == 161

    def test_accepts_full_ipv6(self):
        t = UdpTransport("2001:db8::1", 161, 2.0, 3)
        assert t.host == "2001:db8::1"

    async def test_connect_ipv6(self):
        t = UdpTransport("::1", 161, 2.0, 3)
        mock_transport = MagicMock()
        mock_protocol = MagicMock()

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop.return_value.create_datagram_endpoint = AsyncMock(
                return_value=(mock_transport, mock_protocol)
            )
            await t.connect()
            call_kwargs = mock_loop.return_value.create_datagram_endpoint.call_args
            assert call_kwargs.kwargs.get("remote_addr") == ("::1", 161) or call_kwargs[1].get(
                "remote_addr"
            ) == ("::1", 161)


class TestTcpTransportIPv6:
    def test_accepts_ipv6_address(self):
        t = TcpTransport("::1", 161, 2.0, 3)
        assert t.host == "::1"

    async def test_connect_ipv6(self):
        t = TcpTransport("::1", 161, 2.0, 3)
        with patch(
            "snmpkit.manager.tcp_transport.asyncio.open_connection", new_callable=AsyncMock
        ) as mock_open:
            mock_open.return_value = (MagicMock(), MagicMock())
            await t.connect()
            mock_open.assert_called_once_with("::1", 161)


class TestManagerIPv6:
    def test_manager_accepts_ipv6(self):
        mgr = Manager("::1")
        assert mgr.host == "::1"

    def test_manager_ipv6_tcp(self):
        mgr = Manager("2001:db8::1", transport="tcp")
        assert mgr.host == "2001:db8::1"
        assert mgr._transport_type == "tcp"

    async def test_manager_connect_ipv6_udp(self):
        mgr = Manager("::1")
        mock_transport = MagicMock()
        mock_protocol = MagicMock()

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop.return_value.create_datagram_endpoint = AsyncMock(
                return_value=(mock_transport, mock_protocol)
            )
            await mgr.connect()
            assert mgr.transport is not None

    async def test_manager_connect_ipv6_tcp(self):
        mgr = Manager("::1", transport="tcp")
        with patch(
            "snmpkit.manager.tcp_transport.asyncio.open_connection", new_callable=AsyncMock
        ) as mock_open:
            mock_open.return_value = (MagicMock(), MagicMock())
            await mgr.connect()
            assert isinstance(mgr.transport, TcpTransport)
            await mgr.close()


class TestTrapReceiverIPv6:
    def test_receiver_accepts_ipv6_bind(self):
        from snmpkit.manager.trap_receiver import TrapReceiver

        receiver = TrapReceiver(host="::", port=1162)
        assert receiver.host == "::"
        assert receiver.port == 1162

    def test_receiver_accepts_specific_ipv6(self):
        from snmpkit.manager.trap_receiver import TrapReceiver

        receiver = TrapReceiver(host="::1", port=1162)
        assert receiver.host == "::1"
