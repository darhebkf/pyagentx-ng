"""Tests for TcpTransport."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from snmpkit.manager.exceptions import TimeoutError
from snmpkit.manager.tcp_transport import _LENGTH_PREFIX, TcpTransport


@pytest.fixture
def transport():
    return TcpTransport("192.168.1.1", 161, 2.0, 3)


class TestTcpTransportInit:
    def test_default_values(self, transport):
        assert transport.host == "192.168.1.1"
        assert transport.port == 161
        assert transport.timeout == 2.0
        assert transport.retries == 3
        assert transport._reader is None
        assert transport._writer is None


class TestTcpTransportConnect:
    async def test_connect_opens_connection(self, transport):
        mock_reader = MagicMock()
        mock_writer = MagicMock()

        with patch(
            "snmpkit.manager.tcp_transport.asyncio.open_connection", new_callable=AsyncMock
        ) as mock_open:
            mock_open.return_value = (mock_reader, mock_writer)
            await transport.connect()

            mock_open.assert_called_once_with("192.168.1.1", 161)
            assert transport._reader is mock_reader
            assert transport._writer is mock_writer


class TestTcpTransportClose:
    async def test_close_closes_writer(self, transport):
        mock_writer = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        transport._writer = mock_writer
        transport._reader = MagicMock()

        await transport.close()

        mock_writer.close.assert_called_once()
        mock_writer.wait_closed.assert_called_once()
        assert transport._writer is None
        assert transport._reader is None

    async def test_close_when_not_connected(self, transport):
        await transport.close()
        assert transport._writer is None


class TestTcpTransportSendOnly:
    async def test_send_only_not_connected_raises(self, transport):
        with pytest.raises(RuntimeError, match="not connected"):
            await transport.send_only(b"test")

    async def test_send_only_writes_length_prefixed(self, transport):
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()
        transport._writer = mock_writer

        await transport.send_only(b"hello")

        expected = _LENGTH_PREFIX.pack(5) + b"hello"
        mock_writer.write.assert_called_once_with(expected)
        mock_writer.drain.assert_called_once()


class TestTcpTransportSendRequest:
    async def test_send_request_not_connected_raises(self, transport):
        with pytest.raises(RuntimeError, match="not connected"):
            await transport.send_request(b"test")

    async def test_send_request_returns_response(self, transport):
        response_data = b"\x30\x03response"
        response_frame = _LENGTH_PREFIX.pack(len(response_data)) + response_data

        mock_reader = MagicMock()
        mock_reader.readexactly = AsyncMock(side_effect=[response_frame[:4], response_data])
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()

        transport._reader = mock_reader
        transport._writer = mock_writer

        result = await transport.send_request(b"request")

        assert result == response_data
        mock_writer.write.assert_called_once()

    async def test_send_request_retries_on_timeout(self, transport):
        response_data = b"\x30\x00"

        call_count = [0]

        async def mock_readexactly(n):
            call_count[0] += 1
            if call_count[0] <= 2:
                raise asyncio.TimeoutError()
            if n == 4:
                return _LENGTH_PREFIX.pack(len(response_data))
            return response_data

        mock_reader = MagicMock()
        mock_reader.readexactly = mock_readexactly
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()

        transport._reader = mock_reader
        transport._writer = mock_writer

        result = await transport.send_request(b"request")
        assert result == response_data

    async def test_send_request_raises_after_all_retries(self, transport):
        mock_reader = MagicMock()
        mock_reader.readexactly = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()

        transport._reader = mock_reader
        transport._writer = mock_writer

        with pytest.raises(TimeoutError, match="timed out after 3 attempts"):
            await transport.send_request(b"request")


class TestLengthPrefixFraming:
    def test_prefix_struct_format(self):
        assert _LENGTH_PREFIX.size == 4

    def test_pack_unpack_roundtrip(self):
        for length in [0, 1, 255, 65535, 2**24]:
            packed = _LENGTH_PREFIX.pack(length)
            (unpacked,) = _LENGTH_PREFIX.unpack(packed)
            assert unpacked == length

    def test_big_endian(self):
        packed = _LENGTH_PREFIX.pack(256)
        assert packed == b"\x00\x00\x01\x00"


class TestManagerTcpIntegration:
    def test_manager_accepts_tcp_transport(self):
        from snmpkit.manager import Manager

        mgr = Manager("192.168.1.1", transport="tcp")
        assert mgr._transport_type == "tcp"

    def test_manager_defaults_to_udp(self):
        from snmpkit.manager import Manager

        mgr = Manager("192.168.1.1")
        assert mgr._transport_type == "udp"

    async def test_manager_connect_creates_tcp(self):
        from snmpkit.manager import Manager

        mgr = Manager("192.168.1.1", transport="tcp")
        with patch(
            "snmpkit.manager.tcp_transport.asyncio.open_connection", new_callable=AsyncMock
        ) as mock_open:
            mock_reader = MagicMock()
            mock_writer = MagicMock()
            mock_open.return_value = (mock_reader, mock_writer)
            await mgr.connect()

            assert isinstance(mgr.transport, TcpTransport)
            mock_open.assert_called_once_with("192.168.1.1", 161)
            await mgr.close()
