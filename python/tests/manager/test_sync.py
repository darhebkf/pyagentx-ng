"""Tests for SyncManager."""

from __future__ import annotations

import inspect
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from snmpkit.core import Value
from snmpkit.manager.sync import SyncManager


@contextmanager
def patched_run(mgr, return_value=None):
    """Patch _run and close the coroutine it was handed.

    The sync wrappers build a coroutine and pass it to _run. With _run mocked
    nothing awaits it, so Python warns unless it is closed here.
    """
    with patch.object(mgr, "_run", return_value=return_value) as mock_run:
        yield mock_run
    for call in mock_run.call_args_list:
        for arg in call.args:
            if inspect.iscoroutine(arg):
                arg.close()


class TestSyncManagerInit:
    def test_stores_kwargs(self):
        mgr = SyncManager("192.168.1.1", port=161, community="private", version=2)
        assert mgr._manager_kwargs["host"] == "192.168.1.1"
        assert mgr._manager_kwargs["port"] == 161
        assert mgr._manager_kwargs["community"] == "private"

    def test_default_values(self):
        mgr = SyncManager("10.0.0.1")
        assert mgr._manager_kwargs["port"] == 161
        assert mgr._manager_kwargs["community"] == "public"
        assert mgr._manager_kwargs["version"] == 2
        assert mgr._manager_kwargs["transport"] == "udp"

    def test_v3_params(self):
        mgr = SyncManager(
            "10.0.0.1",
            version=3,
            user="admin",
            auth_protocol="SHA",
            auth_password="authpass",
            priv_protocol="AES",
            priv_password="privpass",
        )
        assert mgr._manager_kwargs["version"] == 3
        assert mgr._manager_kwargs["user"] == "admin"
        assert mgr._manager_kwargs["auth_protocol"] == "SHA"

    def test_tcp_transport(self):
        mgr = SyncManager("10.0.0.1", transport="tcp")
        assert mgr._manager_kwargs["transport"] == "tcp"

    def test_not_connected_initially(self):
        mgr = SyncManager("10.0.0.1")
        assert mgr._loop is None
        assert mgr._thread is None
        assert mgr._manager is None


class TestSyncManagerLifecycle:
    def test_connect_starts_loop_and_thread(self):
        mgr = SyncManager("10.0.0.1")
        with patch.object(SyncManager, "_run") as mock_run:
            mock_run.return_value = None
            mgr._loop = MagicMock()
            mgr._loop.run_forever = MagicMock()
            # Patch to avoid real loop creation
            with patch("snmpkit.manager.sync.uvloop.new_event_loop") as mock_new_loop:
                mock_loop = MagicMock()
                mock_new_loop.return_value = mock_loop
                with patch("threading.Thread") as mock_thread_cls:
                    mock_thread = MagicMock()
                    mock_thread_cls.return_value = mock_thread

                    with patch.object(mgr, "_run", return_value=None) as mock_run:
                        mgr.connect()
                    for call in mock_run.call_args_list:
                        for arg in call.args:
                            if inspect.iscoroutine(arg):
                                arg.close()

                    mock_thread.start.assert_called_once()
                    assert mgr._manager is not None

    def test_context_manager(self):
        with (
            patch.object(SyncManager, "connect") as mock_connect,
            patch.object(SyncManager, "close") as mock_close,
        ):
            with SyncManager("10.0.0.1") as mgr:
                mock_connect.assert_called_once()
                assert mgr is not None
            mock_close.assert_called_once()

    def test_close_stops_loop(self):
        mgr = SyncManager("10.0.0.1")
        mock_loop = MagicMock()
        mock_thread = MagicMock()
        mock_manager = MagicMock()
        mock_manager.close = AsyncMock()

        mgr._loop = mock_loop
        mgr._thread = mock_thread
        mgr._manager = mock_manager

        with patched_run(mgr):
            mgr.close()

        mock_loop.call_soon_threadsafe.assert_called_once_with(mock_loop.stop)
        mock_thread.join.assert_called_once()
        mock_loop.close.assert_called_once()
        assert mgr._loop is None
        assert mgr._thread is None
        assert mgr._manager is None

    def test_close_when_not_connected(self):
        mgr = SyncManager("10.0.0.1")
        mgr.close()  # should not raise


class TestSyncManagerOperations:
    def _make_mgr(self):
        mgr = SyncManager("10.0.0.1")
        mgr._loop = MagicMock()
        mgr._manager = MagicMock()
        return mgr

    def test_get(self):
        mgr = self._make_mgr()
        mgr._manager.get = AsyncMock(return_value=Value.Integer(42))
        with patched_run(mgr, Value.Integer(42)):
            result = mgr.get("1.3.6.1.2.1.1.1.0")
            assert result == Value.Integer(42)

    def test_get_many(self):
        mgr = self._make_mgr()
        expected = [Value.Integer(1), Value.Integer(2)]
        with patch.object(mgr, "_run", return_value=expected):
            result = mgr.get_many("1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0")
            assert result == expected

    def test_get_next(self):
        mgr = self._make_mgr()
        expected = ("1.3.6.1.2.1.1.2.0", Value.OctetString(b"test"))
        with patch.object(mgr, "_run", return_value=expected):
            result = mgr.get_next("1.3.6.1.2.1.1.1.0")
            assert result == expected

    def test_set(self):
        mgr = self._make_mgr()
        with patch.object(mgr, "_run", return_value=None) as mock_run:
            mgr.set("1.3.6.1.2.1.1.4.0", Value.OctetString(b"admin"))
            mock_run.assert_called_once()

    def test_walk(self):
        mgr = self._make_mgr()
        expected = [
            ("1.3.6.1.2.1.1.1.0", Value.OctetString(b"Linux")),
            ("1.3.6.1.2.1.1.2.0", Value.OctetString(b"test")),
        ]
        with patched_run(mgr, expected):
            result = mgr.walk("1.3.6.1.2.1.1")
            assert result == expected

    def test_bulk_walk(self):
        mgr = self._make_mgr()
        expected = [("1.3.6.1.2.1.2.2.1.1.1", Value.Integer(1))]
        with patched_run(mgr, expected):
            result = mgr.bulk_walk("1.3.6.1.2.1.2.2", bulk_size=20)
            assert result == expected

    def test_get_table(self):
        mgr = self._make_mgr()
        expected = {(1,): {1: Value.Integer(1), 2: Value.OctetString(b"eth0")}}
        with patch.object(mgr, "_run", return_value=expected):
            result = mgr.get_table("1.3.6.1.2.1.2.2.1")
            assert result == expected

    def test_send_trap(self):
        mgr = self._make_mgr()
        with patch.object(mgr, "_run", return_value=None) as mock_run:
            mgr.send_trap("1.3.6.1.4.1.99.0.1", uptime=5000)
            mock_run.assert_called_once()

    def test_send_inform(self):
        mgr = self._make_mgr()
        with patch.object(mgr, "_run", return_value=None) as mock_run:
            mgr.send_inform("1.3.6.1.4.1.99.0.1")
            mock_run.assert_called_once()

    def test_run_not_connected_raises(self):
        mgr = SyncManager("10.0.0.1")

        async def never_dispatched():
            return None

        # _run raises before awaiting, so the coroutine has to be closed by
        # hand or Python warns that it was never awaited.
        coro = never_dispatched()
        try:
            with pytest.raises(RuntimeError, match="Not connected"):
                mgr._run(coro)
        finally:
            coro.close()


class TestSyncManagerExport:
    def test_importable_from_package(self):
        from snmpkit.manager import SyncManager as SM

        assert SM is SyncManager
