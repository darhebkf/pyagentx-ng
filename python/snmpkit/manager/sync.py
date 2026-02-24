"""Synchronous SNMP Manager wrapper for non-async code."""

from __future__ import annotations

import asyncio
import threading
from typing import Self

import uvloop

from snmpkit.core import Value
from snmpkit.manager.manager import Manager


class SyncManager:
    """Blocking SNMP Manager for non-async code.

    Wraps the async Manager with a persistent background event loop thread.
    All async operations are dispatched via run_coroutine_threadsafe().

    Example:
        with SyncManager("192.168.1.1") as mgr:
            value = mgr.get("1.3.6.1.2.1.1.1.0")
            print(f"sysDescr: {value}")

            for oid, val in mgr.walk("1.3.6.1.2.1.2.2"):
                print(f"{oid} = {val}")
    """

    def __init__(
        self,
        host: str,
        port: int = 161,
        community: str = "public",
        version: int = 2,
        user: str | None = None,
        auth_protocol: str | None = None,
        auth_password: str | None = None,
        priv_protocol: str | None = None,
        priv_password: str | None = None,
        context_name: str = "",
        timeout: float = 5.0,
        retries: int = 3,
        transport: str = "udp",
    ) -> None:
        self._manager_kwargs = {
            "host": host,
            "port": port,
            "community": community,
            "version": version,
            "user": user,
            "auth_protocol": auth_protocol,
            "auth_password": auth_password,
            "priv_protocol": priv_protocol,
            "priv_password": priv_password,
            "context_name": context_name,
            "timeout": timeout,
            "retries": retries,
            "transport": transport,
        }
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._manager: Manager | None = None

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def connect(self) -> None:
        """Start background event loop and connect."""
        self._loop = uvloop.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()

        self._manager = Manager(**self._manager_kwargs)
        self._run(self._manager.connect())

    def close(self) -> None:
        """Close connection and stop background loop."""
        if self._manager and self._loop:
            self._run(self._manager.close())
            self._manager = None

        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
            if self._thread:
                self._thread.join(timeout=5.0)
                self._thread = None
            self._loop.close()
            self._loop = None

    def _run(self, coro):
        """Dispatch a coroutine to the background loop and wait for result."""
        if self._loop is None:
            raise RuntimeError("Not connected")
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result()

    # Operations

    def get(self, oid: str) -> Value:
        """Get a single OID value."""
        return self._run(self._manager.get(oid))

    def get_many(self, *oids: str) -> list[Value]:
        """Get multiple OID values in a single request."""
        return self._run(self._manager.get_many(*oids))

    def get_next(self, oid: str) -> tuple[str, Value]:
        """Get the next OID and value after the given OID."""
        return self._run(self._manager.get_next(oid))

    def set(self, oid: str, value: Value) -> None:
        """Set an OID value."""
        return self._run(self._manager.set(oid, value))

    def walk(self, oid: str) -> list[tuple[str, Value]]:
        """Walk an OID subtree. Returns a list (not an iterator)."""

        async def _collect():
            results = []
            async for item in self._manager.walk(oid):
                results.append(item)
            return results

        return self._run(_collect())

    def bulk_walk(self, oid: str, bulk_size: int = 10) -> list[tuple[str, Value]]:
        """Walk an OID subtree using GetBulk. Returns a list."""

        async def _collect():
            results = []
            async for item in self._manager.bulk_walk(oid, bulk_size=bulk_size):
                results.append(item)
            return results

        return self._run(_collect())

    def get_table(
        self,
        base_oid: str,
        columns: list[int] | None = None,
        bulk_size: int = 25,
    ) -> dict[tuple[int, ...], dict[int, Value]]:
        """Get a structured SNMP table."""
        return self._run(self._manager.get_table(base_oid, columns=columns, bulk_size=bulk_size))

    def send_trap(self, trap_oid: str, **kwargs) -> None:
        """Send an SNMP Trap."""
        return self._run(self._manager.send_trap(trap_oid, **kwargs))

    def send_inform(self, trap_oid: str, **kwargs) -> None:
        """Send an SNMP Inform and wait for acknowledgement."""
        return self._run(self._manager.send_inform(trap_oid, **kwargs))
