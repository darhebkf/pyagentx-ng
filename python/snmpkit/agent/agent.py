from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

import uvloop

from snmpkit.agent.exceptions import SessionError
from snmpkit.agent.handlers import DataStore, RequestHandler
from snmpkit.agent.protocol import Protocol
from snmpkit.core import PduTypes, VarBind

if TYPE_CHECKING:
    from snmpkit.agent.set_handler import SetHandler
    from snmpkit.agent.updater import Updater

logger = logging.getLogger("snmpkit.agent")


@dataclass
class Registration:
    """Internal registration record."""

    oid: str
    updater: Updater
    freq: int
    context: str | None
    priority: int


class Agent:
    """AgentX subagent for SNMP.

    Example:
        agent = Agent(agent_id="myagent")
        agent.register("1.3.6.1.4.1.12345", MyUpdater())
        agent.run()  # Blocking, uses uvloop
    """

    def __init__(
        self,
        agent_id: str = "snmpkit",
        socket_path: str = "/var/agentx/master",
        timeout: int = 5,
        parallel_encoding: bool = False,
        worker_threads: int = 0,
        queue_size: int = 0,
    ) -> None:
        self.agent_id = agent_id
        self.socket_path = socket_path
        self.timeout = timeout
        self.parallel_encoding = parallel_encoding
        self.worker_threads = worker_threads
        self.queue_size = queue_size

        self.registrations: dict[str, Registration] = {}
        self.set_handlers: dict[str, SetHandler] = {}

        self.protocol: Protocol | None = None
        self.data_store = DataStore()
        self.handler: RequestHandler | None = None

        self.running: bool = False
        self.tasks: list[asyncio.Task] = []

    def register(
        self,
        oid: str,
        updater: Updater,
        freq: int = 10,
        context: str | None = None,
        priority: int = 127,
    ) -> None:
        """Register an OID subtree with an updater.

        Args:
            oid: OID subtree to register (e.g., "1.3.6.1.4.1.12345")
            updater: Updater instance to handle this subtree
            freq: Update frequency in seconds
            context: SNMP context (None for default)
            priority: Registration priority (1-255, lower = higher priority)
        """
        oid = oid.strip(" .")

        try:
            _ = [int(i) for i in oid.split(".")]
        except ValueError as e:
            raise ValueError(f"Invalid OID: {oid}") from e

        updater._bind(self, oid)

        key = f"{oid}:{context or ''}"
        self.registrations[key] = Registration(oid, updater, freq, context, priority)
        self.data_store.init_context(context)

        logger.debug("Registered OID %s (context=%s, freq=%d)", oid, context, freq)

    def register_set(
        self,
        oid: str,
        handler: SetHandler,
        context: str | None = None,
    ) -> None:
        """Register a SET handler for an OID subtree.

        Args:
            oid: OID subtree for SET operations
            handler: SetHandler instance
            context: SNMP context (None for default)
        """
        oid = oid.strip(" .")

        try:
            _ = [int(i) for i in oid.split(".")]
        except ValueError as e:
            raise ValueError(f"Invalid OID: {oid}") from e

        handler._bind(self, oid)

        key = f"{oid}:{context or ''}"
        self.set_handlers[key] = handler

        logger.debug("Registered SET handler for OID %s", oid)

    def unregister(self, oid: str, context: str | None = None) -> None:
        """Unregister an OID subtree.

        Args:
            oid: OID subtree to unregister
            context: SNMP context
        """
        oid = oid.strip(" .")
        key = f"{oid}:{context or ''}"

        if key in self.registrations:
            del self.registrations[key]
        if key in self.set_handlers:
            del self.set_handlers[key]

    async def start(self) -> None:
        """Start the agent (async)."""
        if self.running:
            raise RuntimeError("Agent already running")

        self.running = True
        self.protocol = Protocol(self.agent_id, self.socket_path, self.timeout)
        self.handler = RequestHandler(self.protocol, self.data_store, self.set_handlers)

        try:
            await self._connect_and_register()

            for reg in self.registrations.values():
                task = asyncio.create_task(self._updater_loop(reg))
                self.tasks.append(task)

            await self._request_loop()
        finally:
            await self.stop()

    def start_sync(self) -> None:
        """Start the agent (blocking, uses uvloop)."""
        uvloop.run(self.start())

    async def stop(self) -> None:
        """Stop the agent gracefully."""
        if not self.running:
            return

        logger.info("Stopping agent...")
        self.running = False

        for task in self.tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self.tasks.clear()

        if self.protocol:
            await self.protocol.close_session()
            await self.protocol.disconnect()
            self.protocol = None

        logger.info("Agent stopped")

    async def _send_trap(self, oid: str, varbinds: list[VarBind]) -> None:
        """Send a trap/notification. Called by Updater.send_trap()."""
        if self.protocol is None:
            raise SessionError("Not connected")
        await self.protocol.send_notify(varbinds)
        logger.debug("Sent trap for %s", oid)

    async def _connect_and_register(self) -> None:
        """Connect to master and register all OIDs."""
        if self.protocol is None:
            raise SessionError("Protocol not initialized")

        await self.protocol.connect()
        await self.protocol.open_session()
        await self.protocol.ping()

        for reg in self.registrations.values():
            await self.protocol.register_oid(reg)

    async def _reconnect(self) -> None:
        """Reconnect and re-register after connection loss."""
        logger.info("Reconnecting...")

        if self.protocol:
            await self.protocol.disconnect()

        self.protocol = Protocol(self.agent_id, self.socket_path, self.timeout)
        self.handler = RequestHandler(self.protocol, self.data_store, self.set_handlers)

        while self.running:
            try:
                await self._connect_and_register()
                return
            except Exception as e:
                logger.warning("Reconnect failed: %s, retrying in 2s", e)
                await asyncio.sleep(2)

    async def _updater_loop(self, reg: Registration) -> None:
        """Run the updater loop for a registration."""
        while self.running:
            try:
                await reg.updater.update()
                varbinds = reg.updater.get_varbinds()
                self.data_store.update(reg.oid, reg.context, varbinds)
                logger.debug("Updated %s: %d values", reg.oid, len(varbinds))
            except Exception as e:
                logger.error("Updater error for %s: %s", reg.oid, e)

            await asyncio.sleep(reg.freq)

    async def _request_loop(self) -> None:
        """Main loop to handle incoming requests."""
        if self.protocol is None or self.handler is None:
            raise SessionError("Not initialized")

        while self.running:
            try:
                result = await self.protocol.recv_pdu()
                if result is None:
                    continue

                header, payload = result
                logger.debug(
                    "Received PDU type=%d session=%d",
                    header.pdu_type,
                    header.session_id,
                )

                if header.pdu_type == PduTypes.GET:
                    await self.handler.handle_get(header, payload)
                elif header.pdu_type == PduTypes.GET_NEXT:
                    await self.handler.handle_getnext(header, payload)
                elif header.pdu_type == PduTypes.GET_BULK:
                    await self.handler.handle_getbulk(header, payload)
                elif header.pdu_type == PduTypes.TEST_SET:
                    await self.handler.handle_testset(header, payload)
                elif header.pdu_type == PduTypes.COMMIT_SET:
                    await self.handler.handle_commitset(header)
                elif header.pdu_type == PduTypes.UNDO_SET:
                    await self.handler.handle_undoset(header)
                elif header.pdu_type == PduTypes.CLEANUP_SET:
                    await self.handler.handle_cleanupset(header)
                elif header.pdu_type == PduTypes.CLOSE:
                    logger.info("Received Close PDU from master")
                    self.running = False
                    break
                else:
                    logger.warning("Unhandled PDU type: %d", header.pdu_type)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Request loop error: %s", e)
                if self.running:
                    await self._reconnect()
