"""Concurrent SNMP polling for multiple targets."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass

from snmpkit.core import Value
from snmpkit.manager.manager import Manager

logger = logging.getLogger("snmpkit.poll")


@dataclass
class PollTarget:
    """A target device for polling."""

    host: str
    port: int = 161
    community: str = "public"
    version: int = 2
    # v3 fields
    user: str | None = None
    auth_protocol: str | None = None
    auth_password: str | None = None
    priv_protocol: str | None = None
    priv_password: str | None = None
    timeout: float = 5.0
    retries: int = 3


@dataclass
class PollResult:
    """Result from polling a single target/OID."""

    target: str
    oid: str
    value: Value | None = None
    error: str | None = None


async def _poll_target(target: PollTarget, oids: list[str]) -> list[PollResult]:
    """Poll a single target for all OIDs."""
    target_str = f"{target.host}:{target.port}"
    results: list[PollResult] = []

    try:
        async with Manager(
            host=target.host,
            port=target.port,
            community=target.community,
            version=target.version,
            user=target.user,
            auth_protocol=target.auth_protocol,
            auth_password=target.auth_password,
            priv_protocol=target.priv_protocol,
            priv_password=target.priv_password,
            timeout=target.timeout,
            retries=target.retries,
        ) as mgr:
            values = await mgr.get_many(*oids)
            for oid, value in zip(oids, values):
                results.append(PollResult(target=target_str, oid=oid, value=value))
    except Exception as exc:
        for oid in oids:
            results.append(PollResult(target=target_str, oid=oid, error=str(exc)))

    return results


async def poll_many(
    targets: list[PollTarget],
    oids: list[str],
    concurrency: int = 50,
) -> AsyncIterator[PollResult]:
    """Poll multiple targets concurrently and stream results.

    Args:
        targets: List of devices to poll
        oids: OIDs to get from each target
        concurrency: Max number of concurrent requests

    Yields:
        PollResult for each target/OID combination
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def bounded_poll(target: PollTarget) -> list[PollResult]:
        async with semaphore:
            return await _poll_target(target, oids)

    tasks = [asyncio.create_task(bounded_poll(t)) for t in targets]

    for coro in asyncio.as_completed(tasks):
        results = await coro
        for result in results:
            yield result
