"""SNMP Manager for querying devices."""

from __future__ import annotations

import logging
import random
from collections.abc import AsyncIterator
from typing import Self

from snmpkit.core import (
    Oid,
    SnmpVarBind,
    Value,
    decode_snmp_response,
    encode_snmp_get_v1,
    encode_snmp_get_v2c,
    encode_snmp_getbulk_v2c,
    encode_snmp_getnext_v1,
    encode_snmp_getnext_v2c,
    encode_snmp_set_v2c,
)
from snmpkit.manager.exceptions import (
    EndOfMibViewError,
    GenericError,
    NoSuchInstanceError,
    NoSuchObjectError,
)
from snmpkit.manager.transport import UdpTransport

logger = logging.getLogger("snmpkit.manager")


class Manager:
    """SNMP Manager for querying network devices.

    Example:
        async with Manager("192.168.1.1") as mgr:
            value = await mgr.get("1.3.6.1.2.1.1.1.0")
            print(f"sysDescr: {value}")

            async for oid, val in mgr.walk("1.3.6.1.2.1.2.2"):
                print(f"{oid} = {val}")
    """

    def __init__(
        self,
        host: str,
        port: int = 161,
        community: str = "public",
        version: int = 2,
        timeout: float = 5.0,
        retries: int = 3,
    ) -> None:
        """Initialize SNMP Manager.

        Args:
            host: Target device hostname or IP
            port: SNMP port (default 161)
            community: SNMPv1/v2c community string
            version: SNMP version (1 or 2 for v2c)
            timeout: Request timeout in seconds
            retries: Number of retry attempts
        """
        self._host = host
        self._port = port
        self._community = community
        self._version = version
        self._timeout = timeout
        self._retries = retries

        self._transport: UdpTransport | None = None
        self._request_id: int = random.randint(1, 2**31 - 1)

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def connect(self) -> None:
        """Connect to the target device."""
        self._transport = UdpTransport(
            self._host,
            self._port,
            self._timeout,
            self._retries,
        )
        await self._transport.connect()
        logger.info("Connected to %s:%d", self._host, self._port)

    async def close(self) -> None:
        """Close the connection."""
        if self._transport:
            await self._transport.close()
            self._transport = None

    def _next_request_id(self) -> int:
        self._request_id = (self._request_id + 1) % (2**31)
        return self._request_id

    async def get(self, oid: str) -> Value:
        """Get a single OID value.

        Args:
            oid: OID to retrieve (e.g., "1.3.6.1.2.1.1.1.0")

        Returns:
            The value at the OID
        """
        results = await self.get_many(oid)
        return results[0]

    async def get_many(self, *oids: str) -> list[Value]:
        """Get multiple OID values in a single request.

        Args:
            oids: OIDs to retrieve

        Returns:
            List of values in same order as requested OIDs
        """
        if self._transport is None:
            raise RuntimeError("Not connected")

        oid_objects = [Oid(o) for o in oids]
        request_id = self._next_request_id()

        if self._version == 1:
            request = encode_snmp_get_v1(self._community, request_id, oid_objects)
        else:
            request = encode_snmp_get_v2c(self._community, request_id, oid_objects)

        response_data = await self._transport.send_request(request)
        response = decode_snmp_response(response_data)

        self._check_error(response.error_status, response.error_index)

        values: list[Value] = []
        for vb in response.varbinds:
            self._check_exception_value(vb.value)
            values.append(vb.value)

        return values

    async def get_next(self, oid: str) -> tuple[str, Value]:
        """Get the next OID and value after the given OID.

        Args:
            oid: Starting OID

        Returns:
            Tuple of (next_oid, value)
        """
        if self._transport is None:
            raise RuntimeError("Not connected")

        oid_obj = Oid(oid)
        request_id = self._next_request_id()

        if self._version == 1:
            request = encode_snmp_getnext_v1(self._community, request_id, [oid_obj])
        else:
            request = encode_snmp_getnext_v2c(self._community, request_id, [oid_obj])

        response_data = await self._transport.send_request(request)
        response = decode_snmp_response(response_data)

        self._check_error(response.error_status, response.error_index)

        if not response.varbinds:
            raise EndOfMibViewError("No varbinds in response")

        vb = response.varbinds[0]
        self._check_exception_value(vb.value)

        return (str(vb.oid), vb.value)

    async def get_bulk(
        self,
        *oids: str,
        non_repeaters: int = 0,
        max_repetitions: int = 10,
    ) -> list[tuple[str, Value]]:
        """Bulk get multiple OIDs efficiently.

        Args:
            oids: OIDs to retrieve
            non_repeaters: Number of OIDs to get once (not repeated)
            max_repetitions: Max rows to return for repeated OIDs

        Returns:
            List of (oid, value) tuples
        """
        if self._transport is None:
            raise RuntimeError("Not connected")

        if self._version == 1:
            raise ValueError("GetBulk not supported in SNMPv1")

        oid_objects = [Oid(o) for o in oids]
        request_id = self._next_request_id()

        request = encode_snmp_getbulk_v2c(
            self._community,
            request_id,
            non_repeaters,
            max_repetitions,
            oid_objects,
        )

        response_data = await self._transport.send_request(request)
        response = decode_snmp_response(response_data)

        self._check_error(response.error_status, response.error_index)

        results: list[tuple[str, Value]] = []
        for vb in response.varbinds:
            if self._is_exception_value(vb.value):
                continue
            results.append((str(vb.oid), vb.value))

        return results

    async def set(self, oid: str, value: Value) -> None:
        """Set an OID value.

        Args:
            oid: OID to set
            value: Value to set
        """
        if self._transport is None:
            raise RuntimeError("Not connected")

        if self._version == 1:
            raise ValueError("SET not implemented for SNMPv1")

        request_id = self._next_request_id()
        varbind = SnmpVarBind(Oid(oid), value)

        request = encode_snmp_set_v2c(
            self._community,
            request_id,
            [varbind],
        )

        response_data = await self._transport.send_request(request)
        response = decode_snmp_response(response_data)

        self._check_error(response.error_status, response.error_index)

    async def walk(self, oid: str) -> AsyncIterator[tuple[str, Value]]:
        """Walk an OID subtree using GetNext.

        Args:
            oid: Root OID to walk

        Yields:
            Tuples of (oid, value) for each OID in the subtree
        """
        root = Oid(oid)
        current = oid

        while True:
            try:
                next_oid, value = await self.get_next(current)
            except EndOfMibViewError:
                break

            next_oid_obj = Oid(next_oid)
            if not next_oid_obj.starts_with(root):
                break

            yield (next_oid, value)
            current = next_oid

    async def bulk_walk(
        self,
        oid: str,
        bulk_size: int = 10,
    ) -> AsyncIterator[tuple[str, Value]]:
        """Walk an OID subtree using GetBulk (more efficient).

        Args:
            oid: Root OID to walk
            bulk_size: Number of rows per request

        Yields:
            Tuples of (oid, value) for each OID in the subtree
        """
        root = Oid(oid)
        current = oid

        while True:
            results = await self.get_bulk(
                current,
                non_repeaters=0,
                max_repetitions=bulk_size,
            )

            if not results:
                break

            for result_oid, value in results:
                result_oid_obj = Oid(result_oid)
                if not result_oid_obj.starts_with(root):
                    return

                yield (result_oid, value)
                current = result_oid

    def _check_error(self, error_status: int, error_index: int) -> None:
        if error_status != 0:
            raise GenericError(error_status, error_index)

    def _check_exception_value(self, value: Value) -> None:
        value_str = str(value)
        if "NoSuchObject" in value_str:
            raise NoSuchObjectError("OID does not exist")
        elif "NoSuchInstance" in value_str:
            raise NoSuchInstanceError("Instance does not exist")
        elif "EndOfMibView" in value_str:
            raise EndOfMibViewError("End of MIB view")

    def _is_exception_value(self, value: Value) -> bool:
        value_str = str(value)
        return any(x in value_str for x in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"))
