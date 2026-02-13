"""SNMP Manager for querying devices."""

from __future__ import annotations

import logging
import random
import time
from collections.abc import AsyncIterator
from typing import Self

from snmpkit.core import (
    Oid,
    SnmpVarBind,
    Value,
    decode_snmp_response,
    decode_snmp_v3_response,
    encode_snmp_get_v1,
    encode_snmp_get_v2c,
    encode_snmp_get_v3,
    encode_snmp_get_v3_secure,
    encode_snmp_getbulk_v2c,
    encode_snmp_getbulk_v3_secure,
    encode_snmp_getnext_v1,
    encode_snmp_getnext_v2c,
    encode_snmp_getnext_v3_secure,
    encode_snmp_set_v2c,
    encode_snmp_set_v3_secure,
    password_to_localized_key,
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
        # v1/v2c
        community: str = "public",
        version: int = 2,
        # v3 USM
        user: str | None = None,
        auth_protocol: str | None = None,
        auth_password: str | None = None,
        priv_protocol: str | None = None,
        priv_password: str | None = None,
        context_name: str = "",
        # Common
        timeout: float = 5.0,
        retries: int = 3,
    ) -> None:
        self.host = host
        self.port = port
        self.community = community
        self.version = version
        self.timeout = timeout
        self.retries = retries

        # v3 USM
        self.user = user or ""
        self.auth_protocol = auth_protocol
        self.auth_password = auth_password
        self.priv_protocol = priv_protocol
        self.priv_password = priv_password
        self.context_name = context_name

        # v3 engine state (populated by discovery)
        self._engine_id: bytes = b""
        self._engine_boots: int = 0
        self._engine_time: int = 0
        self._discovery_time: float = 0.0

        # v3 derived keys (computed after discovery)
        self._auth_key: bytes | None = None
        self._priv_key: bytes | None = None

        self.transport: UdpTransport | None = None
        self._msg_id: int = random.randint(1, 2**31 - 1)
        self.request_id: int = random.randint(1, 2**31 - 1)

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def connect(self) -> None:
        """Connect to the target device."""
        self.transport = UdpTransport(
            self.host,
            self.port,
            self.timeout,
            self.retries,
        )
        await self.transport.connect()
        logger.info("Connected to %s:%d", self.host, self.port)

        if self.version == 3:
            await self._discover_engine()

    async def close(self) -> None:
        """Close the connection."""
        if self.transport:
            await self.transport.close()
            self.transport = None

    def _next_request_id(self) -> int:
        self.request_id = (self.request_id + 1) % (2**31)
        return self.request_id

    def _next_msg_id(self) -> int:
        self._msg_id = (self._msg_id + 1) % (2**31)
        return self._msg_id

    def _current_engine_time(self) -> int:
        """Estimate current engine time based on discovery + elapsed."""
        if self._discovery_time == 0.0:
            return self._engine_time
        elapsed = int(time.monotonic() - self._discovery_time)
        return self._engine_time + elapsed

    # SNMPv3 engine discovery (RFC 3414 Section 4)
    #
    # Send an empty v3 message with no auth/priv to get
    # the engine ID, boots, and time from the Report PDU.
    async def _discover_engine(self) -> None:
        if self.transport is None:
            raise RuntimeError("Not connected")

        msg_id = self._next_msg_id()
        request_id = self._next_request_id()

        # Discovery message: empty engine_id, no auth/priv
        discovery_msg = encode_snmp_get_v3(
            msg_id=msg_id,
            request_id=request_id,
            oids=[],
            engine_id=b"",
            engine_boots=0,
            engine_time=0,
            user_name="",
            auth=False,
            priv_=False,
        )

        response_data = await self.transport.send_request(discovery_msg)

        # Parse the Report PDU to extract USM parameters
        # The response contains engine_id, boots, time in the USM header
        self._parse_discovery_response(response_data)
        self._discovery_time = time.monotonic()

        logger.info(
            "Discovered engine: id=%s boots=%d time=%d",
            self._engine_id.hex(),
            self._engine_boots,
            self._engine_time,
        )

        # Derive localized keys if auth/priv configured
        if self.auth_protocol and self.auth_password:
            self._auth_key = password_to_localized_key(
                self.auth_password,
                self._engine_id,
                self.auth_protocol,
            )
            logger.debug("Auth key derived (%s)", self.auth_protocol)

        if self.priv_protocol and self.priv_password:
            # Privacy key uses auth protocol for derivation
            auth_proto = self.auth_protocol or "SHA"
            self._priv_key = password_to_localized_key(
                self.priv_password,
                self._engine_id,
                auth_proto,
            )
            logger.debug("Priv key derived (%s)", self.priv_protocol)

    def _parse_discovery_response(self, data: bytes) -> None:
        """Extract engine_id, boots, time from a v3 Report PDU."""
        # The USM security parameters are BER-encoded inside the message.
        # We need to find the msgSecurityParameters OCTET STRING and
        # parse the USM SEQUENCE inside it.
        #
        # Message structure:
        # SEQUENCE {
        #   INTEGER (version = 3)
        #   SEQUENCE (headerData) { msgID, maxSize, flags, secModel }
        #   OCTET STRING (securityParams - contains USM SEQUENCE)
        #   ... (scoped PDU)
        # }
        pos = 0

        # Outer SEQUENCE
        if data[pos] != 0x30:
            raise ValueError("Invalid SNMPv3 message")
        pos += 1
        _, pos = self._decode_ber_length(data, pos)

        # version INTEGER
        pos = self._skip_ber_tlv(data, pos)

        # headerData SEQUENCE
        pos = self._skip_ber_tlv(data, pos)

        # msgSecurityParameters OCTET STRING
        if data[pos] != 0x04:
            raise ValueError("Expected OCTET STRING for security parameters")
        pos += 1
        sp_len, pos = self._decode_ber_length(data, pos)
        sp_data = data[pos : pos + sp_len]

        # Parse USM SEQUENCE inside security parameters
        self._parse_usm_params(sp_data)

    def _parse_usm_params(self, data: bytes) -> None:
        """Parse USM security parameters SEQUENCE."""
        pos = 0

        # SEQUENCE
        if data[pos] != 0x30:
            raise ValueError("Expected SEQUENCE in USM params")
        pos += 1
        _, pos = self._decode_ber_length(data, pos)

        # engineID OCTET STRING
        if data[pos] != 0x04:
            raise ValueError("Expected OCTET STRING for engineID")
        pos += 1
        eid_len, pos = self._decode_ber_length(data, pos)
        self._engine_id = bytes(data[pos : pos + eid_len])
        pos += eid_len

        # engineBoots INTEGER
        if data[pos] != 0x02:
            raise ValueError("Expected INTEGER for engineBoots")
        pos += 1
        boots_len, pos = self._decode_ber_length(data, pos)
        self._engine_boots = int.from_bytes(data[pos : pos + boots_len], "big", signed=True)
        pos += boots_len

        # engineTime INTEGER
        if data[pos] != 0x02:
            raise ValueError("Expected INTEGER for engineTime")
        pos += 1
        time_len, pos = self._decode_ber_length(data, pos)
        self._engine_time = int.from_bytes(data[pos : pos + time_len], "big", signed=True)
        pos += time_len

    @staticmethod
    def _decode_ber_length(data: bytes, pos: int) -> tuple[int, int]:
        """Decode BER length, return (length, new_pos)."""
        if data[pos] < 0x80:
            return data[pos], pos + 1
        num_bytes = data[pos] & 0x7F
        pos += 1
        length = int.from_bytes(data[pos : pos + num_bytes], "big")
        return length, pos + num_bytes

    @staticmethod
    def _skip_ber_tlv(data: bytes, pos: int) -> int:
        """Skip a complete TLV and return position after it."""
        pos += 1  # tag
        if data[pos] < 0x80:
            length = data[pos]
            pos += 1
        else:
            num_bytes = data[pos] & 0x7F
            pos += 1
            length = int.from_bytes(data[pos : pos + num_bytes], "big")
            pos += num_bytes
        return pos + length

    # Request encoding

    def _encode_get(self, oid_objects: list[Oid], request_id: int) -> bytes:
        if self.version == 1:
            return encode_snmp_get_v1(self.community, request_id, oid_objects)
        elif self.version == 3:
            return self._encode_v3_get(oid_objects, request_id)
        else:
            return encode_snmp_get_v2c(self.community, request_id, oid_objects)

    def _encode_getnext(self, oid_objects: list[Oid], request_id: int) -> bytes:
        if self.version == 1:
            return encode_snmp_getnext_v1(self.community, request_id, oid_objects)
        elif self.version == 3:
            return self._encode_v3_getnext(oid_objects, request_id)
        else:
            return encode_snmp_getnext_v2c(self.community, request_id, oid_objects)

    def _encode_getbulk(
        self,
        oid_objects: list[Oid],
        request_id: int,
        non_repeaters: int,
        max_repetitions: int,
    ) -> bytes:
        if self.version == 3:
            return self._encode_v3_getbulk(oid_objects, request_id, non_repeaters, max_repetitions)
        else:
            return encode_snmp_getbulk_v2c(
                self.community, request_id, non_repeaters, max_repetitions, oid_objects
            )

    def _encode_set(self, varbinds: list[SnmpVarBind], request_id: int) -> bytes:
        if self.version == 3:
            return self._encode_v3_set(varbinds, request_id)
        else:
            return encode_snmp_set_v2c(self.community, request_id, varbinds)

    # v3 encode helpers

    def _v3_kwargs(self) -> dict:
        """Common kwargs for v3 secure encode functions."""
        kwargs: dict = {
            "engine_id": self._engine_id,
            "engine_boots": self._engine_boots,
            "engine_time": self._current_engine_time(),
            "user_name": self.user,
            "context_name": self.context_name.encode() if self.context_name else b"",
        }
        if self._auth_key and self.auth_protocol:
            kwargs["auth_protocol"] = self.auth_protocol
            kwargs["auth_key"] = self._auth_key
        if self._priv_key and self.priv_protocol:
            kwargs["priv_protocol"] = self.priv_protocol
            kwargs["priv_key"] = self._priv_key
        return kwargs

    def _encode_v3_get(self, oid_objects: list[Oid], request_id: int) -> bytes:
        msg_id = self._next_msg_id()
        return encode_snmp_get_v3_secure(
            msg_id=msg_id,
            request_id=request_id,
            oids=oid_objects,
            **self._v3_kwargs(),
        )

    def _encode_v3_getnext(self, oid_objects: list[Oid], request_id: int) -> bytes:
        msg_id = self._next_msg_id()
        return encode_snmp_getnext_v3_secure(
            msg_id=msg_id,
            request_id=request_id,
            oids=oid_objects,
            **self._v3_kwargs(),
        )

    def _encode_v3_getbulk(
        self,
        oid_objects: list[Oid],
        request_id: int,
        non_repeaters: int,
        max_repetitions: int,
    ) -> bytes:
        msg_id = self._next_msg_id()
        return encode_snmp_getbulk_v3_secure(
            msg_id=msg_id,
            request_id=request_id,
            non_repeaters=non_repeaters,
            max_repetitions=max_repetitions,
            oids=oid_objects,
            **self._v3_kwargs(),
        )

    def _encode_v3_set(self, varbinds: list[SnmpVarBind], request_id: int) -> bytes:
        msg_id = self._next_msg_id()
        return encode_snmp_set_v3_secure(
            msg_id=msg_id,
            request_id=request_id,
            varbinds=varbinds,
            **self._v3_kwargs(),
        )

    def _decode_response(self, response_data: bytes):
        """Decode response, handling v3 decryption/auth verification."""
        if self.version == 3:
            kwargs: dict = {}
            if self._auth_key and self.auth_protocol:
                kwargs["auth_protocol"] = self.auth_protocol
                kwargs["auth_key"] = self._auth_key
            if self._priv_key and self.priv_protocol:
                kwargs["priv_protocol"] = self.priv_protocol
                kwargs["priv_key"] = self._priv_key
            kwargs["engine_boots"] = self._engine_boots
            kwargs["engine_time"] = self._current_engine_time()
            return decode_snmp_v3_response(response_data, **kwargs)
        return decode_snmp_response(response_data)

    # Operations

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
        if self.transport is None:
            raise RuntimeError("Not connected")

        oid_objects = [Oid(o) for o in oids]
        request_id = self._next_request_id()

        request = self._encode_get(oid_objects, request_id)
        response_data = await self.transport.send_request(request)
        response = self._decode_response(response_data)

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
        if self.transport is None:
            raise RuntimeError("Not connected")

        oid_obj = Oid(oid)
        request_id = self._next_request_id()

        request = self._encode_getnext([oid_obj], request_id)
        response_data = await self.transport.send_request(request)
        response = self._decode_response(response_data)

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
        if self.transport is None:
            raise RuntimeError("Not connected")

        if self.version == 1:
            raise ValueError("GetBulk not supported in SNMPv1")

        oid_objects = [Oid(o) for o in oids]
        request_id = self._next_request_id()

        request = self._encode_getbulk(oid_objects, request_id, non_repeaters, max_repetitions)
        response_data = await self.transport.send_request(request)
        response = self._decode_response(response_data)

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
        if self.transport is None:
            raise RuntimeError("Not connected")

        if self.version == 1:
            raise ValueError("SET not implemented for SNMPv1")

        request_id = self._next_request_id()
        varbind = SnmpVarBind(Oid(oid), value)

        request = self._encode_set([varbind], request_id)
        response_data = await self.transport.send_request(request)
        response = self._decode_response(response_data)

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
