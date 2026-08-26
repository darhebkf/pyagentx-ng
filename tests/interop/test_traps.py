"""snmpkit's trap receiver against traps emitted by net-snmp's snmptrap."""

import asyncio
import subprocess

import pytest
from snmpkit.manager import TrapReceiver

from ._config import COMMUNITY, TRAP_PORT

COLD_START = "1.3.6.1.6.3.1.1.5.1"


@pytest.fixture
async def receiver():
    rx = TrapReceiver(host="127.0.0.1", port=TRAP_PORT)
    await rx.start()
    await asyncio.sleep(0.2)
    yield rx
    await rx.stop()


def send_trap(*varbinds: str, version: str = "2c") -> None:
    subprocess.run(
        [
            "snmptrap",
            f"-v{version}",
            "-c",
            COMMUNITY,
            f"127.0.0.1:{TRAP_PORT}",
            "",
            COLD_START,
            *varbinds,
        ],
        check=True,
        capture_output=True,
    )


async def test_receives_a_v2c_trap(receiver):
    send_trap()
    trap = await asyncio.wait_for(receiver.__anext__(), timeout=10)
    assert trap.trap_oid == COLD_START


async def test_receives_trap_varbinds(receiver):
    send_trap("1.3.6.1.2.1.1.6.0", "s", "server room")
    trap = await asyncio.wait_for(receiver.__anext__(), timeout=10)
    payload = {oid: bytes(val) for oid, val in trap.varbinds if hasattr(val, "__bytes__")}
    assert any(b"server room" == v for v in payload.values())


async def test_receives_a_v1_trap(receiver):
    subprocess.run(
        [
            "snmptrap",
            "-v1",
            "-c",
            COMMUNITY,
            f"127.0.0.1:{TRAP_PORT}",
            "1.3.6.1.4.1.99999",
            "127.0.0.1",
            "6",
            "17",
            "",
            "1.3.6.1.2.1.1.6.0",
            "s",
            "v1 trap",
        ],
        check=True,
        capture_output=True,
    )
    trap = await asyncio.wait_for(receiver.__anext__(), timeout=10)
    assert trap.specific_trap == 17
