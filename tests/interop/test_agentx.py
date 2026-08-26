"""A snmpkit subagent registered with a real net-snmp master, queried back
through snmpkit's manager. Exercises the whole AgentX loop."""

import subprocess
import sys
import time

import pytest
from snmpkit.manager import Manager

from ._config import AGENTX_SOCKET, COMMUNITY, HOST, PORT

SUBTREE = "1.3.6.1.4.1.99999"
HELPER = "tests/interop/subagent.py"


def _served() -> bool:
    result = subprocess.run(
        [
            "snmpget",
            "-v2c",
            "-c",
            COMMUNITY,
            "-t",
            "1",
            "-r",
            "0",
            f"{HOST}:{PORT}",
            f"{SUBTREE}.1.0",
        ],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and "No Such Object" not in result.stdout


@pytest.fixture(scope="module")
def subagent():
    """Run the subagent as its own process, as a real deployment would."""
    proc = subprocess.Popen(
        [sys.executable, HELPER, AGENTX_SOCKET],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    deadline = time.time() + 30
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"subagent exited early:\n{proc.stdout.read()}")
        if _served():
            break
        time.sleep(0.5)
    else:
        proc.kill()
        raise RuntimeError("master never served the subagent's subtree")

    yield proc

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


async def test_master_serves_values_from_the_snmpkit_subagent(subagent):
    async with Manager(HOST, port=PORT, community=COMMUNITY, timeout=5) as mgr:
        number = await mgr.get(f"{SUBTREE}.1.0")
        text = await mgr.get(f"{SUBTREE}.2.0")

    assert int(number) == 42
    assert bytes(text) == b"hello from snmpkit"


async def test_walk_reaches_the_registered_subtree(subagent):
    async with Manager(HOST, port=PORT, community=COMMUNITY, timeout=5) as mgr:
        rows = [(oid, val) async for oid, val in mgr.walk(SUBTREE)]

    assert [oid for oid, _ in rows] == [f"{SUBTREE}.1.0", f"{SUBTREE}.2.0"]


def test_net_snmp_client_also_sees_it(subagent):
    """Proves interop with net-snmp's own tools, not just snmpkit talking to itself."""
    result = subprocess.run(
        ["snmpwalk", "-v2c", "-c", COMMUNITY, f"{HOST}:{PORT}", SUBTREE],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "42" in result.stdout
    assert "hello from snmpkit" in result.stdout
