"""Starts a real net-snmp agent for the interop suite."""

import subprocess
import time

import pytest

from ._config import COMMUNITY, HOST, PORT, SYS_DESCR


def _agent_answers() -> bool:
    result = subprocess.run(
        ["snmpget", "-v2c", "-c", COMMUNITY, "-t", "1", "-r", "0", f"{HOST}:{PORT}", SYS_DESCR],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


@pytest.fixture(scope="session", autouse=True)
def snmpd():
    """Run snmpd for the whole session. Fails loudly if it never comes up."""
    proc = subprocess.Popen(
        ["/usr/sbin/snmpd", "-f", "-Lo", "-C", "-c", "/etc/snmp/snmpd.conf"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    deadline = time.time() + 30
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"snmpd exited early:\n{proc.stdout.read()}")
        if _agent_answers():
            break
        time.sleep(0.3)
    else:
        proc.kill()
        raise RuntimeError("snmpd did not answer within 30s")

    yield proc

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
