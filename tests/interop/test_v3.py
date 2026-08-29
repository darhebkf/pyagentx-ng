"""SNMPv3 USM against a real agent, one case per auth/priv combination."""

import asyncio

import pytest
from snmpkit.manager import Manager

from ._config import HOST, PORT, SYS_DESCR, V3_USERS

IDS = [user[0] for user in V3_USERS]


def _manager(user, auth_proto, auth_pass, priv_proto, priv_pass) -> Manager:
    return Manager(
        HOST,
        port=PORT,
        version=3,
        user=user,
        auth_protocol=auth_proto,
        auth_password=auth_pass,
        priv_protocol=priv_proto,
        priv_password=priv_pass,
        timeout=5.0,
        retries=2,
    )


@pytest.mark.parametrize("user,auth_p,auth_k,priv_p,priv_k", V3_USERS, ids=IDS)
async def test_v3_get(user, auth_p, auth_k, priv_p, priv_k):
    async with _manager(user, auth_p, auth_k, priv_p, priv_k) as mgr:
        value = await mgr.get(SYS_DESCR)
    assert b"Linux" in bytes(value)


@pytest.mark.parametrize("user,auth_p,auth_k,priv_p,priv_k", V3_USERS, ids=IDS)
async def test_v3_walk(user, auth_p, auth_k, priv_p, priv_k):
    async with _manager(user, auth_p, auth_k, priv_p, priv_k) as mgr:
        rows = [(oid, val) async for oid, val in mgr.walk("1.3.6.1.2.1.1")]
    assert len(rows) >= 7


async def test_v3_bulk_walk():
    user, auth_p, auth_k, priv_p, priv_k = V3_USERS[1]
    async with _manager(user, auth_p, auth_k, priv_p, priv_k) as mgr:
        rows = [(oid, val) async for oid, val in mgr.bulk_walk("1.3.6.1.2.1.2.2.1.2")]
    assert rows, "ifDescr should return at least the loopback interface"


async def test_v3_wrong_password_is_rejected():
    """A bad key must fail, not silently succeed."""
    from snmpkit.manager import SnmpError

    async with _manager(
        "authPrivAesUser", "SHA", "wrongpassword123", "AES", "privpass123456"
    ) as mgr:
        with pytest.raises(SnmpError):
            await mgr.get(SYS_DESCR)


@pytest.mark.parametrize("user,auth_p,auth_k,priv_p,priv_k", V3_USERS, ids=IDS)
async def test_concurrent_gets_on_one_manager(user, auth_p, auth_k, priv_p, priv_k):
    """v3 routes on msgID, so concurrent requests must not cross over."""
    oids = [
        "1.3.6.1.2.1.1.1.0",
        "1.3.6.1.2.1.1.4.0",
        "1.3.6.1.2.1.1.5.0",
        "1.3.6.1.2.1.1.6.0",
    ]
    async with _manager(user, auth_p, auth_k, priv_p, priv_k) as mgr:
        together = await asyncio.gather(*(mgr.get(oid) for oid in oids))
        apart = [await mgr.get(oid) for oid in oids]

    assert together == apart
    assert len(set(together)) > 1, "identical values would hide a mismatch"
