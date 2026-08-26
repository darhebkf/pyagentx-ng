"""v2c against a real agent, including the MIB layer end to end."""

from snmpkit.manager import Manager, NoSuchObjectError
from snmpkit.mib import MibTree

from ._config import COMMUNITY, HOST, MIB_DIR, PORT, SYS_DESCR


async def test_get_returns_the_agents_sysdescr():
    async with Manager(HOST, port=PORT, community=COMMUNITY) as mgr:
        value = await mgr.get(SYS_DESCR)
    assert b"Linux" in bytes(value)


async def test_walk_returns_the_system_group():
    async with Manager(HOST, port=PORT, community=COMMUNITY) as mgr:
        rows = [(oid, val) async for oid, val in mgr.walk("1.3.6.1.2.1.1")]
    assert len(rows) >= 7
    assert any(oid.startswith("1.3.6.1.2.1.1.1") for oid, _ in rows)


async def test_get_table_returns_interfaces():
    async with Manager(HOST, port=PORT, community=COMMUNITY) as mgr:
        table = await mgr.get_table("1.3.6.1.2.1.2.2.1")
    assert table, "ifTable should have at least the loopback interface"
    first = next(iter(table.values()))
    assert 2 in first, "column 2 is ifDescr"


async def test_missing_oid_is_not_unreachable():
    """The distinction an online/offline fault depends on."""
    async with Manager(HOST, port=PORT, community=COMMUNITY) as mgr:
        try:
            await mgr.get("1.3.6.1.4.1.99999.42.42.0")
        except NoSuchObjectError as e:
            assert e.unreachable is False
        else:
            raise AssertionError("expected NoSuchObjectError")


async def test_query_by_mib_name_against_the_real_agent():
    tree = MibTree()
    tree.load_dir(MIB_DIR)

    async with Manager(HOST, port=PORT, community=COMMUNITY, mib=tree) as mgr:
        descr = await mgr.get("sysDescr.0")
        assert b"Linux" in bytes(descr)

        named = [
            (mgr.translate(oid), mgr.format(oid, val)) async for oid, val in mgr.walk("ifDescr")
        ]

    assert named, "the agent should report at least one interface"
    assert all(name.startswith("IF-MIB::ifDescr.") for name, _ in named)
    assert any(value == "lo" for _, value in named)
