"""Tests for MIB name resolution wired into the Manager."""

from pathlib import Path

import pytest
from snmpkit.core import Value
from snmpkit.manager import Manager
from snmpkit.mib import MibTree

SMIV2 = Path(__file__).resolve().parents[3] / "tests" / "mibs" / "smiv2"


@pytest.fixture(scope="module")
def tree() -> MibTree:
    loaded = MibTree()
    loaded.load_dir(str(SMIV2))
    return loaded


@pytest.fixture
def mgr(tree: MibTree) -> Manager:
    return Manager("192.0.2.1", community="public", mib=tree)


class TestResolve:
    """Tests for turning MIB names into numeric OIDs."""

    def test_bare_name(self, mgr: Manager):
        assert mgr.resolve("sysUpTime") == "1.3.6.1.2.1.1.3"

    def test_name_with_instance_suffix(self, mgr: Manager):
        assert mgr.resolve("sysUpTime.0") == "1.3.6.1.2.1.1.3.0"
        assert mgr.resolve("ifDescr.3") == "1.3.6.1.2.1.2.2.1.2.3"

    def test_module_qualified_name(self, mgr: Manager):
        assert mgr.resolve("IF-MIB::ifDescr") == "1.3.6.1.2.1.2.2.1.2"
        assert mgr.resolve("IF-MIB::ifDescr.1") == "1.3.6.1.2.1.2.2.1.2.1"

    def test_numeric_oid_passes_through(self, mgr: Manager):
        assert mgr.resolve("1.3.6.1.2.1.1.3.0") == "1.3.6.1.2.1.1.3.0"
        assert mgr.resolve(".1.3.6.1.2.1.1.3") == ".1.3.6.1.2.1.1.3"

    def test_unknown_name_raises(self, mgr: Manager):
        with pytest.raises(ValueError, match="not in the loaded MIBs"):
            mgr.resolve("noSuchObjectAnywhere")

    @pytest.mark.parametrize("bad", ["ifDescr.ifIndex", "sysUpTime.0.extra", "ifDescr.1.x"])
    def test_non_numeric_instance_suffix_raises(self, mgr: Manager, bad: str):
        with pytest.raises(ValueError, match="must be numeric"):
            mgr.resolve(bad)

    def test_unicode_digits_are_not_treated_as_numeric(self, mgr: Manager):
        # str.isdigit() alone accepts these, which would pass garbage through.
        with pytest.raises(ValueError):
            mgr.resolve("\u00b2bogus")

    def test_empty_oid_raises(self, mgr: Manager):
        with pytest.raises(ValueError, match="empty"):
            mgr.resolve("   ")

    def test_without_a_mib_everything_passes_through(self):
        plain = Manager("192.0.2.1", community="public")
        assert plain.resolve("sysUpTime") == "sysUpTime"
        assert plain.resolve("1.3.6.1.2.1.1.3.0") == "1.3.6.1.2.1.1.3.0"


class TestTranslateAndFormat:
    """Tests for naming and rendering values on the way back out."""

    def test_translate_keeps_the_instance(self, mgr: Manager):
        assert mgr.translate("1.3.6.1.2.1.2.2.1.2.3") == "IF-MIB::ifDescr.3"

    def test_translate_returns_input_when_unknown(self, mgr: Manager):
        assert mgr.translate("9.9.9.9") == "9.9.9.9"

    def test_format_applies_the_enum(self, mgr: Manager):
        assert mgr.format("1.3.6.1.2.1.2.2.1.7.1", Value.Integer(1)) == "up"

    def test_format_accepts_a_name(self, mgr: Manager):
        assert mgr.format("ifOperStatus.1", Value.Integer(2)) == "down"

    def test_format_applies_the_display_hint(self, mgr: Manager):
        mac = Value.OctetString(bytes([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]))
        assert mgr.format("ifPhysAddress.1", mac) == "00:1a:2b:3c:4d:5e"

    def test_format_without_a_mib_is_str(self):
        plain = Manager("192.0.2.1", community="public")
        assert plain.format("1.3.6.1.2.1.1.3.0", Value.Integer(1)) == str(Value.Integer(1))
