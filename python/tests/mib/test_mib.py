"""Tests for the MIB tree via Rust bindings."""

from pathlib import Path

import pytest
from snmpkit.core import Value
from snmpkit.mib import MibNode, MibTree

MIBS = Path(__file__).resolve().parents[3] / "tests" / "mibs"
SMIV2 = MIBS / "smiv2"
SMIV1 = MIBS / "smiv1"
BROKEN = MIBS / "broken"


@pytest.fixture(scope="module")
def tree() -> MibTree:
    """The published SMIv2 modules."""
    loaded = MibTree()
    loaded.load_dir(str(SMIV2))
    return loaded


class TestLoading:
    """Tests for getting MIB text into a tree."""

    def test_load_dir_returns_module_count(self):
        tree = MibTree()
        assert tree.load_dir(str(SMIV2)) == 6
        assert set(tree.modules) == {
            "SNMPv2-SMI",
            "SNMPv2-TC",
            "SNMPv2-CONF",
            "SNMPv2-MIB",
            "IF-MIB",
            "IANAifType-MIB",
        }

    def test_load_dir_recurses_by_default(self):
        tree = MibTree()
        assert tree.load_dir(str(MIBS)) == 9

    def test_load_dir_without_recursion_finds_nothing(self):
        tree = MibTree()
        assert tree.load_dir(str(MIBS), recursive=False) == 0

    def test_load_file(self):
        tree = MibTree()
        assert tree.load_file(str(SMIV2 / "SNMPv2-SMI")) == 1
        assert tree.modules == ["SNMPv2-SMI"]

    def test_load_str(self):
        tree = MibTree()
        count = tree.load_str(
            "TEST-MIB DEFINITIONS ::= BEGIN\nwidget OBJECT IDENTIFIER ::= { iso 42 }\nEND"
        )
        assert count == 1
        assert tree.lookup("widget").oid == "1.42"

    def test_load_file_on_a_missing_path_raises(self):
        with pytest.raises(ValueError, match="not a file"):
            MibTree().load_file(str(MIBS / "NO-SUCH-MIB"))

    def test_load_dir_on_a_missing_path_raises(self):
        with pytest.raises(ValueError, match="not a directory"):
            MibTree().load_dir(str(MIBS / "nowhere"))

    def test_load_str_on_garbage_finds_no_modules(self):
        assert MibTree().load_str("this is not a MIB at all") == 0

    def test_the_published_modules_load_without_diagnostics(self, tree: MibTree):
        assert tree.diagnostics == []


class TestLookup:
    """Tests for resolving names and OIDs."""

    def test_sys_up_time_resolves_name_to_oid_to_name(self, tree: MibTree):
        node = tree.lookup("sysUpTime")
        assert node.oid == "1.3.6.1.2.1.1.3"
        assert node.module == "SNMPv2-MIB"
        assert tree.lookup(node.oid).name == "sysUpTime"

    def test_lookup_accepts_a_leading_dot(self, tree: MibTree):
        assert tree.lookup(".1.3.6.1.2.1.1.3").name == "sysUpTime"

    def test_lookup_accepts_a_module_qualifier(self, tree: MibTree):
        assert tree.lookup("IF-MIB::ifDescr").oid == "1.3.6.1.2.1.2.2.1.2"

    def test_lookup_returns_none_when_unknown(self, tree: MibTree):
        assert tree.lookup("noSuchObjectAnywhere") is None

    def test_getitem_raises_key_error_when_unknown(self, tree: MibTree):
        with pytest.raises(KeyError):
            tree["noSuchObjectAnywhere"]

    def test_contains_and_len(self, tree: MibTree):
        assert "ifDescr" in tree
        assert "noSuchObjectAnywhere" not in tree
        assert len(tree) > 140

    def test_translate_keeps_the_instance_suffix(self, tree: MibTree):
        assert tree.translate(".1.3.6.1.2.1.2.2.1.2.3") == "IF-MIB::ifDescr.3"
        assert tree.translate("1.3.6.1.2.1.1.3.0") == "SNMPv2-MIB::sysUpTime.0"

    def test_translate_returns_none_for_an_unrooted_oid(self, tree: MibTree):
        assert tree.translate("9.9.9.9") is None


class TestMetadata:
    """Tests for what an object carries beyond its OID."""

    def test_syntax_and_base_type(self, tree: MibTree):
        node = tree["ifIndex"]
        assert node.syntax == "InterfaceIndex"
        assert node.base_type == "Integer32"

    def test_access_and_status(self, tree: MibTree):
        assert tree["ifDescr"].max_access == "read-only"
        assert tree["ifDescr"].status == "current"
        assert tree["ifAdminStatus"].max_access == "read-write"

    def test_description(self, tree: MibTree):
        assert "unique value" in tree["ifIndex"].description

    def test_kind(self, tree: MibTree):
        assert tree["ifTable"].kind == "table"
        assert tree["ifEntry"].kind == "row"
        assert tree["ifDescr"].kind == "column"
        assert tree["ifNumber"].kind == "scalar"
        assert tree["linkDown"].kind == "notification"
        assert tree["mib-2"].kind == "node"

    def test_notification_objects(self, tree: MibTree):
        assert "ifIndex" in tree["linkDown"].objects

    def test_str_and_repr(self, tree: MibTree):
        node = tree["ifDescr"]
        assert str(node) == "IF-MIB::ifDescr"
        assert repr(node) == "MibNode(IF-MIB::ifDescr, 1.3.6.1.2.1.2.2.1.2)"


class TestTables:
    """Tests for conceptual table detection (RFC 2578 §7.1.12)."""

    def test_if_table_row_type_and_index(self, tree: MibTree):
        table = tree["ifTable"]
        assert table.is_table
        assert table.row_type == "IfEntry"

        row = tree["ifEntry"]
        assert row.is_row
        assert row.index == ["ifIndex"]
        assert not row.implied

    def test_columns_are_reachable_from_the_table_and_the_row(self, tree: MibTree):
        from_table = [c.name for c in tree["ifTable"].columns]
        from_row = [c.name for c in tree["ifEntry"].columns]
        assert from_table == from_row
        assert len(from_table) == 22
        assert from_table[:3] == ["ifIndex", "ifDescr", "ifType"]

    def test_augmenting_row_inherits_its_index(self, tree: MibTree):
        row = tree["ifXEntry"]
        assert row.augments == "ifEntry"
        assert row.index == ["ifIndex"]

    def test_a_scalar_has_no_columns(self, tree: MibTree):
        assert tree["sysUpTime"].columns == []


class TestEnumsAndFormatting:
    """Tests for turning a raw value into what a user should see."""

    def test_enum_labels_survive(self, tree: MibTree):
        assert tree["ifAdminStatus"].enums == {"up": 1, "down": 2, "testing": 3}

    def test_enums_are_none_when_not_enumerated(self, tree: MibTree):
        assert tree["ifMtu"].enums is None

    def test_enum_name_and_value(self, tree: MibTree):
        node = tree["ifOperStatus"]
        assert node.enum_name(1) == "up"
        assert node.enum_value("down") == 2
        assert node.enum_name(999) is None
        assert node.enum_value("sideways") is None

    def test_enums_come_through_a_textual_convention(self, tree: MibTree):
        enums = tree["ifType"].enums
        assert enums["ethernetCsmacd"] == 6
        assert len(enums) > 200

    def test_format_uses_the_enum_label(self, tree: MibTree):
        assert tree["ifAdminStatus"].format(1) == "up"
        assert tree["ifOperStatus"].format(2) == "down"

    def test_format_falls_back_to_the_number_for_an_unknown_label(self, tree: MibTree):
        assert tree["ifAdminStatus"].format(97) == "97"

    def test_display_hint_is_inherited_from_the_textual_convention(self, tree: MibTree):
        assert tree["ifPhysAddress"].display_hint == "1x:"
        assert tree["sysDescr"].display_hint == "255a"

    def test_format_applies_the_display_hint(self, tree: MibTree):
        mac = bytes([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E])
        assert tree["ifPhysAddress"].format(mac) == "00:1a:2b:3c:4d:5e"
        assert tree["sysDescr"].format(b"Linux router") == "Linux router"

    def test_format_accepts_a_value(self, tree: MibTree):
        assert tree["ifAdminStatus"].format(Value.Integer(1)) == "up"
        assert tree["sysDescr"].format(Value.OctetString(b"router")) == "router"

    def test_format_rejects_something_it_cannot_render(self, tree: MibTree):
        with pytest.raises(TypeError):
            tree["sysDescr"].format(object())

    def test_integer_display_hint_with_implied_decimals(self):
        tree = MibTree()
        tree.load_str("""
            HINT-MIB DEFINITIONS ::= BEGIN
            Centidegrees ::= TEXTUAL-CONVENTION
                DISPLAY-HINT "d-2"
                STATUS       current
                DESCRIPTION  "Degrees to two decimal places."
                SYNTAX       INTEGER
            temperature OBJECT-TYPE
                SYNTAX      Centidegrees
                MAX-ACCESS  read-only
                STATUS      current
                DESCRIPTION "The temperature."
                ::= { iso 42 }
            END
        """)
        node = tree["temperature"]
        assert node.display_hint == "d-2"
        assert node.format(2350) == "23.50"
        assert node.format(-125) == "-1.25"


class TestNavigation:
    """Tests for walking the tree."""

    def test_parent_and_children(self, tree: MibTree):
        entry = tree["ifEntry"]
        assert entry.parent.name == "ifTable"
        assert [c.name for c in entry.children][:2] == ["ifIndex", "ifDescr"]

    def test_roots(self, tree: MibTree):
        assert [r.name for r in tree.roots] == ["ccitt", "iso", "joint-iso-ccitt"]

    def test_children_by_key(self, tree: MibTree):
        assert [c.name for c in tree.children("ifTable")] == ["ifEntry"]

    def test_children_of_an_unknown_key_raises(self, tree: MibTree):
        with pytest.raises(KeyError):
            tree.children("noSuchObjectAnywhere")

    def test_walk_a_subtree(self, tree: MibTree):
        names = [n.name for n in tree.walk("ifTable")]
        assert names[0] == "ifTable"
        assert names[1] == "ifEntry"
        assert len(names) == 24
        assert "ifOutQLen" in names

    def test_walk_the_whole_tree(self, tree: MibTree):
        walked = tree.walk()
        assert len(walked) == len(tree)
        assert len({n.oid for n in walked}) == len(walked)

    def test_walked_nodes_are_mib_nodes(self, tree: MibTree):
        assert isinstance(tree.walk("ifTable")[0], MibNode)


class TestSmiV1:
    """Tests for SMIv1 modules (RFC 1155, RFC 1212)."""

    @staticmethod
    @pytest.fixture(scope="class")
    def v1() -> MibTree:
        loaded = MibTree()
        loaded.load_dir(str(SMIV1))
        return loaded

    def test_smiv1_root_path_resolves(self, v1: MibTree):
        assert v1["internet"].oid == "1.3.6.1"
        assert v1["enterprises"].oid == "1.3.6.1.4.1"

    def test_smiv1_access_and_status_keywords(self, v1: MibTree):
        node = v1["sysDescr"]
        assert node.oid == "1.3.6.1.2.1.1.1"
        assert node.max_access == "read-only"
        assert node.status == "mandatory"

    def test_smiv1_counter_and_gauge_are_base_types(self, v1: MibTree):
        assert v1["ifInOctets"].base_type == "Counter32"
        assert v1["ifSpeed"].base_type == "Gauge32"

    def test_smiv1_tables_are_detected(self, v1: MibTree):
        assert v1["ipAddrTable"].is_table
        assert v1["ipAddrEntry"].index == ["ipAdEntAddr"]


class TestErrorRecovery:
    """Tests that a bad MIB loads with diagnostics rather than failing."""

    @staticmethod
    @pytest.fixture(scope="class")
    def damaged() -> MibTree:
        loaded = MibTree()
        loaded.load_dir(str(SMIV2))
        loaded.load_dir(str(BROKEN))
        return loaded

    def test_good_definitions_survive_the_damage(self, damaged: MibTree):
        assert damaged["goodScalarOne"].oid == "1.3.6.1.4.1.99999.1"
        assert damaged["goodScalarTwo"].oid == "1.3.6.1.4.1.99999.9"
        assert damaged["goodScalarTwo"].base_type == "OCTET STRING"

    def test_unparsable_definitions_are_dropped(self, damaged: MibTree):
        assert damaged.lookup("nonsenseMacro") is None
        assert damaged.lookup("orphan") is None
        assert damaged.lookup("loopA") is None

    def test_bad_keywords_are_reported_but_the_object_loads(self, damaged: MibTree):
        assert damaged.lookup("badAccess") is not None
        assert damaged.lookup("badStatus") is not None

    @pytest.mark.parametrize(
        "expected",
        ["nonsenseMacro", "read-sideways", "lukewarm", "neverDefinedAnywhere"],
    )
    def test_each_problem_is_reported(self, damaged: MibTree, expected: str):
        assert any(expected in line for line in damaged.diagnostics)

    def test_diagnostics_name_the_module_and_line(self, damaged: MibTree):
        assert any(line.startswith("BROKEN-MIB:") for line in damaged.diagnostics)
