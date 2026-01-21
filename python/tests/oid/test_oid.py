"""Unit Tests for OID operations via Rust bindings."""

import pytest
from snmpkit.core import Oid


class TestOidParsing:
    """Tests for OID string parsing."""

    def test_parse_basic(self):
        """Parse a simple OID string."""
        oid = Oid("1.3.6.1")
        assert str(oid) == "1.3.6.1"
        assert oid.parts == [1, 3, 6, 1]

    def test_parse_leading_dot(self):
        """Parse OID with leading dot."""
        oid = Oid(".1.3.6.1")
        assert str(oid) == "1.3.6.1"

    def test_parse_long_oid(self):
        """Parse a long OID (enterprise)."""
        oid = Oid("1.3.6.1.4.1.27108.3.1.1")
        assert len(oid) == 10
        assert oid.parts == [1, 3, 6, 1, 4, 1, 27108, 3, 1, 1]

    def test_parse_single_part(self):
        """Parse single-part OID."""
        oid = Oid("1")
        assert str(oid) == "1"
        assert len(oid) == 1

    def test_parse_empty_raises(self):
        """Empty string should raise ValueError."""
        with pytest.raises(ValueError, match="empty"):
            Oid("")

    def test_parse_invalid_part_raises(self):
        """Invalid part should raise ValueError."""
        with pytest.raises(ValueError, match="invalid"):
            Oid("1.3.abc.1")

    def test_parse_negative_raises(self):
        """Negative numbers should raise ValueError."""
        with pytest.raises(ValueError):
            Oid("1.3.-6.1")

    def test_parse_whitespace_stripped(self):
        """Whitespace should be stripped."""
        oid = Oid("  1.3.6.1  ")
        assert str(oid) == "1.3.6.1"


class TestOidComparison:
    """Tests for OID comparison operations."""

    def test_equal(self):
        """Equal OIDs compare equal."""
        oid1 = Oid("1.3.6.1")
        oid2 = Oid("1.3.6.1")
        assert oid1 == oid2

    def test_not_equal(self):
        """Different OIDs compare not equal."""
        oid1 = Oid("1.3.6.1")
        oid2 = Oid("1.3.6.2")
        assert oid1 != oid2

    def test_less_than_same_length(self):
        """Lexicographic comparison for same length."""
        oid1 = Oid("1.3.6.1")
        oid2 = Oid("1.3.6.2")
        assert oid1 < oid2
        assert not oid2 < oid1

    def test_less_than_different_length(self):
        """Shorter OID is less than longer with same prefix."""
        oid1 = Oid("1.3.6.1")
        oid2 = Oid("1.3.6.1.1")
        assert oid1 < oid2

    def test_greater_than(self):
        """Greater than comparison."""
        oid1 = Oid("1.3.6.2")
        oid2 = Oid("1.3.6.1")
        assert oid1 > oid2

    def test_less_equal(self):
        """Less than or equal comparison."""
        oid1 = Oid("1.3.6.1")
        oid2 = Oid("1.3.6.1")
        oid3 = Oid("1.3.6.2")
        assert oid1 <= oid2
        assert oid1 <= oid3

    def test_greater_equal(self):
        """Greater than or equal comparison."""
        oid1 = Oid("1.3.6.2")
        oid2 = Oid("1.3.6.2")
        oid3 = Oid("1.3.6.1")
        assert oid1 >= oid2
        assert oid1 >= oid3

    def test_lexicographic_ordering(self):
        """Verify proper lexicographic ordering (1.10 > 1.2)."""
        oid1 = Oid("1.2")
        oid2 = Oid("1.10")
        # Numeric comparison: 1.10 > 1.2
        assert oid2 > oid1

    def test_sorting(self):
        """OIDs should sort in lexicographic order."""
        oids = [
            Oid("1.3.6.1.10"),
            Oid("1.3.6.1.2"),
            Oid("1.3.6.1.1"),
            Oid("1.3.6.2"),
        ]
        sorted_oids = sorted(oids)
        assert [str(o) for o in sorted_oids] == [
            "1.3.6.1.1",
            "1.3.6.1.2",
            "1.3.6.1.10",
            "1.3.6.2",
        ]


class TestOidMethods:
    """Tests for OID instance methods."""

    def test_len(self):
        """Length returns number of parts."""
        oid = Oid("1.3.6.1.4.1")
        assert len(oid) == 6

    def test_parts(self):
        """Parts returns list of integers."""
        oid = Oid("1.3.6.1")
        assert oid.parts == [1, 3, 6, 1]
        assert isinstance(oid.parts[0], int)

    def test_str(self):
        """String representation is dotted notation."""
        oid = Oid("1.3.6.1")
        assert str(oid) == "1.3.6.1"

    def test_repr(self):
        """Repr shows Oid constructor form."""
        oid = Oid("1.3.6.1")
        assert repr(oid) == "Oid('1.3.6.1')"

    def test_hash(self):
        """OIDs are hashable and equal OIDs have same hash."""
        oid1 = Oid("1.3.6.1")
        oid2 = Oid("1.3.6.1")
        oid3 = Oid("1.3.6.2")
        assert hash(oid1) == hash(oid2)
        # Different OIDs may have different hashes (not guaranteed but likely)
        assert hash(oid1) != hash(oid3) or oid1 != oid3

    def test_hash_in_set(self):
        """OIDs can be used in sets."""
        oids = {Oid("1.3.6.1"), Oid("1.3.6.1"), Oid("1.3.6.2")}
        assert len(oids) == 2

    def test_hash_in_dict(self):
        """OIDs can be used as dict keys."""
        d = {Oid("1.3.6.1"): "value1", Oid("1.3.6.2"): "value2"}
        assert d[Oid("1.3.6.1")] == "value1"


class TestOidPrefixMethods:
    """Tests for prefix/parent/child operations."""

    def test_starts_with_true(self):
        """OID starts with prefix."""
        oid = Oid("1.3.6.1.4.1.27108")
        prefix = Oid("1.3.6.1")
        assert oid.starts_with(prefix)

    def test_starts_with_false(self):
        """OID does not start with different prefix."""
        oid = Oid("1.3.6.1.4.1")
        prefix = Oid("1.3.6.2")
        assert not oid.starts_with(prefix)

    def test_starts_with_self(self):
        """OID starts with itself."""
        oid = Oid("1.3.6.1")
        assert oid.starts_with(oid)

    def test_starts_with_longer_prefix(self):
        """OID doesn't start with longer OID."""
        oid = Oid("1.3.6.1")
        longer = Oid("1.3.6.1.4.1")
        assert not oid.starts_with(longer)

    def test_is_parent_of_true(self):
        """Parent is parent of child."""
        parent = Oid("1.3.6.1")
        child = Oid("1.3.6.1.4")
        assert parent.is_parent_of(child)

    def test_is_parent_of_false_sibling(self):
        """OID is not parent of sibling."""
        oid1 = Oid("1.3.6.1")
        oid2 = Oid("1.3.6.2")
        assert not oid1.is_parent_of(oid2)

    def test_is_parent_of_false_self(self):
        """OID is not parent of itself."""
        oid = Oid("1.3.6.1")
        assert not oid.is_parent_of(oid)

    def test_is_parent_of_false_reverse(self):
        """Child is not parent of parent."""
        parent = Oid("1.3.6.1")
        child = Oid("1.3.6.1.4")
        assert not child.is_parent_of(parent)

    def test_parent(self):
        """Parent returns OID without last part."""
        oid = Oid("1.3.6.1.4")
        parent = oid.parent()
        assert parent is not None
        assert str(parent) == "1.3.6.1"

    def test_parent_of_single_part(self):
        """Single-part OID has no parent."""
        oid = Oid("1")
        assert oid.parent() is None

    def test_child(self):
        """Child appends a sub-identifier."""
        oid = Oid("1.3.6.1")
        child = oid.child(4)
        assert str(child) == "1.3.6.1.4"

    def test_child_chain(self):
        """Multiple child calls chain correctly."""
        oid = Oid("1.3.6")
        result = oid.child(1).child(4).child(1)
        assert str(result) == "1.3.6.1.4.1"


class TestOidEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_large_sub_identifier(self):
        """Large sub-identifiers are supported."""
        oid = Oid("1.3.6.1.4.1.2147483647")
        assert oid.parts[-1] == 2147483647

    def test_zero_sub_identifier(self):
        """Zero is a valid sub-identifier."""
        oid = Oid("1.3.6.0.0.0")
        assert oid.parts == [1, 3, 6, 0, 0, 0]

    def test_many_parts(self):
        """OID with many parts works correctly."""
        parts = ".".join(str(i) for i in range(1, 129))
        oid = Oid(parts)
        assert len(oid) == 128

    def test_copy_independence(self):
        """Parts list is a copy, modifications don't affect OID."""
        oid = Oid("1.3.6.1")
        parts = oid.parts
        parts.append(999)
        # Original OID should be unchanged
        assert len(oid) == 4
        assert 999 not in oid.parts
