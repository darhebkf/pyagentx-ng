"""Tests for snmpkit core functionality."""

import pytest
import snmpkit
from snmpkit.core import Value


def test_version():
    """Test that version is exposed."""
    assert snmpkit.__version__ == "1.7.0"


def test_import():
    """Test that package can be imported."""
    assert snmpkit is not None


class TestValueInt:
    def test_integer(self):
        assert int(Value.Integer(42)) == 42

    def test_counter32(self):
        assert int(Value.Counter32(100)) == 100

    def test_gauge32(self):
        assert int(Value.Gauge32(99)) == 99

    def test_timeticks(self):
        assert int(Value.TimeTicks(500)) == 500

    def test_counter64(self):
        assert int(Value.Counter64(2**40)) == 2**40

    def test_octetstring_raises(self):
        with pytest.raises(TypeError):
            int(Value.OctetString(b"hello"))

    def test_null_raises(self):
        with pytest.raises(TypeError):
            int(Value.Null())


class TestValueFloat:
    def test_integer(self):
        assert float(Value.Integer(42)) == 42.0

    def test_counter32(self):
        assert float(Value.Counter32(100)) == 100.0

    def test_octetstring_raises(self):
        with pytest.raises(TypeError):
            float(Value.OctetString(b"hello"))


class TestValueBytes:
    def test_octetstring(self):
        assert bytes(Value.OctetString(b"hello")) == b"hello"

    def test_opaque(self):
        assert bytes(Value.Opaque(b"\x01\x02")) == b"\x01\x02"

    def test_integer_raises(self):
        with pytest.raises(TypeError):
            bytes(Value.Integer(42))


class TestValueBool:
    def test_integer_truthy(self):
        assert bool(Value.Integer(1)) is True

    def test_integer_zero_truthy(self):
        # Even Integer(0) is truthy — it's a valid value, not an exception
        assert bool(Value.Integer(0)) is True

    def test_null_falsy(self):
        assert bool(Value.Null()) is False

    def test_no_such_object_falsy(self):
        assert bool(Value.NoSuchObject()) is False

    def test_no_such_instance_falsy(self):
        assert bool(Value.NoSuchInstance()) is False

    def test_end_of_mib_view_falsy(self):
        assert bool(Value.EndOfMibView()) is False


class TestValueHash:
    def test_equal_values_same_hash(self):
        assert hash(Value.Integer(42)) == hash(Value.Integer(42))

    def test_usable_in_set(self):
        s = {Value.Integer(1), Value.Integer(1), Value.Integer(2)}
        assert len(s) == 2

    def test_exception_values_in_set(self):
        s = {Value.NoSuchObject(), Value.NoSuchInstance(), Value.EndOfMibView()}
        assert len(s) == 3


class TestValueArithmetic:
    """Verify Value works with Python arithmetic via __int__/__float__."""

    def test_division(self):
        v = Value.Integer(550)
        assert int(v) / 10 == 55.0

    def test_round(self):
        v = Value.Integer(1234)
        assert round(int(v) / 100, 2) == 12.34
