"""Unit Tests for manager exceptions."""

from snmpkit.manager.exceptions import (
    EndOfMibViewError,
    GenericError,
    NoSuchInstanceError,
    NoSuchObjectError,
    SnmpError,
    TimeoutError,
)


class TestSnmpError:
    """Tests for SnmpError base class."""

    def test_base_exception(self):
        """SnmpError is a base Exception."""
        err = SnmpError("test error")
        assert isinstance(err, Exception)
        assert str(err) == "test error"


class TestTimeoutError:
    """Tests for TimeoutError."""

    def test_inherits_snmp_error(self):
        """TimeoutError inherits from SnmpError."""
        err = TimeoutError("timed out")
        assert isinstance(err, SnmpError)


class TestNoSuchObjectError:
    """Tests for NoSuchObjectError."""

    def test_inherits_snmp_error(self):
        """NoSuchObjectError inherits from SnmpError."""
        err = NoSuchObjectError("not found")
        assert isinstance(err, SnmpError)


class TestNoSuchInstanceError:
    """Tests for NoSuchInstanceError."""

    def test_inherits_snmp_error(self):
        """NoSuchInstanceError inherits from SnmpError."""
        err = NoSuchInstanceError("not found")
        assert isinstance(err, SnmpError)


class TestEndOfMibViewError:
    """Tests for EndOfMibViewError."""

    def test_inherits_snmp_error(self):
        """EndOfMibViewError inherits from SnmpError."""
        err = EndOfMibViewError("end of mib")
        assert isinstance(err, SnmpError)


class TestGenericError:
    """Tests for GenericError."""

    def test_inherits_snmp_error(self):
        """GenericError inherits from SnmpError."""
        err = GenericError(2, 1)
        assert isinstance(err, SnmpError)

    def test_stores_status_and_index(self):
        """GenericError stores status and index."""
        err = GenericError(5, 3)
        assert err.status == 5
        assert err.index == 3

    def test_message_format(self):
        """GenericError formats message correctly."""
        err = GenericError(2, 1)
        assert "status=2" in str(err)
        assert "index=1" in str(err)
