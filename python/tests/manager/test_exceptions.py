"""Unit Tests for manager exceptions."""

from snmpkit.manager.exceptions import (
    AuthenticationError,
    EndOfMibViewError,
    GenericError,
    NoSuchInstanceError,
    NoSuchObjectError,
    SnmpError,
    TimeoutError,
    UnreachableError,
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


class TestUnreachableError:
    """Tests for UnreachableError."""

    def test_inherits_snmp_error(self):
        """UnreachableError inherits from SnmpError."""
        err = UnreachableError("no route")
        assert isinstance(err, SnmpError)


class TestUnreachableFlag:
    """Tests for the unreachable flag that drives online/offline faults."""

    def test_device_down_errors_are_unreachable(self):
        """Failures meaning the device never answered set unreachable."""
        assert TimeoutError("t").unreachable is True
        assert UnreachableError("u").unreachable is True

    def test_device_answered_errors_are_not_unreachable(self):
        """A device that answered is online, even if the object is missing."""
        assert NoSuchObjectError("n").unreachable is False
        assert NoSuchInstanceError("n").unreachable is False
        assert EndOfMibViewError("n").unreachable is False
        assert GenericError(5, 1).unreachable is False

    def test_base_defaults_to_reachable(self):
        """An unclassified SnmpError must not report the device as down."""
        assert SnmpError("x").unreachable is False

    def test_every_exception_carries_the_flag(self):
        """Callers can branch on the flag without knowing the class."""
        for err in (
            SnmpError("x"),
            TimeoutError("x"),
            UnreachableError("x"),
            NoSuchObjectError("x"),
            NoSuchInstanceError("x"),
            EndOfMibViewError("x"),
            GenericError(1, 1),
        ):
            assert isinstance(err.unreachable, bool)


class TestAuthenticationError:
    """Tests for AuthenticationError."""

    def test_inherits_snmp_error(self):
        """A bad v3 key must be catchable as SnmpError."""
        err = AuthenticationError("authentication verification failed")
        assert isinstance(err, SnmpError)

    def test_is_not_unreachable(self):
        """The device answered; it just could not be verified."""
        assert AuthenticationError("x").unreachable is False


class TestAuthFailedFlag:
    """Tests for the flag that separates bad credentials from an offline device."""

    def test_only_authentication_error_sets_auth_failed(self):
        """A device with wrong credentials is up, but yields no data."""
        assert AuthenticationError("x").auth_failed is True
        assert AuthenticationError("x").unreachable is False

    def test_other_errors_do_not_set_auth_failed(self):
        for err in (
            SnmpError("x"),
            TimeoutError("x"),
            UnreachableError("x"),
            NoSuchObjectError("x"),
            GenericError(1, 1),
        ):
            assert err.auth_failed is False
