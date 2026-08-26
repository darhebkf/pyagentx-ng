"""SNMP Manager exceptions."""


class SnmpError(Exception):
    """Base SNMP error."""

    unreachable: bool = False

    # Device is reachable, but credentials are wrong.
    auth_failed: bool = False


class TimeoutError(SnmpError):
    """Request timed out."""

    unreachable = True


class UnreachableError(SnmpError):
    """Device could not be reached: DNS failure, refused, or no route."""

    unreachable = True


class AuthenticationError(SnmpError):
    """SNMPv3 authentication or decryption failed.

    Not unreachable: the device answered, the response just could not be
    verified or decrypted with the supplied credentials.
    """

    auth_failed = True


class NoSuchObjectError(SnmpError):
    """OID does not exist."""


class NoSuchInstanceError(SnmpError):
    """Instance does not exist."""


class EndOfMibViewError(SnmpError):
    """End of MIB view reached."""


class GenericError(SnmpError):
    """Generic SNMP error with error-status code."""

    def __init__(self, status: int, index: int) -> None:
        self.status = status
        self.index = index
        super().__init__(f"SNMP error: status={status}, index={index}")
