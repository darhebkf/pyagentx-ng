"""SNMP Manager exceptions."""


class SnmpError(Exception):
    """Base SNMP error."""


class TimeoutError(SnmpError):
    """Request timed out."""


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
