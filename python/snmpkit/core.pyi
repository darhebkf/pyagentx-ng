"""Type stubs for snmpkit.core (Rust extension module)."""

from typing import Final

__version__: str
HEADER_SIZE: Final[int]

class Oid:
    def __init__(self, s: str) -> None: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __lt__(self, other: Oid) -> bool: ...
    def __le__(self, other: Oid) -> bool: ...
    def __gt__(self, other: Oid) -> bool: ...
    def __ge__(self, other: Oid) -> bool: ...
    @property
    def parts(self) -> list[int]: ...
    def starts_with(self, prefix: Oid) -> bool: ...
    def is_parent_of(self, other: Oid) -> bool: ...
    def parent(self) -> Oid | None: ...
    def child(self, sub_id: int) -> Oid: ...

class Value:
    Integer: type[Value]
    OctetString: type[Value]
    Null: type[Value]
    ObjectIdentifier: type[Value]
    IpAddress: type[Value]
    Counter32: type[Value]
    Gauge32: type[Value]
    TimeTicks: type[Value]
    Opaque: type[Value]
    Counter64: type[Value]
    NoSuchObject: type[Value]
    NoSuchInstance: type[Value]
    EndOfMibView: type[Value]
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...
    def __int__(self) -> int: ...
    def __float__(self) -> float: ...
    def __bytes__(self) -> bytes: ...
    def __bool__(self) -> bool: ...

class VarBind:
    def __init__(self, oid: Oid, value: Value) -> None: ...
    @property
    def oid(self) -> Oid: ...
    @property
    def value(self) -> Value: ...

class AgentXHeader:
    @property
    def pdu_type(self) -> int: ...
    @property
    def flags(self) -> int: ...
    @property
    def session_id(self) -> int: ...
    @property
    def transaction_id(self) -> int: ...
    @property
    def packet_id(self) -> int: ...
    @property
    def payload_length(self) -> int: ...

class AgentXResponse:
    @property
    def sys_uptime(self) -> int: ...
    @property
    def error(self) -> int: ...
    @property
    def index(self) -> int: ...
    @property
    def varbinds(self) -> list[VarBind]: ...
    @property
    def is_error(self) -> bool: ...

class AgentXGet:
    @property
    def ranges(self) -> list[tuple[Oid, Oid, bool]]: ...

class AgentXGetBulk:
    @property
    def non_repeaters(self) -> int: ...
    @property
    def max_repetitions(self) -> int: ...
    @property
    def ranges(self) -> list[tuple[Oid, Oid, bool]]: ...

class AgentXTestSet:
    @property
    def varbinds(self) -> list[VarBind]: ...

class PduTypes:
    OPEN: Final[int]
    CLOSE: Final[int]
    REGISTER: Final[int]
    UNREGISTER: Final[int]
    GET: Final[int]
    GET_NEXT: Final[int]
    GET_BULK: Final[int]
    TEST_SET: Final[int]
    COMMIT_SET: Final[int]
    UNDO_SET: Final[int]
    CLEANUP_SET: Final[int]
    NOTIFY: Final[int]
    PING: Final[int]
    RESPONSE: Final[int]

class CloseReasons:
    OTHER: Final[int]
    PARSE_ERROR: Final[int]
    PROTOCOL_ERROR: Final[int]
    TIMEOUTS: Final[int]
    SHUTDOWN: Final[int]
    BY_MANAGER: Final[int]

class ResponseErrors:
    NO_ERROR: Final[int]
    OPEN_FAILED: Final[int]
    NOT_OPEN: Final[int]
    INDEX_WRONG_TYPE: Final[int]
    INDEX_ALREADY_ALLOCATED: Final[int]
    INDEX_NONE_AVAILABLE: Final[int]
    INDEX_NOT_ALLOCATED: Final[int]
    UNSUPPORTED_CONTEXT: Final[int]
    DUPLICATE_REGISTRATION: Final[int]
    UNKNOWN_REGISTRATION: Final[int]
    UNKNOWN_AGENT_CAPS: Final[int]
    PARSE_ERROR: Final[int]
    REQUEST_DENIED: Final[int]
    PROCESSING_ERROR: Final[int]

def encode_open_pdu(
    session_id: int,
    transaction_id: int,
    packet_id: int,
    timeout: int,
    oid: Oid,
    description: str,
) -> bytes: ...
def encode_close_pdu(
    session_id: int,
    transaction_id: int,
    packet_id: int,
    reason: int,
) -> bytes: ...
def encode_register_pdu(
    session_id: int,
    transaction_id: int,
    packet_id: int,
    subtree: Oid,
    priority: int,
    timeout: int,
    context: str | None = None,
) -> bytes: ...
def encode_unregister_pdu(
    session_id: int,
    transaction_id: int,
    packet_id: int,
    subtree: Oid,
    priority: int,
    context: str | None = None,
) -> bytes: ...
def encode_response_pdu(
    session_id: int,
    transaction_id: int,
    packet_id: int,
    sys_uptime: int,
    error: int,
    index: int,
    varbinds: list[VarBind],
) -> bytes: ...
def encode_notify_pdu(
    session_id: int,
    transaction_id: int,
    packet_id: int,
    varbinds: list[VarBind],
    context: str | None = None,
) -> bytes: ...
def encode_ping_pdu(
    session_id: int,
    transaction_id: int,
    packet_id: int,
) -> bytes: ...
def decode_header(data: bytes) -> AgentXHeader: ...
def decode_response_pdu(data: bytes, payload_len: int) -> AgentXResponse: ...
def decode_get_pdu(data: bytes, payload_len: int) -> AgentXGet: ...
def decode_getbulk_pdu(data: bytes, payload_len: int) -> AgentXGetBulk: ...
def decode_testset_pdu(data: bytes, payload_len: int) -> AgentXTestSet: ...

# SNMP Manager bindings

class SnmpVarBind:
    def __init__(self, oid: Oid, value: Value) -> None: ...
    @property
    def oid(self) -> Oid: ...
    @property
    def value(self) -> Value: ...
    def __repr__(self) -> str: ...

class SnmpResponse:
    @property
    def request_id(self) -> int: ...
    @property
    def error_status(self) -> int: ...
    @property
    def error_index(self) -> int: ...
    @property
    def varbinds(self) -> list[SnmpVarBind]: ...
    @property
    def is_error(self) -> bool: ...
    @property
    def error_message(self) -> str: ...
    def __repr__(self) -> str: ...

class SnmpVersion:
    V1: Final[int]
    V2C: Final[int]
    V3: Final[int]

class SnmpErrorStatus:
    NO_ERROR: Final[int]
    TOO_BIG: Final[int]
    NO_SUCH_NAME: Final[int]
    BAD_VALUE: Final[int]
    READ_ONLY: Final[int]
    GEN_ERR: Final[int]
    NO_ACCESS: Final[int]
    WRONG_TYPE: Final[int]
    WRONG_LENGTH: Final[int]
    WRONG_ENCODING: Final[int]
    WRONG_VALUE: Final[int]
    NO_CREATION: Final[int]
    INCONSISTENT_VALUE: Final[int]
    RESOURCE_UNAVAILABLE: Final[int]
    COMMIT_FAILED: Final[int]
    UNDO_FAILED: Final[int]
    AUTHORIZATION_ERROR: Final[int]
    NOT_WRITABLE: Final[int]
    INCONSISTENT_NAME: Final[int]

def encode_snmp_get_v1(
    community: str,
    request_id: int,
    oids: list[Oid],
) -> bytes: ...
def encode_snmp_getnext_v1(
    community: str,
    request_id: int,
    oids: list[Oid],
) -> bytes: ...
def encode_snmp_get_v2c(
    community: str,
    request_id: int,
    oids: list[Oid],
) -> bytes: ...
def encode_snmp_getnext_v2c(
    community: str,
    request_id: int,
    oids: list[Oid],
) -> bytes: ...
def encode_snmp_getbulk_v2c(
    community: str,
    request_id: int,
    non_repeaters: int,
    max_repetitions: int,
    oids: list[Oid],
) -> bytes: ...
def encode_snmp_set_v2c(
    community: str,
    request_id: int,
    varbinds: list[SnmpVarBind],
) -> bytes: ...
def encode_snmp_get_v3(
    msg_id: int,
    request_id: int,
    oids: list[Oid],
    engine_id: bytes,
    engine_boots: int,
    engine_time: int,
    user_name: str,
    auth: bool = False,
    priv_: bool = False,
) -> bytes: ...
def encode_snmp_getbulk_v3(
    msg_id: int,
    request_id: int,
    non_repeaters: int,
    max_repetitions: int,
    oids: list[Oid],
    engine_id: bytes,
    engine_boots: int,
    engine_time: int,
    user_name: str,
    auth: bool = False,
    priv_: bool = False,
) -> bytes: ...
def decode_snmp_response(data: bytes) -> SnmpResponse: ...
def peek_correlation_id(data: bytes) -> int: ...

# SNMPv1 Trap

def encode_snmp_trap_v1(
    community: str,
    enterprise: str,
    agent_addr: tuple[int, int, int, int],
    generic_trap: int,
    specific_trap: int,
    timestamp: int,
    varbinds: list[SnmpVarBind],
) -> bytes: ...

# Trap/Inform/Response v2c

def encode_snmp_trap_v2c(
    community: str,
    request_id: int,
    varbinds: list[SnmpVarBind],
) -> bytes: ...
def encode_snmp_inform_v2c(
    community: str,
    request_id: int,
    varbinds: list[SnmpVarBind],
) -> bytes: ...
def encode_snmp_response_v2c(
    community: str,
    request_id: int,
    error_status: int,
    error_index: int,
    varbinds: list[SnmpVarBind],
) -> bytes: ...

# SNMPv3 secure encode

def encode_snmp_get_v3_secure(
    msg_id: int,
    request_id: int,
    oids: list[Oid],
    engine_id: bytes,
    engine_boots: int,
    engine_time: int,
    user_name: str,
    context_name: bytes = b"",
    auth_protocol: str | None = None,
    auth_key: bytes | None = None,
    priv_protocol: str | None = None,
    priv_key: bytes | None = None,
) -> bytes: ...
def encode_snmp_getnext_v3_secure(
    msg_id: int,
    request_id: int,
    oids: list[Oid],
    engine_id: bytes,
    engine_boots: int,
    engine_time: int,
    user_name: str,
    context_name: bytes = b"",
    auth_protocol: str | None = None,
    auth_key: bytes | None = None,
    priv_protocol: str | None = None,
    priv_key: bytes | None = None,
) -> bytes: ...
def encode_snmp_getbulk_v3_secure(
    msg_id: int,
    request_id: int,
    non_repeaters: int,
    max_repetitions: int,
    oids: list[Oid],
    engine_id: bytes,
    engine_boots: int,
    engine_time: int,
    user_name: str,
    context_name: bytes = b"",
    auth_protocol: str | None = None,
    auth_key: bytes | None = None,
    priv_protocol: str | None = None,
    priv_key: bytes | None = None,
) -> bytes: ...
def encode_snmp_set_v3_secure(
    msg_id: int,
    request_id: int,
    varbinds: list[SnmpVarBind],
    engine_id: bytes,
    engine_boots: int,
    engine_time: int,
    user_name: str,
    context_name: bytes = b"",
    auth_protocol: str | None = None,
    auth_key: bytes | None = None,
    priv_protocol: str | None = None,
    priv_key: bytes | None = None,
) -> bytes: ...

# Trap/Inform/Response v3 secure

def encode_snmp_trap_v3_secure(
    msg_id: int,
    request_id: int,
    varbinds: list[SnmpVarBind],
    engine_id: bytes,
    engine_boots: int,
    engine_time: int,
    user_name: str,
    context_name: bytes = b"",
    auth_protocol: str | None = None,
    auth_key: bytes | None = None,
    priv_protocol: str | None = None,
    priv_key: bytes | None = None,
) -> bytes: ...
def encode_snmp_inform_v3_secure(
    msg_id: int,
    request_id: int,
    varbinds: list[SnmpVarBind],
    engine_id: bytes,
    engine_boots: int,
    engine_time: int,
    user_name: str,
    context_name: bytes = b"",
    auth_protocol: str | None = None,
    auth_key: bytes | None = None,
    priv_protocol: str | None = None,
    priv_key: bytes | None = None,
) -> bytes: ...
def encode_snmp_response_v3_secure(
    msg_id: int,
    request_id: int,
    error_status: int,
    error_index: int,
    varbinds: list[SnmpVarBind],
    engine_id: bytes,
    engine_boots: int,
    engine_time: int,
    user_name: str,
    context_name: bytes = b"",
    auth_protocol: str | None = None,
    auth_key: bytes | None = None,
    priv_protocol: str | None = None,
    priv_key: bytes | None = None,
) -> bytes: ...

# SNMPv3 response decode

def decode_snmp_v3_response(
    data: bytes,
    auth_protocol: str | None = None,
    auth_key: bytes | None = None,
    priv_protocol: str | None = None,
    priv_key: bytes | None = None,
    engine_boots: int = 0,
    engine_time: int = 0,
) -> SnmpResponse: ...

# SNMPv3 USM crypto

def password_to_key(password: str, protocol: str) -> bytes: ...
def localize_key(key: bytes, engine_id: bytes, protocol: str) -> bytes: ...
def password_to_localized_key(password: str, engine_id: bytes, protocol: str) -> bytes: ...
def password_to_privacy_key(
    password: str,
    engine_id: bytes,
    auth_protocol: str,
    priv_protocol: str,
) -> bytes: ...
def encrypt_scoped_pdu(
    plaintext: bytes,
    key: bytes,
    engine_boots: int,
    engine_time: int,
    protocol: str,
) -> tuple[bytes, bytes]: ...
def decrypt_scoped_pdu(
    ciphertext: bytes,
    key: bytes,
    priv_parameters: bytes,
    engine_boots: int,
    engine_time: int,
    protocol: str,
) -> bytes: ...

# Generic message decoder

class SnmpMessage:
    @property
    def version(self) -> int: ...
    @property
    def community(self) -> bytes: ...
    @property
    def pdu_type(self) -> int: ...
    @property
    def request_id(self) -> int: ...
    @property
    def error_status(self) -> int: ...
    @property
    def error_index(self) -> int: ...
    @property
    def varbinds(self) -> list[SnmpVarBind]: ...
    # v1 trap fields
    @property
    def enterprise(self) -> str: ...
    @property
    def agent_addr(self) -> tuple[int, int, int, int]: ...
    @property
    def generic_trap(self) -> int: ...
    @property
    def specific_trap(self) -> int: ...
    @property
    def timestamp(self) -> int: ...
    @property
    def msg_id(self) -> int: ...
    @property
    def engine_id(self) -> bytes: ...
    @property
    def engine_boots(self) -> int: ...
    @property
    def engine_time(self) -> int: ...
    @property
    def user_name(self) -> bytes: ...
    @property
    def context_name(self) -> bytes: ...
    def __repr__(self) -> str: ...

def decode_snmp_message(data: bytes) -> SnmpMessage: ...
def decode_snmp_v3_message(
    data: bytes,
    auth_protocol: str | None = None,
    auth_key: bytes | None = None,
    priv_protocol: str | None = None,
    priv_key: bytes | None = None,
    engine_boots: int = 0,
    engine_time: int = 0,
) -> SnmpMessage: ...

class MibNode:
    @property
    def name(self) -> str: ...
    @property
    def module(self) -> str: ...
    @property
    def oid(self) -> str: ...
    @property
    def numeric_oid(self) -> list[int]: ...
    @property
    def kind(self) -> str: ...
    @property
    def syntax(self) -> str | None: ...
    @property
    def base_type(self) -> str | None: ...
    @property
    def max_access(self) -> str | None: ...
    @property
    def status(self) -> str | None: ...
    @property
    def description(self) -> str | None: ...
    @property
    def reference(self) -> str | None: ...
    @property
    def units(self) -> str | None: ...
    @property
    def defval(self) -> str | None: ...
    @property
    def display_hint(self) -> str | None: ...
    @property
    def enums(self) -> dict[str, int] | None: ...
    @property
    def index(self) -> list[str]: ...
    @property
    def implied(self) -> bool: ...
    @property
    def augments(self) -> str | None: ...
    @property
    def row_type(self) -> str | None: ...
    @property
    def objects(self) -> list[str]: ...
    @property
    def is_table(self) -> bool: ...
    @property
    def is_row(self) -> bool: ...
    @property
    def is_column(self) -> bool: ...
    @property
    def is_scalar(self) -> bool: ...
    @property
    def parent(self) -> MibNode | None: ...
    @property
    def children(self) -> list[MibNode]: ...
    @property
    def columns(self) -> list[MibNode]: ...
    def enum_name(self, value: int) -> str | None: ...
    def enum_value(self, name: str) -> int | None: ...
    def format(self, value: int | bytes | str | Value) -> str: ...
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class MibTree:
    def __init__(self) -> None: ...
    def load_file(self, path: str) -> int: ...
    def load_dir(self, path: str, recursive: bool = True) -> int: ...
    def load_str(self, text: str, origin: str = "<string>") -> int: ...
    def lookup(self, key: str) -> MibNode | None: ...
    def translate(self, oid: str) -> str | None: ...
    def nearest(self, oid: str) -> MibNode | None: ...
    def children(self, key: str) -> list[MibNode]: ...
    def walk(self, key: str | None = None) -> list[MibNode]: ...
    @property
    def roots(self) -> list[MibNode]: ...
    @property
    def modules(self) -> list[str]: ...
    @property
    def diagnostics(self) -> list[str]: ...
    def __len__(self) -> int: ...
    def __contains__(self, key: str) -> bool: ...
    def __getitem__(self, key: str) -> MibNode: ...
    def __repr__(self) -> str: ...
