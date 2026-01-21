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
