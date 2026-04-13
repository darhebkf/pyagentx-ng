# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.6.0] - 2026-04-13

### Added

- **`Value.__int__()`** — Convert numeric SNMP values (Integer, Counter32, Gauge32, TimeTicks, Counter64) to Python `int`. Raises `TypeError` for non-numeric types.
- **`Value.__float__()`** — Convert numeric SNMP values to Python `float`. Raises `TypeError` for non-numeric types.
- **`Value.__bytes__()`** — Convert OctetString and Opaque values to Python `bytes`. Raises `TypeError` for other types.
- **`Value.__bool__()`** — Returns `False` for Null, NoSuchObject, NoSuchInstance, EndOfMibView; `True` for all other values.
- **`Value.__hash__()`** — Makes Value hashable, usable in sets and as dict keys.

## [1.5.0] - 2026-04-09

### Added

- **`Manager.set_many(*varbinds)`** — Set multiple OID/value pairs in a single SNMP SET PDU for atomic multi-varbind operations (e.g., USM user creation with createAndGo)
- **`SyncManager.set_many(*varbinds)`** — Blocking wrapper for `set_many`

### Changed

- **`Manager.get_many(..., raise_exceptions=True)`** — New `raise_exceptions` parameter. When `False`, returns `Value.NoSuchObject()` / `Value.NoSuchInstance()` / `Value.EndOfMibView()` as values instead of raising, enabling per-varbind exception handling in polling scenarios
- **`SyncManager.get_many(..., raise_exceptions=True)`** — Matching parameter on sync wrapper
- `Manager.set()` now delegates to `set_many()` internally (no behavior change)

## [1.4.0] - 2026-02-25

### Added

- **SNMPv1 Trap Support (RFC 1157)**
  - `Manager.send_trap()` now supports `version=1` with enterprise OID, agent address, generic/specific trap types
  - `encode_snmp_trap_v1()` Rust binding for v1 Trap-PDU (0xA4 tag)
  - `TrapReceiver` accepts v1 traps with enterprise, agent_addr, generic_trap, specific_trap fields on `TrapMessage`

- **TCP Transport (RFC 3430)**
  - `TcpTransport` class with 4-byte big-endian length-prefix framing
  - `Manager(transport="tcp")` parameter for TCP connections
  - Full send_request/send_only with retry support

- **IPv6 Transport**
  - Dual-stack UDP and TCP transport (IPv4 + IPv6)
  - `TrapReceiver` supports `::` bind for dual-stack listening

- **Synchronous API**
  - `SyncManager` — blocking wrapper with persistent background uvloop thread
  - Context manager support (`with SyncManager(...) as mgr`)
  - All Manager operations: `get`, `get_many`, `set`, `walk`, `bulk_walk`, `get_table`, `send_trap`, `send_inform`

- **SNMPv3 TrapReceiver**
  - `TrapReceiver.add_user(V3User)` for multi-user v3 trap receiving
  - USM key derivation and caching per (engine_id, user_name)
  - Auth/priv decryption for incoming v3 traps and informs
  - v3 InformRequest ACK with proper security parameters
  - `V3User` dataclass for credential management
  - `TrapMessage` extended with v3 fields: engine_id, user_name, context_name, msg_id

- **Notification Filtering**
  - `TrapFilter` dataclass with allowed_sources, allowed_communities, allowed_oid_prefixes, denied_sources
  - OID prefix matching uses `Oid.starts_with()` (not string prefix)
  - OR logic for allow filters, deny takes precedence
  - `TrapReceiver.add_filter(TrapFilter)` integration

- **Rust Bindings**
  - `decode_snmp_v3_message()` — generic v3 message decoder with auth/priv support
  - `encode_snmp_trap_v1()` — v1 trap PDU encoding
  - `PySnmpMessage` extended with v1 trap fields and v3 security fields

## [1.3.0] - 2026-02-22

### Added

- **Manager Trap/Inform Support**
  - `Manager.send_trap()` — fire-and-forget SNMPv2c trap sending
  - `Manager.send_inform()` — SNMPv2c InformRequest with Response ACK
  - `_build_trap_varbinds()` helper for sysUpTime + snmpTrapOID + user varbinds

- **TrapReceiver**
  - Async UDP listener for incoming traps and informs
  - Async iterator protocol (`async for msg in receiver`)
  - Auto-ACK for InformRequests (RFC 3416)
  - `TrapMessage` dataclass with parsed trap OID, uptime, varbinds, and source
  - Filters non-trap PDU types (GET/SET/etc.)

- **Table Operations**
  - `Manager.get_table()` — GETBULK-based SNMP table walks
  - Column filtering via `columns` parameter
  - Returns `dict[tuple[int, ...], dict[int, Value]]` indexed by row/column

- **Concurrent Polling**
  - `poll_many()` async generator for polling multiple targets
  - `PollTarget` dataclass with per-target configuration (host, port, community, v3 credentials)
  - `PollResult` dataclass with target, OID, value, and error fields
  - Semaphore-bounded concurrency with per-target error isolation

- **Rust Bindings**
  - `encode_snmp_trap_v2c()` / `encode_snmp_inform_v2c()` — trap/inform PDU encoding
  - `encode_snmp_response_v2c()` — response PDU encoding (for inform ACKs)
  - `decode_snmp_message()` — generic SNMP message decoder (version, community, PDU type, varbinds)

- **CI**
  - Test matrix expanded to Python 3.11, 3.12, 3.13, 3.14

### Fixed

- `Value.__str__` and `__repr__` now work correctly in Python (PyO3 complex enum `fmt::Display` was not auto-wired)
- Manager exception checks use equality comparison instead of string matching
- Parenthesized multiple exception types for Python 3.11 compatibility

## [1.2.1] - 2026-02-19

### Changed

- Minimum Python version lowered from 3.14 to 3.11

## [1.2.0] - 2026-02-11

### Added

- **SNMPv3 Security (USM)**
  - Full RFC 3414 (USM), RFC 3826 (AES), RFC 7860 (HMAC-SHA-2) implementation
  - Authentication: HMAC-MD5-96, HMAC-SHA-96, HMAC-SHA-224/256/384/512
  - Privacy: DES-CBC, AES-128-CFB encryption/decryption
  - Key derivation: password_to_key (RFC 3414 A.2.1), localize_key (RFC 3414 A.2.2)
  - Automatic engine discovery on connect for SNMPv3

- **Manager SNMPv3 Support**
  - `Manager(version=3, user=..., auth_protocol=..., auth_password=..., priv_protocol=..., priv_password=...)`
  - authPriv, authNoPriv, and noAuthNoPriv security levels
  - Automatic engine ID/boots/time discovery via Report PDU
  - Localized key derivation from passwords
  - All operations (get, set, walk, bulk_walk) work with SNMPv3

- **Rust Crypto Modules**
  - `src/snmp/auth.rs` - HMAC authentication with all 6 hash algorithms
  - `src/snmp/privacy.rs` - DES-CBC and AES-CFB-128 encrypt/decrypt
  - `src/snmp/discovery.rs` - Engine discovery helpers
  - Secure v3 encode/decode PyO3 bindings

## [1.1.0] - 2026-02-08

### Added

- **SNMP Manager API**
  - `Manager` class for querying SNMP devices
  - `get()`, `get_many()`, `get_next()`, `get_bulk()` operations
  - `walk()` async iterator for traversing OID subtrees
  - `set()` for SNMPv2c write operations
  - Full SNMPv1/v2c/v3 support with authentication and privacy
  - UDP transport with configurable timeouts and retries
  - Async context manager for connection lifecycle

- **Manager PDUs (RFC 3411-3418)**
  - SNMP GET/GETNEXT/GETBULK/SET request encoding
  - SNMPv3 security model with USM
  - Response decoding with error handling

- **ASN.1 BER Encoding**
  - Complete BER encoder for SNMP message construction
  - High-performance Rust implementation

- **Exception Hierarchy for Manager**
  - `NoSuchObjectError`, `NoSuchInstanceError`, `EndOfMibViewError`
  - `GenericError` with status and index

- **Performance**
  - 170,910 SNMP GET requests/sec
  - 108,857 SNMPv3 requests/sec
  - 389,342 AgentX PDUs/sec
  - 127x faster BER encoding than pure Python

- **Documentation**
  - Redesigned landing page with split layout
  - Interactive code snippet with Manager and Agent examples
  - One-click install command copy

### Changed

- All Python class attributes are now public (removed underscore prefix)
  - `Manager`: `host`, `port`, `community`, `version`, `timeout`, `retries`, `transport`
  - `Agent`: `agent_id`, `socket_path`, `timeout`, `registrations`, `protocol`
  - `Protocol`: `session_id`, `transaction_id`, `packet_id`
  - `UdpTransport`: `host`, `port`, `timeout`, `retries`, `transport`, `protocol`

## [1.0.1] - 2026-01-23

### Fixed

- README images now use raw GitHub URLs for PyPI compatibility

## [1.0.0] - 2026-01-22

### Added

- **Rust Core**
  - `Oid` type with parsing, comparison, parent/child operations
  - Radix trie for O(1) OID lookups
  - All SNMP value types: Integer, OctetString, Counter32, Counter64, Gauge32, TimeTicks, IpAddress, ObjectIdentifier, Opaque
  - Complete AgentX PDU encoding/decoding (RFC 2741)
  - Optional parallel encoding with rayon

- **Python Agent API**
  - `Agent` class with async/sync entry points
  - `Updater` base class with `set_*` methods for all SNMP types
  - `SetHandler` for SNMP SET operations (test/commit/undo/cleanup)
  - Typed exception hierarchy (`SnmpkitError`, `ConnectionError`, `RegistrationError`, etc.)
  - SNMP context support for multi-tenant scenarios
  - Automatic reconnection on connection loss
  - uvloop integration for high performance

- **Performance**
  - PDU encoding 11.5x faster than pyagentx3
  - Value creation 6.4x faster than pyagentx3
  - OID parsing 1.5x faster than pyagentx3

- **Documentation**
  - Nextra-based docs site
  - Agent quickstart, updater, set-handler, traps, advanced guides
  - Real-world examples
  - Performance benchmarks

### Technical Requirements

- Python 3.14+
- Rust 1.83.0+

[Unreleased]: https://github.com/darhebkf/snmpkit/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/darhebkf/snmpkit/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/darhebkf/snmpkit/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/darhebkf/snmpkit/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/darhebkf/snmpkit/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/darhebkf/snmpkit/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/darhebkf/snmpkit/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/darhebkf/snmpkit/releases/tag/v1.0.0
