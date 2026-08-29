# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.9.0] - 2026-08-30

### Added

- **`peek_correlation_id(data)`** — the id a response will be matched on, read straight off the wire: msgID for v3 (RFC 3412 §6.2, in the plaintext header) and the PDU request-id for v1/v2c. It needs no USM keys, so a transport can route a datagram before anything is decrypted.

### Fixed

- **Concurrent requests on one `Manager` were handed each other's responses.** Both transports tracked a single outstanding request: `UdpTransport` kept one `_response` and one `asyncio.Event`, so two overlapping `send_request` calls both cleared it, both waited on the same event, and both woke on whichever datagram arrived first — returning the same bytes to both callers. `TcpTransport` was worse: two coroutines calling `readexactly` on one stream tore the length-prefixed framing apart. Both now keep a registry of in-flight requests keyed by correlation id, and TCP reads frames in one background task that hands each to the request it answers.

  This is why a caller polling several OID groups at once had to build a `Manager` per group. One `Manager` per device is now correct, which is one socket and, for v3, one engine discovery instead of one per group.

## [1.8.0] - 2026-08-30

### Added

- **`password_to_privacy_key(password, engine_id, auth_protocol, priv_protocol)`** — derives a localized privacy key of the length the cipher actually needs, extending it per draft-blumenthal-aes-usm-04 §3.1.2.1 when the authentication hash is shorter than the key. `Manager` uses it during discovery, so no caller change is required.
- **`PrivProtocol::derived_key_length()`** — the key material USM derives before the cipher takes its key. Distinct from `key_length()`, because DES derives 16 bytes and uses 8 of them as the key with the other 8 as the pre-IV (RFC 3414 §8.1.1.1).
- **Interop coverage for AES-192 and AES-256**, as two more USM users on the net-snmp agent in `tests/interop/`.

### Fixed

- **AES-192 and AES-256 silently encrypted with AES-128.** Both were accepted by `Manager`, declared in `PrivProtocol::key_length()` and advertised in the docs, but `encrypt_scoped_pdu` routed them into a function hardcoded to `cfb_mode::Encryptor<Aes128>` that sliced the key to its first 16 bytes. A caller asking for AES-256 got AES-128 with no error, and the extra key material was never used. The CFB functions are now generic over the cipher and take the whole key. There was no path that produced a long enough key either: the privacy key was derived with the authentication hash alone, so SHA-1 yielded 20 bytes where AES-256 needs 32.

  Net-SNMP applies the Blumenthal extension unless the Reeder flag is set, so snmpkit matches that default and interoperates with `createUser ... AES-192` and `AES-256` out of the box.

## [1.7.0] - 2026-08-12

### Added

- **MIB parsing** — `src/mib/` reads the SMI definition language and resolves it into one browsable OID tree. This is the MIB *text* format, not ASN.1/BER; the wire encoding in `src/asn1/` is unchanged.
  - SMIv2 per RFC 2578 (`OBJECT-TYPE`, `MODULE-IDENTITY`, `OBJECT-IDENTITY`, `NOTIFICATION-TYPE`), RFC 2579 (`TEXTUAL-CONVENTION`, `DISPLAY-HINT`) and RFC 2580 (conformance macros, parsed then discarded)
  - SMIv1 per RFC 1155/1212/1215 — the `ACCESS`/`STATUS mandatory` keywords, `Counter`/`Gauge`/`NetworkAddress` as base types, and `TRAP-TYPE` mapped to a notification OID using RFC 2576 §3.1
  - `IMPORTS` resolution across loaded modules, symbolic name <-> numeric OID in both directions, and type chains followed through textual conventions down to a base type
  - Enumeration labels, `DISPLAY-HINT` formatting (RFC 2579 §3.1), and conceptual table detection with `INDEX`, `IMPLIED` and `AUGMENTS`
  - Error recovery: a malformed definition is skipped and reported as a diagnostic rather than failing the module. Verified against all 328 MIBs Net-SNMP ships.
- **`snmpkit.mib.MibTree`** — `load_file()`, `load_dir()`, `load_str()`, `lookup()`, `translate()`, `children()`, `walk()`, plus `modules` and `diagnostics`
- **`snmpkit.mib.MibNode`** — `oid`, `name`, `module`, `kind`, `syntax`, `base_type`, `max_access`, `status`, `description`, `units`, `display_hint`, `enums`, `index`, `augments`, `columns`, and `format()` for rendering a value the way its MIB says it should look
- **`Manager(..., mib=tree)` / `SyncManager(..., mib=tree)`** — every method that takes an OID also takes a MIB name, bare (`ifDescr`), module-qualified (`IF-MIB::ifDescr`) or with an instance suffix (`sysUpTime.0`). Numeric OIDs are unaffected, so this is additive. A name that is not in the loaded MIBs raises `ValueError`.
- **`Manager.resolve()`, `Manager.translate()`, `Manager.format()`** — name to OID, OID to name, and value rendering per the object's enumeration or `DISPLAY-HINT`
- **`MibTree.nearest()`** — the deepest node at or above an OID, ignoring any instance suffix

### Changed

- **`SnmpError.unreachable`** — every manager exception now carries a boolean saying whether the device failed to answer at all (`TimeoutError`, `UnreachableError`) or answered that an object does not exist (`NoSuchObjectError`, `NoSuchInstanceError`, `EndOfMibViewError`, `GenericError`). Callers driving an online/offline fault should branch on this rather than on the exception class.
- **`SnmpError.auth_failed`** — set only by `AuthenticationError`. Bad SNMPv3 credentials leave a device reachable but unreadable, so it is deliberately *not* `unreachable`. Consumers that treat "reachable and no error" as healthy must branch on this too, or a device with wrong credentials looks fine while returning nothing.
- **`Manager.resolve()` validates the instance suffix.** A MIB name with a non-numeric suffix (`ifDescr.ifIndex`, `sysUpTime.0.extra`) raised nothing and returned a malformed OID; it now raises `ValueError`. The numeric-passthrough check is ASCII-only, so Unicode digits no longer slip through.

- **Interop test suite** (`tests/interop/`) — runs snmpkit against a real net-snmp `snmpd` inside a podman container, on Debian bookworm's Python 3.11 so the declared floor is exercised too. Covers SNMPv3 across four auth/priv combinations, an AgentX subagent registered with a live master and queried back through the manager, and the trap receiver against traps emitted by `snmptrap`. Run with `kyle test:interop`.
- **Tooling moved from uv to PDM**, with `use_uv = true` so PDM still resolves and installs through uv. `uv.lock` is replaced by `pdm.lock`. Dev dependencies are consolidated into a single PEP 735 `[dependency-groups]` entry, and `pdm run test <path>` applies `-n auto` automatically. `kyle` gains `lock`, `deps:outdated`, `deps:sync` and `bench`.

### Fixed

- **AgentX `VarBind` was encoded in the wrong field order, so subagents never worked against a real master.** RFC 2741 §5.4 orders a VarBind as type, reserved, name, data; snmpkit emitted name, type, reserved, data. Encode and decode agreed with each other, so every roundtrip test passed while `snmpd` timed out on every Get and answered `genError` to clients. Found by running a subagent against a live net-snmp master. Wire-layout tests now assert the byte order against the RFC rather than only round-tripping.
- **SNMPv3 authentication failures raised a bare `ValueError`**, escaping the `SnmpError` hierarchy — the same leak as the transport errors below. They now raise `AuthenticationError`, which `troubleshooting` had documented for some time without it existing. It is not `unreachable`: the device answered, the response just could not be verified.
- **A refused UDP port waited out the full timeout.** The OS reports ICMP port-unreachable immediately, but `error_received` only logged it and the request fell through to `timeout x retries`. The error now ends the attempt at once and raises `UnreachableError`: against a closed local port with `timeout=2, retries=3` this went from 6.0s to 0.018s. A host that is genuinely silent still waits the full budget, as it must.
- **Transport errors escaped the `SnmpError` hierarchy.** A bad hostname raised `socket.gaierror` and a failed connection raised `OSError`, so a caller catching `SnmpError` missed them entirely. Both are now converted to `UnreachableError` at the transport boundary, for UDP and TCP.
- `AGENTS.md` claimed Python 3.14+ was required. The real floor is 3.11 (`requires-python = ">=3.11"`), and CI tests 3.11 through 3.14.

### Notes

- No new Rust dependencies. The lexer, parser and resolver are hand-written, matching the existing policy for the ASN.1 layer, OID trie and USM crypto.
- RFC 2579 §3.1 says leading zeros are omitted, but only in its integer-format section, so `DISPLAY-HINT "x"` on an INTEGER renders unpadded. The octet-format spec states no padding rule, so for `OCTET STRING` hints such as `PhysAddress`'s `1x:` snmpkit pads one zero-filled pair per octet (`00:0c:29:5f:8a:1b`) where Net-SNMP does not (`0:c:29:5f:8a:1b`) — a MAC address with dropped leading zeros is the wrong thing to put in front of a user. Case follows Net-SNMP.

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

[Unreleased]: https://github.com/darhebkf/snmpkit/compare/v1.9.0...HEAD
[1.9.0]: https://github.com/darhebkf/snmpkit/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/darhebkf/snmpkit/compare/v1.7.0...v1.8.0
[1.4.0]: https://github.com/darhebkf/snmpkit/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/darhebkf/snmpkit/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/darhebkf/snmpkit/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/darhebkf/snmpkit/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/darhebkf/snmpkit/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/darhebkf/snmpkit/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/darhebkf/snmpkit/releases/tag/v1.0.0
