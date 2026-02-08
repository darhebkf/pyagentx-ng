# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/darhebkf/snmpkit/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/darhebkf/snmpkit/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/darhebkf/snmpkit/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/darhebkf/snmpkit/releases/tag/v1.0.0
