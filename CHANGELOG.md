# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2025-XX-XX

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

[Unreleased]: https://github.com/darhebkf/snmpkit/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/darhebkf/snmpkit/releases/tag/v1.0.0
