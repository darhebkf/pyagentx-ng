# snmpkit

Modern SNMP implementation in Rust with multi-language bindings.

## What is this?

snmpkit is a cross-platform SNMP toolkit aiming to:
1. Replace Net-SNMP with pure Rust implementation
2. Provide multi-language bindings (Python, C#, Node.js, WASM, C/C++)
3. Propose SNMPv4 streaming telemetry extension (RFC submission)
4. Offer better CLI tools than Net-SNMP

Current features:
- **SNMP Manager** (RFC 3411+) - Query SNMP devices (GET, SET, WALK, BULK) - COMPLETE
- **SNMPv3 Security** (RFC 3414, 3826, 7860) - USM auth/priv crypto - COMPLETE
- **AgentX subagent** (RFC 2741) - Extend SNMP agents with custom data - COMPLETE

## Architecture

Rust core with multi-language bindings:
- **Rust** - Performance-critical core (PDU encoding, OID trie, ASN.1, USM)
- **Python** - asyncio networking and user-facing API (current)
- **Node.js** - NAPI-RS bindings (planned)
- **C#** - csbindgen FFI (planned)
- **WASM** - wasm-bindgen for browser (planned)
- **C/C++** - cbindgen headers (planned)
- **CLI** - clap-based tools (planned)

### Multi-Language Binding Stack

| Target | Tool | Package Registry |
|--------|------|------------------|
| Rust | Native cargo | crates.io |
| Python | PyO3 + Maturin | PyPI |
| Node.js/Bun | NAPI-RS | npm (@snmpkit/native) |
| Browser | wasm-bindgen + wasm-pack | npm (@snmpkit/wasm) |
| C# | csbindgen | NuGet |
| C/C++ | cbindgen | Headers only |
| CLI | clap + cargo-dist | cargo install / binaries |

### Entry Points

| Function | Type | Description |
|----------|------|-------------|
| `snmpkit.run(coro)` | Blocking | Entry point for async apps (wraps uvloop.run) |
| `agent.start()` | Async | Coroutine, use with `await` inside async code |
| `agent.start_sync()` | Blocking | For sync scripts, uses uvloop internally |

Users never need to import uvloop directly - snmpkit handles it.

## Tech Stack

| Component | Technology |
|-----------|------------|
| Core | Rust 2024 edition |
| Bindings | PyO3 0.27 |
| Build | maturin |
| Python | 3.14+ (GIL-free) |
| Async | asyncio + uvloop |
| Async runtime | tokio (CLI/standalone) |
| Docs | Nextra + Bun + Biome |
| Task runner | Kyle |
| Testing | pytest-xdist, cargo test |

## Module Structure

```
snmpkit/
├── core/          # Rust bindings (Oid, Value, VarBind, SNMP encode/decode)
├── agent/         # AgentX subagent - COMPLETE
└── manager/       # SNMP manager - COMPLETE
```

Import patterns:
```python
# High-level API (most users)
from snmpkit.manager import Manager
from snmpkit.agent import Agent, Updater, SetHandler

# Low-level Rust bindings (advanced)
from snmpkit.core import Oid, Value, VarBind
from snmpkit.core import encode_snmp_get_v2c, decode_snmp_response
```

## Key Files

```
snmpkit/
├── src/                    # Rust core
│   ├── lib.rs              # PyO3 module entry point
│   ├── oid/                # OID type with radix trie
│   ├── types/              # SNMP value types
│   ├── asn1/               # ASN.1/BER encoding
│   ├── agentx/             # AgentX PDUs (RFC 2741)
│   └── snmp/               # SNMP PDUs (RFC 3411+)
│       ├── pdu.rs          # PDU types
│       ├── message.rs      # v1/v2c messages
│       ├── v3.rs           # v3 messages
│       ├── usm.rs          # USM security parameters
│       ├── auth.rs          # Authentication (HMAC-MD5/SHA/SHA2)
│       ├── privacy.rs       # Encryption (DES-CBC, AES-CFB)
│       ├── discovery.rs     # Engine discovery
│       └── bindings.rs     # PyO3 bindings
├── python/snmpkit/         # Python package
│   ├── __init__.py
│   ├── core/               # Rust bindings (built by maturin)
│   ├── agent/              # Python AgentX API
│   └── manager/            # Python Manager API (v1/v2c/v3)
├── docs/                   # TypeScript/Nextra docs
│   ├── app/
│   └── package.json
├── Cargo.toml              # Rust config
├── pyproject.toml          # Python config
└── Kylefile                # Task runner
```

## Development

Linux/macOS/Unix only. Requires [kyle](https://github.com/achmedius/kyle) task runner.

**Important**: Always use `kyle` for all development tasks. Do NOT run `cargo`, `pytest`, `npm`, etc. directly.

```bash
# First time setup (installs Rust, uv, bun, maturin)
kyle setup

# Or just install project deps if tools are present
kyle setup:deps

kyle dev          # Build and install
kyle test         # Run all tests
kyle format       # Format all code
kyle lint         # Lint all code
kyle docs:dev     # Start docs server
```

## RFCs

- RFC 2741: AgentX Protocol
- RFC 3411-3418: SNMP Architecture
- RFC 3826: AES for SNMPv3
- RFC 7860: HMAC-SHA-2 for SNMPv3

## Code Quality

### Rust Style

- **Edition**: 2024
- **Formatting**: `cargo fmt` (rustfmt defaults)
- **Linting**: `cargo clippy` - all warnings addressed
- **Error handling**: Use `Result<T, E>` with proper error types, no `unwrap()` in library code
- **Derive macros**: Use `#[derive(Debug, Clone, PartialEq, Eq)]` where appropriate
- **Visibility**: Prefer private by default, expose with `pub` only what's needed
- **Testing**: Unit tests inline with `#[cfg(test)]`, integration tests in `tests/`
- **No unsafe**: Avoid unless absolutely necessary and well-documented

### Python Style

- **Version**: 3.14+ (GIL-free threading)
- **Formatting**: `ruff format`
- **Linting**: `ruff check` (E, F, I rules)
- **Type hints**: Full coverage with `pyright` strict mode
- **Async**: async-first design, sync wrappers where needed
- **Docstrings**: Google style for public API

### TypeScript Style (docs)

- **Formatting**: Biome
- **Linting**: Biome check
- **Type checking**: `tsgo --noEmit`

### General Principles

- Simple, readable code over clever code
- No premature optimization
- Test all public API
- Roundtrip tests for encode/decode functions
- Follow RFC specs exactly (2741 for AgentX, 3411+ for SNMP)

## Documentation Maintenance

**Important**: Update documentation alongside code changes.

When modifying code:
1. Update `guide.local.md` with implementation details
2. Update `docs/public/llms.txt` with user-facing API changes
3. Update this file (`llms.txt`) with architecture/structure changes

Files to keep in sync:
- `guide.local.md` - Detailed implementation guide
- `todo.local.md` - Architecture decisions and roadmap
- `roadmap.local.txt` - Version roadmap
- `llms.txt` (root) - Contributor overview
- `docs/public/llms.txt` - User documentation

## Version Roadmap

- **v1.0.1** - AgentX subagent (RELEASED)
- **v1.1.0** - Python Manager API (RELEASED)
- **v1.2.0** - SNMPv3 Security (USM crypto) (COMPLETE)
- **v2.0.0** - Pure Rust SNMP Stack
- **v2.1.0** - CLI Tools
- **v3.0.0** - Multi-Language Bindings
- **v4.0.0** - SNMPv4 Streaming Telemetry (RFC Proposal)

## Related Projects

- Net-SNMP: https://net-snmp.org (reference, to replace)
- pysnmp: https://github.com/lextudio/pysnmp (Python reference)
- gNMI: https://github.com/openconfig/gnmi (telemetry reference)
