# Contributing to snmpkit

## Development Setup

You can use [kyle](https://github.com/achmedius/kyle), to help development.

```bash
git clone https://github.com/darhebkf/snmpkit.git
cd snmpkit
kyle setup
```

`kyle setup` installs Rust, uv, PDM, bun, and the project dependencies. If you
already have those toolchains, `kyle setup:deps` installs just the dependencies.

Python 3.11 or newer. PDM manages dependencies and resolves through uv; the
lockfile is `pdm.lock`.

## Everyday tasks

It is possible to use kyle for common tasks:
```bash
kyle dev          # build the Rust extension and install it in the venv
kyle refresh      # rebuild the extension and refresh all dev dependencies
kyle test         # Rust + Python
kyle lint         # clippy, ruff, biome
kyle format       # rustfmt, ruff, biome
kyle check        # type checking
kyle bench        # benchmarks against pysnmp
kyle docs:dev     # docs site on localhost
```

Run `kyle pre-commit` before opening a PR.

kyle forwards arguments, so a single file or expression works too:

```bash
kyle test:python python/tests/mib/test_mib.py
kyle test:python -k display_hint
```

## Dependencies

```bash
kyle lock              # regenerate pdm.lock
kyle deps:outdated     # what has newer releases
kyle deps:sync         # match the venv to the lockfile exactly
kyle deps:frozen       # install exactly what pdm.lock pins, no re-resolve
```

PDM manages dependencies and resolves through uv, so both are needed; `kyle
setup` installs them. Rust dependencies are a deliberate decision — the ASN.1
layer, OID trie and USM crypto are hand-written on purpose, and the only
non-crypto crates are `pyo3`, `bitflags` and optional `rayon`.

## Project Structure

```
snmpkit/
├── src/                    # Rust core
│   ├── lib.rs              # PyO3 module entry point
│   ├── oid/                # OID type and radix trie
│   ├── types/              # SNMP value types
│   ├── asn1/               # ASN.1/BER wire encoding
│   ├── agentx/             # AgentX protocol (RFC 2741)
│   ├── mib/                # MIB definition language (SMI)
│   └── snmp/               # SNMP PDUs, v3 and USM
├── python/
│   ├── snmpkit/            # Python package
│   │   ├── agent/          # AgentX subagent API
│   │   ├── manager/        # Manager API
│   │   ├── mib/            # MIB tree API
│   │   └── core.pyi        # Type stubs for the Rust module
│   └── tests/
├── tests/                  # Rust integration tests and MIB fixtures
├── docs/                   # Nextra documentation site
└── benchmarks/             # Performance benchmarks vs pysnmp
```

## Code Style

New code should be indistinguishable from the code already around it: match the
naming, module layout, error handling and test style of the nearest existing
module. Prefer extending a module over adding one.

- Rust: `cargo fmt` defaults, clippy clean, no `unwrap()` or `expect()` outside
  tests, unit tests inline in `#[cfg(test)] mod tests`
- Python: `ruff format`, full type hints on public API, async-first
- Comment why, not what. A spec reference earns its place; prose does not.

## Pull Requests

1. Fork and create a feature branch
2. Make your changes, with tests
3. `kyle test && kyle lint`
4. Update `docs/app/docs/**` for user-facing changes, `AGENTS.md` for structural
   ones, and `CHANGELOG.md` for anything version-visible
5. Commit using conventional commits, push, and open a PR
