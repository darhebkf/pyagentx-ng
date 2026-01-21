# Contributing to snmpkit

## Development Setup

1. Install Rust: https://rustup.rs/
2. Install Python 3.14+
3. Install uv: `curl -LsSf https://astral.sh/uv/install.sh | sh`
4. Clone and install:

```bash
git clone https://github.com/darhebkf/snmpkit.git
cd snmpkit
uv sync --all-extras
```

## Building

```bash
# Development build (uses maturin develop)
uv run maturin develop

# Release build
uv run maturin build --release
```

## Testing

```bash
# Run all tests
uv run pytest

# Run Rust tests only
cargo test

# Run Python tests only
uv run pytest python/tests/
```

## Linting

```bash
# Python
uv run ruff check .
uv run ruff format .

# Rust
cargo fmt
cargo clippy
```

## Pre-commit Hooks

Install pre-commit hooks:

```bash
uv run pre-commit install
```

Run manually:

```bash
uv run pre-commit run --all-files
```

## Project Structure

```
snmpkit/
├── src/                    # Rust source code
│   ├── lib.rs             # PyO3 module entry point
│   ├── oid/               # OID type and trie
│   ├── types/             # SNMP value types
│   └── agentx/            # AgentX protocol implementation
├── python/
│   └── snmpkit/           # Python package
│       ├── agent/         # Agent, Updater, SetHandler
│       └── core.pyi       # Type stubs for Rust module
├── docs/                   # Nextra documentation site
└── benchmarks/            # Performance benchmarks
```

## Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests and linting
5. Commit with a descriptive message
6. Push and open a PR

## Code Style

- Rust: Follow rustfmt defaults
- Python: Follow ruff defaults (based on Black + isort)
- Commit messages: Use conventional commits format
