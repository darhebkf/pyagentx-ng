<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/darhebkf/snmpkit/refs/heads/main/docs/public/logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/darhebkf/snmpkit/refs/heads/main/docs/public/logo-light.svg">
    <img src="https://raw.githubusercontent.com/darhebkf/snmpkit/refs/heads/main/docs/public/logo-light.svg" alt="SNMPKIT" width="280">
  </picture>
</p>

<p align="center">
  <em>High-performance SNMP toolkit for Python, powered by Rust</em>
</p>

---

## Features

- **AgentX subagent**: Full RFC 2741 Compliance
- **Fast** - Rust core for PDU encoding and OID operations
- **Type-safe**: Full type hints throughout

## Installation

```bash
uv add snmpkit
```

## Quick Start

```python
from snmpkit.agent import Agent, Updater

class MyUpdater(Updater):
    async def update(self):
        self.set_INTEGER("1.0", 42)
        self.set_OCTETSTRING("2.0", "hello")

agent = Agent(agent_id="MyAgent")
agent.register("1.3.6.1.4.1.12345", MyUpdater(), freq=10)
agent.start_sync()  # or: await agent.start()
```

## Documentation

**[snmpkit.dev](https://snmpkit.dev)** - Full documentation, guides, and API reference

## Development

Requires [kyle](https://github.com/achmedius/kyle) task runner. Linux/macOS/Unix only.

```bash
# First time setup (installs Rust, uv, bun, maturin)
kyle setup

# Or if you have the tools already
kyle setup:deps   # Just install project dependencies

kyle dev          # Build and install in dev mode
kyle test         # Run all tests (Python + Rust)
kyle format          # Format all code (Python + Rust + TS)
kyle lint         # Lint all code
kyle docs:dev     # Start docs dev server
kyle check        # Type check and lint
```

## License

Check out the [License](LICENSE) for more information!
