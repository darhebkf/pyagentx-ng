<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/public/logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="docs/public/logo-light.svg">
    <img src="docs/public/logo-light.svg" alt="SNMPKIT" width="280">
  </picture>
</p>

<p align="center">
  <em>High-performance SNMP toolkit with Rust core and Python uvloop</em>
</p>

---

## Features

- **AgentX subagent** (RFC 2741) - Extend SNMP agents with custom data
- **SNMP manager** (planned) - Query SNMP devices (GET, SET, WALK)
- **Async-first** - Built on asyncio + uvloop
- **Fast** - Rust core for PDU encoding and OID operations
- **Type-safe** - Full type hints throughout

## Tech Stack

| Component | Technology |
|-----------|------------|
| Core | Rust 2024 |
| Python | 3.14+ (GIL-free) |
| Docs | TypeScript / Nextra |
| Build | maturin + uv |
| Task runner | [kyle](https://github.com/achmedius/kyle) |

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
