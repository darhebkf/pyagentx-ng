"""A snmpkit AgentX subagent, run as its own process by the interop suite.

Subagents are separate processes in production, and running it that way here
keeps it off the test's event loop, where a blocked test would otherwise stop
the agent answering the master.
"""

import sys

import snmpkit
from snmpkit.agent import Agent, Updater

SUBTREE = "1.3.6.1.4.1.99999"


class InteropUpdater(Updater):
    async def update(self) -> None:
        self.set_INTEGER("1.0", 42)
        self.set_OCTETSTRING("2.0", "hello from snmpkit")


async def main(socket_path: str) -> None:
    agent = Agent(agent_id="snmpkit-interop", socket_path=socket_path, timeout=10)
    agent.register(SUBTREE, InteropUpdater(), freq=1)
    await agent.start()


if __name__ == "__main__":
    snmpkit.run(main(sys.argv[1]))
