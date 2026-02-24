"""Trap filtering for TrapReceiver."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from snmpkit.core import Oid

if TYPE_CHECKING:
    from snmpkit.manager.trap_receiver import TrapMessage


@dataclass
class TrapFilter:
    """Filter for incoming trap messages.

    Uses OR logic: a trap matches if ANY condition matches.
    Empty filter (no conditions) accepts all traps.

    OID prefix matching uses Oid.starts_with() for correctness
    (avoids "1.3.6.1.4" matching "1.3.6.1.40").

    Example:
        filt = TrapFilter(
            allowed_sources=["192.168.1.0/24"],
            allowed_oid_prefixes=["1.3.6.1.4.1.99"],
        )
        receiver.add_filter(filt)
    """

    allowed_sources: list[str] = field(default_factory=list)
    allowed_communities: list[str] = field(default_factory=list)
    allowed_oid_prefixes: list[str] = field(default_factory=list)
    denied_sources: list[str] = field(default_factory=list)

    def matches(self, trap: TrapMessage) -> bool:
        """Check if a trap matches this filter.

        Returns True if the trap should be accepted, False if rejected.
        """
        source_ip = trap.source[0]

        # Deny list takes precedence
        if self.denied_sources and source_ip in self.denied_sources:
            return False

        # If no allow conditions, accept all (that aren't denied)
        has_allow_conditions = (
            self.allowed_sources or self.allowed_communities or self.allowed_oid_prefixes
        )
        if not has_allow_conditions:
            return True

        # OR logic: any allow condition matching = accept
        if self.allowed_sources and source_ip in self.allowed_sources:
            return True

        if self.allowed_communities and trap.community in self.allowed_communities:
            return True

        if self.allowed_oid_prefixes and trap.trap_oid:
            trap_oid = Oid(trap.trap_oid)
            for prefix_str in self.allowed_oid_prefixes:
                prefix = Oid(prefix_str)
                if trap_oid.starts_with(prefix) or trap_oid == prefix:
                    return True

        return False
