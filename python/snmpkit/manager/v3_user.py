"""SNMPv3 user credentials for trap receiving."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class V3User:
    """SNMPv3 USM user credentials.

    Used with TrapReceiver to authenticate/decrypt incoming v3 traps and informs.

    Example:
        user = V3User(
            user_name="admin",
            auth_protocol="SHA",
            auth_password="authpass123",
            priv_protocol="AES",
            priv_password="privpass123",
        )
        receiver = TrapReceiver(port=1162)
        receiver.add_user(user)
    """

    user_name: str
    engine_id: bytes = b""
    auth_protocol: str | None = None
    auth_password: str | None = None
    priv_protocol: str | None = None
    priv_password: str | None = None
