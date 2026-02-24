"""Tests for v3 trap/inform receiving with TrapReceiver."""

from __future__ import annotations

from snmpkit.core import (
    Oid,
    SnmpVarBind,
    Value,
    encode_snmp_trap_v2c,
    encode_snmp_trap_v3_secure,
)
from snmpkit.manager.trap_receiver import (
    _PDU_TRAPV2,
    TrapMessage,
    TrapReceiver,
)
from snmpkit.manager.v3_user import V3User


def _make_v3_trap_bytes(
    user_name: str = "testuser",
    engine_id: bytes = b"\x80\x00\x00\x01\x03",
    auth_protocol: str | None = None,
    auth_key: bytes | None = None,
    priv_protocol: str | None = None,
    priv_key: bytes | None = None,
    varbinds: list | None = None,
) -> bytes:
    vbs = varbinds or [
        SnmpVarBind(Oid("1.3.6.1.2.1.1.3.0"), Value.TimeTicks(12345)),
        SnmpVarBind(
            Oid("1.3.6.1.6.3.1.1.4.1.0"),
            Value.ObjectIdentifier(Oid("1.3.6.1.4.1.99.0.1")),
        ),
    ]

    kwargs: dict = {
        "engine_id": engine_id,
        "engine_boots": 1,
        "engine_time": 100,
        "user_name": user_name,
        "context_name": b"",
    }
    if auth_protocol and auth_key:
        kwargs["auth_protocol"] = auth_protocol
        kwargs["auth_key"] = auth_key
    if priv_protocol and priv_key:
        kwargs["priv_protocol"] = priv_protocol
        kwargs["priv_key"] = priv_key

    return encode_snmp_trap_v3_secure(
        msg_id=1,
        request_id=42,
        varbinds=vbs,
        **kwargs,
    )


class TestV3User:
    def test_create_noauth(self):
        user = V3User(user_name="noauth")
        assert user.user_name == "noauth"
        assert user.auth_protocol is None
        assert user.priv_protocol is None

    def test_create_authnopriv(self):
        user = V3User(
            user_name="authuser",
            auth_protocol="SHA",
            auth_password="authpass123",
        )
        assert user.auth_protocol == "SHA"
        assert user.auth_password == "authpass123"
        assert user.priv_protocol is None

    def test_create_authpriv(self):
        user = V3User(
            user_name="privuser",
            auth_protocol="SHA",
            auth_password="authpass123",
            priv_protocol="AES",
            priv_password="privpass123",
        )
        assert user.priv_protocol == "AES"

    def test_default_engine_id(self):
        user = V3User(user_name="test")
        assert user.engine_id == b""

    def test_importable_from_package(self):
        from snmpkit.manager import V3User as V3U

        assert V3U is V3User


class TestTrapReceiverV3:
    def test_add_user(self):
        receiver = TrapReceiver()
        user = V3User(user_name="testuser")
        receiver.add_user(user)
        assert "testuser" in receiver._users
        assert receiver._users["testuser"] is user

    def test_add_user_replaces(self):
        receiver = TrapReceiver()
        user1 = V3User(user_name="testuser", auth_protocol="MD5")
        user2 = V3User(user_name="testuser", auth_protocol="SHA")
        receiver.add_user(user1)
        receiver.add_user(user2)
        assert receiver._users["testuser"].auth_protocol == "SHA"

    def test_add_user_clears_key_cache(self):
        receiver = TrapReceiver()
        receiver._key_cache[("abc", "testuser")] = (b"key1", b"key2")
        user = V3User(user_name="testuser")
        receiver.add_user(user)
        assert ("abc", "testuser") not in receiver._key_cache

    def test_noauth_v3_trap_accepted(self):
        receiver = TrapReceiver()
        receiver.add_user(V3User(user_name="testuser"))
        data = _make_v3_trap_bytes()
        receiver._handle_datagram(data, ("10.0.0.1", 5000))
        assert not receiver._queue.empty()

    def test_noauth_v3_trap_fields(self):
        receiver = TrapReceiver()
        receiver.add_user(V3User(user_name="testuser"))
        data = _make_v3_trap_bytes()
        receiver._handle_datagram(data, ("10.0.0.1", 5000))
        msg = receiver._queue.get_nowait()

        assert msg.version == 3
        assert msg.pdu_type == _PDU_TRAPV2
        assert msg.trap_oid == "1.3.6.1.4.1.99.0.1"
        assert msg.uptime == 12345
        assert msg.source == ("10.0.0.1", 5000)
        assert msg.user_name == "testuser"

    def test_unknown_user_dropped(self):
        receiver = TrapReceiver()
        receiver.add_user(V3User(user_name="knownuser"))
        data = _make_v3_trap_bytes(user_name="unknownuser")
        receiver._handle_datagram(data, ("10.0.0.1", 5000))
        assert receiver._queue.empty()

    def test_v3_trap_with_varbinds(self):
        receiver = TrapReceiver()
        receiver.add_user(V3User(user_name="testuser"))
        vbs = [
            SnmpVarBind(Oid("1.3.6.1.2.1.1.3.0"), Value.TimeTicks(100)),
            SnmpVarBind(
                Oid("1.3.6.1.6.3.1.1.4.1.0"),
                Value.ObjectIdentifier(Oid("1.3.6.1.4.1.99.0.1")),
            ),
            SnmpVarBind(Oid("1.3.6.1.4.1.99.1.0"), Value.Integer(42)),
        ]
        data = _make_v3_trap_bytes(varbinds=vbs)
        receiver._handle_datagram(data, ("10.0.0.1", 5000))
        msg = receiver._queue.get_nowait()

        assert len(msg.varbinds) == 1
        assert msg.varbinds[0][0] == "1.3.6.1.4.1.99.1.0"
        assert msg.varbinds[0][1] == Value.Integer(42)

    def test_multi_user(self):
        receiver = TrapReceiver()
        receiver.add_user(V3User(user_name="user1"))
        receiver.add_user(V3User(user_name="user2"))

        data1 = _make_v3_trap_bytes(user_name="user1")
        data2 = _make_v3_trap_bytes(user_name="user2")

        receiver._handle_datagram(data1, ("10.0.0.1", 5000))
        receiver._handle_datagram(data2, ("10.0.0.2", 5000))

        assert receiver._queue.qsize() == 2
        msg1 = receiver._queue.get_nowait()
        msg2 = receiver._queue.get_nowait()
        assert msg1.user_name == "user1"
        assert msg2.user_name == "user2"

    def test_mixed_v2c_v3(self):
        receiver = TrapReceiver()
        receiver.add_user(V3User(user_name="testuser"))

        v2c_vbs = [
            SnmpVarBind(Oid("1.3.6.1.2.1.1.3.0"), Value.TimeTicks(100)),
            SnmpVarBind(
                Oid("1.3.6.1.6.3.1.1.4.1.0"),
                Value.ObjectIdentifier(Oid("1.3.6.1.4.1.99.0.1")),
            ),
        ]
        v2c_data = encode_snmp_trap_v2c("public", 1, v2c_vbs)
        v3_data = _make_v3_trap_bytes()

        receiver._handle_datagram(v2c_data, ("10.0.0.1", 5000))
        receiver._handle_datagram(v3_data, ("10.0.0.2", 5000))

        assert receiver._queue.qsize() == 2
        msg1 = receiver._queue.get_nowait()
        msg2 = receiver._queue.get_nowait()
        assert msg1.version == 1
        assert msg2.version == 3


class TestPeekVersion:
    def test_v1(self):
        from snmpkit.core import encode_snmp_trap_v1

        data = encode_snmp_trap_v1("public", "1.3.6.1.4.1.99", (10, 0, 0, 1), 6, 1, 0, [])
        assert TrapReceiver._peek_version(data) == 0

    def test_v2c(self):
        vbs = [
            SnmpVarBind(Oid("1.3.6.1.2.1.1.3.0"), Value.TimeTicks(0)),
            SnmpVarBind(
                Oid("1.3.6.1.6.3.1.1.4.1.0"),
                Value.ObjectIdentifier(Oid("1.3.6.1.4.1.99.0.1")),
            ),
        ]
        data = encode_snmp_trap_v2c("public", 1, vbs)
        assert TrapReceiver._peek_version(data) == 1

    def test_v3(self):
        data = _make_v3_trap_bytes()
        assert TrapReceiver._peek_version(data) == 3

    def test_invalid_data(self):
        assert TrapReceiver._peek_version(b"") is None
        assert TrapReceiver._peek_version(b"\x00") is None
        assert TrapReceiver._peek_version(b"\x30") is None


class TestPeekV3UserName:
    def test_extracts_username(self):
        data = _make_v3_trap_bytes(user_name="admin")
        assert TrapReceiver._peek_v3_user_name(data) == "admin"

    def test_empty_username(self):
        data = _make_v3_trap_bytes(user_name="")
        assert TrapReceiver._peek_v3_user_name(data) == ""

    def test_invalid_data(self):
        assert TrapReceiver._peek_v3_user_name(b"") is None
        assert TrapReceiver._peek_v3_user_name(b"\x30\x00") is None


class TestPeekV3EngineId:
    def test_extracts_engine_id(self):
        engine = b"\x80\x00\x00\x01\x03"
        data = _make_v3_trap_bytes(engine_id=engine)
        assert TrapReceiver._peek_v3_engine_id(data) == engine

    def test_invalid_data(self):
        assert TrapReceiver._peek_v3_engine_id(b"") == b""


class TestKeyDerivation:
    def test_noauth_returns_none(self):
        receiver = TrapReceiver()
        user = V3User(user_name="noauth")
        auth_key, priv_key = receiver._get_keys(user, b"\x80\x00\x00\x01\x03")
        assert auth_key is None
        assert priv_key is None

    def test_auth_derives_key(self):
        receiver = TrapReceiver()
        user = V3User(user_name="authuser", auth_protocol="SHA", auth_password="authpass123")
        auth_key, priv_key = receiver._get_keys(user, b"\x80\x00\x00\x01\x03")
        assert auth_key is not None
        assert len(auth_key) > 0
        assert priv_key is None

    def test_authpriv_derives_both(self):
        receiver = TrapReceiver()
        user = V3User(
            user_name="privuser",
            auth_protocol="SHA",
            auth_password="authpass123",
            priv_protocol="AES",
            priv_password="privpass123",
        )
        auth_key, priv_key = receiver._get_keys(user, b"\x80\x00\x00\x01\x03")
        assert auth_key is not None
        assert priv_key is not None

    def test_keys_cached(self):
        receiver = TrapReceiver()
        user = V3User(user_name="authuser", auth_protocol="SHA", auth_password="authpass123")
        engine = b"\x80\x00\x00\x01\x03"
        k1 = receiver._get_keys(user, engine)
        k2 = receiver._get_keys(user, engine)
        assert k1 == k2
        # Verify cache hit (same key in cache dict)
        assert len(receiver._key_cache) == 1

    def test_different_engines_different_keys(self):
        receiver = TrapReceiver()
        user = V3User(user_name="authuser", auth_protocol="SHA", auth_password="authpass123")
        k1 = receiver._get_keys(user, b"\x80\x00\x00\x01\x03")
        k2 = receiver._get_keys(user, b"\x80\x00\x00\x02\x04")
        assert k1[0] != k2[0]


class TestTrapMessageV3Fields:
    def test_default_v3_fields(self):
        msg = TrapMessage(
            source=("10.0.0.1", 5000),
            version=1,
            community="public",
            pdu_type=0xA7,
            request_id=1,
            trap_oid="1.3.6.1.4.1.99.0.1",
            uptime=0,
            varbinds=[],
        )
        assert msg.engine_id == b""
        assert msg.user_name == ""
        assert msg.context_name == ""
        assert msg.msg_id == 0
