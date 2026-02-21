"""Tests for poll_many()."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from snmpkit.core import Value
from snmpkit.manager.poll import PollResult, PollTarget, _poll_target, poll_many


class TestPollTarget:
    """Tests for PollTarget dataclass."""

    def test_defaults(self):
        t = PollTarget(host="10.0.0.1")
        assert t.host == "10.0.0.1"
        assert t.port == 161
        assert t.community == "public"
        assert t.version == 2
        assert t.timeout == 5.0
        assert t.retries == 3

    def test_custom(self):
        t = PollTarget(host="10.0.0.1", port=1161, community="private", version=3)
        assert t.port == 1161
        assert t.community == "private"
        assert t.version == 3

    def test_v3_fields(self):
        t = PollTarget(
            host="10.0.0.1",
            version=3,
            user="admin",
            auth_protocol="SHA",
            auth_password="authpass",
            priv_protocol="AES",
            priv_password="privpass",
        )
        assert t.user == "admin"
        assert t.auth_protocol == "SHA"
        assert t.priv_protocol == "AES"


class TestPollResult:
    """Tests for PollResult dataclass."""

    def test_success_result(self):
        r = PollResult(target="10.0.0.1:161", oid="1.3.6.1.2.1.1.1.0", value=Value.Integer(42))
        assert r.target == "10.0.0.1:161"
        assert r.oid == "1.3.6.1.2.1.1.1.0"
        assert r.value == Value.Integer(42)
        assert r.error is None

    def test_error_result(self):
        r = PollResult(target="10.0.0.1:161", oid="1.3.6.1.2.1.1.1.0", error="Timeout")
        assert r.value is None
        assert r.error == "Timeout"


class TestPollTarget_:
    """Tests for _poll_target internal function."""

    async def test_successful_poll(self):
        target = PollTarget(host="10.0.0.1")
        oids = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0"]

        mock_mgr = AsyncMock()
        mock_mgr.get_many = AsyncMock(
            return_value=[Value.OctetString(b"Linux"), Value.TimeTicks(12345)]
        )
        mock_mgr.__aenter__ = AsyncMock(return_value=mock_mgr)
        mock_mgr.__aexit__ = AsyncMock(return_value=None)

        with patch("snmpkit.manager.poll.Manager", return_value=mock_mgr):
            results = await _poll_target(target, oids)

        assert len(results) == 2
        assert results[0].target == "10.0.0.1:161"
        assert results[0].oid == "1.3.6.1.2.1.1.1.0"
        assert results[0].value == Value.OctetString(b"Linux")
        assert results[0].error is None
        assert results[1].oid == "1.3.6.1.2.1.1.3.0"
        assert results[1].value == Value.TimeTicks(12345)

    async def test_error_isolation(self):
        """Errors on one target don't affect others — each OID gets an error result."""
        target = PollTarget(host="10.0.0.1")
        oids = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0"]

        mock_mgr = AsyncMock()
        mock_mgr.__aenter__ = AsyncMock(side_effect=ConnectionRefusedError("refused"))
        mock_mgr.__aexit__ = AsyncMock(return_value=None)

        with patch("snmpkit.manager.poll.Manager", return_value=mock_mgr):
            results = await _poll_target(target, oids)

        assert len(results) == 2
        for r in results:
            assert r.value is None
            assert "refused" in r.error

    async def test_target_string_format(self):
        """Target string is host:port."""
        target = PollTarget(host="192.168.1.1", port=1161)

        mock_mgr = AsyncMock()
        mock_mgr.get_many = AsyncMock(return_value=[Value.Integer(1)])
        mock_mgr.__aenter__ = AsyncMock(return_value=mock_mgr)
        mock_mgr.__aexit__ = AsyncMock(return_value=None)

        with patch("snmpkit.manager.poll.Manager", return_value=mock_mgr):
            results = await _poll_target(target, ["1.3.6.1.2.1.1.1.0"])

        assert results[0].target == "192.168.1.1:1161"


class TestPollMany:
    """Tests for poll_many() async generator."""

    async def test_polls_all_targets(self):
        targets = [
            PollTarget(host="10.0.0.1"),
            PollTarget(host="10.0.0.2"),
        ]
        oids = ["1.3.6.1.2.1.1.1.0"]

        mock_mgr = AsyncMock()
        mock_mgr.get_many = AsyncMock(return_value=[Value.OctetString(b"test")])
        mock_mgr.__aenter__ = AsyncMock(return_value=mock_mgr)
        mock_mgr.__aexit__ = AsyncMock(return_value=None)

        with patch("snmpkit.manager.poll.Manager", return_value=mock_mgr):
            results = []
            async for r in poll_many(targets, oids):
                results.append(r)

        assert len(results) == 2
        target_strs = {r.target for r in results}
        assert "10.0.0.1:161" in target_strs
        assert "10.0.0.2:161" in target_strs

    async def test_multiple_oids(self):
        targets = [PollTarget(host="10.0.0.1")]
        oids = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0"]

        mock_mgr = AsyncMock()
        mock_mgr.get_many = AsyncMock(
            return_value=[Value.OctetString(b"Linux"), Value.TimeTicks(100)]
        )
        mock_mgr.__aenter__ = AsyncMock(return_value=mock_mgr)
        mock_mgr.__aexit__ = AsyncMock(return_value=None)

        with patch("snmpkit.manager.poll.Manager", return_value=mock_mgr):
            results = []
            async for r in poll_many(targets, oids):
                results.append(r)

        assert len(results) == 2
        oid_set = {r.oid for r in results}
        assert "1.3.6.1.2.1.1.1.0" in oid_set
        assert "1.3.6.1.2.1.1.3.0" in oid_set

    async def test_error_isolation_across_targets(self):
        """One failing target doesn't break other targets."""
        targets = [
            PollTarget(host="10.0.0.1"),  # will fail
            PollTarget(host="10.0.0.2"),  # will succeed
        ]
        oids = ["1.3.6.1.2.1.1.1.0"]

        call_count = [0]

        def make_mock(*args, **kwargs):
            idx = call_count[0]
            call_count[0] += 1
            m = AsyncMock()
            if idx == 0:
                m.__aenter__ = AsyncMock(side_effect=ConnectionRefusedError("refused"))
            else:
                m.get_many = AsyncMock(return_value=[Value.OctetString(b"ok")])
                m.__aenter__ = AsyncMock(return_value=m)
            m.__aexit__ = AsyncMock(return_value=None)
            return m

        with patch("snmpkit.manager.poll.Manager", side_effect=make_mock):
            results = []
            async for r in poll_many(targets, oids):
                results.append(r)

        assert len(results) == 2
        errors = [r for r in results if r.error is not None]
        successes = [r for r in results if r.value is not None]
        assert len(errors) == 1
        assert len(successes) == 1

    async def test_empty_targets(self):
        """poll_many with no targets yields nothing."""
        results = []
        async for r in poll_many([], ["1.3.6.1.2.1.1.1.0"]):
            results.append(r)
        assert results == []

    async def test_manager_receives_target_params(self):
        """poll_many passes all PollTarget fields to Manager."""
        targets = [
            PollTarget(
                host="10.0.0.1",
                port=1161,
                community="private",
                version=2,
                timeout=10.0,
                retries=5,
            )
        ]
        oids = ["1.3.6.1.2.1.1.1.0"]

        with patch("snmpkit.manager.poll.Manager") as MockManager:
            mock_mgr = AsyncMock()
            mock_mgr.get_many = AsyncMock(return_value=[Value.Integer(1)])
            mock_mgr.__aenter__ = AsyncMock(return_value=mock_mgr)
            mock_mgr.__aexit__ = AsyncMock(return_value=None)
            MockManager.return_value = mock_mgr

            async for _ in poll_many(targets, oids):
                pass

            MockManager.assert_called_once_with(
                host="10.0.0.1",
                port=1161,
                community="private",
                version=2,
                user=None,
                auth_protocol=None,
                auth_password=None,
                priv_protocol=None,
                priv_password=None,
                timeout=10.0,
                retries=5,
            )
