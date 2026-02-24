"""Tests for TrapFilter."""

from __future__ import annotations

from snmpkit.core import Oid, SnmpVarBind, Value, encode_snmp_trap_v2c
from snmpkit.manager.trap_filter import TrapFilter
from snmpkit.manager.trap_receiver import TrapMessage, TrapReceiver


def _make_trap(
    source: str = "192.168.1.1",
    community: str = "public",
    trap_oid: str = "1.3.6.1.4.1.99.0.1",
) -> TrapMessage:
    return TrapMessage(
        source=(source, 5000),
        version=1,
        community=community,
        pdu_type=0xA7,
        request_id=1,
        trap_oid=trap_oid,
        uptime=0,
        varbinds=[],
    )


class TestTrapFilterNoConditions:
    def test_empty_filter_accepts_all(self):
        filt = TrapFilter()
        assert filt.matches(_make_trap()) is True

    def test_empty_filter_accepts_any_source(self):
        filt = TrapFilter()
        assert filt.matches(_make_trap(source="10.0.0.1")) is True


class TestTrapFilterAllowedSources:
    def test_allowed_source_matches(self):
        filt = TrapFilter(allowed_sources=["192.168.1.1"])
        assert filt.matches(_make_trap(source="192.168.1.1")) is True

    def test_disallowed_source_rejected(self):
        filt = TrapFilter(allowed_sources=["192.168.1.1"])
        assert filt.matches(_make_trap(source="10.0.0.1")) is False

    def test_multiple_allowed_sources(self):
        filt = TrapFilter(allowed_sources=["192.168.1.1", "10.0.0.1"])
        assert filt.matches(_make_trap(source="192.168.1.1")) is True
        assert filt.matches(_make_trap(source="10.0.0.1")) is True
        assert filt.matches(_make_trap(source="172.16.0.1")) is False


class TestTrapFilterDeniedSources:
    def test_denied_source_rejected(self):
        filt = TrapFilter(denied_sources=["10.0.0.1"])
        assert filt.matches(_make_trap(source="10.0.0.1")) is False

    def test_non_denied_source_accepted(self):
        filt = TrapFilter(denied_sources=["10.0.0.1"])
        assert filt.matches(_make_trap(source="192.168.1.1")) is True

    def test_deny_takes_precedence_over_allow(self):
        filt = TrapFilter(
            allowed_sources=["10.0.0.1"],
            denied_sources=["10.0.0.1"],
        )
        assert filt.matches(_make_trap(source="10.0.0.1")) is False


class TestTrapFilterAllowedCommunities:
    def test_allowed_community_matches(self):
        filt = TrapFilter(allowed_communities=["public"])
        assert filt.matches(_make_trap(community="public")) is True

    def test_disallowed_community_rejected(self):
        filt = TrapFilter(allowed_communities=["public"])
        assert filt.matches(_make_trap(community="private")) is False

    def test_multiple_communities(self):
        filt = TrapFilter(allowed_communities=["public", "monitored"])
        assert filt.matches(_make_trap(community="public")) is True
        assert filt.matches(_make_trap(community="monitored")) is True
        assert filt.matches(_make_trap(community="secret")) is False


class TestTrapFilterOidPrefix:
    def test_exact_oid_matches(self):
        filt = TrapFilter(allowed_oid_prefixes=["1.3.6.1.4.1.99.0.1"])
        assert filt.matches(_make_trap(trap_oid="1.3.6.1.4.1.99.0.1")) is True

    def test_prefix_matches(self):
        filt = TrapFilter(allowed_oid_prefixes=["1.3.6.1.4.1.99"])
        assert filt.matches(_make_trap(trap_oid="1.3.6.1.4.1.99.0.1")) is True

    def test_no_false_prefix_match(self):
        """1.3.6.1.4 must NOT match 1.3.6.1.40 (string prefix would)."""
        filt = TrapFilter(allowed_oid_prefixes=["1.3.6.1.4"])
        assert filt.matches(_make_trap(trap_oid="1.3.6.1.40.1")) is False

    def test_different_subtree_rejected(self):
        filt = TrapFilter(allowed_oid_prefixes=["1.3.6.1.4.1.100"])
        assert filt.matches(_make_trap(trap_oid="1.3.6.1.4.1.99.0.1")) is False

    def test_multiple_prefixes(self):
        filt = TrapFilter(allowed_oid_prefixes=["1.3.6.1.4.1.99", "1.3.6.1.4.1.100"])
        assert filt.matches(_make_trap(trap_oid="1.3.6.1.4.1.99.0.1")) is True
        assert filt.matches(_make_trap(trap_oid="1.3.6.1.4.1.100.5")) is True
        assert filt.matches(_make_trap(trap_oid="1.3.6.1.4.1.200")) is False


class TestTrapFilterOrLogic:
    def test_source_or_community(self):
        filt = TrapFilter(
            allowed_sources=["192.168.1.1"],
            allowed_communities=["monitored"],
        )
        # Matches source
        assert filt.matches(_make_trap(source="192.168.1.1", community="other")) is True
        # Matches community
        assert filt.matches(_make_trap(source="10.0.0.1", community="monitored")) is True
        # Matches neither
        assert filt.matches(_make_trap(source="10.0.0.1", community="other")) is False

    def test_all_conditions_or(self):
        filt = TrapFilter(
            allowed_sources=["192.168.1.1"],
            allowed_communities=["public"],
            allowed_oid_prefixes=["1.3.6.1.4.1.99"],
        )
        # Only OID matches
        assert (
            filt.matches(
                _make_trap(source="10.0.0.1", community="other", trap_oid="1.3.6.1.4.1.99.0.1")
            )
            is True
        )


class TestTrapReceiverWithFilters:
    def _make_trap_data(self, trap_oid: str = "1.3.6.1.4.1.99.0.1") -> bytes:
        vbs = [
            SnmpVarBind(Oid("1.3.6.1.2.1.1.3.0"), Value.TimeTicks(100)),
            SnmpVarBind(
                Oid("1.3.6.1.6.3.1.1.4.1.0"),
                Value.ObjectIdentifier(Oid(trap_oid)),
            ),
        ]
        return encode_snmp_trap_v2c("public", 1, vbs)

    def test_no_filters_accepts_all(self):
        receiver = TrapReceiver()
        receiver._handle_datagram(self._make_trap_data(), ("10.0.0.1", 5000))
        assert receiver._queue.qsize() == 1

    def test_filter_accepts_matching(self):
        receiver = TrapReceiver()
        receiver.add_filter(TrapFilter(allowed_sources=["10.0.0.1"]))
        receiver._handle_datagram(self._make_trap_data(), ("10.0.0.1", 5000))
        assert receiver._queue.qsize() == 1

    def test_filter_rejects_non_matching(self):
        receiver = TrapReceiver()
        receiver.add_filter(TrapFilter(allowed_sources=["192.168.1.1"]))
        receiver._handle_datagram(self._make_trap_data(), ("10.0.0.1", 5000))
        assert receiver._queue.qsize() == 0

    def test_filter_by_oid_prefix(self):
        receiver = TrapReceiver()
        receiver.add_filter(TrapFilter(allowed_oid_prefixes=["1.3.6.1.4.1.99"]))
        receiver._handle_datagram(self._make_trap_data("1.3.6.1.4.1.99.0.1"), ("10.0.0.1", 5000))
        receiver._handle_datagram(self._make_trap_data("1.3.6.1.4.1.200.0.1"), ("10.0.0.2", 5000))
        assert receiver._queue.qsize() == 1

    def test_denied_source_filter(self):
        receiver = TrapReceiver()
        receiver.add_filter(TrapFilter(denied_sources=["10.0.0.1"]))
        receiver._handle_datagram(self._make_trap_data(), ("10.0.0.1", 5000))
        receiver._handle_datagram(self._make_trap_data(), ("10.0.0.2", 5000))
        assert receiver._queue.qsize() == 1

    def test_multiple_filters_or_logic(self):
        receiver = TrapReceiver()
        receiver.add_filter(TrapFilter(allowed_sources=["10.0.0.1"]))
        receiver.add_filter(TrapFilter(allowed_sources=["10.0.0.2"]))
        receiver._handle_datagram(self._make_trap_data(), ("10.0.0.1", 5000))
        receiver._handle_datagram(self._make_trap_data(), ("10.0.0.2", 5000))
        receiver._handle_datagram(self._make_trap_data(), ("10.0.0.3", 5000))
        assert receiver._queue.qsize() == 2


class TestTrapFilterExport:
    def test_importable_from_package(self):
        from snmpkit.manager import TrapFilter as TF

        assert TF is TrapFilter
