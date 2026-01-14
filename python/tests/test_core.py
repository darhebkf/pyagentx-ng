"""Tests for snmpkit core functionality."""

import snmpkit


def test_version():
    """Test that version is exposed."""
    assert snmpkit.__version__ == "0.1.0"


def test_import():
    """Test that package can be imported."""
    assert snmpkit is not None
