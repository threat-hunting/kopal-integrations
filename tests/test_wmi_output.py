"""Tests for WMI integration: standard output structure.

Validates that WMI actions return the standard shape
{ success, data, error, meta } per doc/design/output-standards.md.

Run: uv run pytest tests/test_wmi_output.py -v
"""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, ".")


def _standard_keys() -> set[str]:
    return {"success", "data", "error", "meta"}


def _meta_keys() -> set[str]:
    return {"action", "timestamp"}


@pytest.fixture(autouse=True)
def _mock_secrets():
    """Mock secrets so WMI UDFs can run without real credentials."""
    with patch("custom_actions.wmi.secrets") as m:
        m.get.side_effect = lambda key: {
            "WMI_SERVER": "192.168.11.62",
            "WMI_USERNAME": "testuser",
            "WMI_PASSWORD": "testpass",
        }.get(key, "")
        yield m


class TestWmiOutputStructure:
    """Assert WMI actions return standard output shape."""

    def test_test_connectivity_returns_standard_shape(self, _mock_secrets):
        from custom_actions.wmi import test_connectivity

        out = test_connectivity(ip_hostname="192.168.11.62")
        assert isinstance(out, dict)
        assert set(out.keys()) >= _standard_keys()
        assert "meta" in out
        assert set(out["meta"].keys()) >= _meta_keys()
        assert "integrations.soclib.wmi" in str(out["meta"].get("action", ""))
        assert "data" in out
        if not out.get("success"):
            assert "connected" in out.get("data", {}) or "error_message" in out.get("data", {})

    def test_run_query_missing_query_returns_standard_shape(self, _mock_secrets):
        from custom_actions.wmi import run_query

        out = run_query(query="", ip_hostname="192.168.11.62")
        assert isinstance(out, dict)
        assert set(out.keys()) >= _standard_keys()
        assert out.get("success") is False
        assert "query is required" in str(out.get("error", ""))

    def test_run_query_invalid_non_select_returns_standard_shape(self, _mock_secrets):
        from custom_actions.wmi import run_query

        out = run_query(query="DELETE FROM Win32_Process", ip_hostname="192.168.11.62")
        assert isinstance(out, dict)
        assert set(out.keys()) >= _standard_keys()
        assert out.get("success") is False
        assert "SELECT" in str(out.get("error", ""))

    def test_run_query_batch_invalid_input_returns_standard_shape(self, _mock_secrets):
        from custom_actions.wmi import run_query_batch

        out = run_query_batch(queries=[], ip_hostname="192.168.11.62")
        assert isinstance(out, dict)
        assert set(out.keys()) >= _standard_keys()
        assert out.get("success") is False

    def test_list_services_shape_on_connection_failure(self, _mock_secrets):
        from custom_actions.wmi import list_services

        out = list_services(ip_hostname="192.168.11.62")
        assert isinstance(out, dict)
        assert set(out.keys()) >= _standard_keys()
        assert "data" in out
        assert out["meta"]["action"] == "integrations.soclib.wmi.list_services"
