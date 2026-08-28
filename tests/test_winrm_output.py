"""Local tests for WinRM integration: standard output structure and behaviour.

Validates that WinRM actions (Phase 1–3) return the standard shape
{ success, data, error, meta } per doc/design/output-standards.md.

Run from repo root: uv run pytest tests/test_winrm_output.py -v
Or: python -m pytest tests/test_winrm_output.py -v
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

# Ensure package is importable
sys.path.insert(0, ".")


def _standard_keys() -> set[str]:
    return {"success", "data", "error", "meta"}


def _meta_keys() -> set[str]:
    return {"action", "timestamp"}


@pytest.fixture(autouse=True)
def _mock_secrets():
    """Mock kopal_registry.secrets so UDFs can run without real credentials."""
    with patch("custom_actions.winrm.secrets") as m:
        m.get.side_effect = lambda key: {
            "WINRM_USERNAME": "testuser",
            "WINRM_PASSWORD": "testpass",
            "WINRM_TRANSPORT": "ntlm",
            "WINRM_ENDPOINT": "192.168.1.10",
            "WINRM_PROTOCOL": "http",
            "WINRM_PORT": "5985",
        }.get(key, "")
        yield m


class TestWinrmOutputStructure:
    """Assert every WinRM action returns standard output shape."""

    def test_test_connectivity_returns_standard_shape(self, _mock_secrets):
        from custom_actions.winrm import test_connectivity

        # Without real WinRM host this will fail connection; we only check shape
        out = test_connectivity(ip_hostname=None)
        assert isinstance(out, dict)
        assert set(out.keys()) >= _standard_keys()
        assert "meta" in out
        assert set(out["meta"].keys()) >= _meta_keys()
        assert "action" in out["meta"]
        assert "integrations.soclib.winrm" in out["meta"]["action"]
        assert "data" in out

    def test_run_command_missing_command_returns_standard_shape(self, _mock_secrets):
        from custom_actions.winrm import run_command

        out = run_command(command="", ip_hostname=None)
        assert isinstance(out, dict)
        assert set(out.keys()) >= _standard_keys()
        assert out["success"] is False
        assert "error" in out
        assert out["meta"]["action"] == "integrations.soclib.winrm.run_command"

    def test_run_command_success_with_mocked_session(self, _mock_secrets):
        from custom_actions.winrm import run_command

        fake_response = MagicMock()
        fake_response.status_code = 0
        fake_response.std_out = b"hostname\r\n"
        fake_response.std_err = b""
        with patch("custom_actions.winrm._get_winrm") as m_get:
            m_get.return_value.Session.return_value.run_cmd.return_value = fake_response
            out = run_command(command="hostname", ip_hostname="192.168.1.10")
        assert out["success"] is True
        assert "data" in out
        assert out["data"].get("status_code") == 0
        assert "std_out" in out["data"]
        assert "hostname" in out["data"]["std_out"]
        assert out["error"] is None

    def test_run_script_missing_script_returns_standard_shape(self, _mock_secrets):
        from custom_actions.winrm import run_script

        out = run_script(script_str="", script_file=None, ip_hostname=None)
        assert isinstance(out, dict)
        assert set(out.keys()) >= _standard_keys()
        assert out["success"] is False
        assert out["meta"]["action"] == "integrations.soclib.winrm.run_script"

    def test_run_script_success_with_mocked_session(self, _mock_secrets):
        from custom_actions.winrm import run_script

        fake_response = MagicMock()
        fake_response.status_code = 0
        fake_response.std_out = b"result"
        fake_response.std_err = b""
        with patch("custom_actions.winrm._get_winrm") as m_get:
            m_get.return_value.Session.return_value.run_ps.return_value = fake_response
            out = run_script(script_str="Write-Output 'ok'", ip_hostname="192.168.1.10")
        assert out["success"] is True
        assert out["data"].get("status_code") == 0
        assert "std_out" in out["data"]

    def test_list_processes_returns_standard_shape_with_mocked_session(self, _mock_secrets):
        from custom_actions.winrm import list_processes

        fake_response = MagicMock()
        fake_response.status_code = 0
        fake_response.std_out = b'[{"name":"System","pid":4}]'
        fake_response.std_err = b""
        with patch("custom_actions.winrm._get_winrm") as m_get:
            m_get.return_value.Session.return_value.run_ps.return_value = fake_response
            out = list_processes(ip_hostname="192.168.1.10")
        assert set(out.keys()) >= _standard_keys()
        assert out["meta"]["action"] == "integrations.soclib.winrm.list_processes"
        assert out["success"] is True
        assert "processes" in out["data"]
        assert "num_processes" in out["data"]
        assert out["data"]["num_processes"] == 1

    def test_terminate_process_missing_pid_and_name_returns_standard_shape(self, _mock_secrets):
        from custom_actions.winrm import terminate_process

        out = terminate_process(pid=None, name=None, ip_hostname=None)
        assert isinstance(out, dict)
        assert set(out.keys()) >= _standard_keys()
        assert out["success"] is False
        assert "error" in out
        assert out["meta"]["action"] == "integrations.soclib.winrm.terminate_process"

    def test_terminate_process_by_pid_with_mocked_session(self, _mock_secrets):
        from custom_actions.winrm import terminate_process

        fake_response = MagicMock()
        fake_response.status_code = 0
        fake_response.std_out = b""
        fake_response.std_err = b""
        with patch("custom_actions.winrm._get_winrm") as m_get:
            m_get.return_value.Session.return_value.run_ps.return_value = fake_response
            out = terminate_process(pid=1234, ip_hostname="192.168.1.10")
        assert out["success"] is True
        assert "data" in out
        assert out["data"].get("status_code") == 0

    def test_block_ip_missing_name_returns_standard_shape(self, _mock_secrets):
        from custom_actions.winrm import block_ip

        out = block_ip(name="", remote_ip="1.2.3.4", ip_hostname=None)
        assert set(out.keys()) >= _standard_keys()
        assert out["success"] is False
        assert out["meta"]["action"] == "integrations.soclib.winrm.block_ip"

    def test_get_file_missing_path_returns_standard_shape(self, _mock_secrets):
        from custom_actions.winrm import get_file

        out = get_file(file_path="", ip_hostname=None)
        assert set(out.keys()) >= _standard_keys()
        assert out["success"] is False

    def test_list_connections_with_mocked_session_returns_standard_shape(self, _mock_secrets):
        from custom_actions.winrm import list_connections

        fake_response = MagicMock()
        fake_response.status_code = 0
        fake_response.std_out = b'[{"protocol":"tcp","local_address_ip":"0.0.0.0","local_port":5985}]'
        fake_response.std_err = b""
        with patch("custom_actions.winrm._get_winrm") as m_get:
            m_get.return_value.Session.return_value.run_ps.return_value = fake_response
            out = list_connections(ip_hostname="192.168.1.10")
        assert out["success"] is True
        assert "connections" in out["data"]
        assert "num_connections" in out["data"]


class TestWinrmHelpers:
    """Unit tests for internal helpers (output shape)."""

    def test_standard_response_has_required_keys(self):
        from custom_actions.winrm import _standard_response

        r = _standard_response(True, data={"x": 1}, action_name="test")
        assert set(r.keys()) == _standard_keys()
        assert r["success"] is True
        assert r["data"] == {"x": 1}
        assert r["error"] is None
        assert "action" in r["meta"]
        assert "timestamp" in r["meta"]

    def test_standard_response_error(self):
        from custom_actions.winrm import _standard_response

        r = _standard_response(False, error="fail", action_name="run")
        assert r["success"] is False
        assert r["error"] == "fail"
