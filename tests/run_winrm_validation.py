#!/usr/bin/env python3
"""Run WinRM output structure validation without pytest.

Usage (from repo root):
  uv run python tests/run_winrm_validation.py
  python tests/run_winrm_validation.py   # if custom_actions is installed or PYTHONPATH=.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

# Allow importing custom_actions from repo root
sys.path.insert(0, ".")

from tests.kopal_registry_stub import ensure_kopal_registry_stub

ensure_kopal_registry_stub()


def main() -> int:
    from custom_actions import winrm

    required_keys = {"success", "data", "error", "meta"}
    meta_keys = {"action", "timestamp"}
    errors: list[str] = []

    def check_shape(out: dict, action_name: str) -> None:
        if not isinstance(out, dict):
            errors.append(f"{action_name}: result is not a dict")
            return
        missing = required_keys - set(out.keys())
        if missing:
            errors.append(f"{action_name}: missing keys {missing}")
        if "meta" in out:
            if not meta_keys.issubset(set(out["meta"].keys())):
                errors.append(f"{action_name}: meta missing keys {meta_keys - set(out.get('meta', {}).keys())}")
        if "action" in out.get("meta", {}) and "integrations.soclib.winrm" not in out["meta"]["action"]:
            errors.append(f"{action_name}: meta.action should contain integrations.soclib.winrm")

    with patch("custom_actions.winrm.secrets") as m:
        m.get.side_effect = lambda key: {
            "WINRM_USERNAME": "u",
            "WINRM_PASSWORD": "p",
            "WINRM_TRANSPORT": "ntlm",
            "WINRM_ENDPOINT": "192.168.1.10",
            "WINRM_PROTOCOL": "http",
            "WINRM_PORT": "5985",
        }.get(key, "")

        # test_connectivity (will fail connection; we only check shape)
        out = winrm.test_connectivity(ip_hostname=None)
        check_shape(out, "test_connectivity")

        # run_command missing command
        out = winrm.run_command(command="", ip_hostname=None)
        check_shape(out, "run_command")
        if out.get("success") is not False:
            errors.append("run_command(empty): expected success=False")

        # run_command with mock
        fake = MagicMock()
        fake.status_code = 0
        fake.std_out = b"ok"
        fake.std_err = b""
        with patch("custom_actions.winrm._get_winrm") as m_get:
            m_get.return_value.Session.return_value.run_cmd.return_value = fake
            out = winrm.run_command(command="whoami", ip_hostname="127.0.0.1")
        check_shape(out, "run_command(mock)")
        if out.get("success") and ("status_code" not in out.get("data", {})):
            errors.append("run_command(mock): data should contain status_code")

        # run_script missing script
        out = winrm.run_script(script_str="", ip_hostname=None)
        check_shape(out, "run_script")

        # list_processes with mock
        with patch("custom_actions.winrm._get_winrm") as m_get:
            fake.std_out = b'[{"name":"x","pid":1}]'
            fake.std_err = b""
            m_get.return_value.Session.return_value.run_ps.return_value = fake
            out = winrm.list_processes(ip_hostname="127.0.0.1")
        check_shape(out, "list_processes")
        if out.get("success") and ("processes" not in out.get("data", {})):
            errors.append("list_processes: data should contain processes")

        # terminate_process missing pid/name
        out = winrm.terminate_process(pid=None, name=None, ip_hostname=None)
        check_shape(out, "terminate_process")
        if out.get("success") is not False:
            errors.append("terminate_process(no pid/name): expected success=False")

    if errors:
        for e in errors:
            print("FAIL:", e)
        print(f"\n{len(errors)} validation error(s).")
        return 1
    print("OK: All WinRM output structure checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
