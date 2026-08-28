#!/usr/bin/env python3
"""Run WMI actions against a real target (e.g. 192.168.11.62) and validate output structure.

Set env: WMI_SERVER (default 192.168.11.62), WMI_USERNAME, WMI_PASSWORD, optionally WMI_DOMAIN.
Usage: uv run python tests/run_wmi_validation.py
"""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.kopal_registry_stub import ensure_kopal_registry_stub

ensure_kopal_registry_stub()

# Default target from user spec
DEFAULT_HOST = "192.168.11.62"


def get_secret_side_effect(key: str) -> str:
    return os.environ.get(key, "")


def main() -> int:
    from custom_actions import wmi

    host = os.environ.get("WMI_SERVER", DEFAULT_HOST)
    username = os.environ.get("WMI_USERNAME", "")
    password = os.environ.get("WMI_PASSWORD", "")

    if not username or not password:
        print("Set WMI_USERNAME and WMI_PASSWORD environment variables to run live tests.")
        print("Example: $env:WMI_SERVER='192.168.11.62'; $env:WMI_USERNAME='Administrator'; $env:WMI_PASSWORD='...'; uv run python tests/run_wmi_validation.py")
        return 1

    required_keys = {"success", "data", "error", "meta"}
    meta_keys = {"action", "timestamp"}
    errors: list[str] = []

    def check_shape(out: dict, action_name: str) -> bool:
        if not isinstance(out, dict):
            errors.append(f"{action_name}: result is not a dict")
            return False
        missing = required_keys - set(out.keys())
        if missing:
            errors.append(f"{action_name}: missing keys {missing}")
        if "meta" in out and out["meta"]:
            if not meta_keys.issubset(set(out["meta"].keys())):
                errors.append(f"{action_name}: meta missing keys {meta_keys - set(out.get('meta', {}).keys())}")
        if out.get("meta", {}).get("action") and "integrations.soclib.wmi" not in str(out["meta"].get("action", "")):
            errors.append(f"{action_name}: meta.action should contain integrations.soclib.wmi")
        return len(errors) == 0 or not any(e.startswith(action_name) for e in errors[-3:])

    with patch("custom_actions.wmi.secrets") as m:
        m.get.side_effect = lambda k: os.environ.get(k, "")

        actions: list[tuple[str, dict, str]] = [
            ("test_connectivity", {"ip_hostname": host}, "connected or error_message"),
            ("list_services", {"ip_hostname": host}, "services, summary"),
            ("get_system_info", {"ip_hostname": host}, "system_details, os_details, summary"),
            ("list_users", {"ip_hostname": host}, "users, summary"),
            ("run_query", {"query": "SELECT * FROM Win32_Process", "ip_hostname": host}, "rows"),
            ("list_processes", {"ip_hostname": host, "max_count": 5}, "processes, summary"),
            ("list_logical_disks", {"ip_hostname": host}, "logical_disks"),
            ("get_network_adapters", {"ip_hostname": host}, "adapters"),
            ("get_startup_commands", {"ip_hostname": host}, "startup_commands"),
            ("get_environment_variables", {"ip_hostname": host}, "variables"),
            ("get_physical_memory", {"ip_hostname": host}, "memory_modules"),
            ("get_processor_info", {"ip_hostname": host}, "processors"),
            ("get_bios_info", {"ip_hostname": host}, "bios_info"),
            ("get_timezone_info", {"ip_hostname": host}, "timezone_info"),
            ("get_share_info", {"ip_hostname": host}, "shares"),
            ("get_installed_hotfixes", {"ip_hostname": host}, "hotfixes"),
            ("get_scheduled_jobs", {"ip_hostname": host}, "jobs"),
            ("get_event_log_metadata", {"ip_hostname": host}, "log_files"),
            ("get_pagefile_info", {"ip_hostname": host}, "pagefiles"),
            ("get_printer_info", {"ip_hostname": host}, "printers"),
            ("get_driver_info", {"ip_hostname": host}, "drivers"),
            ("list_serial_ports", {"ip_hostname": host}, "serial_ports"),
            ("run_query_batch", {"queries": [{"name": "p", "query": "SELECT ProcessId, Name FROM Win32_Process"}], "ip_hostname": host}, "results"),
        ]

        for action_name, kwargs, expected_in_data in actions:
            fn = getattr(wmi, action_name, None)
            if fn is None:
                errors.append(f"{action_name}: function not found")
                continue
            try:
                out = fn(**kwargs)
            except Exception as e:
                errors.append(f"{action_name}: exception {e}")
                print(f"  {action_name}: EXCEPTION {e}")
                continue
            check_shape(out, action_name)
            if out.get("success"):
                data = out.get("data") or {}
                if expected_in_data and not any(k in data for k in expected_in_data.split(", ")):
                    errors.append(f"{action_name}: expected one of [{expected_in_data}] in data, got keys {list(data.keys())[:8]}")
                print(f"  {action_name}: OK (success=True, data keys: {list(data.keys())[:6]})")
            else:
                print(f"  {action_name}: FAIL success=False error={out.get('error', '')[:80]}")
                if out.get("data"):
                    print(f"    data keys: {list((out.get('data') or {}).keys())}")

        # get_anti_virus_product uses different namespace (SecurityCenter2) - may fail on some hosts
        try:
            out = wmi.get_anti_virus_product(ip_hostname=host)
            check_shape(out, "get_anti_virus_product")
            if out.get("success"):
                print("  get_anti_virus_product: OK")
            else:
                print(f"  get_anti_virus_product: {out.get('error', '')[:60]} (may be expected if SecurityCenter2 not available)")
        except Exception as e:
            print(f"  get_anti_virus_product: EXCEPTION {e}")

        # get_file_properties needs a path that exists
        try:
            out = wmi.get_file_properties(path="C:\\Windows\\System32\\kernel32.dll", ip_hostname=host)
            check_shape(out, "get_file_properties")
            if out.get("success") and (out.get("data") or {}).get("file_properties"):
                print("  get_file_properties: OK")
            else:
                print(f"  get_file_properties: success={out.get('success')} (path may not exist)")
        except Exception as e:
            errors.append(f"get_file_properties: exception {e}")
            print(f"  get_file_properties: EXCEPTION {e}")

    if errors:
        print("\nErrors:")
        for e in errors:
            print("  -", e)
        return 1
    print("\nAll output shapes validated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
