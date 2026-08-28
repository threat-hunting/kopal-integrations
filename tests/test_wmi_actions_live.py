#!/usr/bin/env python3
"""Live test of WMI actions against a real target.

Usage:
    # Set environment variables:
    export WMI_SERVER=192.168.11.62
    export WMI_USERNAME=Administrator
    export WMI_PASSWORD=your_password
    export WMI_DOMAIN=  # Optional
    
    # Run:
    python tests/test_wmi_actions_live.py
"""

import os
import sys
import time
from typing import Any

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock secrets module before importing wmi
class MockSecrets:
    def get(self, key: str) -> str | None:
        env_key = key
        val = os.environ.get(env_key)
        if val:
            return val
        return None

# Patch secrets before importing wmi
import custom_actions.wmi as wmi_module
wmi_module.secrets = MockSecrets()  # type: ignore

from custom_actions import wmi


def test_action(action_name: str, action_func: Any, *args, **kwargs) -> tuple[bool, dict[str, Any], float]:
    """Test a single action and return (success, result, duration_seconds)."""
    print(f"\n{'='*70}")
    print(f"Testing: {action_name}")
    print(f"{'='*70}")
    print(f"Args: {args}")
    print(f"Kwargs: {kwargs}")
    
    start_time = time.time()
    try:
        result = action_func(*args, **kwargs)
        duration = time.time() - start_time
        
        success = result.get("success", False)
        error = result.get("error")
        data = result.get("data", {})
        
        print(f"\nDuration: {duration:.2f} seconds")
        print(f"Success: {success}")
        if error:
            print(f"Error: {error}")
        
        # Show summary if available
        if isinstance(data, dict):
            summary = data.get("summary", {})
            if summary:
                print(f"Summary: {summary}")
            
            # Show count of items if available
            for key in ["users", "services", "processes", "rows", "items", "shares", "hotfixes"]:
                if key in data:
                    items = data[key]
                    if isinstance(items, list):
                        print(f"Returned {len(items)} {key}")
                        if len(items) > 0 and len(items) <= 3:
                            print(f"  Sample: {items[0]}")
                        break
        
        return success, result, duration
    except Exception as e:
        duration = time.time() - start_time
        print(f"\nDuration: {duration:.2f} seconds")
        print(f"EXCEPTION: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False, {"error": str(e), "exception_type": type(e).__name__}, duration


def main():
    """Test all WMI actions."""
    # Get target from env
    target = os.environ.get("WMI_SERVER", "192.168.11.62")
    username = os.environ.get("WMI_USERNAME", "")
    password = os.environ.get("WMI_PASSWORD", "")
    
    if not username or not password:
        print("ERROR: WMI_USERNAME and WMI_PASSWORD environment variables are required")
        print("Example:")
        print("  export WMI_SERVER=192.168.11.62")
        print("  export WMI_USERNAME=Administrator")
        print("  export WMI_PASSWORD=your_password")
        sys.exit(1)
    
    print(f"Target: {target}")
    print(f"Username: {username}")
    print(f"Password: {'*' * len(password)}")
    
    results = []
    
    # Test actions one by one
    test_cases = [
        ("test_connectivity", wmi.test_connectivity, {"ip_hostname": target, "namespace": None}),
        ("list_services", wmi.list_services, {"ip_hostname": target, "namespace": None}),
        ("get_system_info", wmi.get_system_info, {"ip_hostname": target, "namespace": None}),
        ("list_users", wmi.list_users, {"ip_hostname": target, "namespace": None}),
        ("run_query (simple)", wmi.run_query, {"query": "SELECT Name, State FROM Win32_Service WHERE State = 'Running'", "ip_hostname": target, "namespace": None}),
        ("list_processes", wmi.list_processes, {"ip_hostname": target, "namespace": None}),
        ("list_logical_disks", wmi.list_logical_disks, {"ip_hostname": target, "namespace": None}),
        ("get_network_adapters", wmi.get_network_adapters, {"ip_hostname": target, "namespace": None}),
        ("get_startup_commands", wmi.get_startup_commands, {"ip_hostname": target, "namespace": None}),
        ("get_environment_variables", wmi.get_environment_variables, {"ip_hostname": target, "namespace": None}),
        ("get_physical_memory", wmi.get_physical_memory, {"ip_hostname": target, "namespace": None}),
        ("get_processor_info", wmi.get_processor_info, {"ip_hostname": target, "namespace": None}),
        ("get_bios_info", wmi.get_bios_info, {"ip_hostname": target, "namespace": None}),
        ("get_timezone_info", wmi.get_timezone_info, {"ip_hostname": target, "namespace": None}),
        ("get_share_info", wmi.get_share_info, {"ip_hostname": target, "namespace": None}),
        ("get_installed_hotfixes", wmi.get_installed_hotfixes, {"ip_hostname": target, "namespace": None}),
        ("get_scheduled_jobs", wmi.get_scheduled_jobs, {"ip_hostname": target, "namespace": None}),
        ("get_event_log_metadata", wmi.get_event_log_metadata, {"ip_hostname": target, "namespace": None}),
        ("get_pagefile_info", wmi.get_pagefile_info, {"ip_hostname": target, "namespace": None}),
        ("get_printer_info", wmi.get_printer_info, {"ip_hostname": target, "namespace": None}),
        ("get_driver_info", wmi.get_driver_info, {"ip_hostname": target, "namespace": None}),
        ("get_anti_virus_product", wmi.get_anti_virus_product, {"ip_hostname": target, "namespace": None}),
        ("list_serial_ports", wmi.list_serial_ports, {"ip_hostname": target, "namespace": None}),
    ]
    
    # Skip get_installed_software - it's very slow (Win32_Product)
    
    for test_name, action_func, kwargs in test_cases:
        success, result, duration = test_action(test_name, action_func, **kwargs)
        results.append({
            "name": test_name,
            "success": success,
            "duration": duration,
            "error": result.get("error") if not success else None,
        })
        
        # If action takes more than 30 seconds, warn
        if duration > 30:
            print(f"\nWARNING: {test_name} took {duration:.2f} seconds (very slow!)")
        
        # If action failed, show details
        if not success:
            print(f"\nFAILED: {test_name}")
            error = result.get("error", "Unknown error")
            print(f"   Error: {error}")
        
        time.sleep(1)  # Small delay between tests
    
    # Summary
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    
    total = len(results)
    passed = sum(1 for r in results if r["success"])
    failed = total - passed
    total_time = sum(r["duration"] for r in results)
    avg_time = total_time / total if total > 0 else 0
    
    print(f"Total actions: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Total time: {total_time:.2f} seconds")
    print(f"Average time: {avg_time:.2f} seconds")
    
    # Show slow actions
    slow_actions = [r for r in results if r["duration"] > 10]
    if slow_actions:
        print(f"\nSlow actions (>10s):")
        for r in sorted(slow_actions, key=lambda x: x["duration"], reverse=True):
            print(f"  {r['name']}: {r['duration']:.2f}s")
    
    # Show failed actions
    if failed > 0:
        print(f"\nFailed actions:")
        for r in results:
            if not r["success"]:
                print(f"  {r['name']}: {r['error']}")
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
