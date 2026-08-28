#!/usr/bin/env python3
"""Test list_users timing to identify performance issues."""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class MockSecrets:
    def get(self, key: str) -> str | None:
        return os.environ.get(key)

import custom_actions.wmi as wmi_module
wmi_module.secrets = MockSecrets()  # type: ignore

from custom_actions import wmi

target = os.environ.get("WMI_SERVER", "192.168.11.62")
username = os.environ.get("WMI_USERNAME", "")
password = os.environ.get("WMI_PASSWORD", "")

print(f"Testing list_users on {target}")
print(f"Username: {username}")
print(f"Password: {'SET' if password else 'NOT SET'}\n")

if not username or not password:
    print("ERROR: Set WMI_USERNAME and WMI_PASSWORD environment variables")
    sys.exit(1)

# Test with different max_count values
for max_count in [10, 50, 100, None]:
    print(f"\n{'='*60}")
    print(f"Testing with max_count={max_count}")
    print(f"{'='*60}")
    
    start = time.time()
    try:
        result = wmi.list_users(ip_hostname=target, namespace=None, max_count=max_count)
        duration = time.time() - start
        
        success = result.get("success", False)
        error = result.get("error")
        data = result.get("data", {})
        
        print(f"Duration: {duration:.2f} seconds")
        print(f"Success: {success}")
        
        if success:
            users = data.get("users", [])
            summary = data.get("summary", {})
            print(f"Users returned: {len(users)}")
            print(f"Summary: {summary}")
        else:
            print(f"Error: {error}")
            
        if duration > 30:
            print(f"WARNING: Took {duration:.2f} seconds (very slow!)")
            
    except Exception as e:
        duration = time.time() - start
        print(f"Duration: {duration:.2f} seconds")
        print(f"EXCEPTION: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    
    time.sleep(2)  # Small delay between tests

print("\n" + "="*60)
print("Test completed")
