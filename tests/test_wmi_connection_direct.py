#!/usr/bin/env python3
"""Direct WMI connection test to debug connection issues.

Tests the actual WMI connection without going through the action wrappers.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock secrets
class MockSecrets:
    def get(self, key: str) -> str | None:
        env_key = key
        val = os.environ.get(env_key)
        if val:
            return val
        return None

import custom_actions.wmi as wmi_module
wmi_module.secrets = MockSecrets()  # type: ignore

from custom_actions import wmi


def test_direct_connection():
    """Test direct WMI connection."""
    target = os.environ.get("WMI_SERVER", "192.168.11.62")
    username = os.environ.get("WMI_USERNAME", "")
    password = os.environ.get("WMI_PASSWORD", "")
    
    print(f"Target: {target}")
    print(f"Username: {username}")
    print(f"Password: {'*' * len(password) if password else 'NOT SET'}")
    
    # Check secrets
    print("\nChecking secrets...")
    for key in ["WMI_SERVER", "WMI_USERNAME", "WMI_PASSWORD", "WMI_DOMAIN"]:
        val = wmi_module._get_secret(key, "")
        print(f"  {key}: {'SET' if val else 'NOT SET'} ({len(val)} chars)")
    
    # Get credentials
    print("\nGetting credentials...")
    username_cred, password_cred, domain_cred = wmi_module._get_credentials()
    print(f"  Username: {username_cred}")
    print(f"  Password: {'SET' if password_cred else 'NOT SET'} ({len(password_cred)} chars)")
    print(f"  Domain: {domain_cred or '(empty)'}")
    
    if not username_cred or not password_cred:
        print("\nERROR: Username or password is empty!")
        return False
    
    # Test connection
    print(f"\nTesting connection to {target}...")
    host = wmi_module._get_host(None)
    ns = wmi_module._normalize_namespace(None)
    print(f"  Host: {host}")
    print(f"  Namespace: {ns}")
    
    start = time.time()
    dcom, iWbemServices, err = wmi_module._wmi_connect(host, ns, timeout_seconds=30.0)
    duration = time.time() - start
    
    print(f"\nConnection result (took {duration:.2f}s):")
    if err:
        print(f"  ERROR: {err}")
        return False
    else:
        print("  SUCCESS: Connected!")
        if dcom:
            print("  DCOM: Connected")
        if iWbemServices:
            print("  WMI Services: Available")
        
        # Test a simple query
        print("\nTesting simple query: SELECT Name FROM Win32_ComputerSystem")
        start = time.time()
        rows, query_err = wmi_module._run_single_query(host, ns, "SELECT Name FROM Win32_ComputerSystem", connect_timeout=30.0, query_timeout=10.0, max_rows=10)
        query_duration = time.time() - start
        
        print(f"Query result (took {query_duration:.2f}s):")
        if query_err:
            print(f"  ERROR: {query_err}")
        else:
            print(f"  SUCCESS: Got {len(rows)} rows")
            if rows:
                print(f"  Sample: {rows[0]}")
        
        # Cleanup
        wmi_module._wmi_disconnect(dcom, iWbemServices)
        return True


if __name__ == "__main__":
    success = test_direct_connection()
    sys.exit(0 if success else 1)
