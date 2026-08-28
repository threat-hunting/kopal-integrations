#!/usr/bin/env python3
"""Debug WMI authentication to understand access_denied issue."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dtypes import NULL
except ImportError as e:
    print(f"ERROR: impacket not installed: {e}")
    sys.exit(1)

target = os.environ.get("WMI_SERVER", "192.168.11.62")
username = os.environ.get("WMI_USERNAME", "Administrator")
password = os.environ.get("WMI_PASSWORD", "")
domain = os.environ.get("WMI_DOMAIN", "")

print(f"Target: {target}")
print(f"Username: {username}")
print(f"Domain: {domain or '(empty - will use empty string)'}")
print(f"Password: {'SET (' + str(len(password)) + ' chars)' if password else 'NOT SET'}")

if not password:
    print("\nERROR: WMI_PASSWORD not set")
    sys.exit(1)

# Try different domain formats
domain_variants = [
    ("", "Empty string"),
    (None, "None"),
]

if domain:
    domain_variants.insert(0, (domain, f"From env: {domain}"))

for domain_val, desc in domain_variants:
    print(f"\n{'='*60}")
    print(f"Trying domain: {desc}")
    print(f"{'='*60}")
    
    try:
        # DCOMConnection signature: (self, target, username='', password='', domain='', ...)
        # So domain should be string, empty string for local
        domain_param = domain_val if domain_val is not None else ""
        
        print(f"Creating DCOMConnection with domain='{domain_param}' (type: {type(domain_param).__name__})")
        dcom = DCOMConnection(
            target,
            username,
            password,
            domain_param,
            oxidResolver=True,
        )
        print("[OK] DCOM connection created")
        
        print("Creating WMI interface...")
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        print("[OK] WMI interface created")
        
        print("Creating WMI login...")
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        print("[OK] WMI login object created")
        
        print("Logging into namespace root/cimv2...")
        namespace = "//./root/cimv2"
        iWbemServices = iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
        print("[OK] WMI login successful!")
        
        print("\nSUCCESS with domain format:", desc)
        
        # Test a simple query
        print("\nTesting query: SELECT Name FROM Win32_ComputerSystem")
        iEnum = iWbemServices.ExecQuery("SELECT Name FROM Win32_ComputerSystem")
        pEnum = iEnum.Next(0xFFFFFFFF, 1)[0]
        record = pEnum.getProperties()
        print(f"Query result: {record}")
        pEnum.RemRelease()
        iEnum.RemRelease()
        
        # Cleanup
        iWbemLevel1Login.RemRelease()
        dcom.disconnect()
        
        print("\n[SUCCESS] FULL SUCCESS - Connection and query worked!")
        sys.exit(0)
        
    except Exception as e:
        print(f"\n[FAILED] FAILED with domain format '{desc}':")
        print(f"  Error type: {type(e).__name__}")
        print(f"  Error message: {e}")
        if "access_denied" in str(e).lower() or "rpc_s_access_denied" in str(e).lower():
            print("\n  This is an authentication/permission issue:")
            print("  - Check username/password are correct")
            print("  - Check user has remote WMI access")
            print("  - Check DCOM permissions on target")
            print("  - Check firewall allows RPC (port 135) and dynamic ports")
        import traceback
        print("\n  Full traceback:")
        traceback.print_exc()
        continue

print("\n" + "="*60)
print("All domain format attempts failed")
sys.exit(1)
