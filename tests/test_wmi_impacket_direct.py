#!/usr/bin/env python3
"""Direct impacket WMI test to understand the connection issue."""

import os
import sys

try:
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dtypes import NULL
except ImportError as e:
    print(f"ERROR: impacket not installed: {e}")
    print("Install with: pip install impacket")
    sys.exit(1)

target = os.environ.get("WMI_SERVER", "192.168.11.62")
username = os.environ.get("WMI_USERNAME", "Administrator")
password = os.environ.get("WMI_PASSWORD", "")
domain = os.environ.get("WMI_DOMAIN", "")

print(f"Target: {target}")
print(f"Username: {username}")
print(f"Domain: {domain or '(empty)'}")
print(f"Password: {'SET' if password else 'NOT SET'}")

if not password:
    print("ERROR: WMI_PASSWORD not set")
    sys.exit(1)

try:
    print("\nCreating DCOM connection...")
    # Domain must be None (not empty string) for local/workgroup
    domain_param = domain.strip() if domain and domain.strip() else None
    dcom = DCOMConnection(
        target,
        username,
        password,
        domain_param,
        oxidResolver=True,
    )
    print("DCOM connection created successfully")
    
    print("\nCreating WMI interface...")
    iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
    print("WMI interface created")
    
    print("\nCreating WMI login...")
    iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
    print("WMI login created")
    
    print("\nLogging into WMI namespace root/cimv2...")
    namespace = "//./root/cimv2"
    iWbemServices = iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
    print("WMI login successful!")
    
    print("\nTesting query: SELECT Name FROM Win32_ComputerSystem")
    iEnum = iWbemServices.ExecQuery("SELECT Name FROM Win32_ComputerSystem")
    print("Query executed")
    
    row_count = 0
    while True:
        try:
            pEnum = iEnum.Next(0xFFFFFFFF, 1)[0]
            record = pEnum.getProperties()
            print(f"Row {row_count + 1}: {record}")
            pEnum.RemRelease()
            row_count += 1
            if row_count >= 5:  # Limit to 5 rows
                break
        except Exception as e:
            if "S_FALSE" in str(e):
                break
            raise
    
    print(f"\nGot {row_count} rows")
    
    # Cleanup
    iEnum.RemRelease()
    iWbemLevel1Login.RemRelease()
    dcom.disconnect()
    
    print("\nSUCCESS: Connection and query worked!")
    
except Exception as e:
    print(f"\nERROR: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
