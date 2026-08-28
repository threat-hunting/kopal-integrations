"""SOCLib WMI integration — integrations.soclib.wmi (engine UDFs).

Standalone WMI over DCOM (impacket). No dependency on WinRM or other integrations.
All actions return standard output: { success, data, error, meta }.
UDF namespace: integrations.soclib.wmi.
Templates: tools.soclib.wmi.
"""

from __future__ import annotations

import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime, timezone
from typing import Annotated, Any

from kopal_registry import RegistrySecret, registry, secrets
from typing_extensions import Doc

ACTION_NAMESPACE = "integrations.soclib.wmi"
DISPLAY_GROUP = "SOCLib / WMI"

wmi_secret = RegistrySecret(
    name="soclib_wmi",
    keys=["WMI_SERVER", "WMI_USERNAME", "WMI_PASSWORD"],
    optional_keys=["WMI_FORCE_NTLMV2", "WMI_NAMESPACE", "WMI_DOMAIN"],
)


def _connection_info(host: str, namespace: str) -> dict[str, Any]:
    """Build connection context for responses (target, namespace, method)."""
    ns_display = namespace.replace("//./", "").replace("/", "\\") if namespace else ""
    return {
        "target": host or "",
        "namespace": ns_display or "root/cimv2",
        "method": "DCOM/WMI",
        "transport": "RPC/DCOM",
    }


def _standard_response(
    success: bool,
    data: Any = None,
    error: str | None = None,
    action_name: str = "",
    connection: dict[str, Any] | None = None,
    error_details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Standard output: success, data, error, meta. Optionally include connection and error_details in meta and data."""
    payload = data if data is not None else {}
    if isinstance(payload, dict):
        payload = dict(payload)
    meta: dict[str, Any] = {
        "action": f"{ACTION_NAMESPACE}.{action_name}" if action_name else ACTION_NAMESPACE,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if connection:
        meta["connection"] = connection
        if success:
            payload["connection"] = connection
    if not success and error_details:
        meta["error_details"] = error_details
        if isinstance(payload, dict):
            payload["error_details"] = error_details
    return {
        "success": success,
        "data": payload,
        "error": error,
        "meta": meta,
    }


def _get_secret(key: str, default: str = "") -> str:
    """Get secret value by key. Returns default if not found or empty."""
    try:
        val = secrets.get(key)
        if val is None:
            return default
        val_str = str(val).strip()
        return val_str if val_str else default
    except Exception as e:
        # Log the exception for debugging but return default
        # In production, secrets.get() should work if secret is properly configured
        return default


def _normalize_namespace(ns: str | None) -> str:
    if not (ns or "").strip():
        ns = _get_secret("WMI_NAMESPACE", "root/cimv2").strip() or "root/cimv2"
    else:
        ns = ns.strip()
    if not ns.startswith("//"):
        ns = "//./" + ns.replace("\\", "/").lstrip("/")
    return ns


def _get_host(ip_hostname: str | None) -> str:
    """Get target host from input or secret."""
    if ip_hostname and ip_hostname.strip():
        return ip_hostname.strip()
    return _get_secret("WMI_SERVER", "").strip()


def _get_credentials() -> tuple[str, str, str]:
    """Get WMI credentials from secrets. Returns (username, password, domain)."""
    username = _get_secret("WMI_USERNAME", "")
    password = _get_secret("WMI_PASSWORD", "")
    domain = _get_secret("WMI_DOMAIN", "").strip()
    
    # Support domain\username format
    if "\\" in username:
        domain_part, _, username_part = username.partition("\\")
        if domain_part:
            domain = domain_part.strip()
        username = username_part.strip()
    
    return username, password, domain


def _check_secrets_available() -> dict[str, bool]:
    """Check which secret keys are available. Returns dict of key -> is_available."""
    result = {}
    for key in ["WMI_SERVER", "WMI_USERNAME", "WMI_PASSWORD", "WMI_DOMAIN", "WMI_NAMESPACE"]:
        try:
            val = secrets.get(key)
            result[key] = val is not None and str(val).strip() != ""
        except Exception:
            result[key] = False
    return result


# Lazy-load impacket
_impacket_dcom: Any = None
_impacket_wmi: Any = None
_impacket_dtypes: Any = None


def _get_impacket() -> tuple[Any, Any, Any]:
    global _impacket_dcom, _impacket_wmi, _impacket_dtypes
    if _impacket_dcom is None:
        try:
            from impacket.dcerpc.v5.dcomrt import DCOMConnection
            from impacket.dcerpc.v5.dcom import wmi
            from impacket.dcerpc.v5.dtypes import NULL
            _impacket_dcom = DCOMConnection
            _impacket_wmi = wmi
            _impacket_dtypes = NULL
        except ImportError as e:
            raise RuntimeError("impacket is not installed; pip install impacket") from e
    return _impacket_dcom, _impacket_wmi, _impacket_dtypes


def _flatten_record(record: dict) -> dict[str, Any]:
    """Convert impacket getProperties() format to plain key->value."""
    out: dict[str, Any] = {}
    for key, val in record.items():
        if isinstance(val, dict) and "value" in val:
            v = val["value"]
        else:
            v = val
        if isinstance(v, list) and len(v) == 1:
            v = v[0]
        out[key] = v
    return out


class _TimeoutError(Exception):
    """Raised when a WMI operation exceeds the timeout."""
    pass


def _run_with_timeout(func, timeout_seconds: float, *args, **kwargs):
    """Run a function with timeout using ThreadPoolExecutor. Raises _TimeoutError if timeout exceeded."""
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(func, *args, **kwargs)
        try:
            return future.result(timeout=timeout_seconds)
        except FutureTimeoutError:
            # Note: The thread may still be running, but we return timeout error
            raise _TimeoutError(f"Operation timed out after {timeout_seconds} seconds")


def _wmi_connect(host: str, namespace: str, timeout_seconds: float = 30.0) -> tuple[Any, Any, str | None]:
    """Returns (dcom, iWbemServices, error_message). On success error is None."""
    if not host:
        return None, None, "WMI_SERVER or ip_hostname is required"
    
    # Get credentials BEFORE timeout wrapper to ensure secrets are read in main thread
    username, password, domain = _get_credentials()
    if not username or not password:
        # Check which secrets are available for better error message
        available = _check_secrets_available()
        missing = [k for k in ["WMI_USERNAME", "WMI_PASSWORD"] if not available.get(k, False)]
        if missing:
            return None, None, f"Missing required secret keys: {', '.join(missing)}. Please configure secret 'soclib_wmi' in Kopal with keys: WMI_SERVER, WMI_USERNAME, WMI_PASSWORD (and optionally WMI_DOMAIN, WMI_NAMESPACE)."
        else:
            return None, None, "WMI_USERNAME and WMI_PASSWORD are required but appear to be empty. Please check that secret 'soclib_wmi' has non-empty values for WMI_USERNAME and WMI_PASSWORD."
    
    try:
        def _connect():
            DCOMConnection, wmi_mod, NULL = _get_impacket()
            # DCOMConnection expects domain as string (empty string for local/workgroup, not None)
            domain_param = domain.strip() if domain and domain.strip() else ""
            dcom = DCOMConnection(
                host,
                username,
                password,
                domain_param,  # Empty string for local/workgroup, domain name for domain auth
                oxidResolver=True,
            )
            
            iInterface = dcom.CoCreateInstanceEx(wmi_mod.CLSID_WbemLevel1Login, wmi_mod.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi_mod.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
            iWbemLevel1Login.RemRelease()
            return dcom, iWbemServices, None

        dcom, iWbemServices, err = _run_with_timeout(_connect, timeout_seconds)
        return dcom, iWbemServices, err
    except _TimeoutError as e:
        return None, None, f"Connection timeout: {str(e)}"
    except Exception as e:
        msg = str(e)
        if "impacket" in msg.lower() and "not installed" in msg.lower():
            return None, None, msg
        # For rpc_s_access_denied, provide more context
        if "access_denied" in msg.lower() or "rpc_s_access_denied" in msg.lower():
            return None, None, f"rpc_s_access_denied: WMI/DCOM authentication failed. Check username/password, user permissions, DCOM settings, and firewall. See error_details.guidance for detailed troubleshooting steps."
        return None, None, msg


def _wmi_query(iWbemServices: Any, wql: str, timeout_seconds: float = 120.0, max_rows: int = 10000) -> list[dict[str, Any]]:
    """Execute WQL and return list of flattened record dicts. Has timeout and max_rows limit."""
    wmi_mod = _get_impacket()[1]
    wql = (wql or "").strip()
    if not wql.rstrip(";").strip():
        return []
    if wql.endswith(";"):
        wql = wql[:-1].strip()
    if not re.match(r"^\s*SELECT\s+", wql, re.IGNORECASE):
        return []

    rows_container: list[dict[str, Any]] = []

    def _query():
        nonlocal rows_container
        iEnum = iWbemServices.ExecQuery(wql)
        row_count = 0
        batch_size = 50  # Fetch multiple rows at once for better performance (reduced from 100 for stability)
        try:
            while row_count < max_rows:
                try:
                    # Fetch batch_size rows at once (or remaining if less)
                    remaining = max_rows - row_count
                    fetch_count = min(batch_size, remaining)
                    enum_results = iEnum.Next(0xFFFFFFFF, fetch_count)
                    
                    if not enum_results or len(enum_results) == 0:
                        break
                    
                    for pEnum in enum_results:
                        if row_count >= max_rows:
                            break
                        try:
                            record = pEnum.getProperties()
                            rows_container.append(_flatten_record(record))
                            row_count += 1
                        finally:
                            pEnum.RemRelease()
                except Exception as e:
                    err_str = str(e)
                    if "S_FALSE" in err_str or "WBEM_S_FALSE" in err_str:
                        # No more rows
                        break
                    # Re-raise other exceptions
                    raise
        finally:
            try:
                iEnum.RemRelease()
            except Exception:
                pass  # Ignore cleanup errors
        return rows_container

    try:
        return _run_with_timeout(_query, timeout_seconds)
    except _TimeoutError:
        # Return partial results if timeout occurred
        return rows_container.copy() if rows_container else []


def _wmi_disconnect(dcom: Any, iWbemServices: Any) -> None:
    try:
        if iWbemServices is not None:
            iWbemServices.RemRelease()
    except Exception:
        pass
    try:
        if dcom is not None:
            dcom.disconnect()
    except Exception:
        pass


def _run_single_query(host: str, namespace: str, wql: str, connect_timeout: float = 30.0, query_timeout: float = 120.0, max_rows: int = 10000) -> tuple[list[dict[str, Any]], str | None]:
    """Run one WQL query. Returns (rows, error_message). Has timeouts to prevent hanging.
    
    Args:
        host: Target hostname/IP
        namespace: WMI namespace
        wql: WQL SELECT query
        connect_timeout: Timeout for DCOM connection (seconds)
        query_timeout: Timeout for query execution (seconds)
        max_rows: Maximum number of rows to fetch (prevents memory issues)
    """
    """Run one WQL query. Returns (rows, error_message). Has timeouts to prevent hanging."""
    dcom, iWbemServices, err = _wmi_connect(host, namespace, timeout_seconds=connect_timeout)
    if err:
        return [], err
    rows = []
    try:
        rows = _wmi_query(iWbemServices, wql, timeout_seconds=query_timeout, max_rows=max_rows)
        return rows, None
    except _TimeoutError as e:
        timeout_msg = f"Query timeout after {query_timeout}s"
        if rows:
            timeout_msg += f" (returned {len(rows)} rows before timeout)"
        return rows, timeout_msg
    except Exception as e:
        return rows if rows else [], str(e)
    finally:
        _wmi_disconnect(dcom, iWbemServices)


def _wmi_failure_guidance(error_message: str) -> str:
    err = (error_message or "").lower()
    if "access is denied" in err or "access_denied" in err or "rpc_s_access_denied" in err:
        guidance = (
            "WMI/DCOM authentication failed (rpc_s_access_denied). Common causes:\n"
            "1. Incorrect username/password - verify credentials in secret 'soclib_wmi'\n"
            "2. User lacks remote WMI permissions - add user to 'Distributed COM Users' and 'Event Log Readers' groups\n"
            "3. DCOM security settings - check Component Services > DCOM Config > Windows Management and Instrumentation\n"
            "4. Firewall blocking RPC (port 135) or dynamic ports (49152-65535)\n"
            "5. For domain accounts, ensure domain is set correctly (WMI_DOMAIN or DOMAIN\\username format)\n"
            "6. For local accounts, ensure domain is empty or not set\n"
            "See doc/integrations/soclib-wmi/troubleshooting-secrets.md for detailed steps."
        )
        return guidance
    # Check for SecurityCenter namespace errors first (even if no explicit invalid_namespace code)
    if "securitycenter" in err and ("namespaces not available" in err or "tried namespaces" in err):
        guidance = (
            "WMI SecurityCenter namespaces not available (WBEM_E_INVALID_NAMESPACE). This means:\n"
            "1. SecurityCenter2 (Windows Vista+) and SecurityCenter (Windows XP/2003) are both unavailable\n"
            "2. Common reasons:\n"
            "   - Windows Server Core (no GUI components including Security Center)\n"
            "   - Security Center service is disabled or not installed\n"
            "   - Very old Windows version (pre-XP)\n"
            "   - Custom/minimal Windows installation\n"
            "3. Alternative approaches:\n"
            "   - Use Win32_Product in root/cimv2 to search for antivirus software by name\n"
            "   - Check running processes/services for antivirus executables\n"
            "   - Use registry queries (HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall)\n"
            "4. To check available namespaces: wmic /namespace:\\\\root PATH __NAMESPACE GET Name"
        )
        return guidance
    if "invalid_namespace" in err or "wbem_e_invalid_namespace" in err or "0x8004100e" in err:
        # Generic namespace error (not SecurityCenter-specific)
        guidance = (
            "WMI namespace not found (WBEM_E_INVALID_NAMESPACE). Common causes:\n"
            "1. Namespace does not exist on target system\n"
            "2. Namespace name is misspelled - check namespace spelling (case-sensitive)\n"
            "3. Try using root/cimv2 as fallback namespace for general WMI queries\n"
            "4. Check available namespaces on target: wmic /namespace:\\\\root PATH __NAMESPACE GET Name"
        )
        return guidance
    if "timeout" in err or "timed out" in err:
        return "Connection timeout: check firewall (port 135 and dynamic RPC), network, and that the target is reachable."
    if "connection" in err and ("refused" in err or "failed" in err):
        return "Cannot connect: ensure WMI/DCOM is enabled on target and firewall allows RPC (135) and dynamic ports."
    if "decode" in err or ("attribute" in err and "decode" in err):
        return "Internal error with credential format. This should be fixed in the code. Please report this error."
    return "Check WMI_SERVER, WMI_USERNAME, WMI_PASSWORD and target WMI/DCOM configuration. See doc/integrations/soclib-wmi/."


def _failure_data(
    error_message: str,
    connection: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build data payload for failed responses: connection, error_message, guidance, error_details, and optional extra."""
    guidance = _wmi_failure_guidance(error_message)
    error_details = {
        "message": error_message,
        "guidance": guidance,
    }
    out: dict[str, Any] = {
        "error_message": error_message,
        "guidance": guidance,
        "error_details": error_details,
    }
    if connection:
        out["connection"] = connection
    if extra:
        out.update(extra)
    return out


def _apply_list_filters(
    rows: list[dict[str, Any]],
    max_count: int | None = None,
    filter_key: str | None = None,
    filter_value: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Apply optional max_count and key=value filter. Returns (filtered_rows, total_before_limit)."""
    total = len(rows)
    if filter_key and filter_value is not None:
        fv = str(filter_value).strip()
        rows = [r for r in rows if str(r.get(filter_key, "")).strip() == fv]
    if max_count is not None and max_count > 0 and len(rows) > max_count:
        rows = rows[:max_count]
    return rows, total


# ---------- Phase 1 ----------


@registry.register(
    default_title="WMI: Test connectivity",
    description="Validate WMI connection to the target by running a simple WQL query (Win32_ComputerSystem). Uses soclib_wmi secret. No dependency on WinRM.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def test_connectivity(
    ip_hostname: Annotated[
        str | None,
        Doc("Optional. Target host or IP. Overrides WMI_SERVER from secret. Example: 192.168.1.10 or dc01.corp.local."),
    ] = None,
    namespace: Annotated[
        str | None,
        Doc("Optional. WMI namespace. Default from secret WMI_NAMESPACE or root/cimv2. Example: root/cimv2."),
    ] = None,
) -> dict[str, Any]:
    """Test WMI connectivity."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_ComputerSystem")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn, extra={"connected": False}),
            error=err,
            action_name="test_connectivity",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    return _standard_response(
        True,
        data={
            "connected": True,
            "message": f"Successfully connected to {host}",
        },
        action_name="test_connectivity",
        connection=conn,
    )


@registry.register(
    default_title="WMI: List services",
    description="Get the list of installed services (Win32_Service). Optionally filter to running only. Returns services array and summary.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def list_services(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host. Overrides WMI_SERVER. Example: 192.168.1.10.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
    only_running: Annotated[
        bool,
        Doc("If true, return only services with State='Running'. Default false."),
    ] = False,
    max_count: Annotated[int | None, Doc("Optional. Maximum number of services to return. Summary includes total_available if set.")] = None,
    filter_key: Annotated[str | None, Doc("Optional. Property name for exact-match filter (e.g. Name). Use with filter_value.")] = None,
    filter_value: Annotated[str | None, Doc("Optional. Value for filter_key (exact match).")] = None,
) -> dict[str, Any]:
    """List services; optional only_running, max_count, filter_key/filter_value."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    wql = "SELECT * FROM Win32_Service WHERE State = 'Running'" if only_running else "SELECT * FROM Win32_Service"
    rows, err = _run_single_query(host, ns, wql)
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="list_services",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    rows, total = _apply_list_filters(rows, max_count=max_count, filter_key=filter_key, filter_value=filter_value)
    running = sum(1 for r in rows if (r.get("State") or "").strip() == "Running")
    summary: dict[str, Any] = {"total_services": len(rows), "running_services": running}
    if max_count is not None and max_count > 0:
        summary["total_available"] = total
    return _standard_response(
        True,
        data={"services": rows, "summary": summary},
        action_name="list_services",
        connection=conn,
    )


@registry.register(
    default_title="WMI: Get system info",
    description="Get system information from Win32_ComputerSystem, Win32_OperatingSystem, and Win32_BootConfiguration.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def get_system_info(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host. Example: 192.168.1.10.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
) -> dict[str, Any]:
    """Get system, OS, and boot config details."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    sys_rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_ComputerSystem")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_system_info",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    os_rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_OperatingSystem")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_system_info",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    boot_rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_BootConfiguration")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_system_info",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    system_details = sys_rows[0] if sys_rows else {}
    os_details = os_rows[0] if os_rows else {}
    boot_config_details = boot_rows[0] if boot_rows else {}
    summary = {}
    if system_details:
        summary["dns_hostname"] = system_details.get("DNSHostName") or ""
        summary["domain"] = system_details.get("Domain") or ""
        summary["memory"] = system_details.get("TotalPhysicalMemory") or ""
        summary["workgroup"] = system_details.get("Workgroup")
    if os_details:
        cap = os_details.get("Caption") or ""
        ver = os_details.get("Version") or ""
        arch = os_details.get("OSArchitecture") or ""
        sp = os_details.get("CSDVersion") or ""
        summary["version"] = f"{cap} [{ver}] {arch} {sp}".strip()
    return _standard_response(
        True,
        data={
            "system_details": system_details,
            "os_details": os_details,
            "boot_config_details": boot_config_details,
            "summary": summary,
        },
        action_name="get_system_info",
        connection=conn,
    )


@registry.register(
    default_title="WMI: List users",
    description="List user accounts (Win32_Account where SIDType=1). Returns users array and summary.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def list_users(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host. Example: 192.168.1.10.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
    max_count: Annotated[int | None, Doc("Optional. Maximum number of users to return.")] = None,
    filter_key: Annotated[str | None, Doc("Optional. Property name for exact-match filter (e.g. Name). Use with filter_value.")] = None,
    filter_value: Annotated[str | None, Doc("Optional. Value for filter_key (exact match).")] = None,
) -> dict[str, Any]:
    """List users (Win32_Account SIDType=1). Optional max_count and filter_key/filter_value."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    # Win32_Account can be slow and return many rows; use shorter timeout and limit max_rows
    # Apply max_count early if provided to reduce query time
    effective_max = max_count if max_count and max_count > 0 else 1000
    rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_Account WHERE SIDType = 1", connect_timeout=30.0, query_timeout=60.0, max_rows=effective_max)
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="list_users",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    # Apply filters (max_count already applied in query, but filter_key/filter_value still needed)
    rows, total_before_filter = _apply_list_filters(rows, max_count=None, filter_key=filter_key, filter_value=filter_value)
    disabled = sum(1 for r in rows if r.get("Disabled") is True)
    summary: dict[str, Any] = {"total_users": len(rows), "disabled_users": disabled}
    # Note: total_available reflects rows before filter_key/filter_value, but max_count was already applied in query
    if max_count is not None and max_count > 0:
        summary["total_available"] = total_before_filter
    return _standard_response(
        True,
        data={"users": rows, "summary": summary},
        action_name="list_users",
        connection=conn,
    )


@registry.register(
    default_title="WMI: Run query",
    description="Run an arbitrary WQL (SELECT) query on the target. Only SELECT queries are allowed. Returns rows array.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def run_query(
    query: Annotated[
        str,
        Doc("WQL query (SELECT only). Example: SELECT * FROM Win32_Process, or SELECT Name, State FROM Win32_Service WHERE State = 'Running'."),
    ],
    ip_hostname: Annotated[str | None, Doc("Optional. Target host. Example: 192.168.1.10.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
) -> dict[str, Any]:
    """Run a single WQL query."""
    if not (query or "").strip():
        return _standard_response(False, data={"error_message": "query is required"}, error="query is required", action_name="run_query")
    q = (query or "").strip()
    if not re.match(r"^\s*SELECT\s+", q, re.IGNORECASE):
        return _standard_response(False, data={"error_message": "Only SELECT queries are allowed"}, error="Only SELECT queries are allowed", action_name="run_query")
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, q)
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="run_query",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    return _standard_response(
        True,
        data={"rows": rows, "summary": {"row_count": len(rows)}},
        action_name="run_query",
        connection=conn,
    )


def _fetch_url_content(url: str, encoding: str = "utf-8") -> tuple[str | None, str | None]:
    """Fetch URL and return (content, error)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SOCLib-WMI/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
        return raw.decode(encoding, errors="replace"), None
    except Exception as e:
        return None, str(e)


@registry.register(
    default_title="WMI: Run query from file",
    description="Run WQL query loaded from a URL (http/https). File must contain a single SELECT query. For path on target, use run_query with query pasted or from workflow. Uses soclib_wmi secret.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def run_query_from_file(
    query_file: Annotated[
        str,
        Doc("URL of the file containing WQL query (http or https). Example: https://raw.githubusercontent.com/org/repo/main/queries/processes.wql."),
    ],
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
    query_file_encoding: Annotated[str, Doc("Encoding of the file. Default utf-8.")] = "utf-8",
) -> dict[str, Any]:
    """Run WQL from URL. Only URL is supported for standalone WMI (no path on target)."""
    if not (query_file or "").strip():
        return _standard_response(False, data={"error_message": "query_file is required"}, error="query_file is required", action_name="run_query_from_file")
    url = (query_file or "").strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        return _standard_response(
            False,
            data={"error_message": "query_file must be an http or https URL for standalone WMI integration"},
            error="query_file must be an http or https URL for standalone WMI integration",
            action_name="run_query_from_file",
        )
    content, fetch_err = _fetch_url_content(url, (query_file_encoding or "utf-8").strip() or "utf-8")
    if fetch_err:
        return _standard_response(False, data={"error_message": f"Failed to fetch query file: {fetch_err}"}, error=f"Failed to fetch query file: {fetch_err}", action_name="run_query_from_file")
    if not (content or "").strip():
        return _standard_response(False, data={"error_message": "Query file is empty"}, error="Query file is empty", action_name="run_query_from_file")
    query = content.strip().split("\n")[0].strip()
    if not query.endswith(";"):
        query = query.rstrip()
    if not re.match(r"^\s*SELECT\s+", query, re.IGNORECASE):
        return _standard_response(False, data={"error_message": "File must contain a single SELECT query"}, error="File must contain a single SELECT query", action_name="run_query_from_file")
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, query)
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="run_query_from_file",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    return _standard_response(
        True,
        data={"rows": rows, "summary": {"row_count": len(rows)}},
        action_name="run_query_from_file",
        connection=conn,
    )


@registry.register(
    default_title="WMI: List processes",
    description="List running processes (Win32_Process). Optional max_count and name_filter.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def list_processes(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host. Example: 192.168.1.10.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
    max_count: Annotated[int | None, Doc("Optional. Maximum number of processes to return. If set, summary includes total_available.")] = None,
    name_filter: Annotated[str | None, Doc("Optional. Substring filter on process Name (case-insensitive).")] = None,
    filter_key: Annotated[str | None, Doc("Optional. WMI property name to filter by (exact match). Use with filter_value.")] = None,
    filter_value: Annotated[str | None, Doc("Optional. Value for filter_key (exact match). Use with filter_key.")] = None,
) -> dict[str, Any]:
    """List processes; optional max_count, name_filter, filter_key/filter_value."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_Process")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="list_processes",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    if (name_filter or "").strip():
        nf = (name_filter or "").strip().lower()
        rows = [r for r in rows if nf in (str(r.get("Name") or "").lower())]
    rows, total = _apply_list_filters(rows, max_count=max_count, filter_key=filter_key, filter_value=filter_value)
    summary: dict[str, Any] = {"total_processes": len(rows)}
    if max_count is not None and max_count > 0:
        summary["total_available"] = total
    return _standard_response(
        True,
        data={"processes": rows, "summary": summary},
        action_name="list_processes",
        connection=conn,
    )


# ---------- Phase 2 ----------


@registry.register(
    default_title="WMI: List logical disks",
    description="List logical disks (Win32_LogicalDisk). Returns DeviceID, DriveType, FreeSpace, Size, FileSystem.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def list_logical_disks(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
    max_count: Annotated[int | None, Doc("Optional. Maximum number of disks to return.")] = None,
    filter_key: Annotated[str | None, Doc("Optional. Property for exact-match filter (e.g. DeviceID). Use with filter_value.")] = None,
    filter_value: Annotated[str | None, Doc("Optional. Value for filter_key.")] = None,
) -> dict[str, Any]:
    """List logical disks. Optional max_count and filter_key/filter_value."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_LogicalDisk")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="list_logical_disks",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    rows, total = _apply_list_filters(rows, max_count=max_count, filter_key=filter_key, filter_value=filter_value)
    summary: dict[str, Any] = {"total_disks": len(rows)}
    if max_count is not None and max_count > 0:
        summary["total_available"] = total
    return _standard_response(
        True,
        data={"logical_disks": rows, "summary": summary},
        action_name="list_logical_disks",
        connection=conn,
    )


@registry.register(
    default_title="WMI: Get network adapters",
    description="Get network adapters and configuration (Win32_NetworkAdapter, Win32_NetworkAdapterConfiguration).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def get_network_adapters(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
    max_count: Annotated[int | None, Doc("Optional. Maximum number of adapters to return.")] = None,
    filter_key: Annotated[str | None, Doc("Optional. Property for exact-match filter. Use with filter_value.")] = None,
    filter_value: Annotated[str | None, Doc("Optional. Value for filter_key.")] = None,
) -> dict[str, Any]:
    """Get network adapters. Optional max_count and filter_key/filter_value."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_NetworkAdapter WHERE PhysicalAdapter = True")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_network_adapters",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    rows, total = _apply_list_filters(rows, max_count=max_count, filter_key=filter_key, filter_value=filter_value)
    summary: dict[str, Any] = {"total_adapters": len(rows)}
    if max_count is not None and max_count > 0:
        summary["total_available"] = total
    return _standard_response(
        True,
        data={"adapters": rows, "summary": summary},
        action_name="get_network_adapters",
        connection=conn,
    )


@registry.register(
    default_title="WMI: Get installed software",
    description="Get installed software (Win32_Product). Warning: Win32_Product can be slow on large systems. Optional max_count.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def get_installed_software(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
    max_count: Annotated[int | None, Doc("Optional. Maximum number of products to return (Win32_Product is slow).")] = None,
    filter_key: Annotated[str | None, Doc("Optional. Property for exact-match filter (e.g. Name, Vendor). Use with filter_value.")] = None,
    filter_value: Annotated[str | None, Doc("Optional. Value for filter_key.")] = None,
) -> dict[str, Any]:
    """Get installed software. Win32_Product may be slow. Optional filter_key/filter_value."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, "SELECT Name, Version, Vendor, InstallDate FROM Win32_Product")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_installed_software",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    rows, total = _apply_list_filters(rows, max_count=max_count, filter_key=filter_key, filter_value=filter_value)
    summary: dict[str, Any] = {"total_items": len(rows)}
    if max_count is not None and max_count > 0:
        summary["total_available"] = total
    return _standard_response(
        True,
        data={"items": rows, "summary": summary},
        action_name="get_installed_software",
        connection=conn,
    )


@registry.register(
    default_title="WMI: Get startup commands",
    description="Get startup commands (Win32_StartupCommand).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def get_startup_commands(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
    max_count: Annotated[int | None, Doc("Optional. Maximum number of startup commands to return.")] = None,
    filter_key: Annotated[str | None, Doc("Optional. Property for exact-match filter. Use with filter_value.")] = None,
    filter_value: Annotated[str | None, Doc("Optional. Value for filter_key.")] = None,
) -> dict[str, Any]:
    """Get startup commands. Optional max_count and filter_key/filter_value."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_StartupCommand")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_startup_commands",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    rows, total = _apply_list_filters(rows, max_count=max_count, filter_key=filter_key, filter_value=filter_value)
    summary: dict[str, Any] = {"total": len(rows)}
    if max_count is not None and max_count > 0:
        summary["total_available"] = total
    return _standard_response(
        True,
        data={"startup_commands": rows, "summary": summary},
        action_name="get_startup_commands",
        connection=conn,
    )


@registry.register(
    default_title="WMI: Get environment variables",
    description="Get environment variables (Win32_Environment). Optional scope: System or User.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def get_environment_variables(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
    scope: Annotated[str | None, Doc("Optional. System or User. If not set, returns all.")] = None,
    max_count: Annotated[int | None, Doc("Optional. Maximum number of variables to return.")] = None,
    filter_key: Annotated[str | None, Doc("Optional. Property for exact-match filter (e.g. Name). Use with filter_value.")] = None,
    filter_value: Annotated[str | None, Doc("Optional. Value for filter_key.")] = None,
) -> dict[str, Any]:
    """Get environment variables. Optional max_count and filter_key/filter_value."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    wql = "SELECT * FROM Win32_Environment"
    if (scope or "").strip():
        scope_val = scope.strip()
        if scope_val.lower() in ("system", "user"):
            wql += f" WHERE SystemVariable = {'True' if scope_val.lower() == 'system' else 'False'}"
    rows, err = _run_single_query(host, ns, wql)
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_environment_variables",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    rows, total = _apply_list_filters(rows, max_count=max_count, filter_key=filter_key, filter_value=filter_value)
    summary: dict[str, Any] = {"total": len(rows)}
    if max_count is not None and max_count > 0:
        summary["total_available"] = total
    return _standard_response(
        True,
        data={"variables": rows, "summary": summary},
        action_name="get_environment_variables",
        connection=conn,
    )


@registry.register(
    default_title="WMI: Get physical memory",
    description="Get physical memory modules (Win32_PhysicalMemory).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def get_physical_memory(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
    max_count: Annotated[int | None, Doc("Optional. Maximum number of modules to return.")] = None,
    filter_key: Annotated[str | None, Doc("Optional. Property for exact-match filter. Use with filter_value.")] = None,
    filter_value: Annotated[str | None, Doc("Optional. Value for filter_key.")] = None,
) -> dict[str, Any]:
    """Get physical memory modules. Optional max_count and filter_key/filter_value."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_PhysicalMemory")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_physical_memory",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    rows, total = _apply_list_filters(rows, max_count=max_count, filter_key=filter_key, filter_value=filter_value)
    summary: dict[str, Any] = {"total_modules": len(rows)}
    if max_count is not None and max_count > 0:
        summary["total_available"] = total
    return _standard_response(
        True,
        data={"memory_modules": rows, "summary": summary},
        action_name="get_physical_memory",
        connection=conn,
    )


@registry.register(
    default_title="WMI: Get processor info",
    description="Get processor information (Win32_Processor).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def get_processor_info(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
) -> dict[str, Any]:
    """Get processor info."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_Processor")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_processor_info",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    return _standard_response(
        True,
        data={"processors": rows, "summary": {"total": len(rows)}},
        action_name="get_processor_info",
        connection=conn,
    )


@registry.register(
    default_title="WMI: Get BIOS info",
    description="Get BIOS information (Win32_BIOS).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def get_bios_info(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
) -> dict[str, Any]:
    """Get BIOS info."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_BIOS")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_bios_info",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    bios_info = rows[0] if rows else {}
    return _standard_response(
        True,
        data={"bios_info": bios_info, "summary": {"present": len(rows) > 0}},
        action_name="get_bios_info",
        connection=conn,
    )


@registry.register(
    default_title="WMI: Get timezone info",
    description="Get timezone information (Win32_TimeZone).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def get_timezone_info(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
) -> dict[str, Any]:
    """Get timezone info."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_TimeZone")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_timezone_info",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    timezone_info = rows[0] if rows else {}
    return _standard_response(
        True,
        data={"timezone_info": timezone_info, "summary": {"total": len(rows)}},
        action_name="get_timezone_info",
        connection=conn,
    )


# ---------- Phase 3 ----------


@registry.register(
    default_title="WMI: Get share info",
    description="Get network shares (Win32_Share).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def get_share_info(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
    max_count: Annotated[int | None, Doc("Optional. Maximum number of shares to return.")] = None,
    filter_key: Annotated[str | None, Doc("Optional. Property for exact-match filter (e.g. Name). Use with filter_value.")] = None,
    filter_value: Annotated[str | None, Doc("Optional. Value for filter_key.")] = None,
) -> dict[str, Any]:
    """Get share info. Optional max_count and filter_key/filter_value."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_Share")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_share_info",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    rows, total = _apply_list_filters(rows, max_count=max_count, filter_key=filter_key, filter_value=filter_value)
    summary: dict[str, Any] = {"total": len(rows)}
    if max_count is not None and max_count > 0:
        summary["total_available"] = total
    return _standard_response(
        True,
        data={"shares": rows, "summary": summary},
        action_name="get_share_info",
        connection=conn,
    )


@registry.register(
    default_title="WMI: Get installed hotfixes",
    description="Get installed hotfixes (Win32_QuickFixEngineering).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def get_installed_hotfixes(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
    max_count: Annotated[int | None, Doc("Optional. Maximum number of hotfixes to return.")] = None,
    filter_key: Annotated[str | None, Doc("Optional. Property for exact-match filter (e.g. HotFixID). Use with filter_value.")] = None,
    filter_value: Annotated[str | None, Doc("Optional. Value for filter_key.")] = None,
) -> dict[str, Any]:
    """Get installed hotfixes. Optional max_count and filter_key/filter_value."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_QuickFixEngineering")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_installed_hotfixes",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    rows, total = _apply_list_filters(rows, max_count=max_count, filter_key=filter_key, filter_value=filter_value)
    summary: dict[str, Any] = {"total": len(rows)}
    if max_count is not None and max_count > 0:
        summary["total_available"] = total
    return _standard_response(
        True,
        data={"hotfixes": rows, "summary": summary},
        action_name="get_installed_hotfixes",
        connection=conn,
    )


@registry.register(
    default_title="WMI: Run query batch",
    description="Run multiple WQL queries in one call. Input: array of { name, query }. Returns results array with name and rows for each.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def run_query_batch(
    queries: Annotated[
        list[dict[str, str]],
        Doc("Array of { name: string, query: string }. Example: [{\"name\": \"procs\", \"query\": \"SELECT * FROM Win32_Process\"}]."),
    ],
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
) -> dict[str, Any]:
    """Run multiple WQL queries."""
    if not queries or not isinstance(queries, list):
        return _standard_response(False, data={"error_message": "queries (array of { name, query }) is required"}, error="queries (array of { name, query }) is required", action_name="run_query_batch")
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    results: list[dict[str, Any]] = []
    for i, item in enumerate(queries):
        if not isinstance(item, dict):
            return _standard_response(False, data=_failure_data(f"queries[{i}] must be an object with name and query", connection=conn), error=f"queries[{i}] must be an object with name and query", action_name="run_query_batch", connection=conn, error_details={"message": f"queries[{i}] must be an object with name and query", "guidance": "Provide a list of objects with name and query keys."})
        name = item.get("name") or f"query_{i}"
        query = (item.get("query") or "").strip()
        if not query or not re.match(r"^\s*SELECT\s+", query, re.IGNORECASE):
            return _standard_response(False, data=_failure_data(f"queries[{i}].query must be a SELECT query", connection=conn), error=f"queries[{i}].query must be a SELECT query", action_name="run_query_batch", connection=conn, error_details={"message": f"queries[{i}].query must be a SELECT query", "guidance": "Each query must be a WQL SELECT statement."})
        rows, err = _run_single_query(host, ns, query)
        if err:
            return _standard_response(False, data=_failure_data(f"{name}: {err}", connection=conn), error=f"{name}: {err}", action_name="run_query_batch", connection=conn, error_details={"message": err, "guidance": _wmi_failure_guidance(err)})
        results.append({"name": name, "rows": rows})
    return _standard_response(
        True,
        data={"results": results, "summary": {"batch_count": len(results)}},
        action_name="run_query_batch",
        connection=conn,
    )


@registry.register(
    default_title="WMI: Get scheduled jobs",
    description="Get scheduled jobs (Win32_ScheduledJob — AT jobs).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def get_scheduled_jobs(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
    max_count: Annotated[int | None, Doc("Optional. Maximum number of jobs to return.")] = None,
    filter_key: Annotated[str | None, Doc("Optional. Property for exact-match filter. Use with filter_value.")] = None,
    filter_value: Annotated[str | None, Doc("Optional. Value for filter_key.")] = None,
) -> dict[str, Any]:
    """Get scheduled jobs (AT). Optional max_count and filter_key/filter_value."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_ScheduledJob")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_scheduled_jobs",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    rows, total = _apply_list_filters(rows, max_count=max_count, filter_key=filter_key, filter_value=filter_value)
    summary: dict[str, Any] = {"total": len(rows)}
    if max_count is not None and max_count > 0:
        summary["total_available"] = total
    return _standard_response(
        True,
        data={"jobs": rows, "summary": summary},
        action_name="get_scheduled_jobs",
        connection=conn,
    )


@registry.register(
    default_title="WMI: Get event log metadata",
    description="Get event log file metadata (Win32_NTEventLogFile).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def get_event_log_metadata(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
    max_count: Annotated[int | None, Doc("Optional. Maximum number of log files to return.")] = None,
    filter_key: Annotated[str | None, Doc("Optional. Property for exact-match filter (e.g. LogFileName). Use with filter_value.")] = None,
    filter_value: Annotated[str | None, Doc("Optional. Value for filter_key.")] = None,
) -> dict[str, Any]:
    """Get event log metadata. Optional max_count and filter_key/filter_value."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_NTEventLogFile")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_event_log_metadata",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    rows, total = _apply_list_filters(rows, max_count=max_count, filter_key=filter_key, filter_value=filter_value)
    summary: dict[str, Any] = {"total": len(rows)}
    if max_count is not None and max_count > 0:
        summary["total_available"] = total
    return _standard_response(
        True,
        data={"log_files": rows, "summary": summary},
        action_name="get_event_log_metadata",
        connection=conn,
    )


@registry.register(
    default_title="WMI: Get pagefile info",
    description="Get page file usage (Win32_PageFileUsage).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def get_pagefile_info(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
    max_count: Annotated[int | None, Doc("Optional. Maximum number of pagefiles to return.")] = None,
    filter_key: Annotated[str | None, Doc("Optional. Property for exact-match filter. Use with filter_value.")] = None,
    filter_value: Annotated[str | None, Doc("Optional. Value for filter_key.")] = None,
) -> dict[str, Any]:
    """Get pagefile info. Optional max_count and filter_key/filter_value."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_PageFileUsage")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_pagefile_info",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    rows, total = _apply_list_filters(rows, max_count=max_count, filter_key=filter_key, filter_value=filter_value)
    summary: dict[str, Any] = {"total": len(rows)}
    if max_count is not None and max_count > 0:
        summary["total_available"] = total
    return _standard_response(
        True,
        data={"pagefiles": rows, "summary": summary},
        action_name="get_pagefile_info",
        connection=conn,
    )


@registry.register(
    default_title="WMI: Get printer info",
    description="Get printers (Win32_Printer).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def get_printer_info(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
    max_count: Annotated[int | None, Doc("Optional. Maximum number of printers to return.")] = None,
    filter_key: Annotated[str | None, Doc("Optional. Property for exact-match filter (e.g. Name). Use with filter_value.")] = None,
    filter_value: Annotated[str | None, Doc("Optional. Value for filter_key.")] = None,
) -> dict[str, Any]:
    """Get printer info. Optional max_count and filter_key/filter_value."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_Printer")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_printer_info",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    rows, total = _apply_list_filters(rows, max_count=max_count, filter_key=filter_key, filter_value=filter_value)
    summary: dict[str, Any] = {"total": len(rows)}
    if max_count is not None and max_count > 0:
        summary["total_available"] = total
    return _standard_response(
        True,
        data={"printers": rows, "summary": summary},
        action_name="get_printer_info",
        connection=conn,
    )


@registry.register(
    default_title="WMI: Get driver info",
    description="Get system drivers (Win32_SystemDriver).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def get_driver_info(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
    max_count: Annotated[int | None, Doc("Optional. Maximum number of drivers to return.")] = None,
    filter_key: Annotated[str | None, Doc("Optional. Property for exact-match filter (e.g. Name, State). Use with filter_value.")] = None,
    filter_value: Annotated[str | None, Doc("Optional. Value for filter_key.")] = None,
) -> dict[str, Any]:
    """Get driver info. Optional max_count and filter_key/filter_value."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_SystemDriver")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_driver_info",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    rows, total = _apply_list_filters(rows, max_count=max_count, filter_key=filter_key, filter_value=filter_value)
    summary: dict[str, Any] = {"total": len(rows)}
    if max_count is not None and max_count > 0:
        summary["total_available"] = total
    return _standard_response(
        True,
        data={"drivers": rows, "summary": summary},
        action_name="get_driver_info",
        connection=conn,
    )


@registry.register(
    default_title="WMI: Get anti-virus product",
    description="Get anti-virus product from WMI SecurityCenter2 (namespace root/SecurityCenter2).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def get_anti_virus_product(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. Default root/SecurityCenter2 for AV. Will try SecurityCenter2 first, then SecurityCenter (for older Windows).")] = None,
) -> dict[str, Any]:
    """Get anti-virus product (SecurityCenter2). Tries SecurityCenter2 first, then falls back to SecurityCenter for older Windows systems."""
    host = _get_host(ip_hostname)
    
    # If namespace is explicitly provided, use it only
    if namespace and namespace.strip():
        ns = namespace.strip()
        if not ns.startswith("//"):
            ns = "//./" + ns.replace("\\", "/").lstrip("/")
        conn = _connection_info(host, ns)
        rows, err = _run_single_query(host, ns, "SELECT * FROM AntiVirusProduct")
        if err:
            if "invalid_namespace" in err.lower() or "wbem_e_invalid_namespace" in err.lower() or "0x8004100e" in err.lower():
                enhanced_err = f"{err} (Namespace '{ns.replace('//./', '')}' may not be available on this Windows system.)"
                return _standard_response(
                    False,
                    data=_failure_data(enhanced_err, connection=conn),
                    error=enhanced_err,
                    action_name="get_anti_virus_product",
                    connection=conn,
                    error_details={"message": enhanced_err, "guidance": _wmi_failure_guidance(enhanced_err)},
                )
            return _standard_response(
                False,
                data=_failure_data(err, connection=conn),
                error=err,
                action_name="get_anti_virus_product",
                connection=conn,
                error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
            )
        return _standard_response(
            True,
            data={"products": rows, "summary": {"total": len(rows), "detection_method": "SecurityCenter2"}},
            action_name="get_anti_virus_product",
            connection=conn,
        )
    
    # Try SecurityCenter2 first (Windows Vista+)
    ns_list = ["root/SecurityCenter2", "root/SecurityCenter"]
    last_err = None
    last_conn = None
    
    for ns_try in ns_list:
        ns = "//./" + ns_try.replace("\\", "/").lstrip("/")
        conn = _connection_info(host, ns)
        rows, err = _run_single_query(host, ns, "SELECT * FROM AntiVirusProduct")
        if not err:
            # Success - return results from SecurityCenter namespace
            return _standard_response(
                True,
                data={"products": rows, "summary": {"total": len(rows), "detection_method": ns_try}, "namespace_used": ns_try},
                action_name="get_anti_virus_product",
                connection=conn,
            )
        # Store error for reporting if all attempts fail
        last_err = err
        last_conn = conn
        # If it's not a namespace error, don't try next namespace
        if "invalid_namespace" not in err.lower() and "wbem_e_invalid_namespace" not in err.lower() and "0x8004100e" not in err.lower():
            break
    
    # All SecurityCenter attempts failed - try comprehensive fallback methods
    if "invalid_namespace" in (last_err or "").lower() or "wbem_e_invalid_namespace" in (last_err or "").lower() or "0x8004100e" in (last_err or "").lower():
        ns_fallback = _normalize_namespace(None)  # root/cimv2
        conn_fallback = _connection_info(host, ns_fallback)
        
        # Specific antivirus vendor/product keywords (avoid generic "security" to reduce false positives)
        av_keywords = [
            "antivirus", "anti-virus", "antimalware", "anti-malware",
            "kaspersky", "norton", "symantec", "mcafee", "trend micro", "trendmicro",
            "avast", "avg", "bitdefender", "eset", "nod32", "f-secure", "fsecure",
            "sophos", "panda", "avira", "malwarebytes", "webroot", "crowdstrike",
            "sentinelone", "carbon black", "cylance", "cylanceprotect", "fortinet",
            "forticlient", "checkpoint", "zonealarm", "comodo", "vipre", "emsisoft",
            "g data", "gdata", "g-data", "k7", "quickheal", "vba32", "trustport",
            "total defense", "bullguard", "ad-aware", "spybot", "spyware",
            "endpoint protection", "endpoint security", "security suite"
        ]
        
        # Windows Defender specific patterns (more specific to avoid false positives)
        defender_patterns = [
            "windows defender", "microsoft defender", "defender antivirus",
            "windefend", "msmpeng", "msmpsvc", "mdcore", "wdnis", "mssense"
        ]
        
        # Exclude these Windows system services/components (not antivirus products)
        exclude_patterns = [
            "base filtering", "cryptographic", "event log", "ike", "ipsec",
            "key distribution", "security accounts", "credential manager",
            "software protection", "windows update", "edge update", "mozilla maintenance",
            "splunk", "extensible authentication", "windows firewall",  # Firewall is not antivirus
            "waasmedic", "update medic",  # Windows Update Medic, not antivirus
            "security accounts manager", "sam",  # Authentication, not antivirus
            "policy agent"  # IPsec policy, not antivirus
        ]
        
        # Only include these specific Windows Defender services (exclude generic security services)
        defender_service_names = [
            "windefend", "msmpeng", "msmpsvc", "mdcore", "mdcoresvc", "wdnis", "wdnissvc",
            "mssense", "sense"
        ]
        
        # Windows Defender specific service display names (to include)
        defender_display_names = [
            "microsoft defender antivirus", "windows defender antivirus",
            "microsoft defender advanced threat protection",
            "microsoft defender antivirus network inspection"
        ]
        
        av_products = []
        detection_methods = []
        
        # Method 1: Win32_Product (installed software)
        wql_product = "SELECT Name, Version, Vendor, InstallDate, Description FROM Win32_Product"
        rows_product, err_product = _run_single_query(host, ns_fallback, wql_product, connect_timeout=30.0, query_timeout=120.0, max_rows=500)
        if not err_product and rows_product:
            for product in rows_product:
                name = (product.get("Name") or "").lower()
                vendor = (product.get("Vendor") or "").lower()
                description = (product.get("Description") or "").lower()
                
                for keyword in av_keywords:
                    if keyword.lower() in name or keyword.lower() in vendor or keyword.lower() in description:
                        # Avoid duplicates
                        existing = any(p.get("displayName", "").lower() == (product.get("Name") or "").lower() for p in av_products)
                        if not existing:
                            av_products.append({
                                "displayName": product.get("Name", ""),
                                "productState": None,
                                "instanceGuid": None,
                                "pathToSignedProductExe": None,
                                "pathToSignedReportingExe": None,
                                "versionNumber": product.get("Version", ""),
                                "vendor": product.get("Vendor", ""),
                                "installDate": product.get("InstallDate", ""),
                                "description": product.get("Description", ""),
                                "detection_method": "Win32_Product",
                            })
                            break
            if rows_product:
                detection_methods.append("Win32_Product")
        
        # Method 2: Win32_Service (antivirus services)
        wql_service = "SELECT Name, DisplayName, PathName, State, StartMode, Description FROM Win32_Service"
        rows_service, err_service = _run_single_query(host, ns_fallback, wql_service, connect_timeout=30.0, query_timeout=60.0, max_rows=1000)
        if not err_service and rows_service:
            for service in rows_service:
                name = (service.get("Name") or "").lower()
                display_name = (service.get("DisplayName") or "").lower()
                path_name = (service.get("PathName") or "").lower()
                description = (service.get("Description") or "").lower()
                
                # Skip excluded Windows system services
                should_exclude = False
                for exclude_pattern in exclude_patterns:
                    if exclude_pattern.lower() in display_name or exclude_pattern.lower() in name:
                        should_exclude = True
                        break
                if should_exclude:
                    continue
                
                # Check for Windows Defender (specific patterns - must match service name or path)
                is_defender = False
                # Only consider it Defender if service name matches or path contains defender executables
                if name in [n.lower() for n in defender_service_names]:
                    is_defender = True
                elif any(pattern.lower() in path_name for pattern in ["windefend", "msmpeng", "msmpsvc", "mdcore", "wdnis", "mssense", "defender\\platform", "defender advanced threat"]):
                    is_defender = True
                elif any(pattern.lower() in display_name for pattern in defender_display_names):
                    is_defender = True
                
                # Exclude "Windows Security Service" unless it's actually Defender-related
                if "security health service" in display_name.lower() and name != "securityhealthservice":
                    # Only include if path contains defender
                    if "defender" not in path_name.lower():
                        should_exclude = True
                
                # Check for other antivirus keywords
                found_av = False
                if is_defender:
                    found_av = True
                else:
                    for keyword in av_keywords:
                        if (keyword.lower() in name or keyword.lower() in display_name or 
                            keyword.lower() in path_name or keyword.lower() in description):
                            found_av = True
                            break
                
                if found_av:
                    # Extract product name from service
                    product_name = service.get("DisplayName") or service.get("Name") or ""
                    # Avoid duplicates
                    existing = any(p.get("displayName", "").lower() == product_name.lower() for p in av_products)
                    if not existing:
                        # Determine vendor
                        vendor = None
                        if is_defender or "defender" in display_name.lower():
                            vendor = "Microsoft"
                        elif "kaspersky" in display_name.lower() or "kaspersky" in path_name.lower():
                            vendor = "Kaspersky"
                        elif "norton" in display_name.lower() or "symantec" in display_name.lower():
                            vendor = "Symantec"
                        elif "mcafee" in display_name.lower() or "mcafee" in path_name.lower():
                            vendor = "McAfee"
                        elif "avast" in display_name.lower() or "avast" in path_name.lower():
                            vendor = "Avast"
                        elif "avg" in display_name.lower() or "avg" in path_name.lower():
                            vendor = "AVG"
                        elif "bitdefender" in display_name.lower() or "bitdefender" in path_name.lower():
                            vendor = "Bitdefender"
                        elif "eset" in display_name.lower() or "nod32" in display_name.lower():
                            vendor = "ESET"
                        elif "sophos" in display_name.lower() or "sophos" in path_name.lower():
                            vendor = "Sophos"
                        elif "trend" in display_name.lower() or "trend" in path_name.lower():
                            vendor = "Trend Micro"
                        
                        av_products.append({
                            "displayName": product_name,
                            "productState": None,
                            "instanceGuid": None,
                            "pathToSignedProductExe": service.get("PathName", ""),
                            "pathToSignedReportingExe": None,
                            "versionNumber": None,
                            "vendor": vendor,
                            "installDate": None,
                            "description": service.get("Description", ""),
                            "detection_method": "Win32_Service",
                            "service_name": service.get("Name", ""),
                            "service_state": service.get("State", ""),
                        })
            if rows_service:
                detection_methods.append("Win32_Service")
        
        # Method 3: Win32_Process (running antivirus processes)
        wql_process = "SELECT Name, ExecutablePath, Description, Version FROM Win32_Process WHERE ExecutablePath IS NOT NULL"
        rows_process, err_process = _run_single_query(host, ns_fallback, wql_process, connect_timeout=30.0, query_timeout=60.0, max_rows=500)
        if not err_process and rows_process:
            for process in rows_process:
                name = (process.get("Name") or "").lower()
                path = (process.get("ExecutablePath") or "").lower()
                description = (process.get("Description") or "").lower()
                
                # Common antivirus process names and paths
                av_process_patterns = [
                    "avast", "avg", "kaspersky", "norton", "symantec", "mcafee",
                    "defender", "msmpeng", "msmpsvc", "windefend", "securityhealthservice",
                    "bitdefender", "eset", "nod32", "sophos", "malwarebytes",
                    "crowdstrike", "sentinelone", "cylance", "forticlient"
                ]
                
                for pattern in av_process_patterns:
                    if pattern in name or pattern in path:
                        # Extract product name from process
                        product_name = process.get("Description") or process.get("Name", "").replace(".exe", "")
                        # Avoid duplicates
                        existing = any(p.get("displayName", "").lower() == product_name.lower() for p in av_products)
                        if not existing:
                            av_products.append({
                                "displayName": product_name,
                                "productState": None,
                                "instanceGuid": None,
                                "pathToSignedProductExe": process.get("ExecutablePath", ""),
                                "pathToSignedReportingExe": None,
                                "versionNumber": process.get("Version", ""),
                                "vendor": None,
                                "installDate": None,
                                "description": process.get("Description", ""),
                                "detection_method": "Win32_Process",
                                "process_name": process.get("Name", ""),
                            })
                            break
            if rows_process:
                detection_methods.append("Win32_Process")
        
        # If any products found via fallback methods, consolidate and return success
        if av_products:
            # Consolidate Microsoft Defender services into a single product entry
            consolidated_products = []
            defender_services = []
            other_products = []
            
            for product in av_products:
                vendor = (product.get("vendor") or "").lower()
                display_name = (product.get("displayName") or "").lower()
                detection_method = product.get("detection_method", "")
                
                # Group Microsoft Defender services together
                if vendor == "microsoft" and ("defender" in display_name or "mdcore" in display_name or "windefend" in display_name):
                    defender_services.append(product)
                else:
                    other_products.append(product)
            
            # Create consolidated Microsoft Defender entry if we have Defender services
            if defender_services:
                # Find the main Defender service (WinDefend) or use the first one
                main_defender = None
                for svc in defender_services:
                    if svc.get("service_name", "").lower() == "windefend":
                        main_defender = svc
                        break
                if not main_defender:
                    main_defender = defender_services[0]
                
                # Extract version from path if available (e.g., "4.18.26010.5-0" from path)
                version = None
                path = main_defender.get("pathToSignedProductExe", "")
                if path:
                    # Try to extract version from path pattern: Platform\X.Y.Z.W-N\ or Platform/X.Y.Z.W-N/
                    # Handle both backslash and forward slash, and handle quoted paths
                    path_clean = path.strip('"').strip("'")
                    version_match = re.search(r'Platform[\\/](\d+\.\d+\.\d+\.\d+-\d+)', path_clean)
                    if version_match:
                        version = version_match.group(1)
                    else:
                        # Alternative: try to get version from process if available
                        version = main_defender.get("versionNumber")
                
                # Determine product state based on service states
                # Check if main Defender service (WinDefend) is running
                main_service_running = False
                for svc in defender_services:
                    if svc.get("service_name", "").lower() == "windefend":
                        main_service_running = svc.get("service_state", "").lower() == "running"
                        break
                
                # ProductState: 0 = Off, 1 = On/Enabled, 2 = Snoozed, 3 = Expired
                # For Defender, if main service is running, consider it enabled (1)
                product_state = 1 if main_service_running else 0
                
                # Count running vs stopped services
                running_count = sum(1 for svc in defender_services if svc.get("service_state", "").lower() == "running")
                stopped_count = len(defender_services) - running_count
                
                # Create consolidated Defender product
                consolidated_defender = {
                    "displayName": "Microsoft Defender Antivirus",
                    "productState": product_state,
                    "productStateDescription": "Enabled" if main_service_running else "Disabled",
                    "instanceGuid": None,
                    "pathToSignedProductExe": main_defender.get("pathToSignedProductExe", ""),
                    "pathToSignedReportingExe": None,
                    "versionNumber": version or main_defender.get("versionNumber"),
                    "vendor": "Microsoft",
                    "installDate": main_defender.get("installDate"),
                    "description": "Microsoft Defender Antivirus - Windows built-in antivirus solution",
                    "detection_method": "Win32_Service (consolidated)",
                    "components": [
                        {
                            "service_name": svc.get("service_name", ""),
                            "display_name": svc.get("displayName", ""),
                            "state": svc.get("service_state", ""),
                            "path": svc.get("pathToSignedProductExe", "")
                        }
                        for svc in defender_services
                    ],
                    "total_components": len(defender_services),
                    "running_components": running_count,
                    "stopped_components": stopped_count,
                    "main_service_status": "Running" if main_service_running else "Stopped"
                }
                consolidated_products.append(consolidated_defender)
            
            # Add other non-Defender products
            consolidated_products.extend(other_products)
            
            return _standard_response(
                True,
                data={
                    "products": consolidated_products,
                    "summary": {
                        "total": len(consolidated_products),
                        "detection_methods": detection_methods,
                        "note": "SecurityCenter namespaces not available. Products detected via fallback methods (Win32_Product, Win32_Service, Win32_Process). Microsoft Defender services consolidated into a single product entry. productState derived from service status. Some fields (instanceGuid) may not be available."
                    },
                    "namespaces_tried": ns_list,
                    "fallback_used": True,
                },
                action_name="get_anti_virus_product",
                connection=conn_fallback,
            )
        
        # All fallback methods failed - return error with comprehensive information
        enhanced_err = (
            f"WMI SecurityCenter namespaces not available on this system. "
            f"Tried: {', '.join(ns_list)}. "
            f"Fallback methods (Win32_Product, Win32_Service, Win32_Process) found no antivirus products. "
            f"This may indicate: no antivirus installed, antivirus not registered in standard WMI classes, or system uses non-standard security solution."
        )
        extra_data = {
            "namespaces_tried": ns_list,
            "fallback_attempted": True,
            "fallback_methods": detection_methods if detection_methods else ["Win32_Product", "Win32_Service", "Win32_Process"],
            "fallback_results": {
                "Win32_Product": f"{'queried' if not err_product else f'error: {err_product}'}",
                "Win32_Service": f"{'queried' if not err_service else f'error: {err_service}'}",
                "Win32_Process": f"{'queried' if not err_process else f'error: {err_process}'}",
            },
            "fallback_suggestions": [
                "No antivirus detected via standard WMI methods. System may use non-standard security solution.",
                "Check if antivirus is installed but not registered in WMI classes.",
                "Use get_installed_software action to manually search for security products.",
                "Check running processes/services manually for antivirus executables."
            ]
        }
        return _standard_response(
            False,
            data=_failure_data(enhanced_err, connection=conn_fallback, extra=extra_data),
            error=enhanced_err,
            action_name="get_anti_virus_product",
            connection=conn_fallback,
            error_details={"message": enhanced_err, "guidance": _wmi_failure_guidance(enhanced_err)},
        )
    
    return _standard_response(
        False,
        data=_failure_data(last_err or "Unknown error", connection=last_conn),
        error=last_err or "Unknown error",
        action_name="get_anti_virus_product",
        connection=last_conn,
        error_details={"message": last_err or "Unknown error", "guidance": _wmi_failure_guidance(last_err or "")},
    )


@registry.register(
    default_title="WMI: Get file properties",
    description="Get file properties (CIM_DataFile) by path on target. Path must be Windows path or UNC.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def get_file_properties(
    path: Annotated[
        str,
        Doc("Full path to file on target. Example: C:\\Windows\\System32\\kernel32.dll or \\\\server\\share\\file.txt."),
    ],
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
) -> dict[str, Any]:
    """Get file properties by path."""
    if not (path or "").strip():
        return _standard_response(False, data={"error_message": "path is required"}, error="path is required", action_name="get_file_properties")
    win_path = (path or "").strip().replace("/", "\\")
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    escaped = win_path.replace("\\", "\\\\").replace("'", "\\'")
    wql = f"SELECT * FROM CIM_DataFile WHERE Name = '{escaped}'"
    rows, err = _run_single_query(host, ns, wql)
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="get_file_properties",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    file_properties = rows[0] if rows else {}
    return _standard_response(
        True,
        data={"file_properties": file_properties, "summary": {"found": len(rows) > 0}},
        action_name="get_file_properties",
        connection=conn,
    )


@registry.register(
    default_title="WMI: List serial ports",
    description="List serial ports (Win32_SerialPort).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[wmi_secret],
)
def list_serial_ports(
    ip_hostname: Annotated[str | None, Doc("Optional. Target host.")] = None,
    namespace: Annotated[str | None, Doc("Optional. WMI namespace. Default root/cimv2.")] = None,
    max_count: Annotated[int | None, Doc("Optional. Maximum number of serial ports to return.")] = None,
    filter_key: Annotated[str | None, Doc("Optional. Property for exact-match filter (e.g. DeviceID). Use with filter_value.")] = None,
    filter_value: Annotated[str | None, Doc("Optional. Value for filter_key.")] = None,
) -> dict[str, Any]:
    """List serial ports. Optional max_count and filter_key/filter_value."""
    host = _get_host(ip_hostname)
    ns = _normalize_namespace(namespace)
    conn = _connection_info(host, ns)
    rows, err = _run_single_query(host, ns, "SELECT * FROM Win32_SerialPort")
    if err:
        return _standard_response(
            False,
            data=_failure_data(err, connection=conn),
            error=err,
            action_name="list_serial_ports",
            connection=conn,
            error_details={"message": err, "guidance": _wmi_failure_guidance(err)},
        )
    rows, total = _apply_list_filters(rows, max_count=max_count, filter_key=filter_key, filter_value=filter_value)
    summary: dict[str, Any] = {"total": len(rows)}
    if max_count is not None and max_count > 0:
        summary["total_available"] = total
    return _standard_response(
        True,
        data={"serial_ports": rows, "summary": summary},
        action_name="list_serial_ports",
        connection=conn,
    )
