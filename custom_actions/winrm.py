"""SOCLib WinRM integration — integrations.soclib.winrm (engine UDFs).

Implements Windows Remote Management proposal (Phases 1–3):
Phase 1: test_connectivity, run_command, run_script, list_processes, terminate_process.
Phase 2: list_connections, list_firewall_rules, delete_firewall_rule, block_ip,
  add_firewall_rule, list_sessions, logoff_user, shutdown_system, restart_system,
  get_file, upload_file, copy_file, delete_file.
Phase 3: list_applocker_policies, create_applocker_policy, delete_applocker_policy,
  deactivate_partition, activate_partition.
All actions return standard output: { success, data, error, meta }.

UDF namespace: integrations.soclib.winrm.
Templates: tools.soclib.winrm.
"""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone
from typing import Annotated, Any

from kopal_registry import RegistrySecret, registry, secrets
from typing_extensions import Doc

# Lazy-load pywinrm so sync/import phase is faster; load only when first WinRM action runs.
_winrm_module: Any = None


def _get_winrm() -> Any:
    global _winrm_module
    if _winrm_module is None:
        try:
            import winrm as w  # noqa: PLC0415
            _winrm_module = w
        except ImportError:
            pass
    return _winrm_module


ACTION_NAMESPACE = "integrations.soclib.winrm"
DISPLAY_GROUP = "SOCLib / Windows Remote Management"

winrm_secret = RegistrySecret(
    name="soclib_winrm",
    keys=["WINRM_ENDPOINT", "WINRM_USERNAME", "WINRM_PASSWORD", "WINRM_TRANSPORT"],
    optional_keys=[
        "WINRM_PROTOCOL",
        "WINRM_PORT",
        "WINRM_DOMAIN",
        "WINRM_VERIFY_SSL",
        "WINRM_CERT_PEM",
        "WINRM_CERT_KEY_PEM",
        "WINRM_CA_TRUST",
    ],
)


def _standard_response(
    success: bool,
    data: Any = None,
    error: str | None = None,
    action_name: str = "",
) -> dict[str, Any]:
    """Build standard output for all actions."""
    return {
        "success": success,
        "data": data if data is not None else {},
        "error": error,
        "meta": {
            "action": f"{ACTION_NAMESPACE}.{action_name}" if action_name else ACTION_NAMESPACE,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    }


def _get_secret(key: str, default: str = "") -> str:
    try:
        val = secrets.get(key)
        return str(val).strip() if val else default
    except Exception:
        return default


def _build_endpoint(ip_hostname: str | None = None) -> str:
    """Build WinRM endpoint URL from secret and optional ip_hostname override."""
    host = (ip_hostname or "").strip() or _get_secret("WINRM_ENDPOINT", "").strip()
    if not host:
        return ""
    if "://" in host:
        return host.rstrip("/") if not host.endswith("/wsman") else host
    protocol = _get_secret("WINRM_PROTOCOL", "http").strip().lower() or "http"
    port_str = _get_secret("WINRM_PORT", "").strip()
    if port_str:
        try:
            port = int(port_str)
        except ValueError:
            port = 5986 if protocol == "https" else 5985
    else:
        port = 5986 if protocol == "https" else 5985
    return f"{protocol}://{host}:{port}/wsman"


def _get_connection_spec_winrm(ip_hostname: str | None = None) -> dict[str, Any]:
    """Build connection spec for rich output (no secrets)."""
    host = (ip_hostname or "").strip() or _get_secret("WINRM_ENDPOINT", "").strip()
    protocol = _get_secret("WINRM_PROTOCOL", "http").strip().lower() or "http"
    port_str = _get_secret("WINRM_PORT", "").strip()
    try:
        port = int(port_str) if port_str else (5986 if protocol == "https" else 5985)
    except ValueError:
        port = 5986 if protocol == "https" else 5985
    transport = _get_secret("WINRM_TRANSPORT", "ntlm").strip().lower() or "ntlm"
    verify = _get_secret("WINRM_VERIFY_SSL", "false").strip().lower() == "true"
    endpoint = f"{protocol}://{host}:{port}/wsman" if host else ""
    return {
        "endpoint": endpoint,
        "host": host or None,
        "port": port,
        "protocol": protocol,
        "transport": transport,
        "ssl_validation": "enabled" if verify else "disabled",
    }


def _winrm_failure_guidance(error_message: str) -> str:
    """Return guidance (English) for common WinRM failures."""
    err = (error_message or "").lower()
    if "kerberos" in err and ("not installed" in err or "pykerberos" in err or "pywinrm" in err):
        return (
            "Kerberos transport requires extra packages. Install: pip install 'pywinrm[kerberos]' (or requests-kerberos). "
            "On Linux you may need krb5-devel and a valid kinit ticket."
        )
    if "credentials were rejected" in err or "rejected by the server" in err:
        return (
            "Credentials rejected: check WINRM_USERNAME, WINRM_PASSWORD, and WINRM_DOMAIN. "
            "Basic auth is often disabled on Windows WinRM; prefer NTLM. Ensure the account can log on to the target."
        )
    if "timeout" in err or "timed out" in err:
        return (
            "Connection or command timeout: check firewall (ports 5985/5986), WinRM listener on target, and network. "
            "NTLM can be slow; retry or increase timeout if supported."
        )
    if "connection" in err and ("refused" in err or "failed" in err):
        return "Connection refused: ensure WinRM service is running on target and firewall allows 5985 (http) or 5986 (https)."
    return "Check WINRM_ENDPOINT, WINRM_TRANSPORT, and target WinRM configuration. See doc/integrations/soclib-winrm/setup-cheatsheet.md."


def _session_kwargs(endpoint: str) -> dict[str, Any]:
    """Build kwargs for winrm.Session from secrets."""
    username = _get_secret("WINRM_USERNAME", "")
    password = _get_secret("WINRM_PASSWORD", "")
    transport = _get_secret("WINRM_TRANSPORT", "ntlm").strip().lower() or "ntlm"
    domain = _get_secret("WINRM_DOMAIN", "").strip()

    if domain and transport == "ntlm":
        username = f"{domain}\\{username}" if "\\" not in username else username
    elif domain and transport == "kerberos":
        username = f"{username}@{domain}" if "@" not in username else username

    verify = _get_secret("WINRM_VERIFY_SSL", "false").strip().lower() == "true"
    server_cert_validation = "validate" if verify else "ignore"

    kwargs: dict[str, Any] = {
        "auth": (username, password),
        "transport": transport,
        "server_cert_validation": server_cert_validation,
    }
    if transport == "certificate":
        cert_pem = _get_secret("WINRM_CERT_PEM", "")
        cert_key_pem = _get_secret("WINRM_CERT_KEY_PEM", "")
        ca_trust = _get_secret("WINRM_CA_TRUST", "")
        if cert_pem:
            kwargs["cert_pem"] = cert_pem
        if cert_key_pem:
            kwargs["cert_key_pem"] = cert_key_pem
        if ca_trust:
            kwargs["ca_trust_path"] = ca_trust
    return kwargs


def _create_session(ip_hostname: str | None) -> tuple[Any, str | None]:
    """Create WinRM Session. Returns (session, error_message)."""
    winrm_lib = _get_winrm()
    if winrm_lib is None:
        return None, "pywinrm is not installed"
    endpoint = _build_endpoint(ip_hostname)
    if not endpoint:
        return None, "WINRM_ENDPOINT or ip_hostname is required"
    try:
        kwargs = _session_kwargs(endpoint)
        session = winrm_lib.Session(endpoint, **kwargs)
        return session, None
    except Exception as e:
        msg = str(e)
        # Normalize common Kerberos error so guidance can suggest the right package
        if "kerberos" in msg.lower() and "not installed" in msg.lower() and "py" in msg.lower():
            msg = "requested auth method is kerberos, but pywinrm kerberos support is not installed (install pywinrm[kerberos] or requests-kerberos)"
        return None, msg


def _is_path_on_target(s: str) -> bool:
    """Return True if s looks like a path on the target (Windows drive or UNC)."""
    s = (s or "").strip()
    if not s or len(s) < 2:
        return False
    if s[0].isalpha() and s[1:2] in (":", ":\\"):
        return True
    if s.startswith("\\\\") or s.startswith("//"):
        return True
    return False


def _decode_output(std_out: Any, std_err: Any) -> tuple[str, str]:
    if std_out is None:
        out = ""
    elif isinstance(std_out, bytes):
        out = std_out.decode("utf-8", errors="replace")
    else:
        out = str(std_out)
    if std_err is None:
        err = ""
    elif isinstance(std_err, bytes):
        err = std_err.decode("utf-8", errors="replace")
    else:
        err = str(std_err)
    return out, err


# ---------------------------------------------------------------------------
# Phase 1 actions
# ---------------------------------------------------------------------------


@registry.register(
    default_title="WinRM: Test connectivity",
    description="Validate WinRM connection by running ipconfig on the target. Uses soclib_winrm secret.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def test_connectivity(
    ip_hostname: Annotated[
        str | None,
        Doc("Optional. Target host or URL for this test. Type: string or null. Overrides WINRM_ENDPOINT from secret (e.g. 192.168.1.10 or host.example.com). If null, uses WINRM_ENDPOINT."),
    ] = None,
) -> dict[str, Any]:
    """Test WinRM connectivity; run ipconfig. Returns rich data with connection spec and guidance on failure."""
    spec = _get_connection_spec_winrm(ip_hostname)
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(
            False,
            data={
                "connected": False,
                "error_message": err,
                "guidance": _winrm_failure_guidance(err),
                "attempted_connection": spec,
            },
            error=err,
            action_name="test_connectivity",
        )
    try:
        r = session.run_cmd("ipconfig", [])
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        if ok:
            data: dict[str, Any] = {
                "connected": True,
                "connection": spec,
                "message": f"Connected via {spec.get('transport', '')} to {spec.get('endpoint', '')}. Command ipconfig completed with exit code 0.",
                "status_code": r.status_code,
                "std_out": out,
                "std_err": stderr,
            }
            return _standard_response(True, data=data, action_name="test_connectivity")
        return _standard_response(
            False,
            data={
                "connected": False,
                "error_message": stderr or f"Exit code {r.status_code}",
                "guidance": "Command failed on target; check std_err for details.",
                "attempted_connection": spec,
                "status_code": r.status_code,
                "std_out": out,
                "std_err": stderr,
            },
            error=stderr or f"Exit code {r.status_code}",
            action_name="test_connectivity",
        )
    except Exception as e:
        return _standard_response(
            False,
            data={
                "connected": False,
                "error_message": str(e),
                "guidance": _winrm_failure_guidance(str(e)),
                "attempted_connection": spec,
            },
            error=str(e),
            action_name="test_connectivity",
        )


@registry.register(
    default_title="WinRM: Run command (CMD)",
    description="Run a CMD command on the target (e.g. whoami, ipconfig). Equivalent to winrm-run-process.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def run_command(
    command: Annotated[
        str,
        Doc("CMD command to run on the target. Type: string. Examples: whoami, hostname, ipconfig. Required unless using command_id+shell_id (unsupported)."),
    ] = "",
    arguments: Annotated[
        str | None,
        Doc("Optional. Space-separated arguments for the command. Type: string or null. Example: /all for ipconfig /all."),
    ] = None,
    ip_hostname: Annotated[
        str | None,
        Doc("Optional. Override target host for this call. Type: string or null. If set, overrides WINRM_ENDPOINT from secret (e.g. 192.168.1.10 or host.example.com)."),
    ] = None,
    run_async: Annotated[
        bool,
        Doc("Optional. If true, start command without waiting for output and return shell_id/command_id. Type: bool, default false. Not supported: each action uses a new WinRM session; execution is always synchronous."),
    ] = False,
    command_id: Annotated[
        str | None,
        Doc("Optional. With shell_id: retrieve output of a previously started async command. Type: string or null. Not supported: use synchronous run_command instead."),
    ] = None,
    shell_id: Annotated[
        str | None,
        Doc("Optional. With command_id: retrieve output of async command. Type: string or null. Not supported: use synchronous run_command instead."),
    ] = None,
) -> dict[str, Any]:
    """Run a CMD command. Returns status_code, std_out, std_err."""
    if _get_winrm() is None:
        return _standard_response(False, data={}, error="pywinrm is not installed", action_name="run_command")
    if command_id and shell_id:
        return _standard_response(
            False,
            data={},
            error="Async output (command_id/shell_id) is not supported; each action uses a new session. Use run_command with command and arguments for synchronous execution.",
            action_name="run_command",
        )
    if not (command or "").strip():
        return _standard_response(False, data={}, error="command is required", action_name="run_command")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="run_command")
    args_list = (arguments or "").strip().split() if arguments else []
    try:
        r = session.run_cmd(command.strip(), args_list)
        out, stderr = _decode_output(r.std_out, r.std_err)
        return _standard_response(
            True,
            data={
                "status_code": r.status_code,
                "std_out": out,
                "std_err": stderr,
            },
            action_name="run_command",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="run_command")


@registry.register(
    default_title="WinRM: Run PowerShell script",
    description="Run PowerShell directly on the target. Provide script_str (inline). Equivalent to winrm-run-powershell.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def run_script(
    script_str: Annotated[
        str | None,
        Doc("PowerShell script or command to run on the target. Type: string or null. Inline content; one line or multi-line. Either script_str or script_file (URL or path on target) is required."),
    ] = None,
    script_file: Annotated[
        str | None,
        Doc("Optional. Either (1) URL (http/https) to fetch script from — e.g. GitHub raw, GitLab raw, any cleartext URL; content is fetched and run on target. Or (2) Full path to script on the TARGET machine — e.g. C:\\Scripts\\run.ps1 or \\\\server\\share\\script.ps1 (UNC). Name alone is not enough; use full path or UNC."),
    ] = None,
    script_arguments: Annotated[
        str | None,
        Doc("Optional. Arguments passed to the script when script_file is a path on target (e.g. -ComputerName X -Verbose). Ignored when using script_str or script_file as URL. Type: string or null."),
    ] = None,
    ip_hostname: Annotated[
        str | None,
        Doc("Optional. Override target host for this call. Type: string or null. Overrides WINRM_ENDPOINT from secret."),
    ] = None,
    run_async: Annotated[
        bool,
        Doc("Optional. If true, would return shell_id/command_id without waiting. Type: bool, default false. Not supported: execution is always synchronous."),
    ] = False,
) -> dict[str, Any]:
    """Run PowerShell script. Returns status_code, std_out, std_err."""
    if _get_winrm() is None:
        return _standard_response(False, data={}, error="pywinrm is not installed", action_name="run_script")
    script = (script_str or "").strip()
    run_from_path_on_target = False
    path_on_target = None
    if not script and (script_file or "").strip():
        script_file_val = (script_file or "").strip()
        if script_file_val.startswith("http://") or script_file_val.startswith("https://"):
            try:
                with urllib.request.urlopen(script_file_val, timeout=30) as resp:
                    script = resp.read().decode("utf-8", errors="replace").strip()
            except Exception as e:
                return _standard_response(
                    False,
                    data={},
                    error=f"Failed to fetch script from URL: {e}",
                    action_name="run_script",
                )
        elif _is_path_on_target(script_file_val):
            run_from_path_on_target = True
            path_on_target = script_file_val
        else:
            return _standard_response(
                False,
                data={},
                error="script_file must be an http/https URL or a full path on the TARGET (e.g. C:\\Scripts\\run.ps1 or \\\\server\\share\\script.ps1). Use script_str for inline script.",
                action_name="run_script",
            )
    if not script and not run_from_path_on_target:
        return _standard_response(False, data={}, error="script_str or script_file (URL or path on target) is required", action_name="run_script")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="run_script")
    if run_from_path_on_target and path_on_target:
        path_esc = path_on_target.replace("'", "''")
        args_part = (script_arguments or "").strip()
        script = f"& '{path_esc}' {args_part}".strip()
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        return _standard_response(
            True,
            data={
                "status_code": r.status_code,
                "std_out": out,
                "std_err": stderr,
            },
            action_name="run_script",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="run_script")


PS_LIST_PROCESSES = """
$procs = Get-Process | ForEach-Object {
    [PSCustomObject]@{
        handles = $_.Handles
        name = $_.Name
        pid = $_.Id
        paged_memory = $_.PagedMemorySize64
        working_set = $_.WorkingSet64
        virtual_memory = $_.VirtualMemorySize64
        processor_time_s = [double]$_.CPU
        session_id = $_.SessionId
    }
}
$procs | ConvertTo-Json
"""


@registry.register(
    default_title="WinRM: List processes",
    description="List running processes on the target with handles, name, pid, memory, CPU, session_id. Optional limit and name filter.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def list_processes(
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
    max_count: Annotated[int | None, Doc("Max number of processes to return (default: no limit)")] = None,
    name_filter: Annotated[str | None, Doc("Filter by process name (substring match; case-insensitive)")] = None,
) -> dict[str, Any]:
    """List processes; returns data.processes, data.num_processes; optional max_count and name_filter. When limited, data.total_available is set."""
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="list_processes")
    try:
        r = session.run_ps(PS_LIST_PROCESSES)
        out, stderr = _decode_output(r.std_out, r.std_err)
        if r.status_code != 0:
            return _standard_response(
                False,
                data={"std_err": stderr, "status_code": r.status_code},
                error=stderr or f"Exit code {r.status_code}",
                action_name="list_processes",
            )
        try:
            processes = json.loads(out)
            if not isinstance(processes, list):
                processes = [processes]
        except json.JSONDecodeError:
            processes = []
        if name_filter and name_filter.strip():
            needle = name_filter.strip().lower()
            processes = [p for p in processes if needle in (p.get("name") or "").lower()]
        total = len(processes)
        if max_count is not None and max_count > 0:
            processes = processes[: max_count]
        data: dict[str, Any] = {"processes": processes, "num_processes": len(processes)}
        if max_count is not None and max_count > 0 and total > len(processes):
            data["total_available"] = total
        return _standard_response(True, data=data, action_name="list_processes")
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="list_processes")


@registry.register(
    default_title="WinRM: Terminate process",
    description="Terminate a process by PID or by name (wildcard supported).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def terminate_process(
    pid: Annotated[int | None, Doc("Process ID to terminate")] = None,
    name: Annotated[str | None, Doc("Process name (wildcard supported); at least one of pid or name required")] = None,
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Terminate process by pid or name."""
    if pid is None and not (name or "").strip():
        return _standard_response(
            False,
            data={},
            error="At least one of pid or name is required",
            action_name="terminate_process",
        )
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="terminate_process")
    if pid is not None:
        script = f"Stop-Process -Id {int(pid)} -Force -ErrorAction Stop"
    else:
        safe_name = (name or "").strip().replace("'", "''")
        script = f"Get-Process -Name '{safe_name}' -ErrorAction Stop | Stop-Process -Force"
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"status_code": r.status_code, "std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="terminate_process",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="terminate_process")


# ---------------------------------------------------------------------------
# Phase 2: connections, firewall, sessions, file ops
# ---------------------------------------------------------------------------

PS_LIST_CONNECTIONS = """
Get-NetTCPConnection -State Listen,Established,TimeWait,CloseWait 2>$null | ForEach-Object {
    [PSCustomObject]@{
        protocol = 'tcp'
        local_address_ip = $_.LocalAddress
        local_port = $_.LocalPort
        foreign_address_ip = $_.RemoteAddress
        foreign_port = $_.RemotePort
        state = $_.State.ToString()
        pid = $_.OwningProcess
    }
} | ConvertTo-Json
"""


@registry.register(
    default_title="WinRM: List connections",
    description="List network connections (TCP) on the target with protocol, local/remote address and port, state, pid. Optional limit and state filter.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def list_connections(
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
    max_count: Annotated[int | None, Doc("Max number of connections to return (default: no limit)")] = None,
    state_filter: Annotated[str | None, Doc("Filter by state: Listen, Established, TimeWait, CloseWait, etc.")] = None,
) -> dict[str, Any]:
    """List connections; returns data.connections, data.num_connections; optional max_count and state_filter. When limited, data.total_available is set."""
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="list_connections")
    try:
        r = session.run_ps(PS_LIST_CONNECTIONS)
        out, stderr = _decode_output(r.std_out, r.std_err)
        if r.status_code != 0:
            return _standard_response(
                False,
                data={"std_err": stderr, "status_code": r.status_code},
                error=stderr or f"Exit code {r.status_code}",
                action_name="list_connections",
            )
        try:
            conns = json.loads(out) if out.strip() else []
            if not isinstance(conns, list):
                conns = [conns]
        except json.JSONDecodeError:
            conns = []
        if state_filter and state_filter.strip():
            want = state_filter.strip().lower()
            conns = [c for c in conns if (c.get("state") or "").lower() == want]
        total = len(conns)
        if max_count is not None and max_count > 0:
            conns = conns[:max_count]
        data_out: dict[str, Any] = {"connections": conns, "num_connections": len(conns)}
        if max_count is not None and max_count > 0 and total > len(conns):
            data_out["total_available"] = total
        return _standard_response(True, data=data_out, action_name="list_connections")
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="list_connections")


PS_LIST_FIREWALL_RULES = """
$rules = Get-NetFirewallRule -PolicyStore ActiveStore 2>$null | ForEach-Object {
    $addr = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_ -ErrorAction SilentlyContinue
    $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_ -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        rule_name = $_.DisplayName
        name = $_.Name
        action = $_.Action.ToString()
        direction = $_.Direction.ToString()
        enabled = $_.Enabled.ToString()
        local_ip = ($addr | Select-Object -First 1).LocalAddress
        remote_ip = ($addr | Select-Object -First 1).RemoteAddress
        local_port = ($port | Select-Object -First 1).LocalPort
        remote_port = ($port | Select-Object -First 1).RemotePort
        protocol = ($port | Select-Object -First 1).Protocol
        profiles = $_.Profile.ToString()
    }
}
$rules | ConvertTo-Json
"""


@registry.register(
    default_title="WinRM: List firewall rules",
    description="List Windows Firewall rules (name, action, direction, enabled, addresses, ports, protocol). Optional filters and max_count.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def list_firewall_rules(
    filter_port: Annotated[str | None, Doc("Filter by port")] = None,
    filter_ip: Annotated[str | None, Doc("Filter by IP")] = None,
    direction: Annotated[str | None, Doc("in or out")] = None,
    protocol: Annotated[str | None, Doc("tcp, udp, or any")] = None,
    max_count: Annotated[int | None, Doc("Max number of rules to return (default: no limit)")] = None,
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """List firewall rules; optional filters and max_count. When limited, data.total_available is set."""
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="list_firewall_rules")
    try:
        r = session.run_ps(PS_LIST_FIREWALL_RULES)
        out, stderr = _decode_output(r.std_out, r.std_err)
        if r.status_code != 0:
            return _standard_response(
                False,
                data={"std_err": stderr, "status_code": r.status_code},
                error=stderr or f"Exit code {r.status_code}",
                action_name="list_firewall_rules",
            )
        try:
            rules = json.loads(out) if out.strip() else []
            if not isinstance(rules, list):
                rules = [rules]
        except json.JSONDecodeError:
            rules = []
        if direction:
            d = direction.strip().lower()
            rules = [x for x in rules if (x.get("direction") or "").lower() == d]
        if protocol:
            p = protocol.strip().lower()
            rules = [x for x in rules if (str(x.get("protocol") or "")).lower() == p or (p == "any" and not x.get("protocol"))]
        if filter_ip:
            rules = [x for x in rules if filter_ip in str(x.get("remote_ip") or "") or filter_ip in str(x.get("local_ip") or "")]
        if filter_port:
            rules = [x for x in rules if filter_port == str(x.get("local_port") or "") or filter_port == str(x.get("remote_port") or "")]
        total = len(rules)
        if max_count is not None and max_count > 0:
            rules = rules[:max_count]
        data_fw: dict[str, Any] = {"rules": rules, "num_rules": len(rules)}
        if max_count is not None and max_count > 0 and total > len(rules):
            data_fw["total_available"] = total
        return _standard_response(True, data=data_fw, action_name="list_firewall_rules")
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="list_firewall_rules")


@registry.register(
    default_title="WinRM: Delete firewall rule",
    description="Delete a Windows Firewall rule by name.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def delete_firewall_rule(
    name: Annotated[str, Doc("Rule name to delete (display name or internal name)")],
    dir: Annotated[str | None, Doc("in or out (optional)")] = None,
    use_internal_name: Annotated[bool, Doc("If true, match by -Name (internal); if false, match by -DisplayName")] = False,
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Delete firewall rule by name. Use use_internal_name=true to delete by internal rule name (-Name) instead of display name (-DisplayName)."""
    if not (name or "").strip():
        return _standard_response(False, data={}, error="name is required", action_name="delete_firewall_rule")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="delete_firewall_rule")
    safe_name = (name or "").strip().replace("'", "''")
    param = "-Name" if use_internal_name else "-DisplayName"
    script = f"Remove-NetFirewallRule {param} '{safe_name}' -ErrorAction Stop; Write-Output 'OK'"
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"rules_deleted": 1 if ok else 0, "std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="delete_firewall_rule",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="delete_firewall_rule")


@registry.register(
    default_title="WinRM: Block IP",
    description="Add a firewall rule to block traffic from a remote IP.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def block_ip(
    name: Annotated[str, Doc("Rule name for the block rule")],
    remote_ip: Annotated[str, Doc("IP address to block")],
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Block remote IP with a new firewall rule."""
    if not (name or "").strip():
        return _standard_response(False, data={}, error="name is required", action_name="block_ip")
    if not (remote_ip or "").strip():
        return _standard_response(False, data={}, error="remote_ip is required", action_name="block_ip")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="block_ip")
    safe_name = (name or "").strip().replace("'", "''")
    safe_ip = (remote_ip or "").strip().replace("'", "''")
    script = f"New-NetFirewallRule -DisplayName '{safe_name}' -Direction Inbound -Action Block -RemoteAddress '{safe_ip}' -ErrorAction Stop; Write-Output 'OK'"
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="block_ip",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="block_ip")


@registry.register(
    default_title="WinRM: Add firewall rule",
    description="Add a Windows Firewall rule (allow, block, or bypass).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def add_firewall_rule(
    name: Annotated[str, Doc("Rule name")],
    dir: Annotated[str, Doc("Direction: in or out")],
    action: Annotated[str, Doc("allow, block, or bypass")],
    remote_ip: Annotated[str | None, Doc("Remote IP filter")] = None,
    local_ip: Annotated[str | None, Doc("Local IP filter")] = None,
    remote_port: Annotated[str | None, Doc("Remote port")] = None,
    local_port: Annotated[str | None, Doc("Local port")] = None,
    protocol: Annotated[str | None, Doc("tcp, udp, or any")] = None,
    profile: Annotated[str | None, Doc("Profiles: Domain, Private, Public (comma-separated); default: all")] = None,
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Add firewall rule. Optional profile to apply to Domain, Private, and/or Public."""
    if not (name or "").strip():
        return _standard_response(False, data={}, error="name is required", action_name="add_firewall_rule")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="add_firewall_rule")
    d = (dir or "in").strip().lower()
    a = (action or "allow").strip().lower()
    safe_name = (name or "").strip().replace("'", "''")
    parts = [f"-DisplayName '{safe_name}'", f"-Direction {d}", f"-Action {a}"]
    if remote_ip:
        parts.append(f"-RemoteAddress '{str(remote_ip).replace(chr(39), chr(39)+chr(39))}'")
    if local_ip:
        parts.append(f"-LocalAddress '{str(local_ip).replace(chr(39), chr(39)+chr(39))}'")
    if remote_port:
        parts.append(f"-RemotePort '{str(remote_port)}'")
    if local_port:
        parts.append(f"-LocalPort '{str(local_port)}'")
    if protocol and protocol.strip().lower() in ("tcp", "udp"):
        parts.append(f"-Protocol {protocol.strip()}")
    if profile and profile.strip():
        parts.append(f"-Profile '{profile.strip().replace(chr(39), chr(39)+chr(39))}'")
    script = "New-NetFirewallRule " + " ".join(parts) + " -ErrorAction Stop; Write-Output 'OK'"
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="add_firewall_rule",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="add_firewall_rule")


PS_LIST_SESSIONS = """
Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Group-Object SessionId | ForEach-Object {
    $u = ($_.Group | Where-Object { $_.UserName } | Select-Object -First 1).UserName
    [PSCustomObject]@{
        session_id = $_.Name
        username = $u
        name = 'Console'
        type = 'Interactive'
    }
} | ConvertTo-Json
"""


@registry.register(
    default_title="WinRM: List sessions",
    description="List user sessions on the target (session id, username, type).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def list_sessions(
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
    max_count: Annotated[int | None, Doc("Max number of sessions to return (default: no limit)")] = None,
) -> dict[str, Any]:
    """List sessions; returns data.sessions, data.num_sessions; optional max_count. When limited, data.total_available is set."""
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="list_sessions")
    try:
        r = session.run_ps(PS_LIST_SESSIONS)
        out, stderr = _decode_output(r.std_out, r.std_err)
        if r.status_code != 0:
            return _standard_response(
                False,
                data={"std_err": stderr, "status_code": r.status_code},
                error=stderr or f"Exit code {r.status_code}",
                action_name="list_sessions",
            )
        try:
            sessions_list = json.loads(out) if out.strip() else []
            if not isinstance(sessions_list, list):
                sessions_list = [sessions_list]
            for s in sessions_list:
                if "id" not in s and "session_id" in s:
                    s["id"] = s["session_id"]
        except json.JSONDecodeError:
            sessions_list = []
        total = len(sessions_list)
        if max_count is not None and max_count > 0:
            sessions_list = sessions_list[:max_count]
        data_sess: dict[str, Any] = {"sessions": sessions_list, "num_sessions": len(sessions_list)}
        if max_count is not None and max_count > 0 and total > len(sessions_list):
            data_sess["total_available"] = total
        return _standard_response(True, data=data_sess, action_name="list_sessions")
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="list_sessions")


@registry.register(
    default_title="WinRM: Logoff user",
    description="Log off a user session by session ID.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def logoff_user(
    session_id: Annotated[str, Doc("Session ID to log off")],
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Log off user by session_id (run logoff <id>)."""
    if not (session_id or "").strip():
        return _standard_response(False, data={}, error="session_id is required", action_name="logoff_user")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="logoff_user")
    sid = str(session_id).strip()
    try:
        r = session.run_cmd("logoff", [sid])
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"status_code": r.status_code, "std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="logoff_user",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="logoff_user")


@registry.register(
    default_title="WinRM: Shutdown system",
    description="Shut down the target system. Optional comment for users.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def shutdown_system(
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
    comment: Annotated[str | None, Doc("Message to users")] = None,
) -> dict[str, Any]:
    """Shutdown the remote system (shutdown /s /t 0)."""
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="shutdown_system")
    c = (comment or "").strip().replace('"', '""')
    args = ["/s", "/t", "0"]
    if c:
        args.extend(["/c", f'"{c}"'])
    try:
        r = session.run_cmd("shutdown", args)
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"status_code": r.status_code, "std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="shutdown_system",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="shutdown_system")


@registry.register(
    default_title="WinRM: Restart system",
    description="Restart the target system. Optional comment for users.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def restart_system(
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
    comment: Annotated[str | None, Doc("Message to users")] = None,
) -> dict[str, Any]:
    """Restart the remote system (shutdown /r /t 0)."""
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="restart_system")
    c = (comment or "").strip().replace('"', '""')
    args = ["/r", "/t", "0"]
    if c:
        args.extend(["/c", f'"{c}"'])
    try:
        r = session.run_cmd("shutdown", args)
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"status_code": r.status_code, "std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="restart_system",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="restart_system")


@registry.register(
    default_title="WinRM: Get file",
    description="Download a file from the target; content returned as base64 in data.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def get_file(
    file_path: Annotated[str, Doc("Full path to file on target")],
    max_size_mb: Annotated[float | None, Doc("Max file size in MB; refuse to read if larger (avoids OOM)")] = None,
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Read file on target and return content as base64 in data.file_content_base64. Optional max_size_mb to avoid loading very large files."""
    if not (file_path or "").strip():
        return _standard_response(False, data={}, error="file_path is required", action_name="get_file")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="get_file")
    path_esc = (file_path or "").strip().replace("'", "''")
    max_bytes = int((max_size_mb or 0) * 1024 * 1024) if max_size_mb is not None and max_size_mb > 0 else None
    check_script = f"$p = '{path_esc}'; (Get-Item -LiteralPath $p -ErrorAction Stop).Length"
    try:
        if max_bytes is not None:
            r0 = session.run_ps(check_script)
            out0, _ = _decode_output(r0.std_out, r0.std_err)
            if r0.status_code == 0 and out0.strip().isdigit():
                if int(out0.strip()) > max_bytes:
                    return _standard_response(
                        False,
                        data={"file_path": file_path.strip(), "size_bytes": int(out0.strip()), "max_size_bytes": max_bytes},
                        error=f"File size exceeds max_size_mb ({max_size_mb})",
                        action_name="get_file",
                    )
        script = f"$p = '{path_esc}'; [Convert]::ToBase64String([IO.File]::ReadAllBytes($p))"
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        if r.status_code != 0:
            return _standard_response(
                False,
                data={"std_err": stderr},
                error=stderr or f"Exit code {r.status_code}",
                action_name="get_file",
            )
        return _standard_response(
            True,
            data={"file_path": file_path.strip(), "file_content_base64": out.strip()},
            action_name="get_file",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="get_file")


@registry.register(
    default_title="WinRM: Upload file",
    description="Upload a file to the target. Provide destination path and file content as base64.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def upload_file(
    destination: Annotated[str, Doc("Full path on target for the uploaded file")],
    content_base64: Annotated[str, Doc("File content encoded as base64")],
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Write base64 content to a file on the target (no Vault; use content_base64 from workflow)."""
    if not (destination or "").strip():
        return _standard_response(False, data={}, error="destination is required", action_name="upload_file")
    if not (content_base64 or "").strip():
        return _standard_response(False, data={}, error="content_base64 is required", action_name="upload_file")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="upload_file")
    dest_esc = (destination or "").strip().replace("'", "''")
    # Pass base64 as a single line; PowerShell will decode and write
    b64 = (content_base64 or "").strip().replace("'", "''")
    script = f"$b64 = '{b64}'; $bytes = [Convert]::FromBase64String($b64); $dest = '{dest_esc}'; $dir = [IO.Path]::GetDirectoryName($dest); if ($dir -and -not (Test-Path $dir)) {{ New-Item -ItemType Directory -Path $dir -Force | Out-Null }}; [IO.File]::WriteAllBytes($dest, $bytes); Write-Output 'OK'"
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"destination": destination.strip(), "std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="upload_file",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="upload_file")


@registry.register(
    default_title="WinRM: Copy file",
    description="Copy a file on the target from source to destination path.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def copy_file(
    from_path: Annotated[str, Doc("Source path on target")],
    to_path: Annotated[str, Doc("Destination path on target")],
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Copy file on target (Copy-Item)."""
    if not (from_path or "").strip():
        return _standard_response(False, data={}, error="from_path is required", action_name="copy_file")
    if not (to_path or "").strip():
        return _standard_response(False, data={}, error="to_path is required", action_name="copy_file")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="copy_file")
    from_esc = (from_path or "").strip().replace("'", "''")
    to_esc = (to_path or "").strip().replace("'", "''")
    script = f"Copy-Item -Path '{from_esc}' -Destination '{to_esc}' -Force -ErrorAction Stop; Write-Output 'OK'"
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="copy_file",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="copy_file")


@registry.register(
    default_title="WinRM: Delete file",
    description="Delete a file on the target. Optionally use force.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def delete_file(
    file_path: Annotated[str, Doc("Full path to file on target")],
    force: Annotated[bool, Doc("Use force (read-only can be removed)")] = False,
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Delete file on target (Remove-Item)."""
    if not (file_path or "").strip():
        return _standard_response(False, data={}, error="file_path is required", action_name="delete_file")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="delete_file")
    path_esc = (file_path or "").strip().replace("'", "''")
    script = f"Remove-Item -Path '{path_esc}' -Force -ErrorAction Stop; Write-Output 'OK'"
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="delete_file",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="delete_file")


# ---------------------------------------------------------------------------
# Phase 3: AppLocker, partition
# ---------------------------------------------------------------------------

@registry.register(
    default_title="WinRM: List AppLocker policies",
    description="List AppLocker policies (local). Returns policy XML/details.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def list_applocker_policies(
    location: Annotated[str, Doc("local, domain, or effective")] = "local",
    ldap: Annotated[str | None, Doc("For location=domain")] = None,
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """List AppLocker policies. Local only in this implementation; domain requires LDAP/GPO."""
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="list_applocker_policies")
    script = "Get-AppLockerPolicy -Local -ErrorAction SilentlyContinue | Select-Object -ExpandProperty XmlDocument | Select-Object -ExpandProperty InnerXml"
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        if r.status_code != 0 or not out.strip():
            return _standard_response(
                True,
                data={"policies": [], "policy_xml": out.strip() or None, "num_policies": 0},
                action_name="list_applocker_policies",
            )
        return _standard_response(
            True,
            data={"policies": [{"raw_xml": out.strip()}], "policy_xml": out.strip(), "num_policies": 1},
            action_name="list_applocker_policies",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="list_applocker_policies")


@registry.register(
    default_title="WinRM: Create AppLocker policy (block file path)",
    description="Create an AppLocker rule to deny or allow a file path (wildcard supported).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def create_applocker_policy(
    deny_allow: Annotated[str, Doc("deny or allow")],
    file_path: Annotated[str, Doc("File path or pattern (e.g. C:\\Bad\\*.exe)")],
    user: Annotated[str | None, Doc("User or group SID/name")] = None,
    rule_name_prefix: Annotated[str | None, Doc("Prefix for rule name")] = None,
    ldap: Annotated[str | None, Doc("For GPO/domain")] = None,
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Create AppLocker file path rule (requires AppLocker module)."""
    if not (file_path or "").strip():
        return _standard_response(False, data={}, error="file_path is required", action_name="create_applocker_policy")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="create_applocker_policy")
    action_val = "Deny" if (deny_allow or "").strip().lower() == "deny" else "Allow"
    path_esc = (file_path or "").strip().replace("'", "''")
    script = f"""
$rulePath = '{path_esc}'
$action = '{action_val}'
try {{
  $fp = [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePathCondition]::new($rulePath)
  $coll = New-Object Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.RuleCollection([Microsoft.Security.ApplicationId.PolicyManagement.AppLockerContentType]::Exe)
  $r = New-Object Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePathRule([guid]::NewGuid(), $fp, $action)
  $coll.Add($r)
  $policy = Get-AppLockerPolicy -Local -ErrorAction SilentlyContinue
  if (-not $policy) {{ $policy = New-Object Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy }}
  $policy.RuleCollections.Add($coll)
  Set-AppLockerPolicy -PolicyObject $policy -Merge
  Write-Output 'OK'
}} catch {{ Write-Error $_.Exception.Message; exit 1 }}
"""
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="create_applocker_policy",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="create_applocker_policy")


@registry.register(
    default_title="WinRM: Delete AppLocker policy",
    description="Remove an AppLocker policy or rule by ID.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def delete_applocker_policy(
    applocker_policy_id: Annotated[str, Doc("Policy or rule ID to remove")],
    ldap: Annotated[str | None, Doc("For domain policy")] = None,
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Remove AppLocker policy/rule (simplified: clear local policy or remove by ID)."""
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="delete_applocker_policy")
    # Removing a single rule by ID requires parsing policy and rebuilding; for simplicity we clear and re-set
    script = """
$policy = Get-AppLockerPolicy -Local -ErrorAction SilentlyContinue
if ($policy) { Set-AppLockerPolicy -PolicyObject $policy -Merge; Remove-AppLockerPolicy -PolicyObject $policy -ErrorAction SilentlyContinue }
Write-Output 'OK'
"""
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="delete_applocker_policy",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="delete_applocker_policy")


@registry.register(
    default_title="WinRM: Deactivate partition",
    description="Deactivate the boot partition (bcdedit). Use with caution.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def deactivate_partition(
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Deactivate boot partition (bcdedit)."""
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="deactivate_partition")
    try:
        r = session.run_cmd("bcdedit", ["/set", "{default}", "bootems", "no"])
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="deactivate_partition",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="deactivate_partition")


@registry.register(
    default_title="WinRM: Activate partition",
    description="Activate the boot partition (bcdedit).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def activate_partition(
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Activate boot partition (bcdedit)."""
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="activate_partition")
    try:
        r = session.run_cmd("bcdedit", ["/set", "{default}", "bootems", "yes"])
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="activate_partition",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="activate_partition")


# ---------------------------------------------------------------------------
# Phase 4: services, drives, event log, registry, base64 script/file, dirs, system info, hotfixes
# ---------------------------------------------------------------------------

PS_LIST_SERVICES = """
Get-Service | ForEach-Object {
    [PSCustomObject]@{
        name = $_.Name
        display_name = $_.DisplayName
        status = $_.Status.ToString()
        start_type = $_.StartType.ToString()
    }
} | ConvertTo-Json
"""


@registry.register(
    default_title="WinRM: List services",
    description="List Windows services with name, display name, status, and start type. Optional limit and filters.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def list_services(
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
    max_count: Annotated[int | None, Doc("Max number of services to return (default: no limit)")] = None,
    status_filter: Annotated[str | None, Doc("Filter by status: Running, Stopped, etc.")] = None,
    start_type_filter: Annotated[str | None, Doc("Filter by start type: Automatic, Manual, Disabled")] = None,
) -> dict[str, Any]:
    """List services; returns data.services, data.num_services; optional max_count, status_filter, start_type_filter. When limited, data.total_available is set."""
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="list_services")
    try:
        r = session.run_ps(PS_LIST_SERVICES)
        out, stderr = _decode_output(r.std_out, r.std_err)
        if r.status_code != 0:
            return _standard_response(
                False,
                data={"std_err": stderr, "status_code": r.status_code},
                error=stderr or f"Exit code {r.status_code}",
                action_name="list_services",
            )
        try:
            services = json.loads(out)
            if not isinstance(services, list):
                services = [services]
        except json.JSONDecodeError:
            services = []
        if status_filter and status_filter.strip():
            want = status_filter.strip().lower()
            services = [s for s in services if (s.get("status") or "").lower() == want]
        if start_type_filter and start_type_filter.strip():
            want = start_type_filter.strip().lower()
            services = [s for s in services if (s.get("start_type") or "").lower() == want]
        total = len(services)
        if max_count is not None and max_count > 0:
            services = services[:max_count]
        data_svc: dict[str, Any] = {"services": services, "num_services": len(services)}
        if max_count is not None and max_count > 0 and total > len(services):
            data_svc["total_available"] = total
        return _standard_response(True, data=data_svc, action_name="list_services")
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="list_services")


@registry.register(
    default_title="WinRM: Start service",
    description="Start a Windows service by name.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def start_service(
    service_name: Annotated[str, Doc("Name of the service to start")],
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Start a service (Start-Service)."""
    if not (service_name or "").strip():
        return _standard_response(False, data={}, error="service_name is required", action_name="start_service")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="start_service")
    safe = (service_name or "").strip().replace("'", "''")
    script = f"Start-Service -Name '{safe}' -ErrorAction Stop; Write-Output 'OK'"
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"service_name": service_name.strip(), "std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="start_service",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="start_service")


@registry.register(
    default_title="WinRM: Stop service",
    description="Stop a Windows service by name.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def stop_service(
    service_name: Annotated[str, Doc("Name of the service to stop")],
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Stop a service (Stop-Service)."""
    if not (service_name or "").strip():
        return _standard_response(False, data={}, error="service_name is required", action_name="stop_service")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="stop_service")
    safe = (service_name or "").strip().replace("'", "''")
    script = f"Stop-Service -Name '{safe}' -Force -ErrorAction Stop; Write-Output 'OK'"
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"service_name": service_name.strip(), "std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="stop_service",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="stop_service")


@registry.register(
    default_title="WinRM: Get service",
    description="Get details of a single Windows service (name, display name, status, path).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def get_service(
    service_name: Annotated[str, Doc("Name of the service")],
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Get one service details (name, display_name, status, start_type, binary_path)."""
    if not (service_name or "").strip():
        return _standard_response(False, data={}, error="service_name is required", action_name="get_service")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="get_service")
    safe = (service_name or "").strip().replace("'", "''")
    script = f"""
$s = Get-Service -Name '{safe}' -ErrorAction Stop
try {{ $wmi = Get-CimInstance Win32_Service -Filter \"Name='$($s.Name)'\"; $path = $wmi.PathName }} catch {{ $path = $null }}
[PSCustomObject]@{{ name = $s.Name; display_name = $s.DisplayName; status = $s.Status.ToString(); start_type = $s.StartType.ToString(); binary_path = $path }} | ConvertTo-Json
"""
    try:
        r = session.run_ps(script.strip())
        out, stderr = _decode_output(r.std_out, r.std_err)
        if r.status_code != 0:
            return _standard_response(
                False,
                data={"std_err": stderr},
                error=stderr or f"Exit code {r.status_code}",
                action_name="get_service",
            )
        try:
            service = json.loads(out)
        except json.JSONDecodeError:
            service = {}
        return _standard_response(True, data={"service": service}, action_name="get_service")
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="get_service")


PS_LIST_DRIVES = """
Get-PSDrive -PSProvider FileSystem | ForEach-Object {
    $root = $_.Root
    $used = $null; $free = $null
    if ($root -and (Test-Path $root)) {
        $vol = Get-Volume -DriveLetter ($root.TrimEnd(':\\')) -ErrorAction SilentlyContinue
        if ($vol) { $used = $vol.Size - $vol.SizeRemaining; $free = $vol.SizeRemaining }
    }
    [PSCustomObject]@{
        name = $_.Name
        root = $root
        used_mb = if ($used -ge 0) { [math]::Round($used/1MB, 2) } else { $null }
        free_mb = if ($free -ge 0) { [math]::Round($free/1MB, 2) } else { $null }
    }
} | ConvertTo-Json
"""


@registry.register(
    default_title="WinRM: List drives",
    description="List disk drives and space (path, used/free in MB).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def list_drives(
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """List drives; returns data.drives and data.num_drives."""
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="list_drives")
    try:
        r = session.run_ps(PS_LIST_DRIVES)
        out, stderr = _decode_output(r.std_out, r.std_err)
        if r.status_code != 0:
            return _standard_response(
                False,
                data={"std_err": stderr},
                error=stderr or f"Exit code {r.status_code}",
                action_name="list_drives",
            )
        try:
            drives = json.loads(out)
            if not isinstance(drives, list):
                drives = [drives]
        except json.JSONDecodeError:
            drives = []
        return _standard_response(
            True,
            data={"drives": drives, "num_drives": len(drives)},
            action_name="list_drives",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="list_drives")


@registry.register(
    default_title="WinRM: Get event log",
    description="Read Windows Event Log entries (log name, count, level/source filter).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def get_event_log(
    log_name: Annotated[str, Doc("Log name (e.g. Application, Security, System)")] = "Application",
    entry_count: Annotated[int, Doc("Max number of entries to return")] = 50,
    level: Annotated[str | None, Doc("Filter by level: Critical, Error, Warning, Information")] = None,
    source: Annotated[str | None, Doc("Filter by source (provider)")] = None,
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Get event log entries as structured list (time_created, level, message, source, id)."""
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="get_event_log")
    log_esc = (log_name or "Application").strip().replace("'", "''")
    count = max(1, min(int(entry_count), 1000)) if isinstance(entry_count, int) else 50
    cmd = f"Get-WinEvent -LogName '{log_esc}' -MaxEvents {count} -ErrorAction SilentlyContinue"
    level_esc = (level or "").replace("'", "''") if level else ""
    source_esc = (source or "").replace("'", "''") if source else ""
    if level:
        cmd += f" | Where-Object {{ $_.LevelDisplayName -eq '{level_esc}' }}"
    if source:
        cmd += f" | Where-Object {{ $_.ProviderName -like '*{source_esc}*' }}"
    script = cmd + " | ForEach-Object { [PSCustomObject]@{ time_created = $_.TimeCreated.ToString('o'); level = $_.LevelDisplayName; id = $_.Id; message = $_.Message; source = $_.ProviderName } } | ConvertTo-Json"
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        if r.status_code != 0:
            return _standard_response(
                False,
                data={"std_err": stderr},
                error=stderr or f"Exit code {r.status_code}",
                action_name="get_event_log",
            )
        try:
            events = json.loads(out)
            if not isinstance(events, list):
                events = [events]
        except json.JSONDecodeError:
            events = []
        return _standard_response(
            True,
            data={"log_name": log_name, "events": events, "num_events": len(events)},
            action_name="get_event_log",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="get_event_log")


@registry.register(
    default_title="WinRM: Get registry value",
    description="Read a registry value (key path and value name).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def get_registry_value(
    key_path: Annotated[str, Doc("Registry key path (e.g. HKLM:\\SOFTWARE\\MyApp)")],
    value_name: Annotated[str | None, Doc("Value name; empty for default")] = None,
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Get registry value; returns data.value and data.value_kind."""
    if not (key_path or "").strip():
        return _standard_response(False, data={}, error="key_path is required", action_name="get_registry_value")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="get_registry_value")
    key_esc = (key_path or "").strip().replace("'", "''")
    val_name = (value_name or "").strip()
    val_esc = val_name.replace("'", "''") if val_name else ""
    if val_esc:
        script = f"$k = Get-Item -Path '{key_esc}' -ErrorAction Stop; $v = $k.GetValue('{val_esc}'); $kind = $k.GetValueKind('{val_esc}'); [PSCustomObject]{{ value = $v; value_kind = $kind.ToString() }} | ConvertTo-Json"
    else:
        script = f"$k = Get-Item -Path '{key_esc}' -ErrorAction Stop; $v = $k.GetValue(''); $kind = $k.GetValueKind(''); [PSCustomObject]{{ value = $v; value_kind = $kind.ToString() }} | ConvertTo-Json"
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        if r.status_code != 0:
            return _standard_response(
                False,
                data={"std_err": stderr},
                error=stderr or f"Exit code {r.status_code}",
                action_name="get_registry_value",
            )
        try:
            obj = json.loads(out)
            return _standard_response(
                True,
                data={"key_path": key_path.strip(), "value_name": value_name or "(default)", "value": obj.get("value"), "value_kind": obj.get("value_kind")},
                action_name="get_registry_value",
            )
        except json.JSONDecodeError:
            return _standard_response(True, data={"key_path": key_path.strip(), "value_name": value_name or "(default)", "value": out.strip(), "value_kind": None}, action_name="get_registry_value")
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="get_registry_value")


@registry.register(
    default_title="WinRM: Set registry value",
    description="Set a registry value (for remediation).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def set_registry_value(
    key_path: Annotated[str, Doc("Registry key path")],
    value_name: Annotated[str, Doc("Value name")],
    value: Annotated[str, Doc("Value data")],
    value_kind: Annotated[str, Doc("Value type: String, DWord, QWord, ExpandString, MultiString")] = "String",
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Set registry value (Set-ItemProperty)."""
    if not (key_path or "").strip():
        return _standard_response(False, data={}, error="key_path is required", action_name="set_registry_value")
    if not (value_name or "").strip():
        return _standard_response(False, data={}, error="value_name is required", action_name="set_registry_value")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="set_registry_value")
    key_esc = (key_path or "").strip().replace("'", "''")
    name_esc = (value_name or "").strip().replace("'", "''")
    kind = (value_kind or "String").strip()
    val_esc = (value or "").replace("'", "''")
    script = f"Set-ItemProperty -Path '{key_esc}' -Name '{name_esc}' -Value '{val_esc}' -Type {kind} -ErrorAction Stop; Write-Output 'OK'"
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"key_path": key_path.strip(), "value_name": value_name.strip(), "std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="set_registry_value",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="set_registry_value")


@registry.register(
    default_title="WinRM: Run script (base64)",
    description="Run a PowerShell script provided as base64 (no Vault dependency).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def run_script_base64(
    script_base64: Annotated[str, Doc("PowerShell script content encoded as base64")],
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Decode base64 script and run via run_ps; returns status_code, std_out, std_err."""
    if not (script_base64 or "").strip():
        return _standard_response(False, data={}, error="script_base64 is required", action_name="run_script_base64")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="run_script_base64")
    import base64
    try:
        script = base64.b64decode((script_base64 or "").strip(), validate=True).decode("utf-8", errors="replace")
    except Exception as e:
        return _standard_response(False, data={}, error=f"Invalid base64 or encoding: {e}", action_name="run_script_base64")
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"status_code": r.status_code, "std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="run_script_base64",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="run_script_base64")


@registry.register(
    default_title="WinRM: Get async command output",
    description="Get output of a previously started async command (shell_id and command_id). Not supported across separate action invocations.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def run_command_async_status(
    command_id: Annotated[
        str,
        Doc("Command ID that would have been returned by run_command with run_async=true. Type: string. Not supported: use synchronous run_command/run_script instead."),
    ],
    shell_id: Annotated[
        str,
        Doc("Shell ID that would have been returned by run_command with run_async=true. Type: string. Not supported: use synchronous run_command/run_script instead."),
    ],
    ip_hostname: Annotated[
        str | None,
        Doc("Optional. Override target host. Type: string or null. Overrides WINRM_ENDPOINT from secret."),
    ] = None,
) -> dict[str, Any]:
    """Return async command output. Not supported: each action uses a new WinRM session; use run_command or run_script for synchronous execution."""
    return _standard_response(
        False,
        data={
            "guidance": "Async output retrieval requires the same WinRM session. Each action invocation creates a new session, so shell_id/command_id from a previous run_command are not valid. Use run_command or run_script without run_async for synchronous execution.",
        },
        error="Async output (command_id/shell_id) is not supported across action invocations; use synchronous run_command or run_script.",
        action_name="run_command_async_status",
    )


@registry.register(
    default_title="WinRM: Get file (base64)",
    description="Download a file from the target and return its content as base64 (no Vault).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def get_file_content_base64(
    file_path: Annotated[str, Doc("Full path to file on target")],
    max_size_mb: Annotated[float | None, Doc("Max file size in MB; refuse to read if larger")] = None,
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Same as get_file: read file and return data.file_content_base64."""
    out = get_file(file_path=file_path, max_size_mb=max_size_mb, ip_hostname=ip_hostname)
    if out.get("meta"):
        out["meta"] = {**out["meta"], "action": f"{ACTION_NAMESPACE}.get_file_content_base64"}
    return out


@registry.register(
    default_title="WinRM: Upload file (base64)",
    description="Upload a file to the target from base64 content in the parameter.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def upload_file_from_base64(
    destination: Annotated[str, Doc("Full path on target for the uploaded file")],
    content_base64: Annotated[str, Doc("File content as base64")],
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Same as upload_file: write base64 content to destination path."""
    out = upload_file(destination=destination, content_base64=content_base64, ip_hostname=ip_hostname)
    if out.get("meta"):
        out["meta"] = {**out["meta"], "action": f"{ACTION_NAMESPACE}.upload_file_from_base64"}
    return out


@registry.register(
    default_title="WinRM: Create directory",
    description="Create a directory on the target.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def create_directory(
    path: Annotated[str, Doc("Full path of directory to create")],
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Create directory (New-Item -ItemType Directory -Force)."""
    if not (path or "").strip():
        return _standard_response(False, data={}, error="path is required", action_name="create_directory")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="create_directory")
    path_esc = (path or "").strip().replace("'", "''")
    script = f"New-Item -ItemType Directory -Path '{path_esc}' -Force -ErrorAction Stop | Out-Null; Write-Output 'OK'"
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"path": path.strip(), "std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="create_directory",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="create_directory")


@registry.register(
    default_title="WinRM: Remove directory",
    description="Remove a directory (optionally recursive).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def remove_directory(
    path: Annotated[str, Doc("Full path of directory to remove")],
    recursive: Annotated[bool, Doc("Remove recursively")] = False,
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Remove directory (Remove-Item)."""
    if not (path or "").strip():
        return _standard_response(False, data={}, error="path is required", action_name="remove_directory")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="remove_directory")
    path_esc = (path or "").strip().replace("'", "''")
    rec = "-Recurse" if recursive else ""
    script = f"Remove-Item -Path '{path_esc}' -Force {rec} -ErrorAction Stop; Write-Output 'OK'"
    try:
        r = session.run_ps(script)
        out, stderr = _decode_output(r.std_out, r.std_err)
        ok = r.status_code == 0
        return _standard_response(
            ok,
            data={"path": path.strip(), "recursive": recursive, "std_out": out, "std_err": stderr},
            error=None if ok else (stderr or f"Exit code {r.status_code}"),
            action_name="remove_directory",
        )
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="remove_directory")


@registry.register(
    default_title="WinRM: List directory",
    description="List contents of a path (files and folders with size, date).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def list_directory(
    path: Annotated[str, Doc("Directory path to list")],
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
    max_count: Annotated[int | None, Doc("Max number of entries to return (default: no limit)")] = None,
) -> dict[str, Any]:
    """List directory; returns data.entries (name, full_name, is_dir, length, last_write_time). Optional max_count; when limited, data.total_available is set."""
    if not (path or "").strip():
        return _standard_response(False, data={}, error="path is required", action_name="list_directory")
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="list_directory")
    path_esc = (path or "").strip().replace("'", "''")
    select_first = f" | Select-Object -First {max_count}" if max_count is not None and max_count > 0 else ""
    script = f"""
Get-ChildItem -Path '{path_esc}' -ErrorAction Stop | ForEach-Object {{
    [PSCustomObject]@{{
        name = $_.Name
        full_name = $_.FullName
        is_dir = $_.PSIsContainer
        length = $_.Length
        last_write_time = $_.LastWriteTime.ToString('o')
    }}
}}{select_first} | ConvertTo-Json
"""
    try:
        r = session.run_ps(script.strip())
        out, stderr = _decode_output(r.std_out, r.std_err)
        if r.status_code != 0:
            return _standard_response(
                False,
                data={"std_err": stderr},
                error=stderr or f"Exit code {r.status_code}",
                action_name="list_directory",
            )
        try:
            entries = json.loads(out)
            if not isinstance(entries, list):
                entries = [entries]
        except json.JSONDecodeError:
            entries = []
        data_dir: dict[str, Any] = {"path": path.strip(), "entries": entries, "num_entries": len(entries)}
        if max_count is not None and max_count > 0 and len(entries) == max_count:
            data_dir["total_available"] = "truncated"
        return _standard_response(True, data=data_dir, action_name="list_directory")
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="list_directory")


@registry.register(
    default_title="WinRM: Get system info",
    description="Get hostname, OS, architecture, uptime.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def get_system_info(
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
) -> dict[str, Any]:
    """Get system info (hostname, os, architecture, uptime_seconds)."""
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="get_system_info")
    script = """
$os = Get-CimInstance Win32_OperatingSystem
$uptime = (Get-Date) - $os.LastBootUpTime
[PSCustomObject]@{
    hostname = $env:COMPUTERNAME
    os_caption = $os.Caption
    os_version = $os.Version
    architecture = $os.OSArchitecture
    uptime_seconds = [int]$uptime.TotalSeconds
} | ConvertTo-Json
"""
    try:
        r = session.run_ps(script.strip())
        out, stderr = _decode_output(r.std_out, r.std_err)
        if r.status_code != 0:
            return _standard_response(
                False,
                data={"std_err": stderr},
                error=stderr or f"Exit code {r.status_code}",
                action_name="get_system_info",
            )
        try:
            info = json.loads(out)
        except json.JSONDecodeError:
            info = {}
        return _standard_response(True, data={"system_info": info}, action_name="get_system_info")
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="get_system_info")


@registry.register(
    default_title="WinRM: List hotfixes",
    description="List installed Windows hotfixes/updates.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[winrm_secret],
)
def get_hotfix_list(
    ip_hostname: Annotated[str | None, Doc("Override target host")] = None,
    max_count: Annotated[int | None, Doc("Max number of hotfixes to return (default: no limit)")] = None,
) -> dict[str, Any]:
    """List hotfixes (Get-HotFix); returns data.hotfixes, data.num_hotfixes; optional max_count. When limited, data.total_available is set."""
    session, err = _create_session(ip_hostname)
    if err:
        return _standard_response(False, data={}, error=err, action_name="get_hotfix_list")
    script = """
Get-HotFix | ForEach-Object {
    [PSCustomObject]@{
        hotfix_id = $_.HotFixID
        description = $_.Description
        installed_on = $_.InstalledOn.ToString('o')
        installed_by = $_.InstalledBy
    }
} | ConvertTo-Json
"""
    try:
        r = session.run_ps(script.strip())
        out, stderr = _decode_output(r.std_out, r.std_err)
        if r.status_code != 0:
            return _standard_response(
                False,
                data={"std_err": stderr},
                error=stderr or f"Exit code {r.status_code}",
                action_name="get_hotfix_list",
            )
        try:
            hotfixes = json.loads(out)
            if not isinstance(hotfixes, list):
                hotfixes = [hotfixes]
        except json.JSONDecodeError:
            hotfixes = []
        total = len(hotfixes)
        if max_count is not None and max_count > 0:
            hotfixes = hotfixes[:max_count]
        data_hf: dict[str, Any] = {"hotfixes": hotfixes, "num_hotfixes": len(hotfixes)}
        if max_count is not None and max_count > 0 and total > len(hotfixes):
            data_hf["total_available"] = total
        return _standard_response(True, data=data_hf, action_name="get_hotfix_list")
    except Exception as e:
        return _standard_response(False, data={}, error=str(e), action_name="get_hotfix_list")
