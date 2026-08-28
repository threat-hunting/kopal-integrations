"""SOCLib AD/LDAP integration — integrations.soclib.ad (engine UDFs).

Implements actions from Splunk SOAR app AD LDAP (ad-ldap_237).
All actions return standard output: { success, data, error, meta }.

NOTE: UDF namespace is "integrations.soclib.ad" (engine).
User-facing YAML templates use namespace "tools.soclib.ad" and call these UDFs.
This follows the same pattern as the official Kopal registry
(e.g. tools.slack_sdk → tools.slack).
"""

from __future__ import annotations

import ssl as ssl_mod
from datetime import datetime, timezone
from typing import Annotated, Any

from ldap3 import (
    ALL,
    BASE,
    LEVEL,
    MODIFY_ADD,
    MODIFY_DELETE,
    MODIFY_REPLACE,
    NTLM,
    SIMPLE,
    SUBTREE,
    Connection,
    Server,
    Tls,
)
from ldap3.utils.dn import parse_dn
from typing_extensions import Doc

import ldap3.extend.microsoft.addMembersToGroups
import ldap3.extend.microsoft.removeMembersFromGroups
import ldap3.extend.microsoft.unlockAccount

from kopal_registry import RegistrySecret, registry, secrets

# Secret name in Kopal: soclib_active_directory (static - must match templates)
# Optional key AD_CA_CERTIFICATE: PEM-encoded CA or server cert for SSL validation (see ssl-validation-requirements.md)
ad_secret = RegistrySecret(
    name="soclib_active_directory",
    keys=["AD_URL", "AD_BIND_DN", "AD_BIND_PASSWORD", "AD_BASE_DN"],
    optional_keys=["AD_CA_CERTIFICATE"],
)

ACTION_NAMESPACE = "integrations.soclib.ad"
DISPLAY_GROUP = "SOCLib / Active Directory"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

UAC_FLAGS: dict[str, int] = {
    "SCRIPT": 0x0001,
    "ACCOUNTDISABLE": 0x0002,
    "HOMEDIR_REQUIRED": 0x0008,
    "LOCKOUT": 0x0010,
    "PASSWD_NOTREQD": 0x0020,
    "PASSWD_CANT_CHANGE": 0x0040,
    "NORMAL_ACCOUNT": 0x0200,
    "INTERDOMAIN_TRUST_ACCOUNT": 0x0800,
    "WORKSTATION_TRUST_ACCOUNT": 0x1000,
    "SERVER_TRUST_ACCOUNT": 0x2000,
    "DONT_EXPIRE_PASSWORD": 0x10000,
    "SMARTCARD_REQUIRED": 0x40000,
    "TRUSTED_FOR_DELEGATION": 0x80000,
    "NOT_DELEGATED": 0x100000,
    "DONT_REQ_PREAUTH": 0x400000,
    "PASSWORD_EXPIRED": 0x800000,
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,
}

# Commonly-checked subset for readable output
UAC_DISPLAY_FLAGS = (
    "ACCOUNTDISABLE",
    "LOCKOUT",
    "PASSWD_NOTREQD",
    "PASSWORD_EXPIRED",
    "DONT_EXPIRE_PASSWORD",
    "NORMAL_ACCOUNT",
    "SMARTCARD_REQUIRED",
    "TRUSTED_FOR_DELEGATION",
)

ATTRIBUTE_PRESETS: dict[str, list[str]] = {
    "basic": [
        "sAMAccountName", "displayName", "mail", "distinguishedName",
    ],
    "security": [
        "sAMAccountName", "displayName", "mail", "distinguishedName",
        "userAccountControl", "lockoutTime", "pwdLastSet",
        "lastLogonTimestamp", "accountExpires", "memberOf",
    ],
    "detailed": [
        "sAMAccountName", "displayName", "mail", "distinguishedName",
        "userAccountControl", "lockoutTime", "pwdLastSet",
        "lastLogonTimestamp", "accountExpires", "memberOf",
        "whenCreated", "whenChanged", "description", "department",
        "title", "manager", "telephoneNumber", "userPrincipalName",
    ],
    "all": ["*"],
}

USER_SEARCH_PRESETS: dict[str, str | None] = {
    "all_users": "(&(objectCategory=person)(objectClass=user))",
    "disabled_users": "(&(objectCategory=person)(objectClass=user)"
                      "(userAccountControl:1.2.840.113556.1.4.803:=2))",
    "locked_users": "(&(objectCategory=person)(objectClass=user)"
                    "(lockoutTime>=1))",
    "expired_passwords": "(&(objectCategory=person)(objectClass=user)"
                         "(pwdLastSet=0)"
                         "(!userAccountControl:1.2.840.113556.1.4.803:=65536))",
    "never_expire_passwords": "(&(objectCategory=person)(objectClass=user)"
                              "(userAccountControl:1.2.840.113556.1.4.803:=65536))",
    "service_accounts": "(&(objectCategory=person)(objectClass=user)"
                        "(|(sAMAccountName=svc_*)(sAMAccountName=sa_*)"
                        "(description=*service*)))",
}

COMPUTER_SEARCH_PRESETS: dict[str, str] = {
    "all_computers": "(objectClass=computer)",
    "disabled_computers": "(&(objectClass=computer)"
                          "(userAccountControl:1.2.840.113556.1.4.803:=2))",
    "servers": "(&(objectClass=computer)(operatingSystem=*Server*))",
    "workstations": "(&(objectClass=computer)(!(operatingSystem=*Server*)))",
}

SEARCH_SCOPE_MAP = {"SUBTREE": SUBTREE, "BASE": BASE, "LEVEL": LEVEL}

DEFAULT_PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
]


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


def _parse_ad_url(url: str) -> tuple[str, int, bool]:
    """
    Parse AD_URL to (host, port, use_ssl).
    Supports: ldap://host, ldap://host:port, ldaps://host:636, host, host:port
    """
    url = (url or "").strip()
    use_ssl = False
    if url.lower().startswith("ldaps://"):
        use_ssl = True
        url = url[8:]
    elif url.lower().startswith("ldap://"):
        url = url[7:]
    if ":" in url:
        host, _, port_str = url.rpartition(":")
        try:
            port = int(port_str)
            return host.strip(), port, use_ssl
        except ValueError:
            pass
    default_port = 636 if use_ssl else 389
    return url, default_port, use_ssl


def _ldap_escape(value: str) -> str:
    """Minimal RFC4515 escaping for LDAP filter."""
    return (
        value.replace("\\", "\\5c")
        .replace("*", "\\2a")
        .replace("(", "\\28")
        .replace(")", "\\29")
        .replace("\x00", "\\00")
    )


def _get_optional_secret(key: str, default: str = "") -> str:
    """Read an optional secret key, returning *default* when the key is absent."""
    try:
        val = secrets.get(key)
        return str(val).strip() if val else default
    except Exception:
        return default


def _build_connection_spec(
    host: str,
    port: int,
    use_ssl: bool,
    use_start_tls: bool,
    validate_ssl: bool,
    secure_mode: str,
    auth_type: str,
    timeout: int,
) -> dict[str, Any]:
    """Build a connection spec dict for reporting (no secrets)."""
    if use_ssl:
        connection_type = "ldaps"
        protocol = "LDAPS (SSL/TLS on port 636)"
    elif use_start_tls:
        connection_type = "start_tls"
        protocol = "LDAP with Start TLS (port 389, upgraded to TLS)"
    else:
        connection_type = "plain_ldap"
        protocol = "LDAP (plain, port 389)"
    return {
        "connection_type": connection_type,
        "protocol": protocol,
        "host": host,
        "port": port,
        "use_ssl": use_ssl,
        "use_start_tls": use_start_tls,
        "ssl_validation": "enabled" if validate_ssl else "disabled",
        "secure_mode": secure_mode,
        "auth_type": auth_type,
        "timeout_seconds": timeout,
    }


def _get_connection_spec_from_secrets() -> tuple[dict[str, Any] | None, str | None]:
    """
    Build connection spec from secrets (no actual connection).
    Returns (spec, None) or (None, error_message) if URL missing/masked.
    """
    try:
        ldap_url = secrets.get("AD_URL")
    except Exception as e:
        return None, f"Missing or invalid secret: {e!s}"
    ldap_url = str(ldap_url or "").strip()
    if not ldap_url or ldap_url.startswith("*"):
        return None, "AD_URL is empty or masked (check credential)"
    host, port, url_ssl = _parse_ad_url(ldap_url)
    if not host:
        return None, "AD_URL host is empty"
    secure_mode = _get_optional_secret("AD_SECURE_CONNECTION", "auto").lower()
    validate_ssl = _get_optional_secret("AD_VALIDATE_SSL", "true").lower() == "true"
    auth_type = _get_optional_secret("AD_AUTH_TYPE", "simple").lower()
    try:
        timeout = int(_get_optional_secret("AD_TIMEOUT", "30") or "30")
    except ValueError:
        timeout = 30
    use_ssl = url_ssl
    use_start_tls = False
    if secure_mode == "ssl":
        use_ssl = True
        if port == 389:
            port = 636
    elif secure_mode == "start_tls":
        use_ssl = False
        use_start_tls = True
    elif secure_mode == "none":
        use_ssl = False
    spec = _build_connection_spec(
        host, port, use_ssl, use_start_tls, validate_ssl, secure_mode, auth_type, timeout
    )
    try:
        ca_pem = secrets.get_or_default("AD_CA_CERTIFICATE")
        spec["ca_certificate_source"] = "custom" if (ca_pem and str(ca_pem).strip()) else "system"
    except Exception:
        spec["ca_certificate_source"] = "system"
    return spec, None


def _connectivity_failure_guidance(error_message: str) -> str:
    """Return guidance text (English) based on common failure patterns."""
    err_lower = (error_message or "").lower()
    if "invalidcredentials" in err_lower or "invalid credentials" in err_lower or "login" in err_lower and "fail" in err_lower:
        return (
            "Check AD_BIND_DN and AD_BIND_PASSWORD in the secret. "
            "Use UPN (user@domain.com) or DN. Ensure the account is not locked or disabled."
        )
    if "ssl" in err_lower or "tls" in err_lower or "certificate" in err_lower or "unexpected_eof" in err_lower:
        return (
            "SSL/TLS or certificate issue. Try AD_VALIDATE_SSL=false for self-signed DC certs, "
            "or ensure the DC has a valid LDAPS certificate and supports the requested protocol (LDAPS or Start TLS)."
        )
    if "connection refused" in err_lower or "connectionrefused" in err_lower:
        return "Host or port unreachable. Verify AD_URL (host and port), firewall, and that the DC is listening on the given port (389 for LDAP, 636 for LDAPS)."
    if "timeout" in err_lower or "timed out" in err_lower:
        return "Connection timed out. Check AD_URL, network reachability, and AD_TIMEOUT. Ensure the DC is reachable from this host."
    if "no such host" in err_lower or "name or service not known" in err_lower or "getaddrinfo" in err_lower:
        return "Host name could not be resolved. Verify AD_URL host (DNS or IP) is correct and reachable."
    if "starttls" in err_lower or "start_tls" in err_lower or "unavailable" in err_lower:
        return (
            "Start TLS failed. The DC may not support Start TLS or may lack a valid server certificate. "
            "Try plain LDAP (AD_SECURE_CONNECTION=none) or LDAPS (AD_SECURE_CONNECTION=ssl, AD_URL with port 636)."
        )
    if "empty or masked" in err_lower or "ad_url" in err_lower and "empty" in err_lower:
        return "AD_URL is missing or masked in the secret. Set AD_URL in the soclib_active_directory credential (e.g. ldap://dc.example.com or ldaps://dc.example.com:636)."
    if "bind" in err_lower and "fail" in err_lower:
        return "Bind failed. Check AD_BIND_DN format (UPN or DN) and AD_BIND_PASSWORD. Ensure the account has LDAP read access."
    return (
        "Verify secret keys (AD_URL, AD_BIND_DN, AD_BIND_PASSWORD, AD_BASE_DN). "
        "Check DC availability and network access. See integration docs for LDAPS/Start TLS requirements."
    )


def _get_connection() -> tuple[Connection | None, str | None]:
    """
    Create and bind LDAP connection from secrets.
    Returns (conn, None) on success, (None, error_message) on failure.

    AD_URL formats: ldap://host, ldap://host:389, ldaps://host:636, host, host:389

    Optional secret keys:
      AD_SECURE_CONNECTION: auto | ssl | start_tls | none  (default: auto)
      AD_VALIDATE_SSL:      true | false                   (default: true)
      AD_AUTH_TYPE:          simple | ntlm                  (default: simple)
      AD_TIMEOUT:            seconds                        (default: 30)
    """
    try:
        ldap_url = secrets.get("AD_URL")
        bind_dn = secrets.get("AD_BIND_DN")
        bind_password = secrets.get("AD_BIND_PASSWORD")
    except Exception as e:
        return None, f"Missing or invalid secret: {e!s}"

    ldap_url = str(ldap_url or "").strip()
    if not ldap_url or ldap_url.startswith("*"):
        return None, "AD_URL is empty or masked (check credential)"

    host, port, url_ssl = _parse_ad_url(ldap_url)
    if not host:
        return None, "AD_URL host is empty"

    # --- optional SSL / auth settings ---
    secure_mode = _get_optional_secret("AD_SECURE_CONNECTION", "auto").lower()
    validate_ssl = _get_optional_secret("AD_VALIDATE_SSL", "true").lower() == "true"
    auth_type = _get_optional_secret("AD_AUTH_TYPE", "simple").lower()
    try:
        timeout = int(_get_optional_secret("AD_TIMEOUT", "30") or "30")
    except ValueError:
        timeout = 30

    # Determine SSL / Start TLS
    use_ssl = url_ssl
    use_start_tls = False
    if secure_mode == "ssl":
        use_ssl = True
        if port == 389:
            port = 636
    elif secure_mode == "start_tls":
        use_ssl = False
        use_start_tls = True
    elif secure_mode == "none":
        use_ssl = False
    # else "auto" → follow url_ssl

    # TLS object — use TLS 1.2 for Windows AD compatibility; some DCs fail with default
    # When AD_VALIDATE_SSL=true, optional AD_CA_CERTIFICATE (PEM) is used as trust store if set
    tls_config = None
    if use_ssl or use_start_tls:
        tls_version = getattr(ssl_mod, "PROTOCOL_TLS_CLIENT", None) or getattr(
            ssl_mod, "PROTOCOL_TLSv1_2", ssl_mod.PROTOCOL_TLS
        )
        ca_cert_pem = None
        try:
            ca_cert_pem = secrets.get_or_default("AD_CA_CERTIFICATE")
        except Exception:
            pass
        if isinstance(ca_cert_pem, str):
            ca_cert_pem = ca_cert_pem.strip() or None
        tls_config = Tls(
            validate=ssl_mod.CERT_REQUIRED if validate_ssl else ssl_mod.CERT_NONE,
            version=tls_version,
            ca_certs_data=ca_cert_pem if ca_cert_pem else None,
        )

    server = Server(
        host, port=port, use_ssl=use_ssl, tls=tls_config,
        get_info=ALL, connect_timeout=timeout,
    )

    authentication = NTLM if auth_type == "ntlm" else SIMPLE

    try:
        conn = Connection(
            server,
            user=bind_dn,
            password=bind_password,
            auto_bind=not use_start_tls,
            auto_referrals=False,
            authentication=authentication,
            receive_timeout=timeout,
        )
        if use_start_tls:
            conn.open()
            conn.start_tls()
            conn.bind()
    except Exception as e:
        return None, str(e)

    if not conn.bound:
        desc = "Bind failed"
        if isinstance(conn.result, dict):
            desc = conn.result.get("description", desc)
        return None, desc
    return conn, None


def _get_root_dn(conn: Connection) -> str | None:
    """Get default naming context from server info."""
    try:
        return conn.server.info.other["defaultNamingContext"][0]
    except (KeyError, TypeError, IndexError):
        return None


def _sam_to_dn(conn: Connection, sam_list: list[str], base_dn: str) -> dict[str, str | bool]:
    """
    Resolve sAMAccountNames to DNs. Returns dict: sam_lower -> dn (str) or False if not found.
    """
    if not sam_list:
        return {}
    filter_parts = "".join(f"(samaccountname={_ldap_escape(s.strip())})" for s in sam_list if s.strip())
    ldap_filter = f"(|{filter_parts})"
    conn.search(
        search_base=base_dn,
        search_filter=ldap_filter,
        search_scope=SUBTREE,
        attributes=["distinguishedName", "sAMAccountName"],
    )
    result = {name.strip().lower(): False for name in sam_list if name.strip()}
    for entry in conn.response:
        if entry.get("type") == "searchResRef":
            continue
        attrs = entry.get("attributes") or {}
        sam = attrs.get("sAMAccountName") or attrs.get("samaccountname")
        dn = attrs.get("distinguishedName") or attrs.get("distinguishedname") or entry.get("dn")
        if sam is not None and dn:
            key = (sam if isinstance(sam, str) else str(sam)).lower()
            if key in result:
                result[key] = dn if isinstance(dn, str) else str(dn)
    return result


def _decode_uac(uac_value: int) -> dict[str, bool]:
    """Decode userAccountControl integer to human-readable flag dict."""
    return {name: bool(uac_value & UAC_FLAGS[name]) for name in UAC_DISPLAY_FLAGS}


def _ensure_list(value: str | list | None) -> list[str]:
    """Accept semicolon-separated string **or** list and return list[str]."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [v.strip() for v in str(value).split(";") if v.strip()]


def _resolve_identifier(
    conn: Connection,
    identifier: str,
    identifier_type: str,
    base_dn: str,
) -> tuple[str | None, str | None]:
    """Resolve a user/object identifier to its DN.

    *identifier_type* can be ``auto``, ``samaccountname``, ``dn``, ``upn``,
    or ``email``.  Returns ``(dn, None)`` on success, ``(None, error)`` on
    failure.
    """
    identifier = identifier.strip()
    if not identifier:
        return None, "Identifier is empty"

    id_type = identifier_type.strip().lower() if identifier_type else "auto"

    # Auto-detect
    if id_type == "auto":
        upper = identifier.upper()
        if "=" in identifier and (upper.startswith("CN=") or upper.startswith("OU=")):
            id_type = "dn"
        elif "@" in identifier:
            id_type = "upn"  # will also try email
        else:
            id_type = "samaccountname"

    if id_type == "dn":
        return identifier, None

    # Build search filter
    if id_type == "upn":
        # Try both UPN and email (common confusion)
        esc = _ldap_escape(identifier)
        search_filter = f"(|(userPrincipalName={esc})(mail={esc}))"
    elif id_type == "email":
        search_filter = f"(mail={_ldap_escape(identifier)})"
    else:  # samaccountname
        search_filter = f"(sAMAccountName={_ldap_escape(identifier)})"

    conn.search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=["distinguishedName", "sAMAccountName"],
        size_limit=1,
    )
    for entry in conn.response:
        if entry.get("type") == "searchResRef":
            continue
        dn = entry.get("dn")
        if dn:
            return dn, None
    return None, f"Object not found: {identifier} (type: {id_type})"


def _resolve_attributes(
    attribute_preset: str | None,
    custom_attributes: str | list | None,
) -> list[str]:
    """Merge an attribute preset with optional custom attributes."""
    attrs: list[str] = []
    if attribute_preset and attribute_preset in ATTRIBUTE_PRESETS:
        attrs = list(ATTRIBUTE_PRESETS[attribute_preset])
    if custom_attributes:
        extra = _ensure_list(custom_attributes)
        attrs.extend(a for a in extra if a not in attrs)
    return attrs if attrs else ["sAMAccountName"]


def _base_dn(conn: Connection) -> str | None:
    """Return configured or auto-detected base DN."""
    return secrets.get("AD_BASE_DN") or _get_root_dn(conn)


# -----------------------------------------------------------------------------
# Phase 1: Connectivity and read actions
# -----------------------------------------------------------------------------


@registry.register(
    default_title="AD: Test connectivity",
    description="Validate connection to Active Directory using the soclib_active_directory secret.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def test_connectivity() -> dict[str, Any]:
    """Test LDAP bind; returns full connection type and spec on success, detailed error and guidance on failure."""
    conn, err = _get_connection()
    if err:
        spec, _ = _get_connection_spec_from_secrets()
        failure_data: dict[str, Any] = {
            "connected": False,
            "error_message": err,
            "guidance": _connectivity_failure_guidance(err),
        }
        if spec:
            failure_data["attempted_connection"] = spec
        return _standard_response(
            False,
            data=failure_data,
            error=err,
            action_name="test_connectivity",
        )
    try:
        default_naming_context = _get_root_dn(conn)
        spec, _ = _get_connection_spec_from_secrets()
        connection_info: dict[str, Any] = {
            "connected": True,
            "connection": dict(spec) if spec else {},
            "message": None,
        }
        if spec:
            connection_info["connection"]["default_naming_context"] = default_naming_context
            ct = spec.get("connection_type", "unknown")
            protocol = spec.get("protocol", "")
            host = spec.get("host", "")
            port = spec.get("port", "")
            connection_info["message"] = (
                f"Connected successfully via {protocol} to {host}:{port}. "
                f"Connection type: {ct}. Default naming context: {default_naming_context or 'N/A'}."
            )
        else:
            connection_info["message"] = "Connected successfully (connection spec could not be read; URL may be masked)."
        conn.unbind()
    except Exception as e:
        return _standard_response(
            False,
            data={
                "connected": False,
                "error_message": str(e),
                "guidance": _connectivity_failure_guidance(str(e)),
            },
            error=str(e),
            action_name="test_connectivity",
        )
    return _standard_response(True, data=connection_info, action_name="test_connectivity")


@registry.register(
    default_title="AD: Run query",
    description="Run an arbitrary LDAP query against Active Directory (filter, search_base, attributes).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def run_query(
    filter: Annotated[str, Doc("LDAP filter (e.g. (sAMAccountName=*))")],
    search_base: Annotated[
        str | None,
        Doc("Search base DN. If empty, uses AD_BASE_DN or defaultNamingContext"),
    ] = None,
    attributes: Annotated[
        str,
        Doc("Semicolon-separated attributes (e.g. sAMAccountName;mail;displayName)"),
    ] = "sAMAccountName",
    attribute_preset: Annotated[
        str | None,
        Doc("Preset attribute set: basic, security, detailed, all (overrides attributes)"),
    ] = None,
    size_limit: Annotated[int, Doc("Max results (0 = unlimited)")] = 0,
    page_size: Annotated[int, Doc("Paged search size (0 = no paging)")] = 1000,
    search_scope: Annotated[
        str, Doc("SUBTREE, BASE, or LEVEL")
    ] = "SUBTREE",
) -> dict[str, Any]:
    """Execute LDAP query; returns entries and total_objects."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="run_query")
    try:
        base = search_base or _base_dn(conn)
        if not base:
            return _standard_response(
                False,
                error="No search_base and AD_BASE_DN / defaultNamingContext not available",
                action_name="run_query",
            )
        if attribute_preset:
            attrs_list = _resolve_attributes(attribute_preset, attributes)
        else:
            attrs_list = [a.strip() for a in attributes.split(";") if a.strip()]
        scope = SEARCH_SCOPE_MAP.get(search_scope.upper(), SUBTREE)
        conn.search(
            search_base=base,
            search_filter=filter,
            search_scope=scope,
            attributes=attrs_list if attrs_list else ["*"],
            size_limit=size_limit,
            paged_size=page_size if page_size > 0 else None,
        )
        entries = []
        for entry in conn.response:
            if entry.get("type") == "searchResRef":
                continue
            dn = entry.get("dn", "")
            attrs = entry.get("attributes", {})
            entries.append({
                "dn": dn,
                "attributes": {k.lower(): v for k, v in attrs.items()},
            })
        return _standard_response(
            True,
            data={"entries": entries, "total_objects": len(entries)},
            action_name="run_query",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="run_query")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Get attributes",
    description="Get attributes for one or more principals (sAMAccountName, userPrincipalName, or distinguishedName). Semicolon-separated.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def get_attributes(
    principals: Annotated[
        str | list,
        Doc("Semicolon-separated principals or list (e.g. user1;user2@domain.com;CN=User,OU=...)"),
    ],
    attributes: Annotated[
        str,
        Doc("Semicolon-separated attributes to return"),
    ] = "sAMAccountName",
    attribute_preset: Annotated[
        str | None,
        Doc("Preset attribute set: basic, security, detailed, all (adds to attributes)"),
    ] = None,
) -> dict[str, Any]:
    """Get attributes for multiple principals. Builds OR filter from UPN, sAMAccountName, DN."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="get_attributes")
    try:
        principal_list = _ensure_list(principals)
        if not principal_list:
            return _standard_response(False, error="At least one principal required", action_name="get_attributes")
        # Build filter: (|(userprincipalname=X)(samaccountname=X)(distinguishedname=X)) for each
        or_parts = []
        for p in principal_list:
            esc = _ldap_escape(p)
            or_parts.append(f"(userprincipalname={esc})(samaccountname={esc})(distinguishedname={esc})")
        ldap_filter = "(|" + "".join(or_parts) + ")"
        base = _base_dn(conn)
        if not base:
            return _standard_response(
                False,
                error="AD_BASE_DN or defaultNamingContext required",
                action_name="get_attributes",
            )
        if attribute_preset:
            attrs_list = _resolve_attributes(attribute_preset, attributes)
        else:
            attrs_list = [a.strip() for a in attributes.split(";") if a.strip()] or ["*"]
        conn.search(
            search_base=base,
            search_filter=ldap_filter,
            search_scope=SUBTREE,
            attributes=attrs_list,
        )
        entries = []
        for entry in conn.response:
            if entry.get("type") == "searchResRef":
                continue
            entries.append({
                "dn": entry.get("dn", ""),
                "attributes": {k.lower(): v for k, v in (entry.get("attributes") or {}).items()},
            })
        return _standard_response(
            True,
            data={"entries": entries, "total_objects": len(entries)},
            action_name="get_attributes",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="get_attributes")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Get user (LDAP)",
    description="Lookup a single AD user by sAMAccountName or UPN; returns common attributes.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def user_get(
    username: Annotated[str, Doc("sAMAccountName (default) or UPN")],
    username_attr: Annotated[str, Doc("LDAP attribute to match username")] = "sAMAccountName",
) -> dict[str, Any]:
    """Lookup one user. Returns standard response with found, dn, display_name, email, etc."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="user_get")
    try:
        base_dn = secrets.get("AD_BASE_DN") or _get_root_dn(conn)
        if not base_dn:
            return _standard_response(False, error="AD_BASE_DN or defaultNamingContext required", action_name="user_get")
        search_filter = f"({username_attr}={_ldap_escape(username)})"
        attrs = [
            "distinguishedName", "cn", "displayName", "mail", "userPrincipalName",
            "memberOf", "whenCreated", "whenChanged", "userAccountControl",
        ]
        ok = conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attrs,
            size_limit=2,
        )
        if not ok or not conn.entries:
            return _standard_response(
                True,
                data={"found": False, "username": username, "filter": search_filter},
                action_name="user_get",
            )
        if len(conn.entries) > 1:
            return _standard_response(
                True,
                data={"found": True, "ambiguous": True, "username": username, "count": len(conn.entries)},
                action_name="user_get",
            )
        entry = conn.entries[0]
        raw = {a: entry[a].value for a in entry.entry_attributes}
        uac_val = raw.get("userAccountControl")
        uac_int = int(uac_val) if uac_val is not None else 0
        return _standard_response(
            True,
            data={
                "found": True,
                "username": username,
                "dn": raw.get("distinguishedName"),
                "display_name": raw.get("displayName") or raw.get("cn"),
                "email": raw.get("mail"),
                "upn": raw.get("userPrincipalName"),
                "groups": raw.get("memberOf") or [],
                "enabled": not bool(uac_int & 0x02) if uac_val is not None else None,
                "uac_raw": uac_int,
                "uac_flags": _decode_uac(uac_int) if uac_val is not None else None,
                "raw": raw,
            },
            action_name="user_get",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="user_get")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


# -----------------------------------------------------------------------------
# Phase 2: Group membership and account status
# -----------------------------------------------------------------------------


@registry.register(
    default_title="AD: Add group members",
    description="Add one or more members to one or more groups. Use sAMAccountName or distinguishedName.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def add_group_members(
    members: Annotated[str, Doc("Semicolon-separated list of members (users/groups)")],
    groups: Annotated[str, Doc("Semicolon-separated list of groups")],
    use_samaccountname: Annotated[bool, Doc("Use sAMAccountName instead of distinguishedName")] = False,
) -> dict[str, Any]:
    """Add members to groups. Returns list of { member, group, function: 'added' }."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="add_group_members")
    try:
        base_dn = secrets.get("AD_BASE_DN") or _get_root_dn(conn)
        if not base_dn:
            return _standard_response(False, error="AD_BASE_DN required", action_name="add_group_members")
        members_list = [m.strip() for m in members.split(";") if m.strip()]
        groups_list = [g.strip() for g in groups.split(";") if g.strip()]
        if use_samaccountname:
            members_d = _sam_to_dn(conn, members_list, base_dn)
            groups_d = _sam_to_dn(conn, groups_list, base_dn)
            members_list = [members_d.get(m.lower()) for m in members_list if members_d.get(m.lower())]
            groups_list = [groups_d.get(g.lower()) for g in groups_list if groups_d.get(g.lower())]
            if not members_list or not groups_list:
                return _standard_response(False, error="Not enough groups or members found", action_name="add_group_members")
        ldap3.extend.microsoft.addMembersToGroups.ad_add_members_to_groups(
            connection=conn, members_dn=members_list, groups_dn=groups_list, fix=True, raise_error=True
        )
        rows = [{"member": m, "group": g, "function": "added"} for m in members_list for g in groups_list]
        return _standard_response(True, data={"results": rows}, action_name="add_group_members")
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="add_group_members")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Remove group members",
    description="Remove one or more members from one or more groups.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def remove_group_members(
    members: Annotated[str, Doc("Semicolon-separated list of members")],
    groups: Annotated[str, Doc("Semicolon-separated list of groups")],
    use_samaccountname: Annotated[bool, Doc("Use sAMAccountName instead of distinguishedName")] = False,
) -> dict[str, Any]:
    """Remove members from groups."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="remove_group_members")
    try:
        base_dn = secrets.get("AD_BASE_DN") or _get_root_dn(conn)
        if not base_dn:
            return _standard_response(False, error="AD_BASE_DN required", action_name="remove_group_members")
        members_list = [m.strip() for m in members.split(";") if m.strip()]
        groups_list = [g.strip() for g in groups.split(";") if g.strip()]
        if use_samaccountname:
            members_d = _sam_to_dn(conn, members_list, base_dn)
            groups_d = _sam_to_dn(conn, groups_list, base_dn)
            members_list = [members_d.get(m.lower()) for m in members_list if members_d.get(m.lower())]
            groups_list = [groups_d.get(g.lower()) for g in groups_list if groups_d.get(g.lower())]
            if not members_list or not groups_list:
                return _standard_response(False, error="Not enough groups or members found", action_name="remove_group_members")
        ldap3.extend.microsoft.removeMembersFromGroups.ad_remove_members_from_groups(
            connection=conn, members_dn=members_list, groups_dn=groups_list, fix=True, raise_error=True
        )
        rows = [{"member": m, "group": g, "function": "removed"} for m in members_list for g in groups_list]
        return _standard_response(True, data={"results": rows}, action_name="remove_group_members")
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="remove_group_members")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Unlock account",
    description="Unlock a locked Active Directory account.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def unlock_account(
    user: Annotated[str, Doc("User sAMAccountName or distinguishedName")],
    use_samaccountname: Annotated[bool, Doc("Use sAMAccountName")] = False,
) -> dict[str, Any]:
    """Unlock AD account."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="unlock_account")
    try:
        base_dn = secrets.get("AD_BASE_DN") or _get_root_dn(conn)
        user_lower = user.strip().lower()
        user_dn = user.strip()
        if use_samaccountname and base_dn:
            sam_map = _sam_to_dn(conn, [user.strip()], base_dn)
            if sam_map.get(user_lower) is False:
                return _standard_response(False, error="No users found", action_name="unlock_account")
            user_dn = sam_map.get(user_lower) or user_dn
        ldap3.extend.microsoft.unlockAccount.ad_unlock_account(connection=conn, user_dn=user_dn)
        return _standard_response(
            True,
            data={"user_dn": user_dn, "unlocked": True},
            action_name="unlock_account",
        )
    except Exception as e:
        return _standard_response(False, data={"unlocked": False}, error=str(e), action_name="unlock_account")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def _account_status(conn: Connection, user: str, use_sam: bool, base_dn: str | None, disable: bool) -> dict[str, Any]:
    """Enable or disable account by toggling userAccountControl bit 0x02."""
    user_lower = user.strip().lower()
    user_dn = user.strip()
    if use_sam and base_dn:
        sam_map = _sam_to_dn(conn, [user.strip()], base_dn)
        if sam_map.get(user_lower) is False:
            return _standard_response(False, error="No users found", action_name="disable_account" if disable else "enable_account")
        user_dn = sam_map.get(user_lower) or user_dn
    conn.search(search_base=user_dn, search_filter="(objectClass=*)", search_scope=SUBTREE, attributes=["userAccountControl"])
    if not conn.entries:
        return _standard_response(False, error="No user found", action_name="disable_account" if disable else "enable_account")
    uac_val = conn.entries[0].entry_attributes_as_dict.get("useraccountcontrol") or conn.entries[0].entry_attributes_as_dict.get("userAccountControl")
    uac = int(uac_val[0] if isinstance(uac_val, list) else uac_val)
    init_status = "disabled" if (uac & 0x02) else "enabled"
    mod_uac = (uac | 0x02) if disable else (uac & (0xFFFFFFFF ^ 0x02))
    ok = conn.modify(user_dn, {"userAccountControl": [(MODIFY_REPLACE, [mod_uac])]})
    if not ok:
        return _standard_response(False, error=str(conn.result), action_name="disable_account" if disable else "enable_account")
    actstr = "disabled" if disable else "enabled"
    return _standard_response(
        True,
        data={"user_dn": user_dn, "starting_status": init_status, "account_status": actstr},
        action_name="disable_account" if disable else "enable_account",
    )


@registry.register(
    default_title="AD: Disable account",
    description="Disable an Active Directory account.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def disable_account(
    user: Annotated[str, Doc("User sAMAccountName or distinguishedName")],
    use_samaccountname: Annotated[bool, Doc("Use sAMAccountName")] = False,
) -> dict[str, Any]:
    """Disable AD account (set userAccountControl disabled bit)."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="disable_account")
    try:
        base_dn = secrets.get("AD_BASE_DN") or _get_root_dn(conn)
        return _account_status(conn, user, use_samaccountname, base_dn, disable=True)
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Enable account",
    description="Enable a disabled Active Directory account.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def enable_account(
    user: Annotated[str, Doc("User sAMAccountName or distinguishedName")],
    use_samaccountname: Annotated[bool, Doc("Use sAMAccountName")] = False,
) -> dict[str, Any]:
    """Enable AD account (clear userAccountControl disabled bit)."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="enable_account")
    try:
        base_dn = secrets.get("AD_BASE_DN") or _get_root_dn(conn)
        return _account_status(conn, user, use_samaccountname, base_dn, disable=False)
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


# -----------------------------------------------------------------------------
# Phase 3: Password and object operations
# -----------------------------------------------------------------------------


@registry.register(
    default_title="AD: Reset password",
    description="Reset user password (user must change at next logon).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def reset_password(
    user: Annotated[str, Doc("User sAMAccountName or distinguishedName")],
    use_samaccountname: Annotated[bool, Doc("Use sAMAccountName")] = False,
) -> dict[str, Any]:
    """Set pwdlastset to 0 to force password change at next logon."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="reset_password")
    try:
        base_dn = secrets.get("AD_BASE_DN") or _get_root_dn(conn)
        user_lower = user.strip().lower()
        user_dn = user.strip()
        if use_samaccountname and base_dn:
            sam_map = _sam_to_dn(conn, [user.strip()], base_dn)
            if sam_map.get(user_lower) is False:
                return _standard_response(False, error="No users found", action_name="reset_password")
            user_dn = sam_map.get(user_lower) or user_dn
        ok = conn.modify(user_dn, {"pwdlastset": [(MODIFY_REPLACE, ["0"])]})
        return _standard_response(True, data={"user_dn": user_dn, "reset": ok}, action_name="reset_password")
    except Exception as e:
        return _standard_response(False, data={"reset": False}, error=str(e), action_name="reset_password")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Set password",
    description="Set a user's password. Passwords must match.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def set_password(
    user: Annotated[str, Doc("User sAMAccountName or distinguishedName")],
    password: Annotated[str, Doc("New password")],
    confirm_password: Annotated[str, Doc("Confirm new password")],
    use_samaccountname: Annotated[bool, Doc("Use sAMAccountName")] = False,
) -> dict[str, Any]:
    """Set user password via LDAP (requires appropriate permissions)."""
    if password != confirm_password:
        return _standard_response(False, data={"set": False}, error="Passwords do not match", action_name="set_password")
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="set_password")
    try:
        base_dn = secrets.get("AD_BASE_DN") or _get_root_dn(conn)
        user_lower = user.strip().lower()
        user_dn = user.strip()
        if use_samaccountname and base_dn:
            sam_map = _sam_to_dn(conn, [user.strip()], base_dn)
            if sam_map.get(user_lower) is False:
                return _standard_response(False, error="No users found", action_name="set_password")
            user_dn = sam_map.get(user_lower) or user_dn
        ok = conn.extend.microsoft.modify_password(user_dn, password)
        return _standard_response(True, data={"user_dn": user_dn, "set": ok}, action_name="set_password")
    except Exception as e:
        return _standard_response(False, data={"set": False}, error=str(e), action_name="set_password")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Move object",
    description="Move an object to another OU (distinguishedName).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def move_object(
    object: Annotated[str, Doc("DistinguishedName of the object to move")],
    destination_ou: Annotated[str, Doc("DistinguishedName of the destination OU")],
) -> dict[str, Any]:
    """Move AD object to new OU."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="move_object")
    try:
        # Get RDN (e.g. CN=User) from object DN
        # parse_dn returns [(attr, value, separator), ...] — only use attr + value
        rdn_parts = parse_dn(object)
        if not rdn_parts or not rdn_parts[0]:
            return _standard_response(False, error="Invalid DN", action_name="move_object")
        rdn = f"{rdn_parts[0][0]}={rdn_parts[0][1]}"
        ok = conn.modify_dn(object, rdn, new_superior=destination_ou)
        if not ok:
            return _standard_response(False, error=str(conn.result), action_name="move_object")
        return _standard_response(
            True,
            data={"source_object": object, "destination_container": destination_ou, "moved": True},
            action_name="move_object",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="move_object")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Set attribute",
    description="Add, delete, or replace a user attribute.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def set_attribute(
    user: Annotated[str, Doc("User sAMAccountName or distinguishedName")],
    attribute: Annotated[str, Doc("Attribute name to modify")],
    action: Annotated[str, Doc("ADD, DELETE, or REPLACE")],
    value: Annotated[str | None, Doc("Value (required for ADD and REPLACE)")] = None,
    use_samaccountname: Annotated[bool, Doc("Use sAMAccountName")] = False,
) -> dict[str, Any]:
    """Modify a single attribute (ADD/DELETE/REPLACE)."""
    if action in ("ADD", "REPLACE") and value is None:
        return _standard_response(False, error=f"Value required for {action}", action_name="set_attribute")
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="set_attribute")
    try:
        base_dn = secrets.get("AD_BASE_DN") or _get_root_dn(conn)
        user_lower = user.strip().lower()
        user_dn = user.strip()
        if use_samaccountname and base_dn:
            sam_map = _sam_to_dn(conn, [user.strip()], base_dn)
            if sam_map.get(user_lower) is False:
                return _standard_response(False, error="No users found", action_name="set_attribute")
            user_dn = sam_map.get(user_lower) or user_dn
        if action == "ADD":
            changes = {attribute: [(MODIFY_ADD, [value])]}
        elif action == "DELETE":
            changes = {attribute: [(MODIFY_DELETE, [])]}
        elif action == "REPLACE":
            changes = {attribute: [(MODIFY_REPLACE, [value])]}
        else:
            return _standard_response(False, error="action must be ADD, DELETE, or REPLACE", action_name="set_attribute")
        ok = conn.modify(user_dn, changes)
        return _standard_response(True, data={"message": "Success" if ok else "Failed"}, action_name="set_attribute")
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="set_attribute")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Rename object",
    description="Rename an object (e.g. cn=NewName or ou=NewOUName).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def rename_object(
    object: Annotated[str, Doc("Object sAMAccountName or distinguishedName")],
    new_name: Annotated[str, Doc("New RDN (e.g. cn=NewUserName)")],
    use_samaccountname: Annotated[bool, Doc("Use sAMAccountName for object")] = False,
) -> dict[str, Any]:
    """Rename AD object (modify RDN)."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="rename_object")
    try:
        base_dn = secrets.get("AD_BASE_DN") or _get_root_dn(conn)
        user_lower = object.strip().lower()
        user_dn = object.strip()
        if use_samaccountname and base_dn:
            sam_map = _sam_to_dn(conn, [object.strip()], base_dn)
            if sam_map.get(user_lower) is False:
                return _standard_response(False, error="No users found", action_name="rename_object")
            user_dn = sam_map.get(user_lower) or user_dn
        ok = conn.modify_dn(user_dn, new_name)
        return _standard_response(True, data={"message": "Success" if ok else "Failed"}, action_name="rename_object")
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="rename_object")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


# =============================================================================
# Phase 4: User lifecycle — create / delete
# =============================================================================


@registry.register(
    default_title="AD: Create user",
    description="Create a new user in Active Directory.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def create_user(
    username: Annotated[str, Doc("sAMAccountName for the new user")],
    user_dn: Annotated[str, Doc("Full DN (e.g. CN=John Doe,OU=Users,DC=example,DC=com)")],
    password: Annotated[str, Doc("Initial password")],
    display_name: Annotated[str | None, Doc("Display name")] = None,
    email: Annotated[str | None, Doc("E-mail address")] = None,
    description: Annotated[str | None, Doc("Description")] = None,
    telephone: Annotated[str | None, Doc("Telephone number")] = None,
    title: Annotated[str | None, Doc("Job title")] = None,
    department: Annotated[str | None, Doc("Department")] = None,
    manager_dn: Annotated[str | None, Doc("Manager DN")] = None,
    custom_attributes: Annotated[dict | None, Doc("Extra attributes as dict")] = None,
    enabled: Annotated[bool, Doc("Create enabled (true) or disabled (false)")] = True,
    must_change_password: Annotated[bool, Doc("User must change password at next logon")] = True,
) -> dict[str, Any]:
    """Create AD user with standard attributes + optional custom attrs."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="create_user")
    try:
        # Extract CN from DN
        cn_value = user_dn.split(",")[0]
        if cn_value.upper().startswith("CN="):
            cn_value = cn_value[3:]

        # Build object class & attributes
        attrs: dict[str, Any] = {
            "cn": cn_value,
            "sAMAccountName": username,
            "userPrincipalName": f"{username}@{_domain_from_dn(user_dn)}",
        }
        if display_name:
            attrs["displayName"] = display_name
        if email:
            attrs["mail"] = email
        if description:
            attrs["description"] = description
        if telephone:
            attrs["telephoneNumber"] = telephone
        if title:
            attrs["title"] = title
        if department:
            attrs["department"] = department
        if manager_dn:
            attrs["manager"] = manager_dn
        if custom_attributes:
            attrs.update(custom_attributes)

        ok = conn.add(user_dn, ["top", "person", "organizationalPerson", "user"], attributes=attrs)
        if not ok:
            return _standard_response(
                False, error=str(conn.result), action_name="create_user",
            )

        # Set password (requires SSL usually)
        try:
            conn.extend.microsoft.modify_password(user_dn, password)
        except Exception as pwd_err:
            return _standard_response(
                False,
                data={"dn": user_dn, "created": True, "password_set": False},
                error=f"User created but password set failed: {pwd_err}",
                action_name="create_user",
            )

        # Enable / UAC
        uac = 0x0200  # NORMAL_ACCOUNT
        if not enabled:
            uac |= 0x02  # ACCOUNTDISABLE
        conn.modify(user_dn, {"userAccountControl": [(MODIFY_REPLACE, [uac])]})

        if must_change_password:
            conn.modify(user_dn, {"pwdLastSet": [(MODIFY_REPLACE, [0])]})

        return _standard_response(
            True,
            data={"dn": user_dn, "username": username, "created": True, "enabled": enabled},
            action_name="create_user",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="create_user")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def _domain_from_dn(dn: str) -> str:
    """Extract domain from DN (e.g. DC=soclib,DC=local → soclib.local)."""
    parts = []
    for component in dn.split(","):
        component = component.strip()
        if component.upper().startswith("DC="):
            parts.append(component[3:])
    return ".".join(parts) if parts else ""


@registry.register(
    default_title="AD: Delete user",
    description="Delete a user or object from Active Directory.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def delete_user(
    user: Annotated[str, Doc("User identifier (sAMAccountName, UPN, email, or DN)")],
    identifier_type: Annotated[
        str, Doc("auto, samaccountname, dn, upn, or email")
    ] = "auto",
) -> dict[str, Any]:
    """Delete an AD object by identifier."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="delete_user")
    try:
        base = _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="delete_user")
        user_dn, resolve_err = _resolve_identifier(conn, user, identifier_type, base)
        if resolve_err:
            return _standard_response(False, error=resolve_err, action_name="delete_user")
        ok = conn.delete(user_dn)
        if not ok:
            return _standard_response(False, error=str(conn.result), action_name="delete_user")
        return _standard_response(True, data={"dn": user_dn, "deleted": True}, action_name="delete_user")
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="delete_user")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


# =============================================================================
# Phase 5: Enrichment, advanced search, SOAR compound actions
# =============================================================================


@registry.register(
    default_title="AD: Check account status",
    description="Get detailed, human-readable account status including UAC flags.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def check_account_status(
    user: Annotated[str, Doc("User identifier")],
    identifier_type: Annotated[str, Doc("auto, samaccountname, dn, upn, email")] = "auto",
) -> dict[str, Any]:
    """Comprehensive read-only account status check."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="check_account_status")
    try:
        base = _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="check_account_status")
        user_dn, resolve_err = _resolve_identifier(conn, user, identifier_type, base)
        if resolve_err:
            return _standard_response(False, error=resolve_err, action_name="check_account_status")
        conn.search(
            search_base=user_dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=[
                "sAMAccountName", "userAccountControl", "lockoutTime",
                "pwdLastSet", "accountExpires", "lastLogonTimestamp",
                "distinguishedName", "displayName",
            ],
        )
        if not conn.entries:
            return _standard_response(False, error="User not found", action_name="check_account_status")
        e = conn.entries[0]
        raw = {a: e[a].value for a in e.entry_attributes}
        uac = int(raw.get("userAccountControl") or 0)
        flags = _decode_uac(uac)
        lockout_time = raw.get("lockoutTime")
        locked = bool(lockout_time and int(str(lockout_time)) > 0) if lockout_time is not None else flags.get("LOCKOUT", False)
        pwd_last_set = raw.get("pwdLastSet")
        must_change = str(pwd_last_set) == "0" if pwd_last_set is not None else False
        acc_exp = raw.get("accountExpires")
        acc_exp_str = "never"
        if acc_exp and str(acc_exp) not in ("0", "9223372036854775807"):
            acc_exp_str = str(acc_exp)
        return _standard_response(
            True,
            data={
                "dn": raw.get("distinguishedName"),
                "samaccountname": raw.get("sAMAccountName"),
                "display_name": raw.get("displayName"),
                "enabled": not flags.get("ACCOUNTDISABLE", False),
                "locked": locked,
                "password_expired": flags.get("PASSWORD_EXPIRED", False),
                "password_never_expires": flags.get("DONT_EXPIRE_PASSWORD", False),
                "password_last_set": str(pwd_last_set) if pwd_last_set else None,
                "account_expires": acc_exp_str,
                "last_logon": str(raw.get("lastLogonTimestamp")) if raw.get("lastLogonTimestamp") else None,
                "must_change_password": must_change,
                "smartcard_required": flags.get("SMARTCARD_REQUIRED", False),
                "delegation_trusted": flags.get("TRUSTED_FOR_DELEGATION", False),
                "uac_raw": uac,
                "uac_flags": flags,
            },
            action_name="check_account_status",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="check_account_status")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Search users",
    description="Advanced user search with preset filters or custom LDAP query.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def search_users(
    query: Annotated[str | None, Doc("Raw LDAP filter (overrides preset_filter)")] = None,
    preset_filter: Annotated[
        str | None,
        Doc("Preset: all_users, disabled_users, locked_users, expired_passwords, never_expire_passwords, service_accounts"),
    ] = None,
    name: Annotated[str | None, Doc("Filter by cn (wildcard OK: *john*)")] = None,
    username: Annotated[str | None, Doc("Filter by sAMAccountName (wildcard OK)")] = None,
    email: Annotated[str | None, Doc("Filter by mail")] = None,
    department: Annotated[str | None, Doc("Filter by department")] = None,
    attribute_preset: Annotated[str | None, Doc("basic, security, detailed, all")] = "basic",
    custom_attributes: Annotated[str | None, Doc("Extra attributes (semicolon-separated)")] = None,
    size_limit: Annotated[int, Doc("Max results")] = 50,
    search_base: Annotated[str | None, Doc("Search base DN")] = None,
) -> dict[str, Any]:
    """Search users with presets or custom filter."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="search_users")
    try:
        base = search_base or _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="search_users")

        # Build filter
        if query:
            ldap_filter = query
        elif preset_filter and preset_filter in USER_SEARCH_PRESETS:
            ldap_filter = USER_SEARCH_PRESETS[preset_filter]
            if not ldap_filter:
                return _standard_response(False, error=f"Preset '{preset_filter}' not supported yet", action_name="search_users")
        else:
            # Build from individual fields
            parts = ["(objectCategory=person)", "(objectClass=user)"]
            if name:
                parts.append(f"(cn={_ldap_escape(name)})")
            if username:
                parts.append(f"(sAMAccountName={_ldap_escape(username)})")
            if email:
                parts.append(f"(mail={_ldap_escape(email)})")
            if department:
                parts.append(f"(department={_ldap_escape(department)})")
            ldap_filter = "(&" + "".join(parts) + ")"

        attrs = _resolve_attributes(attribute_preset, custom_attributes)
        conn.search(
            search_base=base,
            search_filter=ldap_filter,
            search_scope=SUBTREE,
            attributes=attrs,
            size_limit=size_limit,
            paged_size=min(size_limit, 1000) if size_limit > 0 else 1000,
        )
        entries = []
        for entry in conn.response:
            if entry.get("type") == "searchResRef":
                continue
            entries.append({
                "dn": entry.get("dn", ""),
                "attributes": {k.lower(): v for k, v in (entry.get("attributes") or {}).items()},
            })
        return _standard_response(
            True,
            data={"entries": entries, "total_objects": len(entries), "filter_used": ldap_filter},
            action_name="search_users",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="search_users")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Get group members",
    description="List members of an AD group.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def get_group_members(
    group: Annotated[str, Doc("Group name (CN), sAMAccountName, or DN")],
    identifier_type: Annotated[str, Doc("auto, samaccountname, dn")] = "auto",
    recursive: Annotated[bool, Doc("Include nested group members")] = False,
    attributes: Annotated[str | None, Doc("Attributes per member (semicolon-separated)")] = "sAMAccountName;displayName;mail",
) -> dict[str, Any]:
    """List group members with optional recursive expansion."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="get_group_members")
    try:
        base = _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="get_group_members")
        group_dn, resolve_err = _resolve_identifier(conn, group, identifier_type, base)
        if resolve_err:
            return _standard_response(False, error=resolve_err, action_name="get_group_members")

        if recursive:
            member_filter = f"(memberOf:1.2.840.113556.1.4.1941:={_ldap_escape(group_dn)})"
        else:
            member_filter = f"(memberOf={_ldap_escape(group_dn)})"

        attr_list = _ensure_list(attributes) or ["sAMAccountName", "displayName", "mail"]
        if "objectClass" not in attr_list:
            attr_list.append("objectClass")

        conn.search(
            search_base=base,
            search_filter=member_filter,
            search_scope=SUBTREE,
            attributes=attr_list,
            paged_size=1000,
        )
        members = []
        for entry in conn.response:
            if entry.get("type") == "searchResRef":
                continue
            attrs = entry.get("attributes") or {}
            obj_classes = [c.lower() for c in (attrs.get("objectClass") or attrs.get("objectclass") or [])]
            if "computer" in obj_classes:
                obj_type = "computer"
            elif "group" in obj_classes:
                obj_type = "group"
            else:
                obj_type = "user"
            row: dict[str, Any] = {"dn": entry.get("dn", ""), "type": obj_type}
            for k, v in attrs.items():
                if k.lower() != "objectclass":
                    row[k.lower()] = v
            members.append(row)

        return _standard_response(
            True,
            data={
                "group_dn": group_dn,
                "members": members,
                "total_members": len(members),
                "recursive": recursive,
            },
            action_name="get_group_members",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="get_group_members")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: List privileged users",
    description="List members of privileged AD groups (Domain Admins, Enterprise Admins, etc.).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def list_privileged_users(
    groups: Annotated[
        str | list | None,
        Doc("Privileged group names (semicolon-separated or list). Defaults to Domain/Enterprise/Schema Admins + Administrators."),
    ] = None,
    recursive: Annotated[bool, Doc("Include nested members")] = True,
) -> dict[str, Any]:
    """List privileged users across one or more admin groups."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="list_privileged_users")
    try:
        base = _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="list_privileged_users")

        group_names = _ensure_list(groups) if groups else DEFAULT_PRIVILEGED_GROUPS
        all_users: dict[str, dict] = {}  # dn -> {info + groups}
        group_results = []

        for gname in group_names:
            # Resolve group
            gdn, gerr = _resolve_identifier(conn, gname, "auto", base)
            if gerr:
                group_results.append({"group": gname, "error": gerr, "members": 0})
                continue

            if recursive:
                mfilter = f"(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={_ldap_escape(gdn)}))"
            else:
                mfilter = f"(&(objectCategory=person)(objectClass=user)(memberOf={_ldap_escape(gdn)}))"

            conn.search(
                search_base=base,
                search_filter=mfilter,
                search_scope=SUBTREE,
                attributes=["sAMAccountName", "displayName", "mail", "userAccountControl"],
                paged_size=1000,
            )
            count = 0
            for entry in conn.response:
                if entry.get("type") == "searchResRef":
                    continue
                dn = entry.get("dn", "")
                attrs = entry.get("attributes") or {}
                count += 1
                if dn not in all_users:
                    all_users[dn] = {
                        "dn": dn,
                        "samaccountname": _first(attrs.get("sAMAccountName") or attrs.get("samaccountname")),
                        "display_name": _first(attrs.get("displayName") or attrs.get("displayname")),
                        "email": _first(attrs.get("mail")),
                        "groups": [],
                    }
                all_users[dn]["groups"].append(gname)
            group_results.append({"group": gname, "group_dn": gdn, "members": count})

        return _standard_response(
            True,
            data={
                "privileged_users": list(all_users.values()),
                "total_privileged_users": len(all_users),
                "groups_checked": group_results,
            },
            action_name="list_privileged_users",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="list_privileged_users")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def _first(val: Any) -> Any:
    """Return first element if list, else val."""
    if isinstance(val, list):
        return val[0] if val else None
    return val


@registry.register(
    default_title="AD: Full user enrichment",
    description="Complete user enrichment: profile + account status + groups — single call.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def full_user_enrichment(
    user: Annotated[str, Doc("User identifier")],
    identifier_type: Annotated[str, Doc("auto, samaccountname, dn, upn, email")] = "auto",
) -> dict[str, Any]:
    """Compound enrichment: user info, account status flags, group memberships."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="full_user_enrichment")
    try:
        base = _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="full_user_enrichment")
        user_dn, resolve_err = _resolve_identifier(conn, user, identifier_type, base)
        if resolve_err:
            return _standard_response(
                True,
                data={"found": False, "identifier": user, "error": resolve_err},
                action_name="full_user_enrichment",
            )

        # Fetch full attributes
        conn.search(
            search_base=user_dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=[
                "sAMAccountName", "displayName", "mail", "userPrincipalName",
                "distinguishedName", "department", "title", "manager",
                "description", "telephoneNumber", "whenCreated", "whenChanged",
                "userAccountControl", "lockoutTime", "pwdLastSet",
                "lastLogonTimestamp", "accountExpires", "memberOf",
            ],
        )
        if not conn.entries:
            return _standard_response(True, data={"found": False, "identifier": user}, action_name="full_user_enrichment")

        e = conn.entries[0]
        raw = {a: e[a].value for a in e.entry_attributes}
        uac = int(raw.get("userAccountControl") or 0)
        flags = _decode_uac(uac)
        groups_dn = raw.get("memberOf") or []
        if isinstance(groups_dn, str):
            groups_dn = [groups_dn]

        # Check privileged
        priv_lower = {g.lower() for g in DEFAULT_PRIVILEGED_GROUPS}
        is_privileged = False
        group_details = []
        for g in groups_dn:
            gname = g.split(",")[0].replace("CN=", "").replace("cn=", "") if "=" in g else g
            if gname.lower() in priv_lower:
                is_privileged = True
            group_details.append({"dn": g, "name": gname})

        lockout_time = raw.get("lockoutTime")
        locked = bool(lockout_time and int(str(lockout_time)) > 0) if lockout_time is not None else False

        return _standard_response(
            True,
            data={
                "found": True,
                "dn": raw.get("distinguishedName"),
                "samaccountname": raw.get("sAMAccountName"),
                "display_name": raw.get("displayName"),
                "email": raw.get("mail"),
                "upn": raw.get("userPrincipalName"),
                "department": raw.get("department"),
                "title": raw.get("title"),
                "manager": raw.get("manager"),
                "description": raw.get("description"),
                "telephone": raw.get("telephoneNumber"),
                "account_status": {
                    "enabled": not flags.get("ACCOUNTDISABLE", False),
                    "locked": locked,
                    "password_expired": flags.get("PASSWORD_EXPIRED", False),
                    "password_never_expires": flags.get("DONT_EXPIRE_PASSWORD", False),
                    "must_change_password": str(raw.get("pwdLastSet")) == "0",
                    "last_logon": str(raw.get("lastLogonTimestamp")) if raw.get("lastLogonTimestamp") else None,
                    "uac_raw": uac,
                    "uac_flags": flags,
                },
                "groups": group_details,
                "total_groups": len(group_details),
                "is_privileged": is_privileged,
            },
            action_name="full_user_enrichment",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="full_user_enrichment")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Contain user",
    description="SOAR containment: disable, reset password, remove groups, move to quarantine — in one call.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def contain_user(
    user: Annotated[str, Doc("User identifier")],
    identifier_type: Annotated[str, Doc("auto, samaccountname, dn, upn, email")] = "auto",
    actions: Annotated[
        str | list | None,
        Doc("Actions: disable, reset_password, remove_all_groups, move_to_quarantine_ou (semicolon-separated or list)"),
    ] = "disable;reset_password",
    quarantine_ou: Annotated[str | None, Doc("Quarantine OU DN (for move_to_quarantine_ou)")] = None,
) -> dict[str, Any]:
    """Compound containment: multiple remediation steps in a single call."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="contain_user")
    try:
        base = _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="contain_user")
        user_dn, resolve_err = _resolve_identifier(conn, user, identifier_type, base)
        if resolve_err:
            return _standard_response(False, error=resolve_err, action_name="contain_user")

        action_list = _ensure_list(actions) if actions else ["disable", "reset_password"]
        results: dict[str, Any] = {}

        # 1. Disable
        if "disable" in action_list:
            try:
                conn.search(user_dn, "(objectClass=*)", BASE, attributes=["userAccountControl"])
                if conn.entries:
                    uac_val = conn.entries[0].entry_attributes_as_dict.get("userAccountControl") or \
                              conn.entries[0].entry_attributes_as_dict.get("useraccountcontrol")
                    uac = int(uac_val[0] if isinstance(uac_val, list) else uac_val)
                    prev = "disabled" if (uac & 0x02) else "enabled"
                    conn.modify(user_dn, {"userAccountControl": [(MODIFY_REPLACE, [uac | 0x02])]})
                    results["disable"] = {"success": True, "previous_status": prev}
                else:
                    results["disable"] = {"success": False, "error": "not found"}
            except Exception as de:
                results["disable"] = {"success": False, "error": str(de)}

        # 2. Reset password
        if "reset_password" in action_list:
            try:
                conn.modify(user_dn, {"pwdLastSet": [(MODIFY_REPLACE, [0])]})
                results["reset_password"] = {"success": True}
            except Exception as rp:
                results["reset_password"] = {"success": False, "error": str(rp)}

        # 3. Remove all groups
        if "remove_all_groups" in action_list:
            try:
                conn.search(user_dn, "(objectClass=*)", BASE, attributes=["memberOf"])
                groups_list = []
                if conn.entries:
                    mof = conn.entries[0].entry_attributes_as_dict.get("memberOf") or \
                          conn.entries[0].entry_attributes_as_dict.get("memberof") or []
                    groups_list = list(mof)
                removed = []
                for gdn in groups_list:
                    try:
                        ldap3.extend.microsoft.removeMembersFromGroups.ad_remove_members_from_groups(
                            conn, [user_dn], [gdn], fix=True, raise_error=False,
                        )
                        removed.append(gdn)
                    except Exception:
                        pass
                results["remove_all_groups"] = {"success": True, "removed_from": removed}
            except Exception as rg:
                results["remove_all_groups"] = {"success": False, "error": str(rg)}

        # 4. Move to quarantine OU
        if "move_to_quarantine_ou" in action_list:
            if not quarantine_ou:
                results["move_to_quarantine_ou"] = {"success": False, "error": "quarantine_ou not provided"}
            else:
                try:
                    rdn_parts = parse_dn(user_dn)
                    rdn = f"{rdn_parts[0][0]}={rdn_parts[0][1]}" if rdn_parts else ""
                    # Capture original OU
                    original_ou = ",".join(user_dn.split(",")[1:])
                    conn.modify_dn(user_dn, rdn, new_superior=quarantine_ou)
                    results["move_to_quarantine_ou"] = {"success": True, "previous_ou": original_ou}
                except Exception as mv:
                    results["move_to_quarantine_ou"] = {"success": False, "error": str(mv)}

        all_ok = all(r.get("success", False) for r in results.values())
        return _standard_response(
            True,
            data={
                "user_dn": user_dn,
                "actions_performed": results,
                "containment_complete": all_ok,
            },
            action_name="contain_user",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="contain_user")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


# =============================================================================
# Phase 6: Group details, computer management
# =============================================================================


@registry.register(
    default_title="AD: Get user groups",
    description="List groups a user belongs to, with details.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def get_user_groups(
    user: Annotated[str, Doc("User identifier")],
    identifier_type: Annotated[str, Doc("auto, samaccountname, dn, upn, email")] = "auto",
    recursive: Annotated[bool, Doc("Include nested groups")] = False,
) -> dict[str, Any]:
    """List groups with name, description, and type."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="get_user_groups")
    try:
        base = _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="get_user_groups")
        user_dn, resolve_err = _resolve_identifier(conn, user, identifier_type, base)
        if resolve_err:
            return _standard_response(False, error=resolve_err, action_name="get_user_groups")

        if recursive:
            gfilter = f"(member:1.2.840.113556.1.4.1941:={_ldap_escape(user_dn)})"
        else:
            # Read memberOf attribute directly
            conn.search(user_dn, "(objectClass=*)", BASE, attributes=["memberOf"])
            if not conn.entries:
                return _standard_response(True, data={"user_dn": user_dn, "groups": [], "total_groups": 0}, action_name="get_user_groups")
            mof = conn.entries[0].entry_attributes_as_dict.get("memberOf") or \
                  conn.entries[0].entry_attributes_as_dict.get("memberof") or []
            if not mof:
                return _standard_response(True, data={"user_dn": user_dn, "groups": [], "total_groups": 0}, action_name="get_user_groups")
            parts = "".join(f"(distinguishedName={_ldap_escape(g)})" for g in mof)
            gfilter = f"(|{parts})"

        conn.search(
            search_base=base,
            search_filter=gfilter,
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "description", "groupType", "distinguishedName"],
            paged_size=1000,
        )
        groups = []
        for entry in conn.response:
            if entry.get("type") == "searchResRef":
                continue
            a = entry.get("attributes") or {}
            gt = int(_first(a.get("groupType") or a.get("grouptype")) or 0)
            groups.append({
                "dn": entry.get("dn", ""),
                "name": _first(a.get("sAMAccountName") or a.get("samaccountname")),
                "description": _first(a.get("description")),
                "group_type": "security" if gt & 0x80000000 else "distribution",
            })
        return _standard_response(
            True,
            data={"user_dn": user_dn, "groups": groups, "total_groups": len(groups)},
            action_name="get_user_groups",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="get_user_groups")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Get computer",
    description="Lookup a computer object in Active Directory.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def get_computer(
    computer_name: Annotated[str, Doc("Computer name (CN) or DN")],
    attributes: Annotated[str | None, Doc("Extra attributes (semicolon-separated)")] = None,
) -> dict[str, Any]:
    """Get computer info."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="get_computer")
    try:
        base = _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="get_computer")
        name = computer_name.strip().rstrip("$")
        search_filter = f"(&(objectClass=computer)(|(cn={_ldap_escape(name)})(sAMAccountName={_ldap_escape(name)}$)))"
        default_attrs = [
            "cn", "distinguishedName", "operatingSystem", "operatingSystemVersion",
            "lastLogonTimestamp", "whenCreated", "userAccountControl",
            "dNSHostName", "description", "sAMAccountName",
        ]
        extra = _ensure_list(attributes)
        all_attrs = list(set(default_attrs + extra))
        conn.search(base, search_filter, SUBTREE, attributes=all_attrs, size_limit=1)
        if not conn.entries:
            return _standard_response(True, data={"found": False, "computer_name": name}, action_name="get_computer")
        e = conn.entries[0]
        raw = {a: e[a].value for a in e.entry_attributes}
        uac = int(raw.get("userAccountControl") or 0)
        return _standard_response(
            True,
            data={
                "found": True,
                "dn": raw.get("distinguishedName"),
                "name": raw.get("cn"),
                "samaccountname": raw.get("sAMAccountName"),
                "os": raw.get("operatingSystem"),
                "os_version": raw.get("operatingSystemVersion"),
                "dns_hostname": raw.get("dNSHostName"),
                "description": raw.get("description"),
                "last_logon": str(raw.get("lastLogonTimestamp")) if raw.get("lastLogonTimestamp") else None,
                "enabled": not bool(uac & 0x02),
                "raw": raw,
            },
            action_name="get_computer",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="get_computer")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Disable computer",
    description="Disable a computer account in Active Directory.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def disable_computer(
    computer_name: Annotated[str, Doc("Computer name (CN) or DN")],
) -> dict[str, Any]:
    """Disable computer account (SOAR containment)."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="disable_computer")
    try:
        base = _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="disable_computer")
        name = computer_name.strip().rstrip("$")
        search_filter = f"(&(objectClass=computer)(|(cn={_ldap_escape(name)})(sAMAccountName={_ldap_escape(name)}$)))"
        conn.search(base, search_filter, SUBTREE, attributes=["distinguishedName", "userAccountControl"], size_limit=1)
        if not conn.entries:
            return _standard_response(False, error="Computer not found", action_name="disable_computer")
        e = conn.entries[0]
        comp_dn = e.entry_dn
        uac = int(e["userAccountControl"].value or 0)
        conn.modify(comp_dn, {"userAccountControl": [(MODIFY_REPLACE, [uac | 0x02])]})
        return _standard_response(True, data={"dn": comp_dn, "disabled": True}, action_name="disable_computer")
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="disable_computer")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Move computer",
    description="Move a computer object to another OU.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def move_computer(
    computer_name: Annotated[str, Doc("Computer name (CN) or DN")],
    destination_ou: Annotated[str, Doc("Destination OU DN")],
) -> dict[str, Any]:
    """Move computer to new OU (quarantine)."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="move_computer")
    try:
        base = _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="move_computer")
        name = computer_name.strip().rstrip("$")
        search_filter = f"(&(objectClass=computer)(|(cn={_ldap_escape(name)})(sAMAccountName={_ldap_escape(name)}$)))"
        conn.search(base, search_filter, SUBTREE, attributes=["distinguishedName"], size_limit=1)
        if not conn.entries:
            return _standard_response(False, error="Computer not found", action_name="move_computer")
        comp_dn = conn.entries[0].entry_dn
        rdn_parts = parse_dn(comp_dn)
        rdn = f"{rdn_parts[0][0]}={rdn_parts[0][1]}" if rdn_parts else ""
        ok = conn.modify_dn(comp_dn, rdn, new_superior=destination_ou)
        if not ok:
            return _standard_response(False, error=str(conn.result), action_name="move_computer")
        return _standard_response(
            True,
            data={"dn": comp_dn, "destination": destination_ou, "moved": True},
            action_name="move_computer",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="move_computer")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


# =============================================================================
# Phase 7: update_user, create_group, expire_password, set_password_never_expire, remediate_user
# =============================================================================


@registry.register(
    default_title="AD: Update user",
    description="Update multiple attributes of a user at once.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def update_user(
    user: Annotated[str, Doc("User identifier")],
    attributes: Annotated[dict, Doc('Attributes dict, e.g. {"displayName": "New Name", "mail": "x@y.com"}')],
    identifier_type: Annotated[str, Doc("auto, samaccountname, dn, upn, email")] = "auto",
) -> dict[str, Any]:
    """Update multiple user attributes in one call (REPLACE mode)."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="update_user")
    try:
        base = _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="update_user")
        user_dn, resolve_err = _resolve_identifier(conn, user, identifier_type, base)
        if resolve_err:
            return _standard_response(False, error=resolve_err, action_name="update_user")
        updated = []
        failed = []
        for attr_name, attr_value in attributes.items():
            try:
                ok = conn.modify(user_dn, {attr_name: [(MODIFY_REPLACE, [attr_value])]})
                if ok:
                    updated.append(attr_name)
                else:
                    failed.append({"attribute": attr_name, "error": str(conn.result)})
            except Exception as ae:
                failed.append({"attribute": attr_name, "error": str(ae)})
        return _standard_response(
            True,
            data={"dn": user_dn, "updated_attributes": updated, "failed_attributes": failed},
            action_name="update_user",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="update_user")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Create group",
    description="Create a new group in Active Directory.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def create_group(
    group_dn: Annotated[str, Doc("Full DN for the new group")],
    group_name: Annotated[str, Doc("sAMAccountName for the group")],
    group_type: Annotated[str, Doc("security or distribution")] = "security",
    group_scope: Annotated[str, Doc("global, universal, or domain_local")] = "global",
    description: Annotated[str | None, Doc("Group description")] = None,
) -> dict[str, Any]:
    """Create AD group."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="create_group")
    try:
        # groupType is a signed 32-bit integer in AD:
        #   global=2, domain_local=4, universal=8, security flag=0x80000000
        # AD expects the SIGNED value (e.g. global+security = -2147483646)
        scope_map = {"global": 2, "domain_local": 4, "universal": 8}
        scope_val = scope_map.get(group_scope.lower(), 2)
        if group_type.lower() == "security":
            scope_val |= 0x80000000
        # Convert to signed 32-bit for AD
        import ctypes
        gt_signed = ctypes.c_int32(scope_val).value

        # Extract CN from DN for the cn attribute
        cn_value = group_dn.split(",")[0]
        if cn_value.upper().startswith("CN="):
            cn_value = cn_value[3:]

        attrs: dict[str, Any] = {
            "cn": cn_value,
            "sAMAccountName": group_name,
            "groupType": str(gt_signed),
        }
        if description:
            attrs["description"] = description

        ok = conn.add(group_dn, "group", attributes=attrs)
        if not ok:
            return _standard_response(False, error=str(conn.result), action_name="create_group")
        return _standard_response(
            True,
            data={"dn": group_dn, "group_name": group_name, "group_type": group_type,
                  "group_scope": group_scope, "created": True},
            action_name="create_group",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="create_group")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Expire password",
    description="Force password expiration (user must change at next logon).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def expire_password(
    user: Annotated[str, Doc("User identifier")],
    identifier_type: Annotated[str, Doc("auto, samaccountname, dn, upn, email")] = "auto",
) -> dict[str, Any]:
    """Set pwdLastSet=0 to expire password."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="expire_password")
    try:
        base = _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="expire_password")
        user_dn, resolve_err = _resolve_identifier(conn, user, identifier_type, base)
        if resolve_err:
            return _standard_response(False, error=resolve_err, action_name="expire_password")
        ok = conn.modify(user_dn, {"pwdLastSet": [(MODIFY_REPLACE, [0])]})
        return _standard_response(
            True,
            data={"dn": user_dn, "password_expired": ok},
            action_name="expire_password",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="expire_password")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Set password never expire",
    description="Toggle the Password Never Expires flag on a user account.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def set_password_never_expire(
    user: Annotated[str, Doc("User identifier")],
    value: Annotated[bool, Doc("true = password never expires, false = normal expiry")],
    identifier_type: Annotated[str, Doc("auto, samaccountname, dn, upn, email")] = "auto",
) -> dict[str, Any]:
    """Toggle DONT_EXPIRE_PASSWORD flag."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="set_password_never_expire")
    try:
        base = _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="set_password_never_expire")
        user_dn, resolve_err = _resolve_identifier(conn, user, identifier_type, base)
        if resolve_err:
            return _standard_response(False, error=resolve_err, action_name="set_password_never_expire")
        conn.search(user_dn, "(objectClass=*)", BASE, attributes=["userAccountControl"])
        if not conn.entries:
            return _standard_response(False, error="User not found", action_name="set_password_never_expire")
        uac = int(conn.entries[0]["userAccountControl"].value or 0)
        if value:
            new_uac = uac | 0x10000  # DONT_EXPIRE_PASSWORD
        else:
            new_uac = uac & (0xFFFFFFFF ^ 0x10000)
        conn.modify(user_dn, {"userAccountControl": [(MODIFY_REPLACE, [new_uac])]})
        return _standard_response(
            True,
            data={"dn": user_dn, "password_never_expires": value},
            action_name="set_password_never_expire",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="set_password_never_expire")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Remediate user",
    description="SOAR remediation: re-enable account, restore groups, move back — reverse of contain_user.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def remediate_user(
    user: Annotated[str, Doc("User identifier")],
    identifier_type: Annotated[str, Doc("auto, samaccountname, dn, upn, email")] = "auto",
    actions: Annotated[
        str | list | None,
        Doc("Actions: enable, restore_groups, move_to_original_ou (semicolon-separated or list)"),
    ] = "enable",
    groups_to_restore: Annotated[str | list | None, Doc("Group DNs to restore membership")] = None,
    original_ou: Annotated[str | None, Doc("Original OU DN to move back to")] = None,
) -> dict[str, Any]:
    """Reverse containment — remediation steps."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="remediate_user")
    try:
        base = _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="remediate_user")
        user_dn, resolve_err = _resolve_identifier(conn, user, identifier_type, base)
        if resolve_err:
            return _standard_response(False, error=resolve_err, action_name="remediate_user")

        action_list = _ensure_list(actions) if actions else ["enable"]
        results: dict[str, Any] = {}

        if "enable" in action_list:
            try:
                conn.search(user_dn, "(objectClass=*)", BASE, attributes=["userAccountControl"])
                if conn.entries:
                    uac = int(conn.entries[0]["userAccountControl"].value or 0)
                    conn.modify(user_dn, {"userAccountControl": [(MODIFY_REPLACE, [uac & (0xFFFFFFFF ^ 0x02)])]})
                    results["enable"] = {"success": True}
                else:
                    results["enable"] = {"success": False, "error": "not found"}
            except Exception as ee:
                results["enable"] = {"success": False, "error": str(ee)}

        if "restore_groups" in action_list:
            grps = _ensure_list(groups_to_restore) if groups_to_restore else []
            if not grps:
                results["restore_groups"] = {"success": False, "error": "groups_to_restore not provided"}
            else:
                restored = []
                for gdn in grps:
                    try:
                        ldap3.extend.microsoft.addMembersToGroups.ad_add_members_to_groups(
                            conn, [user_dn], [gdn], fix=True, raise_error=False,
                        )
                        restored.append(gdn)
                    except Exception:
                        pass
                results["restore_groups"] = {"success": True, "restored": restored}

        if "move_to_original_ou" in action_list:
            if not original_ou:
                results["move_to_original_ou"] = {"success": False, "error": "original_ou not provided"}
            else:
                try:
                    rdn_parts = parse_dn(user_dn)
                    rdn = f"{rdn_parts[0][0]}={rdn_parts[0][1]}" if rdn_parts else ""
                    conn.modify_dn(user_dn, rdn, new_superior=original_ou)
                    results["move_to_original_ou"] = {"success": True}
                except Exception as mv:
                    results["move_to_original_ou"] = {"success": False, "error": str(mv)}

        return _standard_response(
            True,
            data={"user_dn": user_dn, "actions_performed": results},
            action_name="remediate_user",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="remediate_user")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


# =============================================================================
# Phase 8: search_computers, search_groups, contacts, delete_group,
#           set_account_expiry, get_domain_info
# =============================================================================


@registry.register(
    default_title="AD: Search computers",
    description="Advanced computer search with preset filters.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def search_computers(
    query: Annotated[str | None, Doc("Raw LDAP filter (overrides preset)")] = None,
    preset_filter: Annotated[
        str | None,
        Doc("Preset: all_computers, disabled_computers, servers, workstations"),
    ] = None,
    name: Annotated[str | None, Doc("Filter by cn (wildcard OK)")] = None,
    size_limit: Annotated[int, Doc("Max results")] = 50,
) -> dict[str, Any]:
    """Search computer objects."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="search_computers")
    try:
        base = _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="search_computers")
        if query:
            ldap_filter = query
        elif preset_filter and preset_filter in COMPUTER_SEARCH_PRESETS:
            ldap_filter = COMPUTER_SEARCH_PRESETS[preset_filter]
        else:
            parts = ["(objectClass=computer)"]
            if name:
                parts.append(f"(cn={_ldap_escape(name)})")
            ldap_filter = "(&" + "".join(parts) + ")" if len(parts) > 1 else parts[0]

        attrs = [
            "cn", "distinguishedName", "operatingSystem", "operatingSystemVersion",
            "lastLogonTimestamp", "userAccountControl", "dNSHostName", "sAMAccountName",
        ]
        conn.search(base, ldap_filter, SUBTREE, attributes=attrs, size_limit=size_limit, paged_size=1000)
        entries = []
        for entry in conn.response:
            if entry.get("type") == "searchResRef":
                continue
            entries.append({
                "dn": entry.get("dn", ""),
                "attributes": {k.lower(): v for k, v in (entry.get("attributes") or {}).items()},
            })
        return _standard_response(
            True,
            data={"entries": entries, "total_objects": len(entries), "filter_used": ldap_filter},
            action_name="search_computers",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="search_computers")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Search groups",
    description="Search groups by name, type, or scope.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def search_groups(
    name: Annotated[str | None, Doc("Group name filter (wildcard OK: *admin*)")] = None,
    group_type: Annotated[str | None, Doc("security or distribution")] = None,
    size_limit: Annotated[int, Doc("Max results")] = 50,
) -> dict[str, Any]:
    """Search group objects."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="search_groups")
    try:
        base = _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="search_groups")
        parts = ["(objectClass=group)"]
        if name:
            parts.append(f"(cn={_ldap_escape(name)})")
        ldap_filter = "(&" + "".join(parts) + ")" if len(parts) > 1 else parts[0]
        attrs = ["cn", "distinguishedName", "sAMAccountName", "description", "groupType", "member"]
        conn.search(base, ldap_filter, SUBTREE, attributes=attrs, size_limit=size_limit, paged_size=1000)
        entries = []
        for entry in conn.response:
            if entry.get("type") == "searchResRef":
                continue
            a = entry.get("attributes") or {}
            gt = int(_first(a.get("groupType") or a.get("grouptype")) or 0)
            is_security = bool(gt & 0x80000000)
            type_str = "security" if is_security else "distribution"
            if group_type and type_str != group_type.lower():
                continue
            entries.append({
                "dn": entry.get("dn", ""),
                "name": _first(a.get("sAMAccountName") or a.get("samaccountname") or a.get("cn")),
                "description": _first(a.get("description")),
                "group_type": type_str,
                "member_count": len(a.get("member") or a.get("Member") or []),
            })
        return _standard_response(
            True,
            data={"entries": entries, "total_objects": len(entries)},
            action_name="search_groups",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="search_groups")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Create contact",
    description="Create a contact object in Active Directory.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def create_contact(
    contact_dn: Annotated[str, Doc("Full DN for the contact")],
    display_name: Annotated[str, Doc("Display name")],
    email: Annotated[str | None, Doc("E-mail address")] = None,
    description: Annotated[str | None, Doc("Description")] = None,
    telephone: Annotated[str | None, Doc("Telephone")] = None,
    title: Annotated[str | None, Doc("Title")] = None,
    custom_attributes: Annotated[dict | None, Doc("Extra attributes")] = None,
) -> dict[str, Any]:
    """Create AD contact."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="create_contact")
    try:
        # Extract CN from DN
        cn_value = contact_dn.split(",")[0]
        if cn_value.upper().startswith("CN="):
            cn_value = cn_value[3:]

        attrs: dict[str, Any] = {
            "cn": cn_value,
            "displayName": display_name,
        }
        if email:
            attrs["mail"] = email
        if description:
            attrs["description"] = description
        if telephone:
            attrs["telephoneNumber"] = telephone
        if title:
            attrs["title"] = title
        if custom_attributes:
            attrs.update(custom_attributes)
        ok = conn.add(contact_dn, ["top", "person", "organizationalPerson", "contact"], attributes=attrs)
        if not ok:
            return _standard_response(False, error=str(conn.result), action_name="create_contact")
        return _standard_response(True, data={"dn": contact_dn, "created": True}, action_name="create_contact")
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="create_contact")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Update contact",
    description="Update attributes of an existing AD contact.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def update_contact(
    contact_dn: Annotated[str, Doc("Contact DN")],
    attributes: Annotated[dict, Doc("Attributes to update as dict")],
) -> dict[str, Any]:
    """Update contact attributes (REPLACE)."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="update_contact")
    try:
        updated = []
        failed = []
        for attr_name, attr_value in attributes.items():
            try:
                ok = conn.modify(contact_dn, {attr_name: [(MODIFY_REPLACE, [attr_value])]})
                if ok:
                    updated.append(attr_name)
                else:
                    failed.append({"attribute": attr_name, "error": str(conn.result)})
            except Exception as ae:
                failed.append({"attribute": attr_name, "error": str(ae)})
        return _standard_response(
            True,
            data={"dn": contact_dn, "updated_attributes": updated, "failed_attributes": failed},
            action_name="update_contact",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="update_contact")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Delete group",
    description="Delete a group from Active Directory.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def delete_group(
    group: Annotated[str, Doc("Group name or DN")],
    identifier_type: Annotated[str, Doc("auto, samaccountname, dn")] = "auto",
) -> dict[str, Any]:
    """Delete AD group."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="delete_group")
    try:
        base = _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="delete_group")
        group_dn, resolve_err = _resolve_identifier(conn, group, identifier_type, base)
        if resolve_err:
            return _standard_response(False, error=resolve_err, action_name="delete_group")
        ok = conn.delete(group_dn)
        if not ok:
            return _standard_response(False, error=str(conn.result), action_name="delete_group")
        return _standard_response(True, data={"dn": group_dn, "deleted": True}, action_name="delete_group")
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="delete_group")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Set account expiry",
    description="Set or remove account expiration date.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def set_account_expiry(
    user: Annotated[str, Doc("User identifier")],
    expiry_date: Annotated[
        str | None,
        Doc("Expiry date ISO 8601 (e.g. 2025-12-31). Empty = remove expiry"),
    ] = None,
    identifier_type: Annotated[str, Doc("auto, samaccountname, dn, upn, email")] = "auto",
) -> dict[str, Any]:
    """Set accountExpires attribute."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="set_account_expiry")
    try:
        base = _base_dn(conn)
        if not base:
            return _standard_response(False, error="AD_BASE_DN required", action_name="set_account_expiry")
        user_dn, resolve_err = _resolve_identifier(conn, user, identifier_type, base)
        if resolve_err:
            return _standard_response(False, error=resolve_err, action_name="set_account_expiry")

        if not expiry_date:
            # Remove expiry → set to 0 (never)
            val = "0"
        else:
            # Convert ISO date to Windows FileTime (100-ns intervals since 1601-01-01)
            try:
                dt = datetime.fromisoformat(expiry_date.replace("Z", "+00:00"))
                epoch_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
                delta = dt - epoch_1601
                val = str(int(delta.total_seconds() * 10_000_000))
            except Exception as pe:
                return _standard_response(False, error=f"Invalid date: {pe}", action_name="set_account_expiry")

        ok = conn.modify(user_dn, {"accountExpires": [(MODIFY_REPLACE, [val])]})
        return _standard_response(
            True,
            data={"dn": user_dn, "account_expires": expiry_date or "never", "set": ok},
            action_name="set_account_expiry",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="set_account_expiry")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


@registry.register(
    default_title="AD: Get domain info",
    description="Get Active Directory domain information, password policy, and domain controllers.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[ad_secret],
)
def get_domain_info() -> dict[str, Any]:
    """Read domain-level information from RootDSE and domain object."""
    conn, err = _get_connection()
    if err:
        return _standard_response(False, error=err, action_name="get_domain_info")
    try:
        info = conn.server.info
        root_dn = None
        domain_name = None
        forest_name = None
        functional_level = None
        try:
            root_dn = info.other.get("defaultNamingContext", [None])[0]
            domain_name = info.other.get("ldapServiceName", [None])[0]
            forest_name = info.other.get("rootDomainNamingContext", [None])[0]
            functional_level = info.other.get("domainFunctionality", [None])[0]
        except (TypeError, IndexError, AttributeError):
            pass

        # Password policy
        policy = {}
        if root_dn:
            conn.search(
                root_dn, "(objectClass=domain)", BASE,
                attributes=[
                    "minPwdLength", "maxPwdAge", "minPwdAge", "pwdHistoryLength",
                    "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow",
                ],
            )
            if conn.entries:
                for a in conn.entries[0].entry_attributes:
                    policy[a] = conn.entries[0][a].value

        return _standard_response(
            True,
            data={
                "domain_dn": root_dn,
                "domain_name": domain_name,
                "forest_dn": forest_name,
                "functional_level": functional_level,
                "password_policy": policy,
            },
            action_name="get_domain_info",
        )
    except Exception as e:
        return _standard_response(False, error=str(e), action_name="get_domain_info")
    finally:
        try:
            conn.unbind()
        except Exception:
            pass
