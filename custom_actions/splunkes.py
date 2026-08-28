"""SOCLib Splunk ES integration — integrations.soclib.splunkes (engine UDFs).

Implements actions for Splunk Enterprise Security integration.
All actions return standard output: { success, data, error, meta }.

This integration is fully self-contained: it depends only on the Secret
(soclib_splunk_es). It does not use workspace variables, context, or any
external configuration. Token is provided via SPLUNK_API_TOKEN (same as
Kopal default integrations).

NOTE: UDF namespace is "integrations.soclib.splunkes" (engine).
User-facing YAML templates use namespace "tools.soclib.splunkes" and call these UDFs.
"""

from __future__ import annotations

import httpx
from datetime import datetime, timezone
from typing import Annotated, Any

from kopal_registry import RegistrySecret, registry, secrets
from typing_extensions import Doc

# Secret name in Kopal: soclib_splunk_es (static - must match templates)
splunk_es_secret = RegistrySecret(
    name="soclib_splunk_es",
    keys=["SPLUNK_BASE_URL", "SPLUNK_API_TOKEN"],
    optional_keys=[
        "SPLUNK_VERIFY_SSL",
        "SPLUNK_NAMESPACE_OWNER",
        "SPLUNK_NAMESPACE_APP",
    ],
)

ACTION_NAMESPACE = "integrations.soclib.splunkes"
DISPLAY_GROUP = "SOCLib / Splunk Enterprise Security"

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------


def _standard_response(
    success: bool,
    data: Any = None,
    error: str | None = None,
    action_name: str = "",
    connection: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build standard output for all actions."""
    payload = data if data is not None else {}
    if isinstance(payload, dict):
        payload = dict(payload)
    
    meta: dict[str, Any] = {
        "action": f"{ACTION_NAMESPACE}.{action_name}" if action_name else ACTION_NAMESPACE,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    
    if connection:
        meta["connection"] = connection
        if success and isinstance(payload, dict):
            payload["connection"] = connection
    
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
        return str(val).strip() if val else default
    except Exception:
        return default


def _get_base_url() -> str:
    """Get Splunk base URL from secrets."""
    url = _get_secret("SPLUNK_BASE_URL", "")
    if not url:
        raise ValueError("SPLUNK_BASE_URL is required in secret")
    # Remove trailing slash if present
    return url.rstrip("/")


def _get_api_token() -> str:
    """Get API token from secrets."""
    token = _get_secret("SPLUNK_API_TOKEN", "").strip()
    if not token:
        raise ValueError("SPLUNK_API_TOKEN is required in secret")
    return token


def _get_verify_ssl() -> bool:
    """Get SSL verification setting from secrets."""
    verify_str = _get_secret("SPLUNK_VERIFY_SSL", "true").lower()
    return verify_str == "true"


def _get_namespace_owner() -> str:
    """Get namespace owner from secrets."""
    return _get_secret("SPLUNK_NAMESPACE_OWNER", "nobody")


def _get_namespace_app() -> str:
    """Get namespace app from secrets."""
    return _get_secret("SPLUNK_NAMESPACE_APP", "SplunkEnterpriseSecuritySuite")


def _get_es_base_url() -> str:
    """Get ES API base URL.
    
    Note: In Splunk ES, the missioncontrol app is typically accessed via:
    /servicesNS/{owner}/missioncontrol/public/v2
    The app name in namespace may be 'missioncontrol' or 'SplunkEnterpriseSecuritySuite',
    but the API path uses 'missioncontrol' directly.
    """
    base_url = _get_base_url()
    owner = _get_namespace_owner()
    # ES API uses 'missioncontrol' directly, not the app name
    return f"{base_url}/servicesNS/{owner}/missioncontrol/public/v2"


def _get_headers() -> dict[str, str]:
    """Get HTTP headers for API requests."""
    return {
        "Authorization": f"Bearer {_get_api_token()}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _build_connection_spec() -> dict[str, Any]:
    """Build connection spec for reporting (no secrets)."""
    base_url = _get_base_url()
    owner = _get_namespace_owner()
    app = _get_namespace_app()
    verify_ssl = _get_verify_ssl()
    
    return {
        "base_url": base_url,
        "es_api_base": f"{base_url}/servicesNS/{owner}/{app}/missioncontrol/public/v2",
        "namespace_owner": owner,
        "namespace_app": app,
        "ssl_validation": "enabled" if verify_ssl else "disabled",
    }


async def _make_request(
    method: str,
    url: str,
    params: dict[str, Any] | None = None,
    json_data: dict[str, Any] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Make HTTP request to Splunk ES API."""
    verify_ssl = _get_verify_ssl()
    headers = _get_headers()
    
    async with httpx.AsyncClient(verify=verify_ssl, timeout=timeout) as client:
        try:
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=json_data,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            error_msg = f"HTTP {e.response.status_code}"
            try:
                error_data = e.response.json()
                if "error" in error_data:
                    error_msg = error_data["error"].get("message", str(e.response.text))
                else:
                    error_msg = str(e.response.text)
            except Exception:
                error_msg = str(e.response.text) if e.response.text else str(e)
            raise ValueError(error_msg) from e
        except httpx.RequestError as e:
            raise ValueError(f"Request failed: {str(e)}") from e


def _splunk_failure_guidance(error_message: str) -> str:
    """Return guidance text (English) based on common failure patterns."""
    err_lower = (error_message or "").lower()
    
    if "401" in err_lower or "unauthorized" in err_lower:
        return (
            "Authentication failed. Check SPLUNK_API_TOKEN in secret. "
            "Ensure the token is valid and has not expired. Create a new token from Splunk Web UI: "
            "Settings → Tokens → New Token."
        )
    
    if "403" in err_lower or "forbidden" in err_lower:
        return (
            "Access forbidden. Check API token capabilities. Required capabilities: "
            "mc_investigation_read, mc_finding_read, mc_risk_read, or admin_all_objects. "
            "Verify namespace permissions (SPLUNK_NAMESPACE_OWNER, SPLUNK_NAMESPACE_APP)."
        )
    
    if "404" in err_lower or "not found" in err_lower:
        return (
            "Resource not found. Check SPLUNK_NAMESPACE_APP (should be 'SplunkEnterpriseSecuritySuite' "
            "or 'missioncontrol'). Verify ES is installed and the endpoint exists."
        )
    
    if "429" in err_lower or "rate limit" in err_lower:
        return (
            "Rate limit exceeded. Splunk ES API has rate limiting. "
            "Wait a few seconds and retry, or reduce request frequency."
        )
    
    if "connection" in err_lower and ("refused" in err_lower or "failed" in err_lower):
        return (
            "Connection failed. Check SPLUNK_BASE_URL (format: https://host:port), "
            "network connectivity, firewall rules, and that Splunk is running."
        )
    
    if "ssl" in err_lower or "certificate" in err_lower:
        return (
            "SSL certificate error. For test environments, set SPLUNK_VERIFY_SSL=false. "
            "For production, ensure valid SSL certificate or provide CA certificate."
        )
    
    if "timeout" in err_lower or "timed out" in err_lower:
        return (
            "Request timeout. Check network connectivity, Splunk server status, "
            "and consider increasing timeout if query is complex."
        )
    
    if "expecting value" in err_lower or "line 1 column 1" in err_lower:
        return (
            "Response was not valid JSON (Splunk may have returned XML or empty body). "
            "Ensure the endpoint is called with output_mode=json where required."
        )
    
    return (
        "Check SPLUNK_BASE_URL, SPLUNK_API_TOKEN, network connectivity, and Splunk ES installation. "
        "See doc/integrations/soclib-splunkes/ for troubleshooting."
    )


# ---------------------------------------------------------------------------
# Actions - Phase 1: Core Actions
# ---------------------------------------------------------------------------


@registry.register(
    default_title="Test Connectivity",
    description=(
        "Test connection to Splunk ES and verify API access. "
        "Checks Splunk version, ES installation, and API token permissions."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTintro",
)
async def test_connectivity() -> dict[str, Any]:
    """Test connectivity to Splunk ES."""
    action_name = "test_connectivity"
    connection = _build_connection_spec()
    
    try:
        base_url = _get_base_url()
        api_token = _get_api_token()
        
        # Test 1: Check Splunk version (core API). Splunk returns XML by default; request JSON.
        try:
            version_url = f"{base_url}/services/authentication/users"
            version_response = await _make_request(
                "GET", version_url, params={"output_mode": "json"}, timeout=10.0
            )
            splunk_version = version_response.get("generator", {}).get("version", "Unknown")
        except Exception as e:
            return _standard_response(
                success=False,
                error=f"Failed to get Splunk version: {str(e)}",
                action_name=action_name,
                connection=connection,
            )
        
        # Test 2: Check ES installation. Request JSON (Splunk default is XML).
        try:
            es_check_url = f"{base_url}/services/apps/local/SplunkEnterpriseSecuritySuite"
            await _make_request(
                "GET", es_check_url, params={"output_mode": "json"}, timeout=10.0
            )
            has_es = True
        except Exception:
            has_es = False
        
        # Test 3: Test ES API access
        es_api_accessible = False
        if has_es:
            try:
                es_base_url = _get_es_base_url()
                test_url = f"{es_base_url}/investigations?limit=1"
                await _make_request("GET", test_url, timeout=10.0)
                es_api_accessible = True
            except Exception:
                es_api_accessible = False
        
        return _standard_response(
            success=True,
            data={
                "splunk_version": splunk_version,
                "has_es": has_es,
                "es_api_accessible": es_api_accessible,
                "connection_status": "success",
                "base_url": base_url,
                "namespace_owner": _get_namespace_owner(),
                "namespace_app": _get_namespace_app(),
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Run Query",
    description=(
        "Execute a Splunk SPL (Search Processing Language) query and return results. "
        "Supports time range, search mode, and result limiting."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch#search.2Fjobs",
)
async def run_query(
    query: Annotated[str, Doc("Splunk SPL query. Must start with 'search' or a command like '|'.")],
    start_time: Annotated[str | None, Doc("Earliest time modifier (e.g., '-24h', '-7d', '2024-01-01T00:00:00Z').")] = None,
    end_time: Annotated[str | None, Doc("Latest time modifier (e.g., 'now', '-1h', '2024-01-02T00:00:00Z').")] = None,
    limit: Annotated[int, Doc("Maximum number of results to return.")] = 100,
    search_mode: Annotated[str, Doc("Search mode: 'fast', 'verbose', or 'smart'.")] = "smart",
) -> dict[str, Any]:
    """Run a Splunk SPL query."""
    action_name = "run_query"
    connection = _build_connection_spec()
    
    try:
        if not query or not query.strip():
            return _standard_response(
                success=False,
                error="Query parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        base_url = _get_base_url()
        search_url = f"{base_url}/services/search/jobs"
        
        # Prepare form data
        form_data: dict[str, Any] = {
            "search": query.strip(),
            "exec_mode": "oneshot",
            "output_mode": "json",
            "count": 0,
            "max_count": min(limit, 50000),  # Splunk max
        }
        
        if start_time:
            form_data["earliest_time"] = start_time
        if end_time:
            form_data["latest_time"] = end_time
        
        # Set search mode
        if search_mode in ["fast", "verbose", "smart"]:
            form_data["adhoc_search_level"] = search_mode
        else:
            form_data["adhoc_search_level"] = "smart"
        
        # Make request (oneshot mode returns results directly)
        headers = _get_headers()
        # Remove Content-Type for form data (httpx will set it automatically)
        headers.pop("Content-Type", None)
        
        verify_ssl = _get_verify_ssl()
        async with httpx.AsyncClient(verify=verify_ssl, timeout=60.0) as client:
            response = await client.post(
                search_url,
                headers=headers,
                data=form_data,  # httpx will encode as form-urlencoded
            )
            response.raise_for_status()
            
            # Parse response - oneshot mode returns JSON directly
            content_type = response.headers.get("content-type", "").lower()
            if "json" in content_type:
                try:
                    results_data = response.json()
                    # Response can be: list of events, or dict with "results" key
                    if isinstance(results_data, list):
                        events = results_data
                    elif isinstance(results_data, dict):
                        events = results_data.get("results", [])
                    else:
                        events = []
                except Exception:
                    # Fallback: try to parse as text
                    text = response.text
                    events = []
            else:
                # Non-JSON response (shouldn't happen with output_mode=json)
                events = []
        
        return _standard_response(
            success=True,
            data={
                "results": events,
                "total_events": len(events),
                "query": query.strip(),
                "search_mode": search_mode,
            },
            action_name=action_name,
            connection=connection,
        )
        
    except httpx.HTTPStatusError as e:
        error_msg = f"HTTP {e.response.status_code}: {str(e.response.text) if e.response.text else str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Update Notable Event",
    description=(
        "Update a notable event in Splunk ES. Supports updating status, disposition, "
        "urgency, comment, and owner. Works with event_id or SID+RID combo."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch#search.2Fjobs",
)
async def update_notable_event(
    event_id: Annotated[str, Doc("Event ID or SID+RID combo (e.g., '1234567890.123+0').")],
    status: Annotated[str | None, Doc("New status (e.g., 'new', 'in progress', 'resolved', 'closed').")] = None,
    disposition: Annotated[str | None, Doc("New disposition (e.g., 'True Positive', 'False Positive').")] = None,
    urgency: Annotated[str | None, Doc("New urgency: 'informational', 'low', 'medium', 'high', 'critical'.")] = None,
    comment: Annotated[str | None, Doc("Comment to add to the event.")] = None,
    owner: Annotated[str | None, Doc("New owner username.")] = None,
) -> dict[str, Any]:
    """Update a notable event in Splunk ES."""
    action_name = "update_notable_event"
    connection = _build_connection_spec()
    
    try:
        if not event_id or not event_id.strip():
            return _standard_response(
                success=False,
                error="event_id parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        # Check if at least one update field is provided
        if not any([status, disposition, urgency, comment, owner]):
            return _standard_response(
                success=False,
                error="At least one update field (status, disposition, urgency, comment, owner) must be provided",
                action_name=action_name,
                connection=connection,
            )
        
        base_url = _get_base_url()
        update_url = f"{base_url}/services/notable_update"
        
        # Build request body
        request_body: dict[str, Any] = {
            "ruleUIDs": event_id.strip(),
        }
        
        if status:
            request_body["status"] = status
        if disposition:
            request_body["disposition"] = disposition
        if urgency:
            request_body["urgency"] = urgency
        if comment:
            request_body["comment"] = comment
        if owner:
            request_body["newOwner"] = owner
        
        # Make request
        result = await _make_request("POST", update_url, json_data=request_body, timeout=30.0)
        
        # Parse response
        success_count = result.get("success_count", 0)
        failure_count = result.get("failure_count", 0)
        message = result.get("message", "")
        
        if success_count > 0:
            return _standard_response(
                success=True,
                data={
                    "event_id": event_id.strip(),
                    "success_count": success_count,
                    "failure_count": failure_count,
                    "message": message,
                    "updated_fields": {
                        "status": status,
                        "disposition": disposition,
                        "urgency": urgency,
                        "comment": comment,
                        "owner": owner,
                    },
                },
                action_name=action_name,
                connection=connection,
            )
        else:
            return _standard_response(
                success=False,
                error=message or "Failed to update event",
                data={
                    "event_id": event_id.strip(),
                    "success_count": success_count,
                    "failure_count": failure_count,
                    "message": message,
                },
                action_name=action_name,
                connection=connection,
            )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="List Investigations",
    description=(
        "Retrieve investigations from Splunk ES with filtering and pagination. "
        "Supports filtering by status, urgency, owner, disposition, and time range."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/investigation/public_v2_list_investigations",
)
async def list_investigations(
    limit: Annotated[int, Doc("Maximum number of investigations to return (max: 100). Default: 20.")] = 20,
    offset: Annotated[int, Doc("Starting point for pagination. Default: 0.")] = 0,
    ids: Annotated[str | None, Doc("Comma-separated list of investigation IDs (GUID) or display_ids (e.g., '123,ES-001,332123').")] = None,
    status: Annotated[str | None, Doc("Filter by status ID or label (e.g., 'New', '1').")] = None,
    urgency: Annotated[str | None, Doc("Filter by urgency: 'informational', 'low', 'medium', 'high', 'critical', 'unknown'.")] = None,
    sensitivity: Annotated[str | None, Doc("Filter by sensitivity: 'White', 'Green', 'Amber', 'Red', 'Unassigned'.")] = None,
    owner: Annotated[str | None, Doc("Filter by owner username.")] = None,
    disposition: Annotated[str | None, Doc("Filter by disposition ID or label (e.g., 'disposition:1', 'Undetermined').")] = None,
    sort: Annotated[str | None, Doc("Sort order (e.g., 'create_time:desc', 'status:asc'). Multiple fields separated by comma. Default: 'create_time:desc'.")] = None,
    create_time_min: Annotated[float | None, Doc("Minimum creation time (Unix epoch timestamp).")] = None,
    create_time_max: Annotated[float | None, Doc("Maximum creation time (Unix epoch timestamp).")] = None,
    update_time_min: Annotated[float | None, Doc("Minimum update time (Unix epoch timestamp).")] = None,
    update_time_max: Annotated[float | None, Doc("Maximum update time (Unix epoch timestamp).")] = None,
    search_format: Annotated[bool | None, Doc("If true, response will be formatted for use in Splunk search with 'rest' command.")] = None,
) -> dict[str, Any]:
    """List investigations from Splunk ES."""
    action_name = "list_investigations"
    
    try:
        connection = _build_connection_spec()
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/investigations"
        
        # Build query parameters
        params: dict[str, Any] = {
            "limit": min(limit, 100),  # Max 100 per API
            "offset": max(offset, 0),
        }
        
        if ids:
            params["ids"] = ids
        if status:
            params["status"] = status
        if urgency:
            params["urgency"] = urgency
        if sensitivity:
            params["sensitivity"] = sensitivity
        if owner:
            params["owner"] = owner
        if disposition:
            params["disposition"] = disposition
        if sort:
            params["sort"] = sort
        if create_time_min is not None:
            params["create_time_min"] = create_time_min
        if create_time_max is not None:
            params["create_time_max"] = create_time_max
        if update_time_min is not None:
            params["update_time_min"] = update_time_min
        if update_time_max is not None:
            params["update_time_max"] = update_time_max
        if search_format is not None:
            params["search_format"] = search_format
        
        # Make request
        investigations = await _make_request("GET", url, params=params, timeout=30.0)
        
        # Ensure investigations is a list
        if isinstance(investigations, dict):
            # If response is wrapped, extract list
            investigations = investigations.get("investigations", [investigations])
        elif not isinstance(investigations, list):
            investigations = []
        
        return _standard_response(
            success=True,
            data={
                "investigations": investigations,
                "total": len(investigations),
                "limit": params["limit"],
                "offset": params["offset"],
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Create Investigation",
    description=(
        "Create a new investigation in Splunk ES. "
        "Requires name; optionally includes description, urgency, sensitivity, owner, and finding_id."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/investigation/public_v2_create_investigation",
)
async def create_investigation(
    name: Annotated[str, Doc("Investigation name (required).")],
    description: Annotated[str | None, Doc("Investigation description.")] = None,
    investigation_type: Annotated[str | None, Doc("Investigation type (e.g., 'threat investigation', 'default').")] = None,
    status: Annotated[str | None, Doc("Status ID or status label (e.g., 'New', '1').")] = None,
    disposition: Annotated[str | None, Doc("Disposition ID or disposition label (e.g., 'Undetermined').")] = None,
    urgency: Annotated[str | None, Doc("Urgency: 'informational', 'low', 'medium', 'high', 'critical', 'unknown'.")] = None,
    sensitivity: Annotated[str | None, Doc("Sensitivity: 'White', 'Green', 'Amber', 'Red', 'Unassigned'.")] = None,
    owner: Annotated[str | None, Doc("Owner username.")] = None,
    finding_id: Annotated[str | None, Doc("Associated finding ID (single).")] = None,
    finding_ids: Annotated[list[str] | None, Doc("List of finding IDs (event_ids) to add to investigation.")] = None,
    finding_times: Annotated[list[str] | None, Doc("List of times for findings (relative, ISO, or epoch time).")] = None,
) -> dict[str, Any]:
    """Create a new investigation in Splunk ES."""
    action_name = "create_investigation"
    
    try:
        connection = _build_connection_spec()
        if not name or not name.strip():
            return _standard_response(
                success=False,
                error="name parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/investigations"
        
        # Build request body according to InvestigationCreatePayload schema
        payload: dict[str, Any] = {
            "name": name.strip(),
        }
        
        if description:
            payload["description"] = description
        if investigation_type:
            payload["investigation_type"] = investigation_type
        if status:
            payload["status"] = status
        if disposition:
            payload["disposition"] = disposition
        if urgency:
            payload["urgency"] = urgency
        if sensitivity:
            payload["sensitivity"] = sensitivity
        if owner:
            payload["owner"] = owner
        if finding_id:
            payload["finding_id"] = finding_id
        if finding_ids:
            payload["finding_ids"] = finding_ids
        if finding_times:
            payload["finding_times"] = finding_times
        
        # Make request
        investigation = await _make_request("POST", url, json_data=payload, timeout=30.0)
        
        # Extract IDs
        investigation_id = investigation.get("investigation_id") or investigation.get("id")
        investigation_guid = investigation.get("investigation_guid") or investigation.get("investigation_guid")
        
        return _standard_response(
            success=True,
            data={
                "investigation": investigation,
                "investigation_id": investigation_id,
                "investigation_guid": investigation_guid,
                "name": name.strip(),
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
# ---------------------------------------------------------------------------
# Actions - Phase 2: Extended Actions
# ---------------------------------------------------------------------------


@registry.register(
    default_title="Update Investigation",
    description=(
        "Update an existing investigation in Splunk ES. "
        "Supports updating name, description, status, urgency, sensitivity, owner, and other fields."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/investigation/public_v2_update_investigation",
)
async def update_investigation(
    id: Annotated[str, Doc("Investigation ID (GUID) or display_id (e.g., 'ES-00001').")],
    name: Annotated[str | None, Doc("New investigation name.")] = None,
    description: Annotated[str | None, Doc("New investigation description.")] = None,
    status: Annotated[str | None, Doc("New status ID or label.")] = None,
    urgency: Annotated[str | None, Doc("New urgency: 'informational', 'low', 'medium', 'high', 'critical', 'unknown'.")] = None,
    sensitivity: Annotated[str | None, Doc("New sensitivity: 'White', 'Green', 'Amber', 'Red', 'Unassigned'.")] = None,
    owner: Annotated[str | None, Doc("New owner username.")] = None,
    investigation_type: Annotated[str | None, Doc("New investigation type (e.g., 'threat investigation', 'default').")] = None,
) -> dict[str, Any]:
    """Update an existing investigation in Splunk ES."""
    action_name = "update_investigation"
    connection = _build_connection_spec()
    
    try:
        if not id or not id.strip():
            return _standard_response(
                success=False,
                error="id parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        # Check if at least one update field is provided
        if not any([name, description, status, urgency, sensitivity, owner, investigation_type]):
            return _standard_response(
                success=False,
                error="At least one update field (name, description, status, urgency, sensitivity, owner, investigation_type) must be provided",
                action_name=action_name,
                connection=connection,
            )
        
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/investigations/{id.strip()}"
        
        # Build request body according to InvestigationUpdatePayload schema
        payload: dict[str, Any] = {}
        
        if name:
            payload["name"] = name
        if description:
            payload["description"] = description
        if status:
            payload["status"] = status
        if urgency:
            payload["urgency"] = urgency
        if sensitivity:
            payload["sensitivity"] = sensitivity
        if owner:
            payload["owner"] = owner
        if investigation_type:
            payload["investigation_type"] = investigation_type
        
        # Make request
        investigation = await _make_request("POST", url, json_data=payload, timeout=30.0)
        
        return _standard_response(
            success=True,
            data={
                "investigation": investigation,
                "investigation_id": id.strip(),
                "updated_fields": {k: v for k, v in payload.items() if v is not None},
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Get Findings",
    description=(
        "Retrieve findings from Splunk ES with filtering and pagination. "
        "Supports filtering by investigation_id, status, urgency, and time range."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/findings/public_v2_get_findings",
)
async def get_findings(
    limit: Annotated[int, Doc("Maximum number of findings to return (max: 100). Default: 20.")] = 20,
    offset: Annotated[int, Doc("Starting point for pagination. Default: 0.")] = 0,
    finding_ids: Annotated[str | None, Doc("Comma-separated list of finding IDs (event_ids).")] = None,
    investigation_id: Annotated[str | None, Doc("Filter by investigation ID.")] = None,
    status: Annotated[str | None, Doc("Filter by status (e.g., 'In Progress').")] = None,
    urgency: Annotated[str | None, Doc("Filter by urgency: 'informational', 'low', 'medium', 'high', 'critical', 'unknown'.")] = None,
    owner: Annotated[str | None, Doc("Filter by owner username.")] = None,
    disposition: Annotated[str | None, Doc("Filter by disposition (e.g., 'True Positive - Suspicious Activity').")] = None,
    sort: Annotated[str | None, Doc("Sort order (e.g., 'create_time:desc'). Multiple fields separated by comma.")] = None,
    fields: Annotated[str | None, Doc("Comma-separated list of fields to return (e.g., 'rule_title,event_id,status,urgency'). Only specified fields will be returned.")] = None,
    earliest: Annotated[str | None, Doc("Earliest time for findings (relative time like '-30m', epoch time, or ISO 8601).")] = None,
    latest: Annotated[str | None, Doc("Latest time for findings (relative time like '-30m', epoch time, or ISO 8601). Default: now.")] = None,
    rule_title: Annotated[str | None, Doc("Filter by rule title/description.")] = None,
    create_time_min: Annotated[float | None, Doc("Minimum creation time (Unix epoch timestamp).")] = None,
    create_time_max: Annotated[float | None, Doc("Maximum creation time (Unix epoch timestamp).")] = None,
    update_time_min: Annotated[float | None, Doc("Minimum update time (Unix epoch timestamp).")] = None,
    update_time_max: Annotated[float | None, Doc("Maximum update time (Unix epoch timestamp).")] = None,
    search_format: Annotated[bool | None, Doc("If true, response will be formatted for use in Splunk search with 'rest' command.")] = None,
) -> dict[str, Any]:
    """Get findings from Splunk ES."""
    action_name = "get_findings"
    
    try:
        connection = _build_connection_spec()
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/findings"
        
        # Build query parameters
        params: dict[str, Any] = {
            "limit": min(limit, 100),
            "offset": max(offset, 0),
        }
        
        if finding_ids:
            params["finding_ids"] = finding_ids
        if investigation_id:
            params["investigation_id"] = investigation_id
        if status:
            params["status"] = status
        if urgency:
            params["urgency"] = urgency
        if owner:
            params["owner"] = owner
        if disposition:
            params["disposition"] = disposition
        if sort:
            params["sort"] = sort
        if fields:
            params["fields"] = fields
        if earliest:
            params["earliest"] = earliest
        if latest:
            params["latest"] = latest
        if rule_title:
            params["rule_title"] = rule_title
        if create_time_min is not None:
            params["create_time_min"] = create_time_min
        if create_time_max is not None:
            params["create_time_max"] = create_time_max
        if update_time_min is not None:
            params["update_time_min"] = update_time_min
        if update_time_max is not None:
            params["update_time_max"] = update_time_max
        if search_format is not None:
            params["search_format"] = search_format
        
        # Make request
        findings = await _make_request("GET", url, params=params, timeout=30.0)
        
        # Ensure findings is a list
        if isinstance(findings, dict):
            findings = findings.get("findings", [findings])
        elif not isinstance(findings, list):
            findings = []
        
        return _standard_response(
            success=True,
            data={
                "findings": findings,
                "total": len(findings),
                "limit": params["limit"],
                "offset": params["offset"],
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Create Manual Finding",
    description=(
        "Create a manual finding in Splunk ES. "
        "Requires rule_title, rule_description, security_domain, risk_object, risk_object_type, and risk_score."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/findings/public_v2_create_manual_finding",
)
async def create_manual_finding(
    rule_title: Annotated[str, Doc("The rule title for the manual finding (required).")],
    rule_description: Annotated[str, Doc("The rule description for the manual finding (required).")],
    security_domain: Annotated[str, Doc("The security domain (e.g., 'threat', 'access', 'endpoint') (required).")],
    risk_object: Annotated[str, Doc("The risk object (e.g., username, hostname, IP) (required).")],
    risk_object_type: Annotated[str, Doc("The risk object type (e.g., 'user', 'system', 'other') (required).")],
    risk_score: Annotated[float, Doc("The risk score (required).")],
    status: Annotated[str | None, Doc("The status id or status label (e.g., 'New').")] = None,
    urgency: Annotated[str | None, Doc("Urgency: 'informational', 'low', 'medium', 'high', 'critical', 'unknown'.")] = None,
    owner: Annotated[str | None, Doc("The owner for the manual finding.")] = None,
    disposition: Annotated[str | None, Doc("The disposition id or disposition label.")] = None,
) -> dict[str, Any]:
    """Create a manual finding in Splunk ES."""
    action_name = "create_manual_finding"
    
    try:
        connection = _build_connection_spec()
        # Validate required fields
        if not rule_title or not rule_title.strip():
            return _standard_response(
                success=False,
                error="rule_title parameter is required",
                action_name=action_name,
                connection=connection,
            )
        if not rule_description or not rule_description.strip():
            return _standard_response(
                success=False,
                error="rule_description parameter is required",
                action_name=action_name,
                connection=connection,
            )
        if not security_domain or not security_domain.strip():
            return _standard_response(
                success=False,
                error="security_domain parameter is required",
                action_name=action_name,
                connection=connection,
            )
        if not risk_object or not risk_object.strip():
            return _standard_response(
                success=False,
                error="risk_object parameter is required",
                action_name=action_name,
                connection=connection,
            )
        if not risk_object_type or not risk_object_type.strip():
            return _standard_response(
                success=False,
                error="risk_object_type parameter is required",
                action_name=action_name,
                connection=connection,
            )
        if risk_score is None:
            return _standard_response(
                success=False,
                error="risk_score parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/findings"
        
        # Build request body with required fields
        payload: dict[str, Any] = {
            "rule_title": rule_title.strip(),
            "rule_description": rule_description.strip(),
            "security_domain": security_domain.strip(),
            "risk_object": risk_object.strip(),
            "risk_object_type": risk_object_type.strip(),
            "risk_score": float(risk_score),
        }
        
        # Add optional fields
        if status:
            payload["status"] = status
        if urgency:
            payload["urgency"] = urgency
        if owner:
            payload["owner"] = owner
        if disposition:
            payload["disposition"] = disposition
        
        # Make request
        finding = await _make_request("POST", url, json_data=payload, timeout=30.0)
        
        # Extract finding ID
        finding_id = finding.get("finding_id") or finding.get("id")
        
        return _standard_response(
            success=True,
            data={
                "finding": finding,
                "finding_id": finding_id,
                "rule_title": rule_title.strip(),
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Get Finding by ID",
    description="Retrieve a specific finding by its ID from Splunk ES.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/findings/public_v2_get_finding_by_id",
)
async def get_finding_by_id(
    id: Annotated[str, Doc("Finding ID.")],
) -> dict[str, Any]:
    """Get a finding by ID from Splunk ES."""
    action_name = "get_finding_by_id"
    connection = _build_connection_spec()
    
    try:
        if not id or not id.strip():
            return _standard_response(
                success=False,
                error="id parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/findings/{id.strip()}"
        
        # Make request
        finding = await _make_request("GET", url, timeout=30.0)
        
        return _standard_response(
            success=True,
            data={
                "finding": finding,
                "finding_id": id.strip(),
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Get Host Events",
    description=(
        "Get events pertaining to a host that have occurred in the last N days. "
        "Searches the default index for events matching the hostname."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch#search.2Fjobs",
)
async def get_host_events(
    hostname: Annotated[str, Doc("Hostname or IP address to search events for.")],
    last_n_days: Annotated[int, Doc("Number of days to look back (must be > 0).")] = 7,
) -> dict[str, Any]:
    """Get events for a specific host."""
    action_name = "get_host_events"
    connection = _build_connection_spec()
    
    try:
        if not hostname or not hostname.strip():
            return _standard_response(
                success=False,
                error="hostname parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        if last_n_days <= 0:
            return _standard_response(
                success=False,
                error="last_n_days must be greater than 0",
                action_name=action_name,
                connection=connection,
            )
        
        # Build query
        query = f'search host="{hostname.strip()}" earliest=-{last_n_days}d'
        
        # Use run_query logic
        base_url = _get_base_url()
        search_url = f"{base_url}/services/search/jobs"
        
        form_data: dict[str, Any] = {
            "search": query,
            "exec_mode": "oneshot",
            "output_mode": "json",
            "count": 0,
        }
        
        headers = _get_headers()
        headers.pop("Content-Type", None)
        
        verify_ssl = _get_verify_ssl()
        async with httpx.AsyncClient(verify=verify_ssl, timeout=60.0) as client:
            response = await client.post(
                search_url,
                headers=headers,
                data=form_data,
            )
            response.raise_for_status()
            
            content_type = response.headers.get("content-type", "").lower()
            if "json" in content_type:
                try:
                    results_data = response.json()
                    if isinstance(results_data, list):
                        events = results_data
                    elif isinstance(results_data, dict):
                        events = results_data.get("results", [])
                    else:
                        events = []
                except Exception:
                    events = []
            else:
                events = []
        
        return _standard_response(
            success=True,
            data={
                "events": events,
                "total_events": len(events),
                "hostname": hostname.strip(),
                "last_n_days": last_n_days,
                "query": query,
            },
            action_name=action_name,
            connection=connection,
        )
        
    except httpx.HTTPStatusError as e:
        error_msg = f"HTTP {e.response.status_code}: {str(e.response.text) if e.response.text else str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Post Data",
    description=(
        "Post data to a Splunk index. "
        "Creates an event in Splunk with the provided data."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTinput#receivers.2Fsimple",
)
async def post_data(
    data: Annotated[str, Doc("Data to post to Splunk.")],
    index: Annotated[str | None, Doc("Index to send event to (defaults to default index).")] = None,
    source: Annotated[str | None, Doc("Source for the event (default: 'Kopal').")] = None,
    sourcetype: Annotated[str | None, Doc("Sourcetype for the event (default: 'Automation/Orchestration Platform').")] = None,
    host: Annotated[str | None, Doc("Host for the event.")] = None,
) -> dict[str, Any]:
    """Post data to Splunk index."""
    action_name = "post_data"
    connection = _build_connection_spec()
    
    try:
        if not data or not data.strip():
            return _standard_response(
                success=False,
                error="data parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        base_url = _get_base_url()
        post_url = f"{base_url}/services/receivers/simple"
        
        # Build query parameters
        params: dict[str, Any] = {}
        
        if source:
            params["source"] = source
        else:
            params["source"] = "Kopal"
        
        if sourcetype:
            params["sourcetype"] = sourcetype
        else:
            params["sourcetype"] = "Automation/Orchestration Platform"
        
        if host:
            params["host"] = host
        
        if index:
            params["index"] = index
        
        # Make request
        headers = _get_headers()
        headers.pop("Content-Type", None)  # Let httpx set it
        
        verify_ssl = _get_verify_ssl()
        async with httpx.AsyncClient(verify=verify_ssl, timeout=30.0) as client:
            response = await client.post(
                post_url,
                headers=headers,
                params=params,
                content=data.encode("utf-8"),
            )
            response.raise_for_status()
        
        return _standard_response(
            success=True,
            data={
                "status": "success",
                "data_posted": data[:100] + "..." if len(data) > 100 else data,
                "index": index or "default",
                "source": params["source"],
                "sourcetype": params["sourcetype"],
            },
            action_name=action_name,
            connection=connection,
        )
        
    except httpx.HTTPStatusError as e:
        error_msg = f"HTTP {e.response.status_code}: {str(e.response.text) if e.response.text else str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={
                "error_message": error_msg,
                "guidance": guidance,
            },
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )

# ---------------------------------------------------------------------------
# Actions - Phase 2: Extended Actions (Remaining)
# ---------------------------------------------------------------------------


@registry.register(
    default_title="Get Investigation Notes",
    description="Retrieve notes for a specific investigation from Splunk ES.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/investigation/public_v2_get_notes_from_investigation",
)
async def get_investigation_notes(
    investigation_id: Annotated[str, Doc("Investigation ID (GUID) or display_id.")],
    search: Annotated[str | None, Doc("Keywords to search for in the title or content of notes.")] = None,
    source_type: Annotated[
        str | None,
        Doc("Source type filter: 'Task', 'Incident', or 'All'. Only notes of this type will be returned."),
    ] = None,
) -> dict[str, Any]:
    """Get notes for an investigation."""
    action_name = "get_investigation_notes"
    
    try:
        connection = _build_connection_spec()
        if not investigation_id or not investigation_id.strip():
            return _standard_response(
                success=False,
                error="investigation_id parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/investigations/{investigation_id.strip()}/notes"
        
        # Build query parameters
        params: dict[str, Any] = {}
        if search:
            params["search"] = search
        if source_type:
            params["type"] = source_type
        
        notes = await _make_request("GET", url, params=params if params else None, timeout=30.0)
        
        if isinstance(notes, dict):
            notes = notes.get("notes", [notes])
        elif not isinstance(notes, list):
            notes = []
        
        return _standard_response(
            success=True,
            data={
                "notes": notes,
                "total": len(notes),
                "investigation_id": investigation_id.strip(),
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Create Investigation Note",
    description="Create a new note for an investigation in Splunk ES.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/investigation/public_v2_add_note_to_investigation",
)
async def create_investigation_note(
    investigation_id: Annotated[str, Doc("Investigation ID (GUID) or display_id.")],
    content: Annotated[str, Doc("The data stored within the note (required).")],
    title: Annotated[str | None, Doc("The title of the note.")] = None,
    files: Annotated[list[str] | None, Doc("An array of file IDs to add to the note.")] = None,
) -> dict[str, Any]:
    """Create a note for an investigation."""
    action_name = "create_investigation_note"
    
    try:
        connection = _build_connection_spec()
        if not investigation_id or not investigation_id.strip():
            return _standard_response(
                success=False,
                error="investigation_id parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        if not content or not content.strip():
            return _standard_response(
                success=False,
                error="content parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/investigations/{investigation_id.strip()}/notes"
        
        # Build payload according to CreateNotePayload schema
        payload: dict[str, Any] = {
            "content": content.strip(),
        }
        
        if title:
            payload["title"] = title
        if files:
            payload["files"] = files
        
        created_note = await _make_request("POST", url, json_data=payload, timeout=30.0)
        
        note_id = created_note.get("note_id") or created_note.get("id") or created_note.get("id")
        
        return _standard_response(
            success=True,
            data={
                "note": created_note,
                "note_id": note_id,
                "investigation_id": investigation_id.strip(),
                "content": content.strip(),
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Update Investigation Note",
    description="Update an existing note for an investigation in Splunk ES.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/investigation/public_v2_update_note_in_investigation",
)
async def update_investigation_note(
    investigation_id: Annotated[str, Doc("Investigation ID (GUID) or display_id.")],
    note_id: Annotated[str, Doc("Note ID.")],
    note: Annotated[str, Doc("Updated note content.")],
) -> dict[str, Any]:
    """Update a note for an investigation."""
    action_name = "update_investigation_note"
    connection = _build_connection_spec()
    
    try:
        if not investigation_id or not investigation_id.strip():
            return _standard_response(
                success=False,
                error="investigation_id parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        if not note_id or not note_id.strip():
            return _standard_response(
                success=False,
                error="note_id parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        if not note or not note.strip():
            return _standard_response(
                success=False,
                error="note parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/investigations/{investigation_id.strip()}/notes/{note_id.strip()}"
        
        payload = {"note": note.strip()}
        updated_note = await _make_request("POST", url, json_data=payload, timeout=30.0)
        
        return _standard_response(
            success=True,
            data={
                "note": updated_note,
                "note_id": note_id.strip(),
                "investigation_id": investigation_id.strip(),
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Delete Investigation Note",
    description="Delete a note from an investigation in Splunk ES.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/investigation/public_v2_delete_note_from_investigation",
)
async def delete_investigation_note(
    investigation_id: Annotated[str, Doc("Investigation ID (GUID) or display_id.")],
    note_id: Annotated[str, Doc("Note ID.")],
) -> dict[str, Any]:
    """Delete a note from an investigation."""
    action_name = "delete_investigation_note"
    connection = _build_connection_spec()
    
    try:
        if not investigation_id or not investigation_id.strip():
            return _standard_response(
                success=False,
                error="investigation_id parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        if not note_id or not note_id.strip():
            return _standard_response(
                success=False,
                error="note_id parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/investigations/{investigation_id.strip()}/notes/{note_id.strip()}"
        
        await _make_request("DELETE", url, timeout=30.0)
        
        return _standard_response(
            success=True,
            data={
                "status": "deleted",
                "note_id": note_id.strip(),
                "investigation_id": investigation_id.strip(),
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Add Findings to Investigation",
    description="Add findings to an investigation in Splunk ES.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/investigation/public_v2_add_findings_to_investigation",
)
async def add_findings_to_investigation(
    investigation_id: Annotated[str, Doc("Investigation ID (GUID) or display_id.")],
    finding_ids: Annotated[list[str], Doc("List of finding IDs (event_ids) to add (required).")],
    finding_times: Annotated[list[str] | None, Doc("List of times for findings (relative, ISO, or epoch time). Must match finding_ids length.")] = None,
) -> dict[str, Any]:
    """Add findings to an investigation."""
    action_name = "add_findings_to_investigation"
    
    try:
        connection = _build_connection_spec()
        if not investigation_id or not investigation_id.strip():
            return _standard_response(
                success=False,
                error="investigation_id parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        if not finding_ids or len(finding_ids) == 0:
            return _standard_response(
                success=False,
                error="finding_ids parameter must contain at least one finding ID",
                action_name=action_name,
                connection=connection,
            )
        
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/investigations/{investigation_id.strip()}/findings"
        
        # Build payload according to AddFindingsToInvestigationPayload schema
        # According to OpenAPI spec, both finding_ids and finding_times are required
        payload: dict[str, Any] = {
            "finding_ids": finding_ids,
        }
        
        # finding_times is required according to schema
        if finding_times:
            if len(finding_times) != len(finding_ids):
                return _standard_response(
                    success=False,
                    error="finding_times length must match finding_ids length",
                    action_name=action_name,
                    connection=connection,
                )
            payload["finding_times"] = finding_times
        else:
            # If finding_times not provided, use current time for each finding
            # This satisfies the OpenAPI requirement that finding_times is required
            from datetime import datetime, timezone
            current_time_iso = datetime.now(timezone.utc).isoformat()
            payload["finding_times"] = [current_time_iso] * len(finding_ids)
        
        result = await _make_request("POST", url, json_data=payload, timeout=30.0)
        
        return _standard_response(
            success=True,
            data={
                "result": result,
                "investigation_id": investigation_id.strip(),
                "finding_ids": finding_ids,
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Get Risk Scores",
    description="Retrieve risk scores for an entity (user, system, etc.) from Splunk ES.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/risks/public_v2_risk_entity_risk_scores_retrieve",
)
async def get_risk_scores(
    entity: Annotated[str, Doc("Entity identifier in format 'type:value' (e.g., 'user:admin', 'system:192.168.1.1').")],
) -> dict[str, Any]:
    """Get risk scores for an entity."""
    action_name = "get_risk_scores"
    connection = _build_connection_spec()
    
    try:
        if not entity or not entity.strip():
            return _standard_response(
                success=False,
                error="entity parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/risks/risk_scores/{entity.strip()}"
        
        risk_scores = await _make_request("GET", url, timeout=30.0)
        
        return _standard_response(
            success=True,
            data={
                "risk_scores": risk_scores,
                "entity": entity.strip(),
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Update Risk Scores",
    description="Update risk modifiers for an entity in Splunk ES.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/risks/public_v2_risk_entity_risk_scores_update",
)
async def update_risk_scores(
    entity: Annotated[str, Doc("Entity identifier in format 'type:value' (e.g., 'user:admin', 'system:192.168.1.1').")],
    risk_modifiers: Annotated[list[dict[str, Any]], Doc("List of risk modifiers with modifier_type, modifier_value, and reason.")],
) -> dict[str, Any]:
    """Update risk scores for an entity."""
    action_name = "update_risk_scores"
    connection = _build_connection_spec()
    
    try:
        if not entity or not entity.strip():
            return _standard_response(
                success=False,
                error="entity parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        if not risk_modifiers or len(risk_modifiers) == 0:
            return _standard_response(
                success=False,
                error="risk_modifiers parameter must contain at least one modifier",
                action_name=action_name,
                connection=connection,
            )
        
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/risks/risk_scores/{entity.strip()}"
        
        payload = {"risk_modifiers": risk_modifiers}
        result = await _make_request("POST", url, json_data=payload, timeout=30.0)
        
        return _standard_response(
            success=True,
            data={
                "result": result,
                "entity": entity.strip(),
                "risk_modifiers": risk_modifiers,
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Get Asset",
    description="Retrieve asset information by ID from Splunk ES.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/assets/public_v2_assets",
)
async def get_asset(
    id: Annotated[str, Doc("Asset ID.")],
    search_format: Annotated[bool, Doc("Return format suitable for Splunk search (default: false).")] = False,
) -> dict[str, Any]:
    """Get asset by ID."""
    action_name = "get_asset"
    connection = _build_connection_spec()
    
    try:
        if not id or not id.strip():
            return _standard_response(
                success=False,
                error="id parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/assets/{id.strip()}"
        
        params = {}
        if search_format:
            params["search_format"] = "true"
        
        asset = await _make_request("GET", url, params=params, timeout=30.0)
        
        return _standard_response(
            success=True,
            data={
                "asset": asset,
                "asset_id": id.strip(),
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


# ---------------------------------------------------------------------------
# Actions - Phase 3: Advanced Actions
# ---------------------------------------------------------------------------


@registry.register(
    default_title="Get Identity",
    description="Retrieve identity information by ID from Splunk ES.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/identity/public_v2_get_identity",
)
async def get_identity(
    id: Annotated[str, Doc("Identity ID.")],
) -> dict[str, Any]:
    """Get identity by ID."""
    action_name = "get_identity"
    connection = _build_connection_spec()
    
    try:
        if not id or not id.strip():
            return _standard_response(
                success=False,
                error="id parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/identity/{id.strip()}"
        
        identity = await _make_request("GET", url, timeout=30.0)
        
        return _standard_response(
            success=True,
            data={
                "identity": identity,
                "identity_id": id.strip(),
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Get Task Notes",
    description="Retrieve notes for a task in a response plan phase from Splunk ES.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/responseplan/public_v2_get_notes_from_task",
)
async def get_task_notes(
    investigation_id: Annotated[str, Doc("Investigation ID (GUID) or display_id.")],
    response_plan_id: Annotated[str, Doc("Response Plan ID.")],
    phase_id: Annotated[str, Doc("Phase ID.")],
    task_id: Annotated[str, Doc("Task ID.")],
) -> dict[str, Any]:
    """Get notes for a task."""
    action_name = "get_task_notes"
    connection = _build_connection_spec()
    
    try:
        if not all([investigation_id, response_plan_id, phase_id, task_id]):
            return _standard_response(
                success=False,
                error="All parameters (investigation_id, response_plan_id, phase_id, task_id) are required",
                action_name=action_name,
                connection=connection,
            )
        
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/investigations/{investigation_id.strip()}/responseplans/{response_plan_id.strip()}/phase/{phase_id.strip()}/tasks/{task_id.strip()}/notes"
        
        notes = await _make_request("GET", url, timeout=30.0)
        
        if isinstance(notes, dict):
            notes = notes.get("notes", [notes])
        elif not isinstance(notes, list):
            notes = []
        
        return _standard_response(
            success=True,
            data={
                "notes": notes,
                "total": len(notes),
                "investigation_id": investigation_id.strip(),
                "response_plan_id": response_plan_id.strip(),
                "phase_id": phase_id.strip(),
                "task_id": task_id.strip(),
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Add Task Note",
    description="Add a note to a task in a response plan phase in Splunk ES.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/responseplan/public_v2_add_note_to_task",
)
async def add_task_note(
    investigation_id: Annotated[str, Doc("Investigation ID (GUID) or display_id.")],
    response_plan_id: Annotated[str, Doc("Response Plan ID.")],
    phase_id: Annotated[str, Doc("Phase ID.")],
    task_id: Annotated[str, Doc("Task ID.")],
    note: Annotated[str, Doc("Note content.")],
) -> dict[str, Any]:
    """Add a note to a task."""
    action_name = "add_task_note"
    connection = _build_connection_spec()
    
    try:
        if not all([investigation_id, response_plan_id, phase_id, task_id]):
            return _standard_response(
                success=False,
                error="All parameters (investigation_id, response_plan_id, phase_id, task_id) are required",
                action_name=action_name,
                connection=connection,
            )
        
        if not note or not note.strip():
            return _standard_response(
                success=False,
                error="note parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/investigations/{investigation_id.strip()}/responseplans/{response_plan_id.strip()}/phase/{phase_id.strip()}/tasks/{task_id.strip()}/notes"
        
        payload = {"note": note.strip()}
        created_note = await _make_request("POST", url, json_data=payload, timeout=30.0)
        
        note_id = created_note.get("note_id") or created_note.get("id")
        
        return _standard_response(
            success=True,
            data={
                "note": created_note,
                "note_id": note_id,
                "investigation_id": investigation_id.strip(),
                "response_plan_id": response_plan_id.strip(),
                "phase_id": phase_id.strip(),
                "task_id": task_id.strip(),
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Get Task Note by ID",
    description="Retrieve a specific task note by ID from Splunk ES.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/responseplan/public_v2_get_note_by_id_from_task",
)
async def get_task_note_by_id(
    investigation_id: Annotated[str, Doc("Investigation ID (GUID) or display_id.")],
    response_plan_id: Annotated[str, Doc("Response Plan ID.")],
    phase_id: Annotated[str, Doc("Phase ID.")],
    task_id: Annotated[str, Doc("Task ID.")],
    note_id: Annotated[str, Doc("Note ID.")],
) -> dict[str, Any]:
    """Get a task note by ID."""
    action_name = "get_task_note_by_id"
    connection = _build_connection_spec()
    
    try:
        if not all([investigation_id, response_plan_id, phase_id, task_id, note_id]):
            return _standard_response(
                success=False,
                error="All parameters (investigation_id, response_plan_id, phase_id, task_id, note_id) are required",
                action_name=action_name,
                connection=connection,
            )
        
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/investigations/{investigation_id.strip()}/responseplans/{response_plan_id.strip()}/phase/{phase_id.strip()}/tasks/{task_id.strip()}/notes/{note_id.strip()}"
        
        note = await _make_request("GET", url, timeout=30.0)
        
        return _standard_response(
            success=True,
            data={
                "note": note,
                "note_id": note_id.strip(),
                "investigation_id": investigation_id.strip(),
                "response_plan_id": response_plan_id.strip(),
                "phase_id": phase_id.strip(),
                "task_id": task_id.strip(),
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Update Task Note",
    description="Update an existing task note in Splunk ES.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/responseplan/public_v2_update_note_in_task",
)
async def update_task_note(
    investigation_id: Annotated[str, Doc("Investigation ID (GUID) or display_id.")],
    response_plan_id: Annotated[str, Doc("Response Plan ID.")],
    phase_id: Annotated[str, Doc("Phase ID.")],
    task_id: Annotated[str, Doc("Task ID.")],
    note_id: Annotated[str, Doc("Note ID.")],
    note: Annotated[str, Doc("Updated note content.")],
) -> dict[str, Any]:
    """Update a task note."""
    action_name = "update_task_note"
    connection = _build_connection_spec()
    
    try:
        if not all([investigation_id, response_plan_id, phase_id, task_id, note_id]):
            return _standard_response(
                success=False,
                error="All parameters (investigation_id, response_plan_id, phase_id, task_id, note_id) are required",
                action_name=action_name,
                connection=connection,
            )
        
        if not note or not note.strip():
            return _standard_response(
                success=False,
                error="note parameter is required",
                action_name=action_name,
                connection=connection,
            )
        
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/investigations/{investigation_id.strip()}/responseplans/{response_plan_id.strip()}/phase/{phase_id.strip()}/tasks/{task_id.strip()}/notes/{note_id.strip()}"
        
        payload = {"note": note.strip()}
        updated_note = await _make_request("POST", url, json_data=payload, timeout=30.0)
        
        return _standard_response(
            success=True,
            data={
                "note": updated_note,
                "note_id": note_id.strip(),
                "investigation_id": investigation_id.strip(),
                "response_plan_id": response_plan_id.strip(),
                "phase_id": phase_id.strip(),
                "task_id": task_id.strip(),
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )


@registry.register(
    default_title="Delete Task Note",
    description="Delete a task note from Splunk ES.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[splunk_es_secret],
    doc_url="https://help.splunk.com/en/splunk-enterprise-security-8/api-reference/8.4/splunk-enterprise-security-api-reference/responseplan/public_v2_delete_note_from_task",
)
async def delete_task_note(
    investigation_id: Annotated[str, Doc("Investigation ID (GUID) or display_id.")],
    response_plan_id: Annotated[str, Doc("Response Plan ID.")],
    phase_id: Annotated[str, Doc("Phase ID.")],
    task_id: Annotated[str, Doc("Task ID.")],
    note_id: Annotated[str, Doc("Note ID.")],
) -> dict[str, Any]:
    """Delete a task note."""
    action_name = "delete_task_note"
    connection = _build_connection_spec()
    
    try:
        if not all([investigation_id, response_plan_id, phase_id, task_id, note_id]):
            return _standard_response(
                success=False,
                error="All parameters (investigation_id, response_plan_id, phase_id, task_id, note_id) are required",
                action_name=action_name,
                connection=connection,
            )
        
        es_base_url = _get_es_base_url()
        url = f"{es_base_url}/investigations/{investigation_id.strip()}/responseplans/{response_plan_id.strip()}/phase/{phase_id.strip()}/tasks/{task_id.strip()}/notes/{note_id.strip()}"
        
        await _make_request("DELETE", url, timeout=30.0)
        
        return _standard_response(
            success=True,
            data={
                "status": "deleted",
                "note_id": note_id.strip(),
                "investigation_id": investigation_id.strip(),
                "response_plan_id": response_plan_id.strip(),
                "phase_id": phase_id.strip(),
                "task_id": task_id.strip(),
            },
            action_name=action_name,
            connection=connection,
        )
        
    except ValueError as e:
        error_msg = str(e)
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        guidance = _splunk_failure_guidance(error_msg)
        return _standard_response(
            success=False,
            data={"error_message": error_msg, "guidance": guidance},
            error=error_msg,
            action_name=action_name,
            connection=connection,
        )
