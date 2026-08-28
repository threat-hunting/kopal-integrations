"""Tests for Splunk ES integration: output structure and token from secret.

Validates that Splunk ES actions return the standard shape
{ success, data, error, meta }. Integration is fully self-contained (secrets only).
Token is provided via SPLUNK_API_TOKEN only (same as Kopal default).

Run: uv run pytest tests/test_splunk_es_output.py -v
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _standard_keys() -> set[str]:
    return {"success", "data", "error", "meta"}


@pytest.fixture
def mock_secrets_with_token():
    """Secrets with SPLUNK_API_TOKEN set."""
    return {
        "SPLUNK_BASE_URL": "https://splunk.example.com:8089",
        "SPLUNK_API_TOKEN": "test-token-value",
        "SPLUNK_VERIFY_SSL": "true",
        "SPLUNK_NAMESPACE_OWNER": "nobody",
        "SPLUNK_NAMESPACE_APP": "SplunkEnterpriseSecuritySuite",
    }


class TestSplunkESToken:
    """Test token from secret."""

    def test_get_api_token_uses_secret(self, mock_secrets_with_token):
        with patch("custom_actions.splunkes.secrets") as m:
            m.get.side_effect = lambda key: mock_secrets_with_token.get(key, "")
            from custom_actions.splunkes import _get_api_token

            token = _get_api_token()
            assert token == "test-token-value"

    def test_get_api_token_raises_when_empty(self, mock_secrets_with_token):
        mock_secrets_with_token["SPLUNK_API_TOKEN"] = ""
        with patch("custom_actions.splunkes.secrets") as m:
            m.get.side_effect = lambda key: mock_secrets_with_token.get(key, "")
            from custom_actions.splunkes import _get_api_token

            with pytest.raises(ValueError, match="SPLUNK_API_TOKEN is required"):
                _get_api_token()


class TestSplunkESOutputStructure:
    """Assert Splunk ES test_connectivity returns standard output shape."""

    def test_test_connectivity_returns_standard_shape(self, mock_secrets_with_token):
        call_count = [0]

        async def make_request_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return {"generator": {"version": "9.0"}}
            raise Exception("mock: no ES")

        async def run():
            with patch("custom_actions.splunkes.secrets") as m:
                m.get.side_effect = lambda key: mock_secrets_with_token.get(key, "")
                with patch("custom_actions.splunkes._make_request", new_callable=AsyncMock) as req:
                    req.side_effect = make_request_side_effect
                    from custom_actions.splunkes import test_connectivity

                    return await test_connectivity()

        result = asyncio.run(run())
        assert set(result.keys()) == _standard_keys()
        assert isinstance(result["success"], bool)
        assert "data" in result
        assert "meta" in result
        assert "action" in result["meta"]
        assert "integrations.soclib.splunkes" in result["meta"]["action"]
