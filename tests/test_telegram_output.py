"""Unit tests for SOCLib Telegram helpers and response shape."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def telegram_module():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "custom_actions" / "telegram.py"
    spec = importlib.util.spec_from_file_location("custom_actions.telegram", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_resolve_chat_id_from_param(telegram_module):
    with patch.object(telegram_module, "_get_secret", return_value=""):
        assert telegram_module._resolve_chat_id("@mychannel") == "@mychannel"


def test_resolve_chat_id_from_secret(telegram_module):
    with patch.object(telegram_module, "_get_secret", return_value="-100123"):
        assert telegram_module._resolve_chat_id(None) == "-100123"


def test_resolve_chat_id_missing_raises(telegram_module):
    with patch.object(telegram_module, "_get_secret", return_value=""):
        with pytest.raises(ValueError, match="chat_id is required"):
            telegram_module._resolve_chat_id(None)


def test_telegram_failure_guidance_admin(telegram_module):
    g = telegram_module._telegram_failure_guidance("403: CHAT_ADMIN_REQUIRED")
    assert "administrator" in g.lower()


def test_parse_reply_markup_valid(telegram_module):
    markup = '{"inline_keyboard": [[{"text": "OK", "callback_data": "ok"}]]}'
    parsed = telegram_module._parse_reply_markup(markup)
    assert "inline_keyboard" in parsed


def test_parse_reply_markup_invalid_json(telegram_module):
    with pytest.raises(ValueError, match="valid JSON"):
        telegram_module._parse_reply_markup("{bad")


def test_message_detail(telegram_module):
    msg = {
        "message_id": 42,
        "chat": {"id": -1001, "type": "channel", "title": "Alerts"},
        "date": 123,
        "text": "hello",
    }
    summary = telegram_module._message_detail(msg)
    assert summary["message_id"] == 42
    assert summary["chat_type"] == "channel"


def test_classify_error(telegram_module):
    assert telegram_module._classify_error("403: CHAT_ADMIN_REQUIRED") == "channel_permission"


def test_build_error_details(telegram_module):
    exc = telegram_module.TelegramAPIError("Unauthorized", error_code=401, api_method="getMe")
    details = telegram_module._build_error_details(exc)
    assert details["error_code"] == 401
    assert details["error_type"] == "auth"
    assert details["guidance"]


@pytest.mark.asyncio
async def test_test_connectivity_success(telegram_module):
    fake_result = {"id": 1, "username": "test_bot", "first_name": "Test"}
    with patch.object(telegram_module, "_get_bot_token", return_value="token"):
        with patch.object(telegram_module, "_telegram_request", new=AsyncMock(return_value=fake_result)):
            out = await telegram_module.test_connectivity()
    assert out["success"] is True
    assert out["data"]["bot_username"] == "test_bot"


@pytest.mark.asyncio
async def test_send_message_api_error(telegram_module):
    with patch.object(telegram_module, "_get_bot_token", return_value="token"):
        with patch.object(
            telegram_module,
            "_telegram_request",
            new=AsyncMock(
                side_effect=telegram_module.TelegramAPIError(
                    "chat not found", error_code=400, api_method="sendMessage"
                )
            ),
        ):
            out = await telegram_module.send_message(text="hi", chat_id="999")
    assert out["success"] is False
    assert out["data"]["error_details"]["error_type"] == "chat_not_found"
    assert out["meta"]["error_details"]["guidance"]


@pytest.mark.asyncio
async def test_send_media_group_validates_count(telegram_module):
    with patch.object(telegram_module, "_get_bot_token", return_value="token"):
        out = await telegram_module.send_media_group(media_json='[{"type":"photo","media":"x"}]')
    assert out["success"] is False
    assert "2 to 10" in (out["error"] or "")


@pytest.mark.asyncio
async def test_telegram_request_ok_false(telegram_module):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "ok": False,
        "description": "Unauthorized",
        "error_code": 401,
    }
    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch.object(telegram_module, "_get_bot_token", return_value="bad"):
        with patch("custom_actions.telegram.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(telegram_module.TelegramAPIError, match="Unauthorized"):
                await telegram_module._telegram_request("getMe")
