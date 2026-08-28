"""SOCLib Telegram Bot API integration — integrations.soclib.telegram.

Outbound messaging to Telegram channels, groups, and users via Bot API.
All actions return standard output: { success, data, error, meta }.

UDF namespace: integrations.soclib.telegram
YAML templates: tools.soclib.telegram
Secret: soclib_telegram
"""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from io import BytesIO
from typing import Annotated, Any

import httpx
from kopal_registry import RegistrySecret, registry, secrets
from typing_extensions import Doc

telegram_secret = RegistrySecret(
    name="soclib_telegram",
    keys=["TELEGRAM_BOT_TOKEN"],
    optional_keys=[
        "TELEGRAM_DEFAULT_CHAT_ID",
        "TELEGRAM_API_BASE_URL",
        "TELEGRAM_DEFAULT_PARSE_MODE",
        "TELEGRAM_WEBHOOK_SECRET",
    ],
)

ACTION_NAMESPACE = "integrations.soclib.telegram"
DISPLAY_GROUP = "SOCLib / Telegram"
DEFAULT_API_BASE = "https://api.telegram.org"
DEFAULT_TIMEOUT = 30.0


class TelegramAPIError(ValueError):
    """Telegram Bot API returned ok=false."""

    def __init__(
        self,
        message: str,
        *,
        error_code: int | None = None,
        api_method: str | None = None,
        parameters: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.api_method = api_method
        self.parameters = parameters or {}


def _standard_response(
    success: bool,
    data: Any = None,
    error: str | None = None,
    action_name: str = "",
    connection: dict[str, Any] | None = None,
    *,
    api_method: str | None = None,
    error_details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = data if data is not None else {}
    if isinstance(payload, dict):
        payload = dict(payload)

    meta: dict[str, Any] = {
        "action": f"{ACTION_NAMESPACE}.{action_name}" if action_name else ACTION_NAMESPACE,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if api_method:
        meta["api_method"] = api_method
    if connection:
        meta["connection"] = connection
        if isinstance(payload, dict):
            payload.setdefault("connection", connection)
    if error_details:
        meta["error_details"] = error_details

    return {
        "success": success,
        "data": payload,
        "error": error,
        "meta": meta,
    }


def _get_secret(key: str, default: str = "") -> str:
    try:
        val = secrets.get(key)
        return str(val).strip() if val else default
    except Exception:
        return default


def _get_bot_token() -> str:
    token = _get_secret("TELEGRAM_BOT_TOKEN")
    if not token:
        raise ValueError("TELEGRAM_BOT_TOKEN is required in secret soclib_telegram")
    return token


def _get_api_base_url() -> str:
    base = _get_secret("TELEGRAM_API_BASE_URL", DEFAULT_API_BASE).rstrip("/")
    return base or DEFAULT_API_BASE


def _get_default_parse_mode() -> str | None:
    mode = _get_secret("TELEGRAM_DEFAULT_PARSE_MODE")
    return mode if mode else None


def _build_connection_spec() -> dict[str, Any]:
    return {
        "api_base_url": _get_api_base_url(),
        "default_chat_id": _get_secret("TELEGRAM_DEFAULT_CHAT_ID") or None,
        "default_parse_mode": _get_default_parse_mode(),
        "transport": "https",
    }


def _resolve_chat_id(chat_id: str | None) -> str:
    resolved = (chat_id or "").strip() or _get_secret("TELEGRAM_DEFAULT_CHAT_ID")
    if not resolved:
        raise ValueError(
            "chat_id is required (action parameter or TELEGRAM_DEFAULT_CHAT_ID in secret)"
        )
    return resolved


def _resolve_parse_mode(parse_mode: str | None) -> str | None:
    mode = (parse_mode or "").strip() or (_get_default_parse_mode() or "")
    return mode if mode else None


def _apply_optional_params(params: dict[str, Any], **optional: Any) -> dict[str, Any]:
    for key, val in optional.items():
        if val is not None:
            params[key] = val
    return params


def _classify_error(error_msg: str) -> str:
    lower = error_msg.lower()
    if "unauthorized" in lower or "invalid token" in lower:
        return "auth"
    if "chat_admin_required" in lower:
        return "channel_permission"
    if "chat not found" in lower:
        return "chat_not_found"
    if "blocked by the user" in lower:
        return "user_blocked"
    if "can't parse" in lower:
        return "parse_mode"
    if "message is too long" in lower:
        return "message_too_long"
    if "wrong file identifier" in lower or "failed to get http url content" in lower:
        return "media_source"
    if "request failed" in lower or "timed out" in lower:
        return "network"
    return "api_error"


def _telegram_failure_guidance(error_msg: str, error_code: int | None = None) -> str:
    lower = error_msg.lower()
    if error_code == 401 or "unauthorized" in lower:
        return "Invalid TELEGRAM_BOT_TOKEN. Regenerate token in @BotFather and update secret."
    if "chat_admin_required" in lower:
        return (
            "Bot must be a channel administrator with Post Messages permission. "
            "Add the bot in Channel → Administrators."
        )
    if "chat not found" in lower:
        return (
            "Invalid chat_id or bot is not a member. Verify TELEGRAM_DEFAULT_CHAT_ID "
            "or use @channelusername for public channels."
        )
    if "blocked by the user" in lower:
        return "User blocked the bot. They must unblock and send /start before DM works."
    if "can't parse entities" in lower or "can't parse" in lower:
        return "HTML/Markdown parse error. Check tags/escaping or omit parse_mode."
    if "message is too long" in lower:
        return "Text exceeds 4096 characters. Split the message or send a document."
    if "wrong file identifier" in lower or "failed to get http url content" in lower:
        return "Invalid file_id or URL. Verify the media source is public HTTPS."
    if "have exactly one of" in lower or "is required" in lower:
        return "Check action inputs: required fields and mutually exclusive media sources."
    return "See doc/integrations/soclib-telegram/integration-setup.md and Bot API description."


def _parse_telegram_error_code(description: str) -> int | None:
    match = re.search(r"error code:\s*(\d+)", description, re.IGNORECASE)
    if match:
        return int(match.group(1))
    return None


def _message_detail(message: dict[str, Any]) -> dict[str, Any]:
    chat = message.get("chat") or {}
    from_user = message.get("from") or {}
    photo = message.get("photo") or []
    document = message.get("document") or {}
    video = message.get("video")
    return {
        "message_id": message.get("message_id"),
        "message_thread_id": message.get("message_thread_id"),
        "chat_id": chat.get("id"),
        "chat_type": chat.get("type"),
        "chat_title": chat.get("title") or chat.get("username"),
        "chat_username": chat.get("username"),
        "date": message.get("date"),
        "edit_date": message.get("edit_date"),
        "from_user_id": from_user.get("id"),
        "from_username": from_user.get("username"),
        "text": message.get("text"),
        "caption": message.get("caption"),
        "text_preview": (message.get("text") or message.get("caption") or "")[:200],
        "has_protected_content": message.get("has_protected_content"),
        "is_automatic_forward": message.get("is_automatic_forward"),
        "photo_count": len(photo) if isinstance(photo, list) else 0,
        "document_file_name": document.get("file_name") if document else None,
        "document_file_size": document.get("file_size") if document else None,
        "document_mime_type": document.get("mime_type") if document else None,
        "has_video": bool(video),
    }


def _build_send_success_data(
    result: dict[str, Any],
    *,
    chat_id_used: str,
    api_method: str,
    target_type: str | None = None,
    inputs_resolved: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "message": _message_detail(result),
        "chat_id_used": chat_id_used,
        "telegram": {
            "api_method": api_method,
            "message_id": result.get("message_id"),
        },
    }
    if target_type:
        data["target_type"] = target_type
    if inputs_resolved:
        data["inputs_resolved"] = inputs_resolved
    if extra:
        data.update(extra)
    return data


async def _telegram_request(
    method: str,
    params: dict[str, Any] | None = None,
    *,
    files: dict[str, tuple[str, BytesIO, str]] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Any:
    token = _get_bot_token()
    url = f"{_get_api_base_url()}/bot{token}/{method}"
    payload = {k: v for k, v in (params or {}).items() if v is not None}

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            if files:
                response = await client.post(url, data=payload, files=files)
            else:
                response = await client.post(url, json=payload)
            body = response.json()
        except httpx.TimeoutException as exc:
            raise TelegramAPIError(
                f"Request timed out after {timeout}s",
                api_method=method,
            ) from exc
        except httpx.RequestError as exc:
            raise TelegramAPIError(f"Request failed: {exc}", api_method=method) from exc
        except json.JSONDecodeError as exc:
            raise TelegramAPIError(
                f"Invalid JSON response from Telegram API: {exc}",
                api_method=method,
            ) from exc

    if not body.get("ok"):
        description = str(body.get("description", "Telegram API returned ok=false"))
        raise TelegramAPIError(
            description,
            error_code=body.get("error_code") or _parse_telegram_error_code(description),
            api_method=method,
            parameters=body.get("parameters") if isinstance(body.get("parameters"), dict) else {},
        )
    return body.get("result")


def _build_error_details(exc: Exception) -> dict[str, Any]:
    error_msg = str(exc)
    error_code = getattr(exc, "error_code", None)
    api_method = getattr(exc, "api_method", None)
    parameters = getattr(exc, "parameters", None) or {}
    guidance = _telegram_failure_guidance(error_msg, error_code)
    return {
        "message": error_msg,
        "guidance": guidance,
        "error_code": error_code,
        "error_type": _classify_error(error_msg),
        "api_method": api_method,
        "parameters": parameters,
    }


def _action_error(
    action_name: str,
    exc: Exception,
    connection: dict[str, Any] | None = None,
) -> dict[str, Any]:
    details = _build_error_details(exc)
    return _standard_response(
        success=False,
        data={
            "error_message": details["message"],
            "guidance": details["guidance"],
            "error_details": details,
            "connection": connection,
        },
        error=details["message"],
        action_name=action_name,
        connection=connection,
        api_method=details.get("api_method"),
        error_details=details,
    )


def _parse_reply_markup(reply_markup: str | None) -> dict[str, Any] | None:
    if not reply_markup or not reply_markup.strip():
        return None
    try:
        parsed = json.loads(reply_markup)
    except json.JSONDecodeError as exc:
        raise ValueError(f"reply_markup must be valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("reply_markup JSON must be an object (InlineKeyboardMarkup)")
    return parsed


def _build_send_message_params(
    chat_id: str,
    text: str,
    *,
    parse_mode: str | None = None,
    disable_notification: bool | None = None,
    disable_web_page_preview: bool | None = None,
    reply_to_message_id: int | None = None,
    reply_markup: str | None = None,
    message_thread_id: int | None = None,
    protect_content: bool | None = None,
    allow_sending_without_reply: bool | None = None,
) -> dict[str, Any]:
    if not text or not text.strip():
        raise ValueError("text is required")
    params: dict[str, Any] = {"chat_id": chat_id, "text": text}
    mode = _resolve_parse_mode(parse_mode)
    if mode:
        params["parse_mode"] = mode
    markup = _parse_reply_markup(reply_markup)
    if markup:
        params["reply_markup"] = markup
    return _apply_optional_params(
        params,
        disable_notification=disable_notification,
        disable_web_page_preview=disable_web_page_preview,
        reply_to_message_id=reply_to_message_id,
        message_thread_id=message_thread_id,
        protect_content=protect_content,
        allow_sending_without_reply=allow_sending_without_reply,
    )


# ---------------------------------------------------------------------------
# Phase 1 — Connectivity & outbound messaging
# ---------------------------------------------------------------------------


@registry.register(
    default_title="Test Connectivity",
    description=(
        "Verify Telegram Bot token via getMe. Returns bot id, username, and connection info."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#getme",
)
async def test_connectivity(
    include_webhook_info: Annotated[
        bool, Doc("Also call getWebhookInfo and include webhook summary in output.")
    ] = False,
) -> dict[str, Any]:
    action_name = "test_connectivity"
    connection = _build_connection_spec()
    try:
        result = await _telegram_request("getMe", timeout=10.0)
        data: dict[str, Any] = {
            "connected": True,
            "bot_id": result.get("id"),
            "bot_username": result.get("username"),
            "bot_first_name": result.get("first_name"),
            "bot_is_bot": result.get("is_bot"),
            "can_join_groups": result.get("can_join_groups"),
            "can_read_all_group_messages": result.get("can_read_all_group_messages"),
            "supports_inline_queries": result.get("supports_inline_queries"),
            "telegram": {"api_method": "getMe"},
        }
        if include_webhook_info:
            webhook = await _telegram_request("getWebhookInfo", timeout=10.0)
            data["webhook"] = {
                "active": bool(webhook.get("url")),
                "url": webhook.get("url") or "",
                "pending_update_count": webhook.get("pending_update_count"),
                "last_error_message": webhook.get("last_error_message"),
            }
        return _standard_response(
            success=True,
            data=data,
            action_name=action_name,
            connection=connection,
            api_method="getMe",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Get Webhook Info",
    description=(
        "Return current webhook configuration (getWebhookInfo). "
        "Use to check whether inbound uses webhook or polling."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#getwebhookinfo",
)
async def get_webhook_info() -> dict[str, Any]:
    action_name = "get_webhook_info"
    connection = _build_connection_spec()
    try:
        result = await _telegram_request("getWebhookInfo", timeout=10.0)
        return _standard_response(
            success=True,
            data={
                "url": result.get("url") or "",
                "has_custom_certificate": result.get("has_custom_certificate"),
                "pending_update_count": result.get("pending_update_count"),
                "last_error_date": result.get("last_error_date"),
                "last_error_message": result.get("last_error_message"),
                "max_connections": result.get("max_connections"),
                "allowed_updates": result.get("allowed_updates"),
                "webhook_active": bool(result.get("url")),
                "inbound_mode": "webhook" if result.get("url") else "polling_or_none",
                "telegram": {"api_method": "getWebhookInfo"},
            },
            action_name=action_name,
            connection=connection,
            api_method="getWebhookInfo",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Send Message",
    description=(
        "Send a text message to a Telegram user, group, supergroup, or channel "
        "via sendMessage."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#sendmessage",
)
async def send_message(
    text: Annotated[str, Doc("Message text (1–4096 characters).")],
    chat_id: Annotated[str | None, Doc("Target chat_id or @channelusername. Uses secret default if omitted.")] = None,
    parse_mode: Annotated[str | None, Doc("HTML, MarkdownV2, or Markdown. Uses secret default if omitted.")] = None,
    disable_notification: Annotated[bool | None, Doc("Send silently when true.")] = None,
    disable_web_page_preview: Annotated[bool | None, Doc("Disable link preview when true.")] = None,
    reply_to_message_id: Annotated[int | None, Doc("Reply to an existing message id.")] = None,
    reply_markup: Annotated[str | None, Doc("JSON InlineKeyboardMarkup for buttons (optional).")] = None,
    message_thread_id: Annotated[int | None, Doc("Forum topic thread id (supergroup with topics).")] = None,
    protect_content: Annotated[bool | None, Doc("Prevent forwarding/saving when true.")] = None,
    allow_sending_without_reply: Annotated[bool | None, Doc("Send even if replied-to message missing.")] = None,
) -> dict[str, Any]:
    action_name = "send_message"
    connection = _build_connection_spec()
    try:
        target = _resolve_chat_id(chat_id)
        mode = _resolve_parse_mode(parse_mode)
        params = _build_send_message_params(
            target,
            text,
            parse_mode=parse_mode,
            disable_notification=disable_notification,
            disable_web_page_preview=disable_web_page_preview,
            reply_to_message_id=reply_to_message_id,
            reply_markup=reply_markup,
            message_thread_id=message_thread_id,
            protect_content=protect_content,
            allow_sending_without_reply=allow_sending_without_reply,
        )
        result = await _telegram_request("sendMessage", params)
        return _standard_response(
            success=True,
            data=_build_send_success_data(
                result,
                chat_id_used=target,
                api_method="sendMessage",
                inputs_resolved={
                    "chat_id": target,
                    "parse_mode": mode,
                    "text_length": len(text),
                    "disable_notification": disable_notification,
                    "message_thread_id": message_thread_id,
                },
            ),
            action_name=action_name,
            connection=connection,
            api_method="sendMessage",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Send Message to Channel",
    description=(
        "Send a text post to a Telegram channel. Bot must be channel admin with "
        "post_messages. Validates chat type when possible."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#sendmessage",
)
async def send_message_to_channel(
    text: Annotated[str, Doc("Channel post text (HTML recommended for SOC alerts).")],
    chat_id: Annotated[str | None, Doc("Channel @username or numeric id. Uses secret default if omitted.")] = None,
    parse_mode: Annotated[str | None, Doc("Parse mode (default from secret or HTML).")] = None,
    disable_notification: Annotated[bool | None, Doc("Send silently when true.")] = None,
    validate_channel: Annotated[bool, Doc("Call getChat to verify target is a channel.")] = True,
    message_thread_id: Annotated[int | None, Doc("Forum topic id if channel has topics enabled.")] = None,
    protect_content: Annotated[bool | None, Doc("Prevent forwarding/saving when true.")] = None,
) -> dict[str, Any]:
    action_name = "send_message_to_channel"
    connection = _build_connection_spec()
    try:
        target = _resolve_chat_id(chat_id)
        channel_info: dict[str, Any] | None = None
        if validate_channel:
            chat = await _telegram_request("getChat", {"chat_id": target})
            if chat.get("type") != "channel":
                raise ValueError(
                    f"Target chat type is '{chat.get('type')}', expected 'channel'. "
                    "Use send_message for groups/users."
                )
            channel_info = {
                "id": chat.get("id"),
                "title": chat.get("title"),
                "username": chat.get("username"),
                "type": chat.get("type"),
                "description": chat.get("description"),
                "linked_chat_id": chat.get("linked_chat_id"),
            }

        mode = _resolve_parse_mode(parse_mode) or "HTML"
        params = _build_send_message_params(
            target,
            text,
            parse_mode=mode,
            disable_notification=disable_notification,
            message_thread_id=message_thread_id,
            protect_content=protect_content,
        )
        result = await _telegram_request("sendMessage", params)
        extra = {"channel": channel_info} if channel_info else {}
        return _standard_response(
            success=True,
            data=_build_send_success_data(
                result,
                chat_id_used=target,
                api_method="sendMessage",
                target_type="channel",
                inputs_resolved={
                    "chat_id": target,
                    "parse_mode": mode,
                    "validate_channel": validate_channel,
                },
                extra=extra,
            ),
            action_name=action_name,
            connection=connection,
            api_method="sendMessage",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Send Message to User",
    description=(
        "Send a direct message to a Telegram user. User must have started the bot (/start) first."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#sendmessage",
)
async def send_message_to_user(
    text: Annotated[str, Doc("DM text to send.")],
    chat_id: Annotated[str | None, Doc("User chat id (positive integer). Required unless secret default is a user id.")] = None,
    parse_mode: Annotated[str | None, Doc("Parse mode.")] = None,
    disable_notification: Annotated[bool | None, Doc("Send silently when true.")] = None,
    protect_content: Annotated[bool | None, Doc("Prevent forwarding/saving when true.")] = None,
    reply_to_message_id: Annotated[int | None, Doc("Reply to an existing message id.")] = None,
) -> dict[str, Any]:
    action_name = "send_message_to_user"
    connection = _build_connection_spec()
    try:
        target = _resolve_chat_id(chat_id)
        try:
            numeric = int(target)
            if numeric <= 0:
                raise ValueError(
                    "send_message_to_user expects a private user chat_id (positive integer). "
                    "For channels use send_message_to_channel."
                )
        except ValueError as exc:
            if "positive integer" in str(exc):
                raise
            raise ValueError(
                "send_message_to_user requires numeric user chat_id, not @username."
            ) from exc

        mode = _resolve_parse_mode(parse_mode)
        params = _build_send_message_params(
            target,
            text,
            parse_mode=parse_mode,
            disable_notification=disable_notification,
            protect_content=protect_content,
            reply_to_message_id=reply_to_message_id,
        )
        result = await _telegram_request("sendMessage", params)
        return _standard_response(
            success=True,
            data=_build_send_success_data(
                result,
                chat_id_used=target,
                api_method="sendMessage",
                target_type="private",
                inputs_resolved={"chat_id": target, "parse_mode": mode},
            ),
            action_name=action_name,
            connection=connection,
            api_method="sendMessage",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Send Photo",
    description=(
        "Send a photo via sendPhoto using a public URL, existing file_id, or base64 upload."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#sendphoto",
)
async def send_photo(
    chat_id: Annotated[str | None, Doc("Target chat. Uses secret default if omitted.")] = None,
    photo_url: Annotated[str | None, Doc("HTTPS URL of the photo.")] = None,
    photo_file_id: Annotated[str | None, Doc("Existing Telegram file_id.")] = None,
    photo_base64: Annotated[str | None, Doc("Base64-encoded image bytes for upload.")] = None,
    photo_filename: Annotated[str | None, Doc("Filename when using photo_base64 (default: photo.jpg).")] = None,
    caption: Annotated[str | None, Doc("Optional caption (0–1024 chars).")] = None,
    parse_mode: Annotated[str | None, Doc("Caption parse mode.")] = None,
    disable_notification: Annotated[bool | None, Doc("Send silently when true.")] = None,
    has_spoiler: Annotated[bool | None, Doc("Cover photo with spoiler animation.")] = None,
    show_caption_above_media: Annotated[bool | None, Doc("Show caption above the photo.")] = None,
    message_thread_id: Annotated[int | None, Doc("Forum topic thread id.")] = None,
    protect_content: Annotated[bool | None, Doc("Prevent forwarding/saving when true.")] = None,
    reply_to_message_id: Annotated[int | None, Doc("Reply to an existing message id.")] = None,
) -> dict[str, Any]:
    action_name = "send_photo"
    connection = _build_connection_spec()
    try:
        target = _resolve_chat_id(chat_id)
        params: dict[str, Any] = {"chat_id": target}
        files = None
        source_type: str

        if photo_url and photo_url.strip():
            params["photo"] = photo_url.strip()
            source_type = "url"
        elif photo_file_id and photo_file_id.strip():
            params["photo"] = photo_file_id.strip()
            source_type = "file_id"
        elif photo_base64 and photo_base64.strip():
            raw = base64.b64decode(photo_base64.strip(), validate=True)
            name = (photo_filename or "photo.jpg").strip() or "photo.jpg"
            files = {"photo": (name, BytesIO(raw), "application/octet-stream")}
            source_type = "base64"
        else:
            raise ValueError("Provide exactly one of photo_url, photo_file_id, or photo_base64")

        mode = _resolve_parse_mode(parse_mode)
        if caption:
            params["caption"] = caption
        if mode and caption:
            params["parse_mode"] = mode
        _apply_optional_params(
            params,
            disable_notification=disable_notification,
            has_spoiler=has_spoiler,
            show_caption_above_media=show_caption_above_media,
            message_thread_id=message_thread_id,
            protect_content=protect_content,
            reply_to_message_id=reply_to_message_id,
        )

        result = await _telegram_request("sendPhoto", params, files=files)
        return _standard_response(
            success=True,
            data=_build_send_success_data(
                result,
                chat_id_used=target,
                api_method="sendPhoto",
                inputs_resolved={
                    "chat_id": target,
                    "photo_source": source_type,
                    "has_caption": bool(caption),
                },
            ),
            action_name=action_name,
            connection=connection,
            api_method="sendPhoto",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Send Document",
    description=(
        "Send a document (PDF, CSV, etc.) via sendDocument using URL, file_id, or base64 upload."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#senddocument",
)
async def send_document(
    chat_id: Annotated[str | None, Doc("Target chat. Uses secret default if omitted.")] = None,
    document_url: Annotated[str | None, Doc("HTTPS URL of the document.")] = None,
    document_file_id: Annotated[str | None, Doc("Existing Telegram file_id.")] = None,
    document_base64: Annotated[str | None, Doc("Base64-encoded file for upload.")] = None,
    document_filename: Annotated[str | None, Doc("Filename when using document_base64 (required for upload).")] = None,
    caption: Annotated[str | None, Doc("Optional caption.")] = None,
    parse_mode: Annotated[str | None, Doc("Caption parse mode.")] = None,
    disable_notification: Annotated[bool | None, Doc("Send silently when true.")] = None,
    disable_content_type_detection: Annotated[bool | None, Doc("Force send as document without MIME sniffing.")] = None,
    message_thread_id: Annotated[int | None, Doc("Forum topic thread id.")] = None,
    protect_content: Annotated[bool | None, Doc("Prevent forwarding/saving when true.")] = None,
    reply_to_message_id: Annotated[int | None, Doc("Reply to an existing message id.")] = None,
) -> dict[str, Any]:
    action_name = "send_document"
    connection = _build_connection_spec()
    try:
        target = _resolve_chat_id(chat_id)
        params: dict[str, Any] = {"chat_id": target}
        files = None
        source_type: str

        if document_url and document_url.strip():
            params["document"] = document_url.strip()
            source_type = "url"
        elif document_file_id and document_file_id.strip():
            params["document"] = document_file_id.strip()
            source_type = "file_id"
        elif document_base64 and document_base64.strip():
            if not document_filename or not document_filename.strip():
                raise ValueError("document_filename is required when using document_base64")
            raw = base64.b64decode(document_base64.strip(), validate=True)
            name = document_filename.strip()
            files = {"document": (name, BytesIO(raw), "application/octet-stream")}
            source_type = "base64"
        else:
            raise ValueError(
                "Provide exactly one of document_url, document_file_id, or document_base64"
            )

        mode = _resolve_parse_mode(parse_mode)
        if caption:
            params["caption"] = caption
        if mode and caption:
            params["parse_mode"] = mode
        _apply_optional_params(
            params,
            disable_notification=disable_notification,
            disable_content_type_detection=disable_content_type_detection,
            message_thread_id=message_thread_id,
            protect_content=protect_content,
            reply_to_message_id=reply_to_message_id,
        )

        result = await _telegram_request("sendDocument", params, files=files)
        return _standard_response(
            success=True,
            data=_build_send_success_data(
                result,
                chat_id_used=target,
                api_method="sendDocument",
                inputs_resolved={
                    "chat_id": target,
                    "document_source": source_type,
                    "document_filename": document_filename,
                },
            ),
            action_name=action_name,
            connection=connection,
            api_method="sendDocument",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Send Media Group",
    description=(
        "Send 2–10 photos or documents as an album via sendMediaGroup. "
        "media_json: JSON array of InputMedia objects."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#sendmediagroup",
)
async def send_media_group(
    media_json: Annotated[str, Doc("JSON array of InputMediaPhoto/InputMediaDocument objects (2–10 items).")],
    chat_id: Annotated[str | None, Doc("Target chat. Uses secret default if omitted.")] = None,
    disable_notification: Annotated[bool | None, Doc("Send silently when true.")] = None,
    message_thread_id: Annotated[int | None, Doc("Forum topic thread id.")] = None,
    protect_content: Annotated[bool | None, Doc("Prevent forwarding/saving when true.")] = None,
) -> dict[str, Any]:
    action_name = "send_media_group"
    connection = _build_connection_spec()
    try:
        try:
            media = json.loads(media_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"media_json must be valid JSON array: {exc}") from exc
        if not isinstance(media, list):
            raise ValueError("media_json must be a JSON array")
        if len(media) < 2 or len(media) > 10:
            raise ValueError("media_json must contain 2 to 10 media items")

        target = _resolve_chat_id(chat_id)
        params: dict[str, Any] = {"chat_id": target, "media": media}
        _apply_optional_params(
            params,
            disable_notification=disable_notification,
            message_thread_id=message_thread_id,
            protect_content=protect_content,
        )

        result = await _telegram_request("sendMediaGroup", params)
        messages = [_message_detail(item) for item in result] if isinstance(result, list) else []
        return _standard_response(
            success=True,
            data={
                "messages": messages,
                "count": len(messages),
                "chat_id_used": target,
                "message_ids": [m.get("message_id") for m in messages],
                "telegram": {"api_method": "sendMediaGroup"},
                "inputs_resolved": {
                    "chat_id": target,
                    "media_count": len(media),
                },
            },
            action_name=action_name,
            connection=connection,
            api_method="sendMediaGroup",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)
