"""SOCLib Telegram Bot API — phases 2–4 (read, interact, webhook, advanced).

UDF namespace: integrations.soclib.telegram
YAML templates: tools.soclib.telegram
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from typing_extensions import Doc

from custom_actions.telegram import (
    ACTION_NAMESPACE,
    DISPLAY_GROUP,
    _action_error,
    _apply_optional_params,
    _build_connection_spec,
    _build_send_success_data,
    _get_secret,
    _message_detail,
    _parse_reply_markup,
    _resolve_chat_id,
    _resolve_parse_mode,
    _standard_response,
    _telegram_request,
    registry,
    telegram_secret,
)


def _chat_summary(chat: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": chat.get("id"),
        "type": chat.get("type"),
        "title": chat.get("title"),
        "username": chat.get("username"),
        "first_name": chat.get("first_name"),
        "last_name": chat.get("last_name"),
        "description": chat.get("description"),
        "invite_link": chat.get("invite_link"),
        "linked_chat_id": chat.get("linked_chat_id"),
        "is_forum": chat.get("is_forum"),
        "has_protected_content": chat.get("has_protected_content"),
        "has_visible_history": chat.get("has_visible_history"),
        "active_usernames": chat.get("active_usernames"),
    }


def _member_summary(member: dict[str, Any]) -> dict[str, Any]:
    user = member.get("user") or {}
    return {
        "status": member.get("status"),
        "user_id": user.get("id"),
        "username": user.get("username"),
        "first_name": user.get("first_name"),
        "last_name": user.get("last_name"),
        "is_bot": user.get("is_bot"),
        "can_be_edited": member.get("can_be_edited"),
        "can_post_messages": member.get("can_post_messages"),
        "can_edit_messages": member.get("can_edit_messages"),
        "can_delete_messages": member.get("can_delete_messages"),
        "can_manage_chat": member.get("can_manage_chat"),
        "can_restrict_members": member.get("can_restrict_members"),
        "can_promote_members": member.get("can_promote_members"),
        "can_change_info": member.get("can_change_info"),
        "can_invite_users": member.get("can_invite_users"),
        "can_pin_messages": member.get("can_pin_messages"),
        "is_anonymous": member.get("is_anonymous"),
        "custom_title": member.get("custom_title"),
        "until_date": member.get("until_date"),
    }


def _parse_update_object(update: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Telegram Update object for Kopal workflows."""
    update_id = update.get("update_id")
    parsed: dict[str, Any] = {
        "update_id": update_id,
        "type": "unknown",
        "chat_id": None,
        "chat_type": None,
        "text": None,
        "callback_data": None,
        "callback_query_id": None,
        "message_id": None,
        "from_user_id": None,
        "from_username": None,
    }

    if "callback_query" in update:
        cq = update["callback_query"]
        msg = cq.get("message") or {}
        chat = msg.get("chat") or {}
        from_user = cq.get("from") or {}
        parsed.update(
            {
                "type": "callback_query",
                "chat_id": chat.get("id"),
                "chat_type": chat.get("type"),
                "text": msg.get("text") or msg.get("caption"),
                "callback_data": cq.get("data"),
                "callback_query_id": cq.get("id"),
                "message_id": msg.get("message_id"),
                "from_user_id": from_user.get("id"),
                "from_username": from_user.get("username"),
                "inline_message_id": cq.get("inline_message_id"),
                "message": _message_detail(msg) if msg else None,
                "chat": _chat_summary(chat) if chat else None,
            }
        )
        return parsed

    for key, update_type in (
        ("message", "message"),
        ("edited_message", "edited_message"),
        ("channel_post", "channel_post"),
        ("edited_channel_post", "edited_channel_post"),
    ):
        if key not in update:
            continue
        msg = update[key]
        chat = msg.get("chat") or {}
        from_user = msg.get("from") or {}
        parsed.update(
            {
                "type": update_type,
                "chat_id": chat.get("id"),
                "chat_type": chat.get("type"),
                "text": msg.get("text") or msg.get("caption"),
                "message_id": msg.get("message_id"),
                "from_user_id": from_user.get("id"),
                "from_username": from_user.get("username"),
                "message": _message_detail(msg),
                "chat": _chat_summary(chat),
            }
        )
        return parsed

    for key in (
        "inline_query",
        "chosen_inline_result",
        "shipping_query",
        "pre_checkout_query",
        "poll",
        "poll_answer",
        "my_chat_member",
        "chat_member",
        "chat_join_request",
    ):
        if key in update:
            parsed["type"] = key
            parsed["raw"] = update.get(key)
            return parsed

    return parsed


def _build_inline_keyboard(keyboard_json: str) -> dict[str, Any]:
    if not keyboard_json or not keyboard_json.strip():
        raise ValueError("inline_keyboard_json is required")
    try:
        parsed = json.loads(keyboard_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"inline_keyboard_json must be valid JSON: {exc}") from exc

    if isinstance(parsed, dict):
        if "inline_keyboard" in parsed:
            return parsed
        raise ValueError(
            "inline_keyboard_json object must contain inline_keyboard "
            "or pass a JSON array of button rows"
        )
    if isinstance(parsed, list):
        return {"inline_keyboard": parsed}
    raise ValueError(
        "inline_keyboard_json must be a JSON array of button rows or InlineKeyboardMarkup"
    )


def _parse_json_array(value: str | None, field_name: str) -> list[Any] | None:
    if value is None or not value.strip():
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{field_name} must be valid JSON array: {exc}") from exc
    if not isinstance(parsed, list):
        raise ValueError(f"{field_name} must be a JSON array")
    return parsed


def _parse_poll_options(options: str) -> list[str]:
    trimmed = options.strip()
    if trimmed.startswith("["):
        parsed = _parse_json_array(trimmed, "options")
        if not parsed:
            raise ValueError("options must contain at least 2 poll choices")
        return [str(item) for item in parsed]
    items = [part.strip() for part in trimmed.split(",") if part.strip()]
    if len(items) < 2:
        raise ValueError("options must contain at least 2 poll choices")
    return items


# ---------------------------------------------------------------------------
# Phase 2 — Read, message management, interaction
# ---------------------------------------------------------------------------


@registry.register(
    default_title="Get Updates",
    description=(
        "Fetch pending updates via getUpdates (long polling). "
        "Use to discover chat_id or diagnose inbound when webhook is not set."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#getupdates",
)
async def get_updates(
    offset: Annotated[int | None, Doc("Identifier of the first update to return.")] = None,
    limit: Annotated[int | None, Doc("Limits the number of updates (1–100).")] = None,
    timeout: Annotated[int | None, Doc("Long polling timeout in seconds.")] = None,
    allowed_updates: Annotated[
        str | None, Doc("JSON array of update types to receive (optional).")
    ] = None,
) -> dict[str, Any]:
    action_name = "get_updates"
    connection = _build_connection_spec()
    try:
        params: dict[str, Any] = {}
        allowed = _parse_json_array(allowed_updates, "allowed_updates")
        _apply_optional_params(
            params,
            offset=offset,
            limit=limit,
            timeout=timeout,
            allowed_updates=allowed,
        )
        result = await _telegram_request("getUpdates", params or None, timeout=35.0)
        updates = result if isinstance(result, list) else []
        parsed_updates = [_parse_update_object(item) for item in updates]
        chat_ids = sorted(
            {u["chat_id"] for u in parsed_updates if u.get("chat_id") is not None}
        )
        return _standard_response(
            success=True,
            data={
                "updates": parsed_updates,
                "count": len(parsed_updates),
                "chat_ids_found": chat_ids,
                "telegram": {"api_method": "getUpdates"},
                "inputs_resolved": {
                    "offset": offset,
                    "limit": limit,
                    "timeout": timeout,
                    "allowed_updates": allowed,
                },
            },
            action_name=action_name,
            connection=connection,
            api_method="getUpdates",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Get Chat",
    description="Return chat metadata (title, type, username) via getChat.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#getchat",
)
async def get_chat(
    chat_id: Annotated[
        str | None, Doc("Chat id or @channelusername. Uses secret default if omitted.")
    ] = None,
) -> dict[str, Any]:
    action_name = "get_chat"
    connection = _build_connection_spec()
    try:
        target = _resolve_chat_id(chat_id)
        result = await _telegram_request("getChat", {"chat_id": target})
        return _standard_response(
            success=True,
            data={
                "chat": _chat_summary(result),
                "chat_id_used": target,
                "telegram": {"api_method": "getChat"},
                "inputs_resolved": {"chat_id": target},
            },
            action_name=action_name,
            connection=connection,
            api_method="getChat",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Get Chat Member",
    description=(
        "Return a chat member record via getChatMember. "
        "Use to verify bot admin status in a channel."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#getchatmember",
)
async def get_chat_member(
    user_id: Annotated[int, Doc("Telegram user id to look up in the chat.")],
    chat_id: Annotated[
        str | None, Doc("Chat id or @channelusername. Uses secret default if omitted.")
    ] = None,
) -> dict[str, Any]:
    action_name = "get_chat_member"
    connection = _build_connection_spec()
    try:
        target = _resolve_chat_id(chat_id)
        result = await _telegram_request(
            "getChatMember", {"chat_id": target, "user_id": user_id}
        )
        member = _member_summary(result)
        return _standard_response(
            success=True,
            data={
                "member": member,
                "chat_id_used": target,
                "is_administrator": member.get("status") == "administrator",
                "is_creator": member.get("status") == "creator",
                "telegram": {"api_method": "getChatMember"},
                "inputs_resolved": {"chat_id": target, "user_id": user_id},
            },
            action_name=action_name,
            connection=connection,
            api_method="getChatMember",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Get Chat Member Count",
    description="Return member count for a group, supergroup, or channel.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#getchatmembercount",
)
async def get_chat_member_count(
    chat_id: Annotated[
        str | None, Doc("Chat id or @channelusername. Uses secret default if omitted.")
    ] = None,
) -> dict[str, Any]:
    action_name = "get_chat_member_count"
    connection = _build_connection_spec()
    try:
        target = _resolve_chat_id(chat_id)
        result = await _telegram_request("getChatMemberCount", {"chat_id": target})
        return _standard_response(
            success=True,
            data={
                "member_count": result,
                "chat_id_used": target,
                "telegram": {"api_method": "getChatMemberCount"},
                "inputs_resolved": {"chat_id": target},
            },
            action_name=action_name,
            connection=connection,
            api_method="getChatMemberCount",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Edit Message Text",
    description="Edit text of an existing message via editMessageText.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#editmessagetext",
)
async def edit_message_text(
    text: Annotated[str, Doc("New message text (1–4096 characters).")],
    chat_id: Annotated[
        str | None, Doc("Target chat. Required unless inline_message_id is set.")
    ] = None,
    message_id: Annotated[int | None, Doc("Message id to edit in chat.")] = None,
    inline_message_id: Annotated[
        str | None, Doc("Inline message id (alternative to chat_id + message_id).")
    ] = None,
    parse_mode: Annotated[str | None, Doc("HTML, MarkdownV2, or Markdown.")] = None,
    disable_web_page_preview: Annotated[bool | None, Doc("Disable link preview.")] = None,
    reply_markup: Annotated[str | None, Doc("JSON InlineKeyboardMarkup (optional).")] = None,
) -> dict[str, Any]:
    action_name = "edit_message_text"
    connection = _build_connection_spec()
    try:
        if not text or not text.strip():
            raise ValueError("text is required")
        mode = _resolve_parse_mode(parse_mode)
        params: dict[str, Any] = {"text": text}
        target: str | None = None

        if inline_message_id and inline_message_id.strip():
            params["inline_message_id"] = inline_message_id.strip()
        else:
            if message_id is None:
                raise ValueError(
                    "message_id is required when inline_message_id is omitted"
                )
            target = _resolve_chat_id(chat_id)
            params["chat_id"] = target
            params["message_id"] = message_id

        if mode:
            params["parse_mode"] = mode
        markup = _parse_reply_markup(reply_markup)
        if markup:
            params["reply_markup"] = markup
        _apply_optional_params(params, disable_web_page_preview=disable_web_page_preview)

        result = await _telegram_request("editMessageText", params)
        data: dict[str, Any] = {
            "edited": True,
            "chat_id_used": target,
            "telegram": {"api_method": "editMessageText"},
            "inputs_resolved": {
                "chat_id": target,
                "message_id": message_id,
                "inline_message_id": inline_message_id,
                "parse_mode": mode,
                "text_length": len(text),
            },
        }
        if isinstance(result, dict):
            data["message"] = _message_detail(result)
        else:
            data["result"] = result
        return _standard_response(
            success=True,
            data=data,
            action_name=action_name,
            connection=connection,
            api_method="editMessageText",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Delete Message",
    description="Delete a message via deleteMessage.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#deletemessage",
)
async def delete_message(
    message_id: Annotated[int, Doc("Message id to delete.")],
    chat_id: Annotated[
        str | None, Doc("Target chat. Uses secret default if omitted.")
    ] = None,
) -> dict[str, Any]:
    action_name = "delete_message"
    connection = _build_connection_spec()
    try:
        target = _resolve_chat_id(chat_id)
        result = await _telegram_request(
            "deleteMessage", {"chat_id": target, "message_id": message_id}
        )
        return _standard_response(
            success=True,
            data={
                "deleted": bool(result),
                "message_id": message_id,
                "chat_id_used": target,
                "telegram": {"api_method": "deleteMessage"},
                "inputs_resolved": {"chat_id": target, "message_id": message_id},
            },
            action_name=action_name,
            connection=connection,
            api_method="deleteMessage",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Pin Chat Message",
    description="Pin a message in a group, supergroup, or channel.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#pinchatmessage",
)
async def pin_chat_message(
    message_id: Annotated[int, Doc("Message id to pin.")],
    chat_id: Annotated[
        str | None, Doc("Target chat. Uses secret default if omitted.")
    ] = None,
    disable_notification: Annotated[bool | None, Doc("Pin silently when true.")] = None,
    message_thread_id: Annotated[int | None, Doc("Forum topic thread id.")] = None,
) -> dict[str, Any]:
    action_name = "pin_chat_message"
    connection = _build_connection_spec()
    try:
        target = _resolve_chat_id(chat_id)
        params: dict[str, Any] = {"chat_id": target, "message_id": message_id}
        _apply_optional_params(
            params,
            disable_notification=disable_notification,
            message_thread_id=message_thread_id,
        )
        result = await _telegram_request("pinChatMessage", params)
        return _standard_response(
            success=True,
            data={
                "pinned": bool(result),
                "message_id": message_id,
                "chat_id_used": target,
                "telegram": {"api_method": "pinChatMessage"},
                "inputs_resolved": {
                    "chat_id": target,
                    "message_id": message_id,
                    "disable_notification": disable_notification,
                },
            },
            action_name=action_name,
            connection=connection,
            api_method="pinChatMessage",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Unpin Chat Message",
    description=(
        "Unpin a specific message or all pinned messages via unpinChatMessage."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#unpinchatmessage",
)
async def unpin_chat_message(
    chat_id: Annotated[
        str | None, Doc("Target chat. Uses secret default if omitted.")
    ] = None,
    message_id: Annotated[
        int | None, Doc("Message id to unpin. Omit to unpin all pinned messages.")
    ] = None,
    message_thread_id: Annotated[int | None, Doc("Forum topic thread id.")] = None,
) -> dict[str, Any]:
    action_name = "unpin_chat_message"
    connection = _build_connection_spec()
    try:
        target = _resolve_chat_id(chat_id)
        params: dict[str, Any] = {"chat_id": target}
        _apply_optional_params(
            params,
            message_id=message_id,
            message_thread_id=message_thread_id,
        )
        result = await _telegram_request("unpinChatMessage", params)
        return _standard_response(
            success=True,
            data={
                "unpinned": bool(result),
                "message_id": message_id,
                "chat_id_used": target,
                "unpin_all": message_id is None,
                "telegram": {"api_method": "unpinChatMessage"},
                "inputs_resolved": {
                    "chat_id": target,
                    "message_id": message_id,
                    "message_thread_id": message_thread_id,
                },
            },
            action_name=action_name,
            connection=connection,
            api_method="unpinChatMessage",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Forward Message",
    description="Forward a message from one chat to another.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#forwardmessage",
)
async def forward_message(
    from_chat_id: Annotated[str, Doc("Source chat id or @username.")],
    message_id: Annotated[int, Doc("Message id in the source chat.")],
    chat_id: Annotated[
        str | None, Doc("Destination chat. Uses secret default if omitted.")
    ] = None,
    disable_notification: Annotated[bool | None, Doc("Forward silently when true.")] = None,
    message_thread_id: Annotated[int | None, Doc("Forum topic thread id.")] = None,
    protect_content: Annotated[bool | None, Doc("Prevent forwarding/saving when true.")] = None,
) -> dict[str, Any]:
    action_name = "forward_message"
    connection = _build_connection_spec()
    try:
        target = _resolve_chat_id(chat_id)
        params: dict[str, Any] = {
            "chat_id": target,
            "from_chat_id": from_chat_id.strip(),
            "message_id": message_id,
        }
        _apply_optional_params(
            params,
            disable_notification=disable_notification,
            message_thread_id=message_thread_id,
            protect_content=protect_content,
        )
        result = await _telegram_request("forwardMessage", params)
        return _standard_response(
            success=True,
            data=_build_send_success_data(
                result,
                chat_id_used=target,
                api_method="forwardMessage",
                inputs_resolved={
                    "chat_id": target,
                    "from_chat_id": from_chat_id.strip(),
                    "message_id": message_id,
                },
            ),
            action_name=action_name,
            connection=connection,
            api_method="forwardMessage",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Copy Message",
    description="Copy a message without the forward header via copyMessage.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#copymessage",
)
async def copy_message(
    from_chat_id: Annotated[str, Doc("Source chat id or @username.")],
    message_id: Annotated[int, Doc("Message id in the source chat.")],
    chat_id: Annotated[
        str | None, Doc("Destination chat. Uses secret default if omitted.")
    ] = None,
    caption: Annotated[str | None, Doc("New caption (optional).")] = None,
    parse_mode: Annotated[str | None, Doc("Caption parse mode.")] = None,
    disable_notification: Annotated[bool | None, Doc("Copy silently when true.")] = None,
    message_thread_id: Annotated[int | None, Doc("Forum topic thread id.")] = None,
    protect_content: Annotated[bool | None, Doc("Prevent forwarding/saving when true.")] = None,
    reply_to_message_id: Annotated[int | None, Doc("Reply to an existing message id.")] = None,
) -> dict[str, Any]:
    action_name = "copy_message"
    connection = _build_connection_spec()
    try:
        target = _resolve_chat_id(chat_id)
        mode = _resolve_parse_mode(parse_mode)
        params: dict[str, Any] = {
            "chat_id": target,
            "from_chat_id": from_chat_id.strip(),
            "message_id": message_id,
        }
        if caption:
            params["caption"] = caption
        if mode and caption:
            params["parse_mode"] = mode
        _apply_optional_params(
            params,
            disable_notification=disable_notification,
            message_thread_id=message_thread_id,
            protect_content=protect_content,
            reply_to_message_id=reply_to_message_id,
        )
        result = await _telegram_request("copyMessage", params)
        return _standard_response(
            success=True,
            data={
                "message_id": result,
                "chat_id_used": target,
                "telegram": {"api_method": "copyMessage", "message_id": result},
                "inputs_resolved": {
                    "chat_id": target,
                    "from_chat_id": from_chat_id.strip(),
                    "message_id": message_id,
                    "has_caption": bool(caption),
                },
            },
            action_name=action_name,
            connection=connection,
            api_method="copyMessage",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Send Chat Action",
    description=(
        "Show a chat action (typing, upload_photo, etc.) via sendChatAction. "
        "Useful UX hint before long-running workflow steps."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#sendchataction",
)
async def send_chat_action(
    action: Annotated[
        str,
        Doc(
            "Chat action: typing, upload_photo, record_video, upload_video, "
            "record_voice, upload_voice, upload_document, choose_sticker, "
            "find_location, record_video_note, upload_video_note."
        ),
    ],
    chat_id: Annotated[
        str | None, Doc("Target chat. Uses secret default if omitted.")
    ] = None,
    message_thread_id: Annotated[int | None, Doc("Forum topic thread id.")] = None,
) -> dict[str, Any]:
    action_name = "send_chat_action"
    connection = _build_connection_spec()
    try:
        target = _resolve_chat_id(chat_id)
        params: dict[str, Any] = {"chat_id": target, "action": action.strip()}
        _apply_optional_params(params, message_thread_id=message_thread_id)
        result = await _telegram_request("sendChatAction", params)
        return _standard_response(
            success=True,
            data={
                "sent": bool(result),
                "action": action.strip(),
                "chat_id_used": target,
                "telegram": {"api_method": "sendChatAction"},
                "inputs_resolved": {
                    "chat_id": target,
                    "action": action.strip(),
                    "message_thread_id": message_thread_id,
                },
            },
            action_name=action_name,
            connection=connection,
            api_method="sendChatAction",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Answer Callback Query",
    description=(
        "Respond to an inline keyboard callback_query. "
        "Required after user clicks Approve/Reject buttons."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#answercallbackquery",
)
async def answer_callback_query(
    callback_query_id: Annotated[str, Doc("callback_query.id from parse_update.")],
    text: Annotated[str | None, Doc("Notification text (0–200 characters).")] = None,
    show_alert: Annotated[bool | None, Doc("Show as alert popup when true.")] = None,
    url: Annotated[str | None, Doc("URL to open (optional).")] = None,
    cache_time: Annotated[int | None, Doc("Cache time in seconds for callback answer.")] = None,
) -> dict[str, Any]:
    action_name = "answer_callback_query"
    connection = _build_connection_spec()
    try:
        params: dict[str, Any] = {"callback_query_id": callback_query_id.strip()}
        _apply_optional_params(
            params,
            text=text,
            show_alert=show_alert,
            url=url,
            cache_time=cache_time,
        )
        result = await _telegram_request("answerCallbackQuery", params)
        return _standard_response(
            success=True,
            data={
                "answered": bool(result),
                "callback_query_id": callback_query_id.strip(),
                "telegram": {"api_method": "answerCallbackQuery"},
                "inputs_resolved": {
                    "callback_query_id": callback_query_id.strip(),
                    "has_text": bool(text),
                    "show_alert": show_alert,
                },
            },
            action_name=action_name,
            connection=connection,
            api_method="answerCallbackQuery",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Send Message With Inline Keyboard",
    description=(
        "Send a text message with inline keyboard buttons (Approve/Reject, etc.) "
        "via sendMessage."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#sendmessage",
)
async def send_message_with_inline_keyboard(
    text: Annotated[str, Doc("Message text (1–4096 characters).")],
    inline_keyboard_json: Annotated[
        str,
        Doc(
            "JSON array of button rows or full InlineKeyboardMarkup. "
            'Example: [[{"text":"Approve","callback_data":"approve"}]]'
        ),
    ],
    chat_id: Annotated[
        str | None, Doc("Target chat. Uses secret default if omitted.")
    ] = None,
    parse_mode: Annotated[str | None, Doc("HTML, MarkdownV2, or Markdown.")] = None,
    disable_notification: Annotated[bool | None, Doc("Send silently when true.")] = None,
    disable_web_page_preview: Annotated[bool | None, Doc("Disable link preview.")] = None,
    reply_to_message_id: Annotated[int | None, Doc("Reply to an existing message id.")] = None,
    message_thread_id: Annotated[int | None, Doc("Forum topic thread id.")] = None,
    protect_content: Annotated[bool | None, Doc("Prevent forwarding/saving when true.")] = None,
) -> dict[str, Any]:
    action_name = "send_message_with_inline_keyboard"
    connection = _build_connection_spec()
    try:
        if not text or not text.strip():
            raise ValueError("text is required")
        target = _resolve_chat_id(chat_id)
        mode = _resolve_parse_mode(parse_mode)
        params: dict[str, Any] = {
            "chat_id": target,
            "text": text,
            "reply_markup": _build_inline_keyboard(inline_keyboard_json),
        }
        if mode:
            params["parse_mode"] = mode
        _apply_optional_params(
            params,
            disable_notification=disable_notification,
            disable_web_page_preview=disable_web_page_preview,
            reply_to_message_id=reply_to_message_id,
            message_thread_id=message_thread_id,
            protect_content=protect_content,
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
                    "has_inline_keyboard": True,
                },
            ),
            action_name=action_name,
            connection=connection,
            api_method="sendMessage",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


# ---------------------------------------------------------------------------
# Phase 3 — Webhook & inbound parsing
# ---------------------------------------------------------------------------


@registry.register(
    default_title="Set Webhook",
    description=(
        "Register an HTTPS webhook URL for inbound updates via setWebhook. "
        "Uses TELEGRAM_WEBHOOK_SECRET from secret when secret_token is omitted."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#setwebhook",
)
async def set_webhook(
    url: Annotated[str, Doc("HTTPS webhook URL (Kopal webhook endpoint).")],
    secret_token: Annotated[
        str | None,
        Doc("X-Telegram-Bot-Api-Secret-Token value. Uses TELEGRAM_WEBHOOK_SECRET if omitted."),
    ] = None,
    drop_pending_updates: Annotated[
        bool | None, Doc("Drop pending updates when switching to webhook.")
    ] = None,
    max_connections: Annotated[int | None, Doc("Maximum allowed webhook connections (1–100).")] = None,
    allowed_updates: Annotated[
        str | None, Doc("JSON array of update types to receive.")
    ] = None,
    ip_address: Annotated[str | None, Doc("Fixed IP address for webhook (optional).")] = None,
) -> dict[str, Any]:
    action_name = "set_webhook"
    connection = _build_connection_spec()
    try:
        if not url or not url.strip():
            raise ValueError("url is required")
        token = (secret_token or "").strip() or _get_secret("TELEGRAM_WEBHOOK_SECRET") or None
        allowed = _parse_json_array(allowed_updates, "allowed_updates")
        params: dict[str, Any] = {"url": url.strip()}
        _apply_optional_params(
            params,
            secret_token=token,
            drop_pending_updates=drop_pending_updates,
            max_connections=max_connections,
            allowed_updates=allowed,
            ip_address=ip_address,
        )
        result = await _telegram_request("setWebhook", params)
        return _standard_response(
            success=True,
            data={
                "webhook_set": bool(result),
                "url": url.strip(),
                "secret_token_configured": bool(token),
                "telegram": {"api_method": "setWebhook"},
                "inputs_resolved": {
                    "url": url.strip(),
                    "drop_pending_updates": drop_pending_updates,
                    "max_connections": max_connections,
                    "allowed_updates": allowed,
                    "ip_address": ip_address,
                },
            },
            action_name=action_name,
            connection=connection,
            api_method="setWebhook",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Delete Webhook",
    description="Remove webhook and return to getUpdates polling via deleteWebhook.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#deletewebhook",
)
async def delete_webhook(
    drop_pending_updates: Annotated[
        bool | None, Doc("Drop pending updates when removing webhook.")
    ] = None,
) -> dict[str, Any]:
    action_name = "delete_webhook"
    connection = _build_connection_spec()
    try:
        params: dict[str, Any] = {}
        _apply_optional_params(params, drop_pending_updates=drop_pending_updates)
        result = await _telegram_request("deleteWebhook", params or None)
        return _standard_response(
            success=True,
            data={
                "webhook_deleted": bool(result),
                "inbound_mode": "polling_or_none",
                "telegram": {"api_method": "deleteWebhook"},
                "inputs_resolved": {"drop_pending_updates": drop_pending_updates},
            },
            action_name=action_name,
            connection=connection,
            api_method="deleteWebhook",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Parse Update",
    description=(
        "Normalize a Telegram Update JSON payload into workflow-friendly fields "
        "(type, chat_id, text, callback_data, callback_query_id)."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#update",
)
async def parse_update(
    update_json: Annotated[str, Doc("Raw Telegram Update object as JSON string.")],
) -> dict[str, Any]:
    action_name = "parse_update"
    connection = _build_connection_spec()
    try:
        try:
            update = json.loads(update_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"update_json must be valid JSON: {exc}") from exc
        if not isinstance(update, dict):
            raise ValueError("update_json must be a JSON object (Telegram Update)")
        parsed = _parse_update_object(update)
        return _standard_response(
            success=True,
            data={
                "update": parsed,
                "type": parsed.get("type"),
                "chat_id": parsed.get("chat_id"),
                "text": parsed.get("text"),
                "callback_data": parsed.get("callback_data"),
                "callback_query_id": parsed.get("callback_query_id"),
                "telegram": {"api_method": "parse_update"},
                "inputs_resolved": {"update_id": parsed.get("update_id")},
            },
            action_name=action_name,
            connection=connection,
            api_method="parse_update",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


# ---------------------------------------------------------------------------
# Phase 4 — Advanced outbound
# ---------------------------------------------------------------------------


@registry.register(
    default_title="Send Location",
    description="Send a geographic location via sendLocation.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#sendlocation",
)
async def send_location(
    latitude: Annotated[float, Doc("Latitude of the location.")],
    longitude: Annotated[float, Doc("Longitude of the location.")],
    chat_id: Annotated[
        str | None, Doc("Target chat. Uses secret default if omitted.")
    ] = None,
    horizontal_accuracy: Annotated[float | None, Doc("Location accuracy radius in meters.")] = None,
    live_period: Annotated[int | None, Doc("Live location period in seconds (60–86400).")] = None,
    heading: Annotated[int | None, Doc("Direction in degrees (1–360).")] = None,
    proximity_alert_radius: Annotated[int | None, Doc("Proximity alert radius in meters.")] = None,
    disable_notification: Annotated[bool | None, Doc("Send silently when true.")] = None,
    reply_to_message_id: Annotated[int | None, Doc("Reply to an existing message id.")] = None,
    message_thread_id: Annotated[int | None, Doc("Forum topic thread id.")] = None,
    protect_content: Annotated[bool | None, Doc("Prevent forwarding/saving when true.")] = None,
) -> dict[str, Any]:
    action_name = "send_location"
    connection = _build_connection_spec()
    try:
        target = _resolve_chat_id(chat_id)
        params: dict[str, Any] = {
            "chat_id": target,
            "latitude": latitude,
            "longitude": longitude,
        }
        _apply_optional_params(
            params,
            horizontal_accuracy=horizontal_accuracy,
            live_period=live_period,
            heading=heading,
            proximity_alert_radius=proximity_alert_radius,
            disable_notification=disable_notification,
            reply_to_message_id=reply_to_message_id,
            message_thread_id=message_thread_id,
            protect_content=protect_content,
        )
        result = await _telegram_request("sendLocation", params)
        return _standard_response(
            success=True,
            data=_build_send_success_data(
                result,
                chat_id_used=target,
                api_method="sendLocation",
                inputs_resolved={
                    "chat_id": target,
                    "latitude": latitude,
                    "longitude": longitude,
                },
            ),
            action_name=action_name,
            connection=connection,
            api_method="sendLocation",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Send Poll",
    description="Send a native poll via sendPoll (team vote / runbook confirmation).",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#sendpoll",
)
async def send_poll(
    question: Annotated[str, Doc("Poll question (1–300 characters).")],
    options: Annotated[
        str,
        Doc("Poll options as JSON array or comma-separated list (2–10 items)."),
    ],
    chat_id: Annotated[
        str | None, Doc("Target chat. Uses secret default if omitted.")
    ] = None,
    is_anonymous: Annotated[bool | None, Doc("Anonymous poll when true (default).")] = None,
    poll_type: Annotated[
        str | None, Doc("Poll type: quiz or regular (default regular).")
    ] = None,
    allows_multiple_answers: Annotated[bool | None, Doc("Allow multiple answers when true.")] = None,
    correct_option_id: Annotated[int | None, Doc("Correct option index for quiz polls.")] = None,
    explanation: Annotated[str | None, Doc("Quiz explanation shown after close.")] = None,
    explanation_parse_mode: Annotated[str | None, Doc("Parse mode for explanation.")] = None,
    open_period: Annotated[int | None, Doc("Poll auto-close period in seconds (5–600).")] = None,
    close_date: Annotated[int | None, Doc("Unix timestamp when poll closes.")] = None,
    disable_notification: Annotated[bool | None, Doc("Send silently when true.")] = None,
    message_thread_id: Annotated[int | None, Doc("Forum topic thread id.")] = None,
    protect_content: Annotated[bool | None, Doc("Prevent forwarding/saving when true.")] = None,
) -> dict[str, Any]:
    action_name = "send_poll"
    connection = _build_connection_spec()
    try:
        if not question or not question.strip():
            raise ValueError("question is required")
        option_list = _parse_poll_options(options)
        if len(option_list) > 10:
            raise ValueError("options must contain at most 10 poll choices")
        target = _resolve_chat_id(chat_id)
        params: dict[str, Any] = {
            "chat_id": target,
            "question": question.strip(),
            "options": option_list,
        }
        if poll_type:
            params["type"] = poll_type.strip()
        exp_mode = _resolve_parse_mode(explanation_parse_mode)
        if explanation and exp_mode:
            params["explanation_parse_mode"] = exp_mode
        _apply_optional_params(
            params,
            is_anonymous=is_anonymous,
            allows_multiple_answers=allows_multiple_answers,
            correct_option_id=correct_option_id,
            explanation=explanation,
            open_period=open_period,
            close_date=close_date,
            disable_notification=disable_notification,
            message_thread_id=message_thread_id,
            protect_content=protect_content,
        )
        result = await _telegram_request("sendPoll", params)
        poll_data = result.get("poll") or {} if isinstance(result, dict) else {}
        return _standard_response(
            success=True,
            data={
                "message": _message_detail(result) if isinstance(result, dict) else None,
                "poll_id": poll_data.get("id"),
                "question": poll_data.get("question") or question.strip(),
                "option_count": len(option_list),
                "chat_id_used": target,
                "telegram": {
                    "api_method": "sendPoll",
                    "message_id": result.get("message_id") if isinstance(result, dict) else None,
                },
                "inputs_resolved": {
                    "chat_id": target,
                    "question_length": len(question.strip()),
                    "option_count": len(option_list),
                    "poll_type": poll_type,
                },
            },
            action_name=action_name,
            connection=connection,
            api_method="sendPoll",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Send Contact",
    description="Share a phone contact via sendContact.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#sendcontact",
)
async def send_contact(
    phone_number: Annotated[str, Doc("Contact phone number in international format.")],
    first_name: Annotated[str, Doc("Contact first name.")],
    chat_id: Annotated[
        str | None, Doc("Target chat. Uses secret default if omitted.")
    ] = None,
    last_name: Annotated[str | None, Doc("Contact last name.")] = None,
    vcard: Annotated[str | None, Doc("Additional vCard data.")] = None,
    disable_notification: Annotated[bool | None, Doc("Send silently when true.")] = None,
    reply_to_message_id: Annotated[int | None, Doc("Reply to an existing message id.")] = None,
    message_thread_id: Annotated[int | None, Doc("Forum topic thread id.")] = None,
    protect_content: Annotated[bool | None, Doc("Prevent forwarding/saving when true.")] = None,
) -> dict[str, Any]:
    action_name = "send_contact"
    connection = _build_connection_spec()
    try:
        target = _resolve_chat_id(chat_id)
        params: dict[str, Any] = {
            "chat_id": target,
            "phone_number": phone_number.strip(),
            "first_name": first_name.strip(),
        }
        _apply_optional_params(
            params,
            last_name=last_name,
            vcard=vcard,
            disable_notification=disable_notification,
            reply_to_message_id=reply_to_message_id,
            message_thread_id=message_thread_id,
            protect_content=protect_content,
        )
        result = await _telegram_request("sendContact", params)
        return _standard_response(
            success=True,
            data=_build_send_success_data(
                result,
                chat_id_used=target,
                api_method="sendContact",
                inputs_resolved={
                    "chat_id": target,
                    "phone_number": phone_number.strip(),
                    "first_name": first_name.strip(),
                },
            ),
            action_name=action_name,
            connection=connection,
            api_method="sendContact",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Export Chat Invite Link",
    description=(
        "Generate a primary invite link for a chat via exportChatInviteLink. "
        "Bot must be an administrator with can_invite_users."
    ),
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#exportchatinvitelink",
)
async def export_chat_invite_link(
    chat_id: Annotated[
        str | None, Doc("Target chat. Uses secret default if omitted.")
    ] = None,
) -> dict[str, Any]:
    action_name = "export_chat_invite_link"
    connection = _build_connection_spec()
    try:
        target = _resolve_chat_id(chat_id)
        result = await _telegram_request("exportChatInviteLink", {"chat_id": target})
        return _standard_response(
            success=True,
            data={
                "invite_link": result,
                "chat_id_used": target,
                "telegram": {"api_method": "exportChatInviteLink"},
                "inputs_resolved": {"chat_id": target},
            },
            action_name=action_name,
            connection=connection,
            api_method="exportChatInviteLink",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Leave Chat",
    description="Remove the bot from a group, supergroup, or channel via leaveChat.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#leavechat",
)
async def leave_chat(
    chat_id: Annotated[
        str | None, Doc("Chat to leave. Uses secret default if omitted.")
    ] = None,
) -> dict[str, Any]:
    action_name = "leave_chat"
    connection = _build_connection_spec()
    try:
        target = _resolve_chat_id(chat_id)
        result = await _telegram_request("leaveChat", {"chat_id": target})
        return _standard_response(
            success=True,
            data={
                "left": bool(result),
                "chat_id_used": target,
                "telegram": {"api_method": "leaveChat"},
                "inputs_resolved": {"chat_id": target},
            },
            action_name=action_name,
            connection=connection,
            api_method="leaveChat",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)


@registry.register(
    default_title="Set My Commands",
    description="Configure bot command menu (/help, etc.) via setMyCommands.",
    display_group=DISPLAY_GROUP,
    namespace=ACTION_NAMESPACE,
    secrets=[telegram_secret],
    doc_url="https://core.telegram.org/bots/api#setmycommands",
)
async def set_my_commands(
    commands_json: Annotated[
        str,
        Doc(
            'JSON array of BotCommand objects, e.g. '
            '[{"command":"help","description":"Show help"}]'
        ),
    ],
    scope_json: Annotated[
        str | None, Doc("Optional JSON BotCommandScope object.")
    ] = None,
    language_code: Annotated[str | None, Doc("Two-letter ISO 639-1 language code.")] = None,
) -> dict[str, Any]:
    action_name = "set_my_commands"
    connection = _build_connection_spec()
    try:
        commands = _parse_json_array(commands_json, "commands_json")
        if not commands:
            raise ValueError("commands_json must contain at least one command")
        params: dict[str, Any] = {"commands": commands}
        if scope_json and scope_json.strip():
            try:
                scope = json.loads(scope_json)
            except json.JSONDecodeError as exc:
                raise ValueError(f"scope_json must be valid JSON: {exc}") from exc
            if not isinstance(scope, dict):
                raise ValueError("scope_json must be a JSON object (BotCommandScope)")
            params["scope"] = scope
        _apply_optional_params(params, language_code=language_code)
        result = await _telegram_request("setMyCommands", params)
        return _standard_response(
            success=True,
            data={
                "commands_set": bool(result),
                "command_count": len(commands),
                "telegram": {"api_method": "setMyCommands"},
                "inputs_resolved": {
                    "command_count": len(commands),
                    "language_code": language_code,
                    "has_scope": bool(scope_json and scope_json.strip()),
                },
            },
            action_name=action_name,
            connection=connection,
            api_method="setMyCommands",
        )
    except Exception as exc:
        return _action_error(action_name, exc, connection)
