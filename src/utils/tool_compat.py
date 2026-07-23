"""
src/utils/tool_compat.py
────────────────────────
Compatibility helpers for OpenAI-compatible backends that advertise tools but
sometimes return JSON/text instructions instead of structured tool_calls.
"""

from __future__ import annotations

from typing import Any, Iterable
from uuid import uuid4

from src.utils.json_parser import extract_json


def content_to_text(content: Any) -> str:
    """Flatten LangChain message content into plain text for JSON parsing."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            else:
                parts.append(str(item))
        return "\n".join(part for part in parts if part)
    return str(content or "")


def extract_tool_calls_from_content(
    content: Any,
    allowed_tools: Iterable[str],
    *,
    default_tool_name: str | None = None,
    default_args: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Parse tool intents from message content when the backend failed to populate
    response.tool_calls.

    Supported fallback formats:
    - {"tool": "run_shell", "args": {...}}
    - {"name": "search_cve", "arguments": {...}}
    - {"tool_calls": [{...}, {...}]}
    - {"executable": "<command>"} for legacy run_shell-style flows
    """
    allowed = set(allowed_tools)
    parsed = extract_json(content_to_text(content))
    if parsed is None:
        return []

    if isinstance(parsed, dict) and isinstance(parsed.get("tool_calls"), list):
        raw_calls = parsed["tool_calls"]
    elif isinstance(parsed, list):
        raw_calls = parsed
    else:
        raw_calls = [parsed]

    tool_calls: list[dict[str, Any]] = []
    for raw_call in raw_calls:
        normalized = _normalize_tool_call(
            raw_call,
            allowed,
            default_tool_name=default_tool_name,
            default_args=default_args,
        )
        if normalized:
            tool_calls.append(normalized)
    return tool_calls


def _normalize_tool_call(
    raw_call: Any,
    allowed_tools: set[str],
    *,
    default_tool_name: str | None,
    default_args: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not isinstance(raw_call, dict):
        return None

    name: str | None = None
    args: Any = None

    if isinstance(raw_call.get("function"), dict):
        fn = raw_call["function"]
        name = fn.get("name")
        args = fn.get("arguments")

    if not name:
        for key in ("tool", "tool_name", "name"):
            value = raw_call.get(key)
            if isinstance(value, str) and value.strip():
                name = value.strip()
                break

    if args is None:
        for key in ("args", "arguments", "parameters", "kwargs", "input"):
            if key in raw_call:
                args = raw_call[key]
                break

    if name is None and default_tool_name:
        command = raw_call.get("command") or raw_call.get("executable")
        if isinstance(command, str) and command.strip() and command.strip().lower() != "none":
            name = default_tool_name
            args = {"command": command.strip()}

    if name not in allowed_tools:
        return None

    normalized_args = _normalize_args(args)
    if default_args:
        for key, value in default_args.items():
            normalized_args.setdefault(key, value)

    if name == default_tool_name:
        command = normalized_args.get("command") or raw_call.get("command") or raw_call.get("executable")
        if not isinstance(command, str) or not command.strip() or command.strip().lower() == "none":
            return None
        normalized_args["command"] = command.strip()
        if "timeout" not in normalized_args and "timeout" in raw_call:
            normalized_args["timeout"] = raw_call["timeout"]
        if "mode" not in normalized_args and "mode" in raw_call:
            normalized_args["mode"] = raw_call["mode"]

    return {
        "id": f"compat-{uuid4()}",
        "name": name,
        "args": normalized_args,
    }


def _normalize_args(raw_args: Any) -> dict[str, Any]:
    if raw_args is None:
        return {}
    if isinstance(raw_args, dict):
        return dict(raw_args)
    if isinstance(raw_args, str):
        parsed = extract_json(raw_args)
        if isinstance(parsed, dict):
            return parsed
    return {}
