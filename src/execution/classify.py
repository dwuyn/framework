"""
Regex-first command output classification for deterministic execution.
"""

from __future__ import annotations

import re
from typing import Any

_GENERIC_SUCCESS = (
    "uid=",
    "root@",
    "www-data@",
    "meterpreter >",
    "flag{",
    "htb{",
    "access granted",
    "pwned",
    "session opened",
    "shell obtained",
    "remote code execution",
    "command executed",
)

_GENERIC_SUCCESS_PATTERNS = (
    r"session\s+\d+\s+opened",
    r"reverse shell",
    r"\bwhoami\b.*\n",
)

_PATTERNS = {
    "missing_dependency": [
        r"modulenotfounderror",
        r"no module named",
        r"importerror",
        r"command not found",
        r"is not installed",
        r"cannot import name",
    ],
    "syntax": [
        r"syntaxerror",
        r"unrecognized arguments",
        r"invalid choice",
        r"missing required (?:argument|option)",
        r"the following arguments are required",
        r"usage:",
    ],
    "network": [
        r"connection refused",
        r"connection reset",
        r"failed to connect",
        r"timed out while",
        r"network is unreachable",
        r"name or service not known",
        r"no route to host",
    ],
    "auth": [
        r"permission denied",
        r"access denied",
        r"authentication failed",
        r"login failed",
        r"unauthorized",
        r"\b401\b",
        r"\b403\b",
    ],
    "timeout": [
        r"^\[timeout\]",
        r"timed out",
    ],
    "not_vulnerable": [
        r"not vulnerable",
        r"target .* patched",
        r"does not seem vulnerable",
        r"patch(ed)?",
    ],
    "invalid_command": [
        r"\[invalid_command\]",
        r"foreign literal IP",
        r"malformed fragment",
    ],
}


def classify_output(
    output: str,
    *,
    success_indicators: list[str] | None = None,
    failure_indicators: list[str] | None = None,
) -> dict[str, Any]:
    text = str(output or "")
    lower = text.lower()
    if lower.startswith("[blocked]"):
        return {"status": "blocked", "failure_class": "unknown", "matched": "[BLOCKED]"}
    for item in success_indicators or []:
        if item and item.lower() in lower:
            return {"status": "success", "failure_class": "none", "matched": item}
    for item in _GENERIC_SUCCESS:
        if item in lower:
            return {"status": "success", "failure_class": "none", "matched": item}
    for pattern in _GENERIC_SUCCESS_PATTERNS:
        if re.search(pattern, lower, flags=re.IGNORECASE | re.MULTILINE):
            return {"status": "success", "failure_class": "none", "matched": pattern}
    for item in failure_indicators or []:
        if item and item.lower() in lower:
            return {"status": "failed", "failure_class": "unknown", "matched": item}
    for failure_class, patterns in _PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, lower, flags=re.IGNORECASE | re.MULTILINE):
                return {"status": "failed", "failure_class": failure_class, "matched": pattern}
    if lower.startswith("[error]"):
        return {"status": "failed", "failure_class": "unknown", "matched": "[ERROR]"}
    return {"status": "uncertain", "failure_class": "unknown", "matched": ""}
