"""
src/tools/shell.py
──────────────────
Shell execution tool for LangChain / LangGraph tool calling.

Design choice:
  - Keep command execution permissive.
  - Only reject empty / placeholder commands so the agent does not spin on
    invalid no-op requests.
"""

from __future__ import annotations

import subprocess
from typing import Literal

from langchain_core.tools import tool
from pydantic import BaseModel, Field

def validate_command(command: str, mode: str = "recon") -> tuple[bool, str]:
    """Only reject empty / placeholder commands; otherwise allow execution."""
    cmd = command.strip()
    if not cmd or cmd in ("None", "none", ""):
        return False, "Empty command"
    return True, "OK"


# ── Tool schema ───────────────────────────────────────────────────────────────

class ShellInput(BaseModel):
    command: str = Field(
        description="Complete, executable shell command. No variables like <target_ip>."
    )
    timeout: int = Field(
        default=300,
        ge=1,
        le=600,
        description="Timeout in seconds (1-600).",
    )
    mode: Literal["recon", "execution"] = Field(
        default="recon",
        description="'recon' for recon tools, 'execution' for exploit tools.",
    )


# ── The tool ──────────────────────────────────────────────────────────────────

@tool(args_schema=ShellInput)
def run_shell(command: str, timeout: int = 300, mode: str = "recon") -> str:
    """
    Execute a shell command and return its output.

    Commands are executed permissively after rejecting empty placeholders.
    Use this for reconnaissance (nmap, curl, etc.) and exploit execution.
    Always provide a complete, literal command — no placeholder variables.
    """
    ok, reason = validate_command(command, mode)
    if not ok:
        return f"[BLOCKED] {reason}"

    try:
        proc = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        output = proc.stdout or ""
        if not output.strip():
            return f"[Exit {proc.returncode}] No output produced."
        if len(output) > 50000:
            output = output[:50000] + "\n...[truncated]"
        return output
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Command timed out after {timeout}s"
    except Exception as exc:
        return f"[ERROR] {exc}"
