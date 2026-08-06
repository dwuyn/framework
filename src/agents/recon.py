"""
src/agents/recon.py
────────────────────
ReconAgent as a LangGraph node function.

Fixes:
  P1 — Now a proper graph node; state flows automatically to planning node.
  P2 — LLM bound to run_shell @tool; no regex JSON parsing.
  P4 — Results stored in shared PentestState.
  P6 — Retry logic with exponential back-off; step cap prevents infinite loops.

Improvements:
  - Token usage extracted from every LLM response (M7, M8).
  - Invalid command (BLOCKED) events counted (M12).
  - WorldState updated incrementally after each tool call (not just at done).
  - Structured JSON logging via StructuredLogger.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from src.agents.hypothesis_phase.shared import LOW_SIGNAL_LABELS
from src.config import get_config
from src.memory.episodic import Episode, EpisodicMemory
from src.memory.world_state import ServiceInfo, WorldState
from src.state import PentestState, runtime_exceeded, service_target_key, state_int
from src.tools.shell import run_shell
from src.utils.json_parser import extract_json
from src.utils.structured_logger import extract_token_usage, get_structured_logger
from src.utils.tool_compat import content_to_text, extract_tool_calls_from_content

logger = logging.getLogger(__name__)
slog = get_structured_logger()

_RECON_SYSTEM = """You are an expert penetration tester performing the reconnaissance phase.
Your goal: identify every open port and the exact service/version running on each.

Rules:
- Use only the run_shell tool to execute commands.
- Use a two-phase strategy when possible:
  1. Fast TCP discovery (no root): `nmap -sT -p- --min-rate=1000 <target>`
  2. Targeted version scan: `nmap -sV -sC -p<interesting ports> <target>`
- IMPORTANT: nmap -sS (SYN scan) and nmap -sU (UDP scan) require root. If you are not root,
  use -sT (TCP connect scan) instead. Never use -sS or -sU unless you have confirmed root access.
- For HTTP services: ALWAYS use `curl --max-time 10 -sv http://<target>:<port>` (never omit
  --max-time; omitting it causes curl to hang indefinitely). Also try:
  - `curl --max-time 10 -sv http://<target>:<port>/` to get headers and identify the framework
  - `curl --max-time 10 -I http://<target>:<port>` for just headers (Server, X-Powered-By, etc.)
- For SIP on TCP port 5060 (no root needed):
  - `nmap -sT -sV -p 5060 --script=sip-methods,banner <target>`
  - `printf 'OPTIONS sip:probe@<target> SIP/2.0\r\nVia: SIP/2.0/TCP <attacker>;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nFrom: <sip:probe@<target>>;tag=abc\r\nTo: <sip:probe@<target>>\r\nCall-ID: probe@<target>\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n' | nc -w 5 <target> 5060`
- For unknown/generic services: always do a raw banner grab with `nc -w 5 <target> <port>` first.
- NEVER repeat the same command twice.
- Prefer a native run_shell tool call.
- If this backend does not support native tool calling, output exactly one JSON tool request:
  {"tool": "run_shell", "args": {"command": "<literal command>", "timeout": 300, "mode": "recon"}}
- When you have identified all reachable ports and their services, output a final JSON summary
  (no tool call) with the structure:

{
  "analysis": "Brief summary of findings",
  "port_services": {
    "<port>": {"name": "<service>", "version": "<version>", "accessibility": "open|filtered|closed"}
  },
  "os_info": "<OS guess or null>",
  "done": true
}
"""

# ── Incremental nmap output parser ────────────────────────────────────────────

_PORT_RE = re.compile(
    r"(\d+)/(?:tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?",
    re.IGNORECASE,
)
_VERSION_RE = re.compile(r"(\d+\.\d+[\d.]*)", re.ASCII)

# Rows that nmap uses when it cannot fingerprint a service — never treat these
# as product identifiers.
_LOW_SIGNAL_SERVICES = {
    "tcpwrapped", "unknown", "generic", "none", "n/a",
    "http", "https", "https-alt", "ssl/http", "ssl-http",
    "http-proxy", "socks5", "socks4", "ipp", "ip", "rtsp",
    "http-alt", "upnp", "wsman", "sip", "rtp", "rtcp",
}

# ── Safe label set for recon target filtering (canonical set from shared.py) ─
_GENERIC_LABELS = LOW_SIGNAL_LABELS




def _structured_recon_context(state: PentestState) -> str:
    ws = WorldState.from_dict(state.get("world_state", {}))
    em = EpisodicMemory.from_list(state.get("episodic_memory", []))
    parts = [
        f"World state:\n{ws.to_summary() or '(none)'}",
        f"Recent actions:\n{em.to_context_summary(max_entries=8) if em.total_steps() else '(none)'}",
    ]
    if state.get("os_info"):
        parts.append(f"Known OS hint: {state['os_info']}")
    return "\n\n".join(parts)


def _prepare_invocation_messages(state: PentestState, messages: list[Any]) -> list[Any]:
    system = next((m for m in messages if isinstance(m, SystemMessage)), None)
    non_system = [m for m in messages if not isinstance(m, SystemMessage)]
    prepared: list[Any] = [system] if system else []
    prepared.append(HumanMessage(content=_structured_recon_context(state)))
    prepared.extend(non_system[-6:])
    return prepared


def _build_target_services(ws: WorldState) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    for ip, host in ws.hosts.items():
        for svc in host.services:
            name = str(svc.name or "").strip()
            if not name or name.lower() in {"openssh", "ssh", "unknown", "n/a"}:
                continue
            if str(svc.accessibility or "open").lower() != "open":
                continue
            services.append({
                "target_ip": ip,
                "port": int(svc.port),
                "name": name,
                "version": str(svc.version or ""),
                "confidence": float(svc.confidence or 0.0),
                "banner": str(svc.banner or ""),
                "service_key": service_target_key(ip, svc.port, name),
            })
    # Rank: prefer versioned, non-low-signal, high-confidence, non-SSH services
    def _service_rank(item: dict[str, Any]) -> tuple[float, float, float, float]:
        name_norm = " ".join((item["name"] or "").lower().replace("/", " ").split())
        is_low_signal = 1.0 if name_norm in _GENERIC_LABELS else 0.0
        has_version = 1.0 if item["version"] else 0.0
        non_ssh = 0.0 if name_norm in {"openssh", "ssh"} else 1.0
        return (
            has_version,
            1.0 - is_low_signal,
            non_ssh,
            float(item["confidence"]),
        )
    services.sort(key=_service_rank, reverse=True)
    return services


def _targeted_recon_messages(state: PentestState, already_run: list[str] | None = None,
                              *, service_port: int = 0, service_key: str = "") -> list:
    critic_report = dict(((state.get("retrieval_bundle", {}) or {}).get("critic_report", {}) or {}))
    recon_requests = [str(item).strip() for item in critic_report.get("recon_requests", []) if str(item).strip()]
    request_block = "\n".join(f"- {item}" for item in recon_requests[:6])
    if not request_block:
        request_block = (
            "- collect exact version, banner, product, and platform evidence for the most promising non-SSH service\n"
            "- do not just restate the previous summary without new probing"
        )

    scope_block = ""
    if service_port:
        scope_block = (
            f"\n\nACTIVE TARGET: port {service_port}"
            + (f" ({service_key})" if service_key else "")
            + "\nOnly probe the active target's port during this follow-up. "
              "Do NOT probe unrelated ports (e.g. 5060 when the active target is 8080)."
        )

    already_run_block = ""
    if already_run:
        already_run_block = (
            "\n\nCommands already run (FORBIDDEN — do not repeat any of these):\n"
            + "\n".join(f"  - {cmd}" for cmd in already_run[:20])
            + "\n\nPropose materially different probes. Use different flags, targets, or tools "
              "such as:\n"
              "  - curl --max-time 10 -sv http://<target>:<port>/   (ALWAYS use --max-time)\n"
              "  - curl --max-time 10 -I http://<target>:<port>   (header-only, fast)\n"
              "  - nmap -sT -sV -p <port> --script=banner,http-headers <target>\n"
              "  - nc -w 5 <target> <port>   (raw banner grab)\n"
              "  - For SIP/5060: nmap -sT -sV -p 5060 --script=sip-methods <target>"
        )

    return [
        SystemMessage(content=_RECON_SYSTEM),
        HumanMessage(content=(
            f"Target: {state.get('target_ip', '')}\n"
            "Phase 2 requested targeted follow-up reconnaissance.\n\n"
            f"{_structured_recon_context(state)}\n\n"
            "Specific follow-up requests:\n"
            f"{request_block}\n"
            f"{scope_block}"
            f"{already_run_block}\n\n"
            "IMPORTANT: For HTTP services, always use `curl --max-time 10 -sv <url>` "
            "to get Server: and X-Powered-By: response headers. "
            "Run new recon tool calls to answer those requests. "
            "Only output the final done=true summary after you have gathered materially better evidence."
        )),
    ]



def _parse_nmap_services(output: str) -> list[dict]:
    """
    Extract open ports with service/version from nmap stdout using line-by-line
    parsing of port-table rows only. Never cross-contaminate adjacent ports or
    pick up trailer lines like ``Nmap done``.
    """
    results: list[dict] = []
    for line in output.splitlines():
        line = line.strip()
        # Skip obvious non-row lines: script output, trailers, empty lines
        if not line or line.startswith("|") or line.startswith("Nmap"):
            continue
        m = _PORT_RE.match(line)
        if not m:
            continue
        port = int(m.group(1))
        name = m.group(2).strip()
        banner = (m.group(3) or "").strip()

        # Version: conservative extraction; skip numbers from low-signal rows
        version = ""
        name_lower = name.lower()
        if name_lower not in _LOW_SIGNAL_SERVICES:
            ver_m = _VERSION_RE.search(banner)
            version = ver_m.group(1) if ver_m else ""
        elif banner:
            # Still try to extract version from banner even for generic labels
            # when there's actual banner content (e.g. "nginx 1.14.2")
            ver_m = _VERSION_RE.search(banner)
            version = ver_m.group(1) if ver_m else ""

        results.append({
            "port": port,
            "name": name,
            "version": version,
            "banner": banner,
        })
    return results


def _parse_curl_headers(output: str, port: int) -> list[dict]:
    """
    Extract service identity from curl -sv output.
    Looks for Server: and X-Powered-By: response headers.
    Returns a list of parsed service dicts compatible with _parse_nmap_services output.
    """
    results: list[dict] = []
    server_name = ""
    server_version = ""
    powered_by = ""
    status_line = ""

    for line in output.splitlines():
        line = line.strip()
        # curl verbose: response headers prefixed with '<'
        if line.startswith("< HTTP/"):
            status_line = line.lstrip("< ").strip()
        header_line = line.lstrip("< ").strip()
        lower = header_line.lower()
        if lower.startswith("server:"):
            raw = header_line[7:].strip()
            # e.g. "nginx/1.29.7", "Werkzeug/3.1.8 Python/3.10.20"
            parts = raw.split()
            if parts:
                first = parts[0]
                if "/" in first:
                    server_name, server_version = first.split("/", 1)
                else:
                    server_name = first
                    ver_m = _VERSION_RE.search(raw)
                    server_version = ver_m.group(1) if ver_m else ""
        elif lower.startswith("x-powered-by:"):
            powered_by = header_line[13:].strip()

    if server_name:
        banner = server_name
        if server_version:
            banner = f"{server_name}/{server_version}"
        if powered_by:
            banner = f"{banner} ({powered_by})"
        results.append({
            "port": port,
            "name": server_name.lower(),
            "version": server_version,
            "banner": banner,
        })
    elif status_line:
        # At minimum record that we got an HTTP response
        results.append({
            "port": port,
            "name": "http",
            "version": "",
            "banner": status_line[:120],
        })
    return results


def _parse_nc_banner(output: str, port: int) -> list[dict]:
    """
    Extract a banner from nc/netcat output. Captures the first non-empty
    non-connection-status line as the banner.
    """
    skip_prefixes = (
        "Ncat:", "ncat:", "Connection", "Trying", "Connected",
        "Escape", "bytes sent", "bytes received",
    )
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if any(stripped.startswith(p) for p in skip_prefixes):
            continue
        # Got a real banner line
        ver_m = _VERSION_RE.search(stripped)
        version = ver_m.group(1) if ver_m else ""
        return [{
            "port": port,
            "name": "unknown",
            "version": version,
            "banner": stripped[:200],
        }]
    return []


def _extract_port_from_command(command: str) -> int:
    """Try to extract the port number from a curl/nc command string."""
    import re as _re
    # curl http://host:PORT or https://host:PORT
    m = _re.search(r'https?://[^\s/]+:(\d+)', command)
    if m:
        return int(m.group(1))
    # nc host PORT or nc -nv host PORT
    m = _re.search(r'nc\s+(?:-\S+\s+)*(?:\S+\s+)(\d+)', command)
    if m:
        return int(m.group(1))
    return 0


def _update_world_state_from_output(
    ws: WorldState, target_ip: str, output: str, command: str,
) -> WorldState:
    """
    Parse tool output and incrementally update the WorldState.
    Handles:
    - nmap port table output (primary path)
    - curl -sv response headers (Server:, X-Powered-By:)
    - nc/netcat banner grabs
    """
    if not output or "[BLOCKED]" in output or "[ERROR]" in output:
        return ws

    cmd_lower = command.lower().strip()

    # ── curl header parsing ───────────────────────────────────────────────────
    if cmd_lower.startswith("curl"):
        port = _extract_port_from_command(command)
        if port:
            parsed = _parse_curl_headers(output, port)
            for svc_data in parsed:
                if svc_data["name"] in ("http", "https", "unknown") and not svc_data["version"]:
                    confidence = 0.45  # we confirmed a service is there
                else:
                    confidence = 0.65  # we have a real server name
                svc = ServiceInfo(
                    port=svc_data["port"],
                    name=svc_data["name"],
                    version=svc_data["version"],
                    banner=svc_data["banner"],
                    accessibility="open",
                    confidence=confidence,
                    evidence=[f"curl ({command[:60]}): {svc_data['banner']}"],
                )
                ws.add_service(target_ip, svc)
        return ws

    # ── nc/netcat banner parsing ──────────────────────────────────────────────
    if cmd_lower.startswith("nc ") or cmd_lower.startswith("ncat ") or " nc " in cmd_lower:
        port = _extract_port_from_command(command)
        if port:
            parsed = _parse_nc_banner(output, port)
            for svc_data in parsed:
                svc = ServiceInfo(
                    port=svc_data["port"],
                    name=svc_data["name"],
                    version=svc_data["version"],
                    banner=svc_data["banner"],
                    accessibility="open",
                    confidence=0.50 if svc_data["version"] else 0.42,
                    evidence=[f"nc ({command[:60]}): {svc_data['banner'][:100]}"],
                )
                ws.add_service(target_ip, svc)
        return ws

    # ── nmap port table parsing ───────────────────────────────────────────────
    parsed = _parse_nmap_services(output)
    if not parsed:
        return ws

    for svc_data in parsed:
        svc = ServiceInfo(
            port=svc_data["port"],
            name=svc_data["name"],
            version=svc_data["version"],
            banner=svc_data["banner"],
            accessibility="open",
            # Higher confidence if version was extracted
            confidence=0.55 if svc_data["version"] else 0.4,
            evidence=[f"nmap ({command[:60]}): {svc_data['name']} {svc_data['version']} on port {svc_data['port']}"],
        )
        ws.add_service(target_ip, svc)

    return ws




def _dedup_recent_commands(state: PentestState, command: str) -> bool:
    """
    Return True if *command* (normalized) already appears in the recent
    recon episodic memory window.
    """
    window = int(state.get("recon_command_dedupe_window", 10) or 10)
    if window <= 0:
        return False
    em = EpisodicMemory.from_list(state.get("episodic_memory", []))
    recent_recon = [
        episode for episode in em.by_phase("recon")
        if episode.action_type == "tool_call" and episode.command
    ][-window:]
    normalized = (command or "").strip()
    for episode in recent_recon:
        if (episode.command or "").strip() == normalized:
            return True
    return False


def recon_node(state: PentestState) -> Dict[str, Any]:
    """
    LangGraph node: runs one recon iteration (LLM call + optional tool execution).
    The graph routes back to this node until recon_complete=True or max steps reached.
    """
    cfg = get_config()
    llm = cfg.get_llm(cfg.recon["model"])
    tools = [run_shell]
    llm_with_tools = llm.bind_tools(tools)

    step = state_int(state, "recon_step_count", 0)
    state_int(state, "recon_max_steps", 12)
    target_ip = state["target_ip"]

    # Accumulator baseline
    acc_tokens_in = state_int(state, "total_tokens_in", 0)
    acc_tokens_out = state_int(state, "total_tokens_out", 0)
    acc_requests = state_int(state, "total_llm_requests", 0)
    acc_invalid = state_int(state, "total_invalid_commands", 0)
    phase_timestamps = dict(state.get("phase_timestamps", {}))
    phase_timestamps.setdefault("recon_start", time.time())
    em = EpisodicMemory.from_list(state.get("episodic_memory", []))
    ws = WorldState.from_dict(state.get("world_state", {}))

    timed_out, timeout_reason = runtime_exceeded(state)
    if timed_out:
        return {
            "messages": list(state.get("messages", [])),
            "current_phase": "done",
            "timeout_exceeded": True,
            "execution_summary": timeout_reason,
            "phase_timestamps": phase_timestamps,
            "episodic_memory": em.to_list(),
            "world_state": ws.to_dict(),
        }

    # ── Build message list ────────────────────────────────────────────────────
    messages: list = list(state.get("messages", []))
    is_phase2_followup = state.get("phase2_route") == "recon"
    if is_phase2_followup:
        logger.info("Recon: restarting with targeted follow-up after Phase 2 requested more recon")
        # Build already_run list from state episodic memory so the prompt forbids repeats
        em = EpisodicMemory.from_list(state.get("episodic_memory", []))
        already_run_cmds = [
            ep.command for ep in em.by_phase("recon")
            if ep.action_type == "tool_call" and ep.command
        ]
        # Filter already_run to commands relevant to the active target port
        active_port = int(state.get("phase2_target_port", 0) or 0)
        active_key = str(state.get("phase2_target_service_key", "") or "")
        if active_port:
            already_run_cmds = [
                cmd for cmd in already_run_cmds
                if str(active_port) in cmd or str(target_ip) in cmd
            ]
        messages = _targeted_recon_messages(
            state, already_run=already_run_cmds,
            service_port=active_port, service_key=active_key,
        )
    elif not messages:
        messages = [
            SystemMessage(content=_RECON_SYSTEM),
            HumanMessage(content=(
                f"Target: {target_ip}\n"
                "Start reconnaissance. Begin with an nmap ping/port scan "
                "to find all open ports, then probe each service."
            )),
        ]

    # ── LLM call with retry ───────────────────────────────────────────────────
    t_llm = time.time()
    response = None
    for attempt in range(3):
        try:
            response = llm_with_tools.invoke(
                _prepare_invocation_messages(state, messages),
                stream=False,
            )
            break
        except Exception as exc:
            wait = 2 ** attempt
            logger.error("Recon LLM call failed (attempt %d): %s — retrying in %ds", attempt + 1, exc, wait)
            time.sleep(wait)

    llm_duration_ms = (time.time() - t_llm) * 1000
    tokens_in, tokens_out = extract_token_usage(response) if response else (0, 0)
    acc_tokens_in += tokens_in
    acc_tokens_out += tokens_out
    acc_requests += 1

    slog.node_event(
        "recon", step=step, phase="recon",
        action="llm_call",
        tokens_in=tokens_in, tokens_out=tokens_out,
        duration_ms=llm_duration_ms,
        outcome="error" if response is None else "ok",
    )

    if response is None:
        update = {
            "error_count": state_int(state, "error_count", 0) + 1,
            "last_error": "Recon LLM call failed after 3 attempts",
            "recon_complete": True,
            "messages": messages,
            "total_tokens_in": acc_tokens_in,
            "total_tokens_out": acc_tokens_out,
            "total_tokens": acc_tokens_in + acc_tokens_out,
            "total_llm_requests": acc_requests,
            "phase_timestamps": phase_timestamps,
        }
        return update

    messages.append(response)

    content = content_to_text(response.content)
    tool_calls = list(response.tool_calls or [])
    if not tool_calls:
        tool_calls = extract_tool_calls_from_content(
            response.content,
            {"run_shell"},
            default_tool_name="run_shell",
            default_args={"mode": "recon"},
        )
        if tool_calls:
            logger.warning("Recon model returned JSON/text tool intent; using compatibility parser.")

    # ── Tool execution ────────────────────────────────────────────────────────
    if tool_calls:
        executed_count = 0
        for tc in tool_calls:
            cmd = tc["args"].get("command", tc["name"])
            logger.info("Recon tool call: %s(%s)", tc["name"], cmd)

            if _dedup_recent_commands(state, cmd):
                logger.warning("Recon command dedup: rejecting repeat — %s", cmd)
                messages.append(HumanMessage(
                    content=(
                        f"The command '{cmd[:200]}' was already run in the recent dedup window. "
                        "Propose a materially different probe. Do not repeat the same command."
                    )
                ))
                continue

            executed_count += 1

            t_tool = time.time()
            try:
                tool_result = run_shell.invoke(tc["args"])
                outcome = "success"
                error_msg = ""
                is_blocked = tool_result.startswith("[BLOCKED]")
                if is_blocked:
                    outcome = "blocked"
                    acc_invalid += 1
                logger.info("Recon tool output:\n%s", tool_result[:500])
            except Exception as exc:
                tool_result = f"[ERROR] {exc}"
                outcome = "error"
                error_msg = str(exc)
                is_blocked = False

            tool_duration_ms = (time.time() - t_tool) * 1000

            # Incremental WorldState update from nmap output
            if not is_blocked and outcome == "success":
                ws = _update_world_state_from_output(ws, target_ip, tool_result, cmd)

            slog.tool_event(
                "recon", tc["name"],
                command=cmd, outcome=outcome, blocked=is_blocked,
                duration_ms=tool_duration_ms, step=step,
            )

            ep = Episode(
                step=em.total_steps() + 1,
                timestamp=time.time(),
                phase="recon",
                action_type="tool_call",
                command=cmd,
                args=tc["args"],
                output_summary=str(tool_result)[:500],
                outcome=outcome,
                tokens_used=0,
                error_message=error_msg if not is_blocked else "",
            )
            em.log(ep)

            if tc.get("id", "").startswith("compat-"):
                messages.append(HumanMessage(
                    content=f"Tool '{tc['name']}' output:\n{tool_result}"
                ))
            else:
                messages.append(ToolMessage(content=str(tool_result), tool_call_id=tc["id"]))

        # If all tool calls were dedup-rejected in a phase2 follow-up,
        # advance rather than looping forever — there's nothing more recon can give.
        if not executed_count:
            if is_phase2_followup:
                logger.warning(
                    "Recon dedup: all follow-up commands rejected in phase2 mode — "
                    "forcing recon_complete=True to break loop."
                )
                return {
                    "messages": messages,
                    "current_phase": "recon",
                    "recon_complete": True,
                    "phase2_route": "",
                    "episodic_memory": em.to_list(),
                    "world_state": ws.to_dict(),
                    "total_tokens_in": acc_tokens_in,
                    "total_tokens_out": acc_tokens_out,
                    "total_tokens": acc_tokens_in + acc_tokens_out,
                    "total_llm_requests": acc_requests,
                    "total_invalid_commands": acc_invalid,
                    "phase_timestamps": phase_timestamps,
                }
            return {
                "messages": messages,
                "current_phase": "recon",
                "episodic_memory": em.to_list(),
                "world_state": ws.to_dict(),
                "total_tokens_in": acc_tokens_in,
                "total_tokens_out": acc_tokens_out,
                "total_tokens": acc_tokens_in + acc_tokens_out,
                "total_llm_requests": acc_requests,
                "total_invalid_commands": acc_invalid,
                "phase_timestamps": phase_timestamps,
            }

        update = {
            "messages": messages,
            "recon_step_count": step + 1,
            "current_phase": "recon",
            "episodic_memory": em.to_list(),
            "world_state": ws.to_dict(),
            "total_repeated_actions": em.count_repeats(),
            "total_tokens_in": acc_tokens_in,
            "total_tokens_out": acc_tokens_out,
            "total_tokens": acc_tokens_in + acc_tokens_out,
            "total_llm_requests": acc_requests,
            "total_invalid_commands": acc_invalid,
            "phase_timestamps": phase_timestamps,
        }
        return update

    # ── No tool call → parse final summary ───────────────────────────────────
    parsed = extract_json(content)

    if isinstance(parsed, dict) and parsed.get("done") is True:
        raw_port_services = parsed.get("port_services", {})
        port_services = raw_port_services if isinstance(raw_port_services, dict) else {}
        raw_os_info = parsed.get("os_info")
        os_info = str(raw_os_info) if raw_os_info else None
        logger.info("Recon complete. Found %d ports.", len(port_services))

        # Build / merge final WorldState from summary output
        ws = WorldState.from_dict(state.get("world_state", {}))
        final_ws = WorldState.from_port_services(target_ip, port_services, os_info)
        # Merge: upsert all services from final summary into running WorldState
        for ip, host in final_ws.hosts.items():
            for svc in host.services:
                ws.add_service(ip, svc)
        if os_info and target_ip in ws.hosts:
            ws.hosts[target_ip].os_hint = os_info

        target_services = _build_target_services(ws)
        primary_service = target_services[0] if target_services else {}
        # Derive identity from the chosen active service; never preserve stale values
        app_name = str(primary_service.get("name", "") or "")
        keyword = app_name or str(primary_service.get("name", "") or "")
        app_version = str(primary_service.get("version", "") or "")
        primary_port = int(primary_service.get("port", 0) or 0)
        primary_key = str(primary_service.get("service_key", "") or "")
        primary_product = str(primary_service.get("name", "") or "")

        slog.phase_event("recon", "complete", ports_found=len(port_services))
        phase_timestamps["recon_complete_time"] = time.time()
        update = {
            "messages": messages,
            "recon_complete": True,
            "port_services": port_services,
            "os_info": os_info,
            "recon_step_count": step + 1,
            "app_name": app_name,
            "keyword": keyword,
            "app_version": app_version,
            "target_services": target_services,
            "current_service_index": 0,
            "phase2_target_service_key": primary_key,
            "phase2_target_port": primary_port,
            "phase2_target_product": primary_product,
            "target_port": str(primary_port) or None,
            "current_phase": "recon",
            "world_state": ws.to_dict(),
            "total_tokens_in": acc_tokens_in,
            "total_tokens_out": acc_tokens_out,
            "total_tokens": acc_tokens_in + acc_tokens_out,
            "total_llm_requests": acc_requests,
            "total_invalid_commands": acc_invalid,
            "phase_timestamps": phase_timestamps,
        }
        # Clear phase2_route when phase2 follow-up recon completes successfully
        if is_phase2_followup:
            update["phase2_route"] = ""
        return update

    # LLM replied in text but not done — nudge it
    messages.append(HumanMessage(
        content=(
            "Continue recon. Prefer a native run_shell tool call. If your backend cannot emit"
            " tool_calls, output one JSON object like "
            '{"tool":"run_shell","args":{"command":"<literal command>","mode":"recon"}}. '
            "If finished, output the final JSON summary with 'done': true and the port_services dict."
        )
    ))
    update = {
        "messages": messages,
        "recon_step_count": step + 1,
        "current_phase": "recon",
        "total_tokens_in": acc_tokens_in,
        "total_tokens_out": acc_tokens_out,
        "total_tokens": acc_tokens_in + acc_tokens_out,
        "total_llm_requests": acc_requests,
        "total_invalid_commands": acc_invalid,
        "phase_timestamps": phase_timestamps,
    }
    return update


def route_recon(state: PentestState) -> str:
    """Conditional edge: stay in recon or advance to planning."""
    if state.get("current_phase") == "done":
        return "planning"
    if state.get("recon_complete"):
        return "planning"
    if state_int(state, "recon_step_count", 0) >= state_int(state, "recon_max_steps", 12):
        logger.warning("Recon hit max steps — forcing advance to planning")
        return "planning"
    return "recon"
