"""
Deterministic-first execution node.

Consumes the structured exploit_plan directly, performs preflight checks,
workspace-local dependency setup, placeholder binding, bounded retries, and
candidate-aware verification. LLM usage is fallback-only.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict

from langchain_core.messages import HumanMessage, SystemMessage

from src.config import get_config
from src.execution.classify import classify_output
from src.execution.placeholders import resolve_placeholder_values
from src.execution.preflight import (
    PreflightResult,
    _contains_foreign_ip,
    _prefix_workdir,
    prepare_candidate,
)
from src.execution.tracker import (
    advance_candidate,
    append_attempt,
    build_execution_tracker,
    current_candidate,
    ensure_candidate_result,
    mark_success,
    mark_terminal_failure,
    set_candidate_status,
    tracker_done,
    workspace_dir_for_candidate,
    write_execution_artifacts,
)
from src.memory.episodic import Episode, EpisodicMemory
from src.memory.world_state import WorldState
from src.state import PentestState, runtime_exceeded
from src.tools.shell import run_shell
from src.utils.json_parser import extract_json
from src.utils.structured_logger import extract_token_usage, get_structured_logger

logger = logging.getLogger(__name__)
slog = get_structured_logger()

_FALLBACK_SYSTEM = """You assist exploit execution only when deterministic commands are insufficient.
Return JSON only:
{
  "command": "single literal shell command or empty string",
  "skip": true | false,
  "reason": "short explanation"
}

Rules:
- Return at most one command.
- Do not install system packages or modify system files.
- Do not use placeholders like <TARGET_IP>.
- Prefer using the provided exploit path and working directory.
- If the candidate should be skipped, set skip=true and command="".
"""

_SUCCESS_MARKERS = ("uid=", "root@", "www-data@", "meterpreter >", "flag{", "htb{", "access granted", "pwned")
_RETRYABLE_FAILURES = {"network", "timeout", "auth"}


def _phase_timestamps(state: PentestState) -> dict:
    return dict(state.get("phase_timestamps", {}))





def _detect_privilege_hint(output: str) -> str:
    lower = output.lower()
    if "uid=0" in lower or "root" in lower:
        return "root"
    if "www-data" in lower:
        return "www-data"
    return "unknown"


def _infer_session_type(command: str, output: str) -> str:
    lower_cmd = command.lower()
    lower_out = output.lower()
    if "ssh" in lower_cmd:
        return "ssh"
    if "curl" in lower_cmd or "wget" in lower_cmd:
        return "http-rce"
    if "meterpreter" in lower_cmd or "msf" in lower_cmd:
        return "meterpreter"
    if any(marker in lower_out for marker in ("uid=", "root@", "www-data@", "# ", "$ ")):
        return "shell"
    return "command-exec"


def _build_session_artifact(
    exploit: dict[str, Any],
    verification_command: str,
    proof: str,
) -> dict[str, Any]:
    return {
        "candidate_id": exploit.get("candidate_id", ""),
        "session_type": _infer_session_type(verification_command, proof),
        "verification_type": "candidate_verify" if exploit.get("verify_commands") else "command_replay",
        "verification_command": verification_command.strip(),
        "success_indicator": next((marker for marker in _SUCCESS_MARKERS if marker in proof.lower()), ""),
        "privilege_hint": _detect_privilege_hint(proof),
        "origin_exploit": exploit.get("name", ""),
        "proof": proof[:240],
    }


def _log_episode(
    em: EpisodicMemory,
    *,
    phase: str,
    action_type: str,
    command: str,
    args: dict[str, Any],
    output: str,
    outcome: str,
    error_message: str = "",
) -> None:
    em.log(Episode(
        step=em.total_steps() + 1,
        timestamp=time.time(),
        phase=phase,
        action_type=action_type,
        command=command,
        args=args,
        output_summary=output[:500],
        outcome=outcome,
        error_message=error_message,
    ))


def _run_shell_command(command: str, *, timeout: int) -> tuple[str, str]:
    try:
        output = run_shell.invoke({
            "command": command,
            "timeout": timeout,
            "mode": "execution",
        })
    except Exception as exc:
        return f"[ERROR] {exc}", "error"
    if str(output).startswith("[BLOCKED]"):
        return str(output), "blocked"
    if str(output).startswith("[TIMEOUT]"):
        return str(output), "timeout"
    if str(output).startswith("[ERROR]"):
        return str(output), "error"
    return str(output), "success"


def _verification_succeeded(output: str, success_indicators: list[str]) -> bool:
    classified = classify_output(output, success_indicators=success_indicators)
    return classified.get("status") == "success" or bool(output.strip() and any(marker in output.lower() for marker in _SUCCESS_MARKERS))


def _verify_candidate(
    exploit: dict[str, Any],
    preflight: PreflightResult,
    result: dict[str, Any],
    em: EpisodicMemory,
    exec_cfg: dict[str, Any],
) -> tuple[bool, str, str]:
    verify_commands = list(preflight.verify_commands or [])
    if not verify_commands:
        replay = result.get("rendered_commands", [])
        verify_commands = [replay[min(len(replay) - 1, 0)]] if replay else []
    verify_timeout = int(exec_cfg.get("verify_timeout", 20) or 20)
    for command in verify_commands[:2]:
        output, outcome = _run_shell_command(command, timeout=verify_timeout)
        _log_episode(
            em,
            phase="execution",
            action_type="tool_call",
            command=command,
            args={"command": command, "timeout": verify_timeout, "mode": "execution"},
            output=output,
            outcome=outcome,
            error_message="" if outcome == "success" else outcome,
        )
        if _verification_succeeded(output, preflight.success_indicators):
            return True, command, output
    return False, "", ""


def _llm_fallback_command(
    cfg: Any,
    state: PentestState,
    exploit: dict[str, Any],
    result: dict[str, Any],
    preflight: PreflightResult,
) -> tuple[str, str, int, int, int]:
    llm = cfg.get_llm(cfg.execution["model"])
    recent = result.get("attempt_log", [])[-3:]
    response = llm.invoke([
        SystemMessage(content=_FALLBACK_SYSTEM),
        HumanMessage(content=(
            f"Target: {state.get('target_ip')}:{exploit.get('target_port') or state.get('target_port')}\n"
            f"Attacker: {state.get('attacker_ip')}\n"
            f"Exploit: {exploit.get('name')}\n"
            f"File path: {exploit.get('file_path')}\n"
            f"Working directory: {preflight.working_directory}\n"
            f"Commands tried: {result.get('rendered_commands', [])}\n"
            f"Recent attempt log: {recent}\n"
            f"Usage notes: {exploit.get('reasons', [])}\n"
            f"Success indicators: {preflight.success_indicators}\n"
            f"Failure indicators: {preflight.failure_indicators}\n"
        )),
    ], stream=False)
    tokens_in, tokens_out = extract_token_usage(response)
    parsed = extract_json(getattr(response, "content", "") or "")
    if isinstance(parsed, dict):
        if parsed.get("skip"):
            return "", str(parsed.get("reason", "skip")), tokens_in, tokens_out, 1
        return str(parsed.get("command", "") or "").strip(), str(parsed.get("reason", "")), tokens_in, tokens_out, 1
    return "", "fallback_parse_failed", tokens_in, tokens_out, 1


def _should_retry_same_command(result: dict[str, Any], failure_class: str, exec_cfg: dict[str, Any]) -> bool:
    if failure_class not in _RETRYABLE_FAILURES:
        return False
    max_attempts = int(exec_cfg.get("per_candidate_max_attempts", 3) or 3)
    return int(result.get("attempt_count", 0) or 0) < max_attempts


def _setup_candidate_if_needed(
    tracker: dict[str, Any],
    candidate_id: str,
    preflight: PreflightResult,
    result: dict[str, Any],
    em: EpisodicMemory,
    exec_cfg: dict[str, Any],
) -> tuple[bool, str]:
    if result.get("setup_done") or not preflight.setup_commands:
        return True, ""
    install_timeout = int(exec_cfg.get("install_timeout", 180) or 180)
    for command in preflight.setup_commands:
        output, outcome = _run_shell_command(command, timeout=install_timeout)
        append_attempt(
            tracker,
            candidate_id,
            stage="setup",
            command=command,
            outcome=outcome,
            output=output,
            failure_class="missing_dependency" if outcome != "success" else "none",
        )
        _log_episode(
            em,
            phase="execution",
            action_type="tool_call",
            command=command,
            args={"command": command, "timeout": install_timeout, "mode": "execution"},
            output=output,
            outcome=outcome,
            error_message="" if outcome == "success" else outcome,
        )
        if outcome != "success":
            return False, output
    result["setup_done"] = True
    return True, ""


def _exhausted_payload(
    state: PentestState,
    tracker: dict[str, Any],
    em: EpisodicMemory,
    *,
    summary: str,
    acc_tokens_in: int,
    acc_tokens_out: int,
    acc_requests: int,
    acc_invalid: int,
    retry_spent: int,
    phase_timestamps: dict[str, Any],
) -> Dict[str, Any]:
    write_execution_artifacts(tracker)
    update = {
        "execution_tracker": tracker,
        "episodic_memory": em.to_list(),
        "execution_success": False,
        "execution_summary": summary,
        "current_phase": "done",
        "execution_step_count": state.get("execution_step_count", 0) + 1,
        "total_repeated_actions": em.count_repeats(),
        "total_tokens_in": acc_tokens_in,
        "total_tokens_out": acc_tokens_out,
        "total_tokens": acc_tokens_in + acc_tokens_out,
        "total_llm_requests": acc_requests,
        "total_invalid_commands": acc_invalid,
        "retry_spent": retry_spent,
        "phase_timestamps": phase_timestamps,
    }
    return update


def execution_node(state: PentestState) -> Dict[str, Any]:
    """
    Execute structured exploit candidates deterministically.
    Each invocation runs preflight/setup and at most one exploit command.
    """
    cfg = get_config()
    exec_cfg = cfg.execution
    exploit_plan = list(state.get("exploit_plan", []))
    tracker = dict(state.get("execution_tracker", {}) or {})
    if not tracker:
        tracker = build_execution_tracker(state, exec_cfg)

    ws = WorldState.from_dict(state.get("world_state", {}))
    em = EpisodicMemory.from_list(state.get("episodic_memory", []))
    phase_timestamps = _phase_timestamps(state)
    phase_timestamps.setdefault("execution_start", time.time())

    timed_out, timeout_reason = runtime_exceeded(state)
    if timed_out:
        return {
            "execution_tracker": tracker,
            "episodic_memory": em.to_list(),
            "execution_success": False,
            "execution_summary": timeout_reason,
            "current_phase": "done",
            "timeout_exceeded": True,
            "phase_timestamps": phase_timestamps,
        }

    acc_tokens_in = state.get("total_tokens_in", 0)
    acc_tokens_out = state.get("total_tokens_out", 0)
    acc_requests = state.get("total_llm_requests", 0)
    acc_invalid = state.get("total_invalid_commands", 0)
    retry_spent = state.get("retry_spent", 0)
    step = state.get("execution_step_count", 0)

    if not tracker.get("candidate_order"):
        _log_episode(
            em,
            phase="execution",
            action_type="verifier_check",
            command="no_candidates",
            args={},
            output="No exploit candidates available.",
            outcome="fail",
            error_message="no_candidates",
        )
        return _exhausted_payload(
            state,
            tracker,
            em,
            summary="No exploit candidates available for execution.",
            acc_tokens_in=acc_tokens_in,
            acc_tokens_out=acc_tokens_out,
            acc_requests=acc_requests,
            acc_invalid=acc_invalid,
            retry_spent=retry_spent,
            phase_timestamps=phase_timestamps,
        )

    while True:
        if tracker_done(tracker):
            return _exhausted_payload(
                state,
                tracker,
                em,
                summary="All exploit candidates exhausted.",
                acc_tokens_in=acc_tokens_in,
                acc_tokens_out=acc_tokens_out,
                acc_requests=acc_requests,
                acc_invalid=acc_invalid,
                retry_spent=retry_spent,
                phase_timestamps=phase_timestamps,
            )

        candidate_id, exploit = current_candidate(tracker, exploit_plan)
        if not candidate_id or exploit is None:
            advance_candidate(tracker)
            continue

        result = ensure_candidate_result(tracker, candidate_id)
        placeholder_values, missing_placeholders = resolve_placeholder_values(exploit, state, ws)
        tracker["resolved_placeholders"] = placeholder_values
        selected_lport = str(placeholder_values.get("LPORT") or state.get("lport") or "").strip() or None

        workspace_dir = result.get("workspace_dir") or workspace_dir_for_candidate(
            str(tracker.get("workspace_root", "") or exec_cfg.get("workspace_root", "data/execution_runs")),
            candidate_id,
        )
        result["workspace_dir"] = workspace_dir

        preflight = prepare_candidate(
            exploit,
            workspace_dir,
            placeholder_values,
            missing_placeholders,
            allow_workspace_installs=bool(exec_cfg.get("allow_workspace_installs", True)),
        )

        result["rendered_commands"] = preflight.rendered_commands
        result["working_directory"] = preflight.working_directory
        result["required_placeholders"] = preflight.required_placeholders

        if preflight.status != "ready":
            failure_class = "missing_placeholder" if preflight.missing_placeholders else "unknown"
            terminal_status = "preflight_failed" if preflight.status == "preflight_failed" else "blocked"
            mark_terminal_failure(tracker, candidate_id, status=terminal_status, failure_class=failure_class)
            append_attempt(
                tracker,
                candidate_id,
                stage="preflight",
                command="preflight",
                outcome=terminal_status,
                output=preflight.reason,
                failure_class=failure_class,
            )
            _log_episode(
                em,
                phase="execution",
                action_type="verifier_check",
                command="preflight",
                args={"candidate_id": candidate_id},
                output=preflight.reason,
                outcome="blocked" if terminal_status == "blocked" else "fail",
                error_message=failure_class,
            )
            advance_candidate(tracker)
            continue

        setup_ok, setup_error = _setup_candidate_if_needed(tracker, candidate_id, preflight, result, em, exec_cfg)
        if not setup_ok:
            mark_terminal_failure(tracker, candidate_id, status="blocked", failure_class="missing_dependency")
            append_attempt(
                tracker,
                candidate_id,
                stage="setup",
                command="setup",
                outcome="blocked",
                output=setup_error,
                failure_class="missing_dependency",
            )
            advance_candidate(tracker)
            write_execution_artifacts(tracker)
            update = {
                "execution_tracker": tracker,
                "episodic_memory": em.to_list(),
                "execution_step_count": step + 1,
                "current_phase": "execution",
                "selected_exploit": exploit,
                "total_repeated_actions": em.count_repeats(),
                "total_tokens_in": acc_tokens_in,
                "total_tokens_out": acc_tokens_out,
                "total_tokens": acc_tokens_in + acc_tokens_out,
                "total_llm_requests": acc_requests,
                "total_invalid_commands": acc_invalid,
                "retry_spent": retry_spent,
                "phase_timestamps": phase_timestamps,
                "spent_tokens": acc_tokens_in + acc_tokens_out,
                "spent_steps": em.total_steps(),
                "lport": selected_lport,
            }
            return update

        commands = list(result.get("rendered_commands", []))
        command_index = int(tracker.get("current_command_index", 0) or 0)
        if command_index >= len(commands):
            if not result.get("llm_fallback_used") and int(exec_cfg.get("llm_fallback_attempts", 1) or 1) > 0:
                try:
                    fallback_command, fallback_reason, t_in, t_out, requests = _llm_fallback_command(
                        cfg, state, exploit, result, preflight
                    )
                    acc_tokens_in += t_in
                    acc_tokens_out += t_out
                    acc_requests += requests
                    retry_spent += 1
                    result["llm_fallback_used"] = True
                    tracker["llm_fallback_used"] = True
                    append_attempt(
                        tracker,
                        candidate_id,
                        stage="llm_fallback",
                        command=fallback_command or "skip",
                        outcome="success" if fallback_command else "blocked",
                        output=fallback_reason,
                        failure_class="unknown",
                    )
                    if fallback_command:
                        # Ensure working directory prefix
                        fallback_command = _prefix_workdir(fallback_command, preflight.working_directory)
                        # Validate against foreign IPs
                        tgt_ip = str(state.get("target_ip") or "").strip()
                        atk_ip = str(state.get("attacker_ip") or "").strip()
                        if _contains_foreign_ip(fallback_command, tgt_ip, atk_ip):
                            fallback_command = ""
                            fallback_reason = "Rejected: contains foreign IP"
                        result.setdefault("rendered_commands", []).append(fallback_command)
                        commands = list(result["rendered_commands"])
                    else:
                        mark_terminal_failure(tracker, candidate_id, status="skipped", failure_class="unknown")
                        advance_candidate(tracker)
                        write_execution_artifacts(tracker)
                        update = {
                            "execution_tracker": tracker,
                            "episodic_memory": em.to_list(),
                            "execution_step_count": step + 1,
                            "current_phase": "execution",
                            "selected_exploit": exploit,
                            "total_repeated_actions": em.count_repeats(),
                            "total_tokens_in": acc_tokens_in,
                            "total_tokens_out": acc_tokens_out,
                            "total_tokens": acc_tokens_in + acc_tokens_out,
                            "total_llm_requests": acc_requests,
                            "total_invalid_commands": acc_invalid,
                            "retry_spent": retry_spent,
                            "phase_timestamps": phase_timestamps,
                            "spent_tokens": acc_tokens_in + acc_tokens_out,
                            "spent_steps": em.total_steps(),
                            "lport": selected_lport,
                        }
                        return update
                except Exception as exc:
                    logger.warning("Execution LLM fallback failed: %s", exc)
                    mark_terminal_failure(tracker, candidate_id, status="skipped", failure_class="unknown")
                    advance_candidate(tracker)
                    continue
            else:
                mark_terminal_failure(tracker, candidate_id, status="failed", failure_class="unknown")
                advance_candidate(tracker)
                continue

        commands = list(result.get("rendered_commands", []))
        command_index = int(tracker.get("current_command_index", 0) or 0)
        if command_index >= len(commands):
            advance_candidate(tracker)
            continue

        command = commands[command_index]
        timeout = int(exec_cfg.get("command_timeout", 120) or 120)
        set_candidate_status(tracker, candidate_id, status="running", failure_class="none")
        t_tool = time.time()
        output, outcome = _run_shell_command(command, timeout=timeout)
        classification = classify_output(
            output,
            success_indicators=preflight.success_indicators,
            failure_indicators=preflight.failure_indicators,
        )
        result["attempt_count"] = int(result.get("attempt_count", 0) or 0) + 1
        append_attempt(
            tracker,
            candidate_id,
            stage="command",
            command=command,
            outcome=classification.get("status", outcome),
            output=output,
            failure_class=classification.get("failure_class", "unknown"),
        )
        _log_episode(
            em,
            phase="execution",
            action_type="tool_call",
            command=command,
            args={"command": command, "timeout": timeout, "mode": "execution"},
            output=output,
            outcome=classification.get("status", outcome),
            error_message="" if classification.get("status") == "success" else classification.get("failure_class", outcome),
        )
        slog.tool_event(
            "execution",
            "run_shell",
            command=command,
            outcome=classification.get("status", outcome),
            blocked=classification.get("status") == "blocked",
            duration_ms=(time.time() - t_tool) * 1000,
            step=step,
            candidate_id=candidate_id,
        )
        if classification.get("status") == "blocked":
            acc_invalid += 1
        retry_spent += 1

        if classification.get("status") in {"success", "uncertain"}:
            verified, verification_command, proof = _verify_candidate(exploit, preflight, result, em, exec_cfg)
            if verified:
                artifact = _build_session_artifact(exploit, verification_command, proof)
                mark_success(
                    tracker,
                    candidate_id,
                    verification_command=verification_command,
                    proof=proof,
                )
                write_execution_artifacts(tracker)
                phase_timestamps["execution_success_time"] = time.time()
                update = {
                    "execution_tracker": tracker,
                    "episodic_memory": em.to_list(),
                    "execution_step_count": step + 1,
                    "execution_success": True,
                    "execution_summary": f"Execution succeeded with {exploit.get('name', candidate_id)}.",
                    "session_artifact": artifact,
                    "current_phase": "done",
                    "selected_exploit": exploit,
                    "total_repeated_actions": em.count_repeats(),
                    "total_tokens_in": acc_tokens_in,
                    "total_tokens_out": acc_tokens_out,
                    "total_tokens": acc_tokens_in + acc_tokens_out,
                    "total_llm_requests": acc_requests,
                    "total_invalid_commands": acc_invalid,
                    "retry_spent": retry_spent,
                    "phase_timestamps": phase_timestamps,
                    "spent_tokens": acc_tokens_in + acc_tokens_out,
                    "spent_steps": em.total_steps(),
                    "lport": selected_lport,
                }
                return update
            classification = {"status": "failed", "failure_class": "unknown", "matched": "verify_failed"}

        failure_class = classification.get("failure_class", "unknown")
        if _should_retry_same_command(result, failure_class, exec_cfg):
            set_candidate_status(tracker, candidate_id, status="ready", failure_class=failure_class)
        elif (
            failure_class == "unknown"
            and not result.get("llm_fallback_used")
            and int(exec_cfg.get("llm_fallback_attempts", 1) or 1) > 0
            and command_index + 1 >= len(commands)
        ):
            tracker["current_command_index"] = len(commands)
            set_candidate_status(tracker, candidate_id, status="ready", failure_class=failure_class)
        else:
            tracker["current_command_index"] = command_index + 1
            if tracker["current_command_index"] >= len(commands):
                terminal_status = "blocked" if failure_class == "missing_dependency" else "failed"
                mark_terminal_failure(tracker, candidate_id, status=terminal_status, failure_class=failure_class)
                advance_candidate(tracker)
            else:
                set_candidate_status(tracker, candidate_id, status="ready", failure_class=failure_class)

        write_execution_artifacts(tracker)
        update = {
            "execution_tracker": tracker,
            "episodic_memory": em.to_list(),
            "execution_step_count": step + 1,
            "current_phase": "execution",
            "selected_exploit": exploit,
            "total_repeated_actions": em.count_repeats(),
            "total_tokens_in": acc_tokens_in,
            "total_tokens_out": acc_tokens_out,
            "total_tokens": acc_tokens_in + acc_tokens_out,
            "total_llm_requests": acc_requests,
            "total_invalid_commands": acc_invalid,
            "retry_spent": retry_spent,
            "phase_timestamps": phase_timestamps,
            "spent_tokens": acc_tokens_in + acc_tokens_out,
            "spent_steps": em.total_steps(),
            "lport": selected_lport,
        }
        return update


def route_execution(state: PentestState) -> str:
    """Conditional edge after execution node."""
    if state.get("current_phase") == "done":
        return "end"
    if state.get("execution_step_count", 0) >= state.get("execution_max_steps", 30):
        logger.warning("Execution hit max steps — forcing end")
        return "end"
    if state.get("execution_success"):
        return "end"
    return "execution"
