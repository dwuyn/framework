"""
src/state.py
────────────
Shared PentestState that flows through every node of the LangGraph graph.
All inter-agent communication happens via this TypedDict — no files, no
ad-hoc imports of one agent inside another.
"""

from __future__ import annotations

import time
from typing import Annotated, Any, Mapping, Optional, TypedDict

from langgraph.graph.message import add_messages


class PentestState(TypedDict, total=False):
    # ── Target ────────────────────────────────────────────────────────────────
    target_ip: str
    target_port: Optional[str]
    attacker_ip: Optional[str]

    # ── Phase control ─────────────────────────────────────────────────────────
    # "recon" | "hypothesis" | "planning" | "execution" | "done"
    current_phase: str
    phase2_route: str
    error_count: int
    last_error: Optional[str]

    # ── Recon outputs ─────────────────────────────────────────────────────────
    recon_complete: bool
    # {port: {"name": str, "version": str, "accessibility": str}}
    port_services: dict
    os_info: Optional[str]
    recon_step_count: int
    recon_max_steps: int
    target_services: list
    current_service_index: int

    # ── Planning inputs (derived from recon) ──────────────────────────────────
    keyword: str        # CVE ID or app keyword to search
    app_name: str
    app_version: str
    vuln_type: str

    # ── Planning outputs ──────────────────────────────────────────────────────
    cve_list: list        # list[str] of CVE IDs
    # list[dict] — each has: file_path, name, score, source
    exploit_plan: list
    selected_exploit: Optional[dict]
    planning_output_dir: Optional[str]
    planning_complete: bool

    # ── Debate Tracking ───────────────────────────────────────────────────────
    current_proposal: Optional[dict]
    debate_history: list
    debate_round: int

    # ── Execution outputs ─────────────────────────────────────────────────────
    doc_dir: Optional[str]
    execution_step_count: int
    execution_max_steps: int
    execution_success: bool
    execution_summary: Optional[str]
    execution_tracker: dict

    # ── Structured Memory (Layer 1) ───────────────────────────────────────────
    world_state: dict          # serialized WorldState (JSON-safe dict)
    episodic_memory: list      # serialized list[Episode]
    decision_memory: list      # serialized list[Decision]

    # ── Hypothesis outputs (Layer 3) ──────────────────────────────────────────
    retrieval_bundle: dict     # serialized RetrievalBundle
    vuln_hypotheses: list      # list[dict] — serialized VulnHypothesis
    hypothesis_complete: bool
    hypothesis_rework_count: int
    replan_count: int
    replan_max: int
    attempted_cves: list
    attempted_services: list

    # ── Verification tracking (Layer 2) ───────────────────────────────────────
    verification_log: list     # list of verifier verdicts
    verifier_blocks: int       # count of times verifier sent agent back (legacy; prefer per-phase counters)
    recon_verifier_blocks: int
    hypothesis_verifier_blocks: int

    # ── Phase 2 targeted recon control ──────────────────────────────────────
    phase2_followup_count: int
    phase2_followup_max: int
    phase2_target_service_key: str
    phase2_target_port: int
    phase2_target_product: str
    retrieval_status: str          # "ok" | "no_match" | "query_invalid" | "backend_failed" | "dataset_missing" | "empty"
    retrieval_errors: list
    service_exhausted: bool        # True when current service has exhausted follow-ups
    phase2_exhausted_service_keys: list  # list[str] — services whose Phase 2 follow-up budget is spent
    phase2_loop_count: int         # increments each time hypothesis_phase → recon → hypothesis_phase cycles
    phase2_loop_max: int           # hard cap on the above (default 6); forces planning when exceeded

    # ── Dataset mode ───────────────────────────────────────────────────────
    dataset_mode: str           # "" | "curated" | "hybrid" | "live"
    dataset_case_id: str        # dataset case identifier
    benchmark_cve_cache_path: str  # path to curated CVE cache (runtime override)

    # ── Recon budget controls ────────────────────────────────────────────────
    recon_followup_step_budget: int
    recon_command_dedupe_window: int
    live_retrieval_retry_max: int

    # ── Metrics accumulation ──────────────────────────────────────────────────
    total_tokens: int              # total_tokens_in + total_tokens_out
    total_tokens_in: int           # LLM prompt tokens
    total_tokens_out: int          # LLM completion tokens
    total_llm_requests: int
    total_invalid_commands: int
    total_repeated_actions: int
    retry_spent: int

    # ── Timing (for M11 Time-to-Access) ──────────────────────────────────────
    run_start_time: float          # time.time() at pipeline entry
    run_end_time: float            # time.time() at pipeline exit
    # {"recon_start": t, "recon_end": t, "execution_success_time": t, ...}
    phase_timestamps: dict
    max_runtime_seconds: int
    timeout_exceeded: bool

    # ── Session state (Phase 5: Maintaining Access) ───────────────────────────
    session_verified: bool         # True if session confirmed alive post-exploit
    session_privilege_level: Optional[str]  # "user" | "root" | "www-data" | None
    session_alive: bool            # False if session dropped during Phase 5
    session_artifact: Optional[dict]  # verification command + proof for Phase 5
    lport: Optional[str]

    # ── Conversation (append-only) ────────────────────────────────────────────
    # Uses LangGraph's add_messages reducer so updates are always appended
    messages: Annotated[list, add_messages]


def initial_state(
    target_ip: str,
    target_port: str = "",
    attacker_ip: str = "",
    keyword: str = "",
    app_name: str = "",
    app_version: str = "",
    recon_max_steps: int = 12,
    execution_max_steps: int = 30,
    replan_max: int = 3,
    max_runtime_seconds: int = 3600,
) -> PentestState:
    """Build a fresh PentestState with sensible defaults."""
    return PentestState(
        target_ip=target_ip,
        target_port=target_port or None,
        attacker_ip=attacker_ip or None,
        current_phase="recon",
        phase2_route="",
        error_count=0,
        last_error=None,
        recon_complete=False,
        port_services={},
        os_info=None,
        recon_step_count=0,
        recon_max_steps=recon_max_steps,
        target_services=[],
        current_service_index=0,
        keyword=keyword,
        app_name=app_name,
        app_version=app_version,
        vuln_type="",
        cve_list=[],
        exploit_plan=[],
        selected_exploit=None,
        planning_output_dir=None,
        planning_complete=False,
        # Debate
        current_proposal=None,
        debate_history=[],
        debate_round=0,
        doc_dir=None,
        execution_step_count=0,
        execution_max_steps=execution_max_steps,
        execution_success=False,
        execution_summary=None,
        execution_tracker={},
        # Layer 1: Structured memory
        world_state={},
        episodic_memory=[],
        decision_memory=[],
        # Layer 3: Hypothesis
        retrieval_bundle={},
        vuln_hypotheses=[],
        hypothesis_complete=False,
        hypothesis_rework_count=0,
        replan_count=0,
        replan_max=replan_max,
        attempted_cves=[],
        attempted_services=[],
        # Layer 2: Verification
        verification_log=[],
        verifier_blocks=0,
        recon_verifier_blocks=0,
        hypothesis_verifier_blocks=0,
        # Phase 2 targeted recon control
        phase2_followup_count=0,
        phase2_followup_max=2,
        phase2_target_service_key="",
        phase2_target_port=0,
        phase2_target_product="",
        retrieval_status="",
        retrieval_errors=[],
        service_exhausted=False,
        phase2_exhausted_service_keys=[],
        phase2_loop_count=0,
        phase2_loop_max=6,
        # Dataset mode
        dataset_mode="",
        dataset_case_id="",
        benchmark_cve_cache_path="",
        # Recon budget controls
        recon_followup_step_budget=3,
        recon_command_dedupe_window=10,
        live_retrieval_retry_max=1,
        # Metrics
        total_tokens=0,
        total_tokens_in=0,
        total_tokens_out=0,
        total_llm_requests=0,
        total_invalid_commands=0,
        total_repeated_actions=0,
        retry_spent=0,
        # Timing
        run_start_time=0.0,
        run_end_time=0.0,
        phase_timestamps={},
        max_runtime_seconds=max_runtime_seconds,
        timeout_exceeded=False,
        # Session
        session_verified=False,
        session_privilege_level=None,
        session_alive=False,
        session_artifact=None,
        lport=None,
        messages=[],
    )


def service_target_key(target_ip: str, port: int | str, service_name: str = "") -> str:
    name = str(service_name or "").strip().lower()
    return f"{str(target_ip or '').strip()}:{int(port or 0)}:{name}"


def runtime_exceeded(state: Mapping[str, Any], now: float | None = None) -> tuple[bool, str]:
    max_runtime = int(state.get("max_runtime_seconds", 0) or 0)
    start = float(state.get("run_start_time", 0.0) or 0.0)
    if max_runtime <= 0 or start <= 0:
        return False, ""
    current = now if now is not None else time.time()
    elapsed = current - start
    if elapsed < max_runtime:
        return False, ""
    minutes = max_runtime // 60 if max_runtime % 60 == 0 else round(max_runtime / 60.0, 1)
    return True, f"Run exceeded max runtime ({minutes} minute limit)."
