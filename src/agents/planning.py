"""
Planning sub-graph over retrieval-backed shortlist candidates.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from src.config import get_config
from src.memory.decision import Decision, DecisionMemory
from src.memory.episodic import EpisodicMemory
from src.memory.world_state import WorldState

from src.scoring.calculator import build_exploit_plan_from_bundle
from src.state import PentestState, runtime_exceeded
from src.utils.json_parser import extract_json
from src.utils.structured_logger import extract_token_usage, get_structured_logger

slog = get_structured_logger()
logger = logging.getLogger(__name__)

_PLANNER_SYSTEM = """You are a penetration testing Planner.

You do not need to search for more CVEs or exploits. Retrieval has already produced
a shortlist of vetted candidates with evidence and applicability scores.

Your job:
1. Re-order the shortlisted candidates for execution.
2. Prefer strong applicability, better procedure readiness, and lower expected cost.
3. Avoid candidates that appear to depend on missing prerequisites.

Reply in JSON only:
{
  "keyword": "<app or target keyword>",
  "app_name": "<app name>",
  "app_version": "<version or empty>",
  "selected_candidates": ["candidate_id_1", "candidate_id_2"],
  "cve_list": ["CVE-XXXX-YYYY", "..."],
  "exploit_summary": "Brief best-path summary",
  "done": true
}
"""

_SKEPTIC_SYSTEM = """You are a penetration testing Skeptic.
Critique the Planner's proposed ordering using only the shortlist, prior failures,
and the retrieval evidence already collected.

Focus on:
1. Hard mismatches that slipped through.
2. Missing prerequisites or weak procedure readiness.
3. Rabbit holes already invalidated or repeatedly attempted.
4. Whether a lower-ranked candidate is actually safer or cheaper to try first.
"""

_RISK_OFFICER_SYSTEM = """You are a penetration testing Risk Officer.
Decide whether the proposed shortlist ordering is acceptable.

Output JSON only:
{
  "verdict": "APPROVE" or "REJECT",
  "reason": "brief explanation"
}
"""





def _timeout_payload(state: PentestState, *, phase: str, decision_memory: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
    timed_out, timeout_reason = runtime_exceeded(state)
    if not timed_out:
        return None
    payload = {
        "current_phase": "done",
        "timeout_exceeded": True,
        "execution_summary": timeout_reason,
    }
    if decision_memory is not None:
        payload["decision_memory"] = decision_memory
    return payload


def _estimate_candidate_cost(exploit: dict[str, Any]) -> float:
    if exploit.get("estimated_cost") is not None:
        try:
            return round(float(exploit.get("estimated_cost") or 0.0), 3)
        except Exception:
            pass
    file_path = str(exploit.get("file_path", "")).lower()
    name = str(exploit.get("name", "")).lower()
    cost = 1.0
    if "github" in file_path:
        cost += 0.25
    if "exploitdb" in file_path:
        cost += 0.10
    if "google" in file_path or exploit.get("source") == "google":
        cost += 0.35
    if any(token in name for token in ("meterpreter", "msf", "metasploit")):
        cost += 0.40
    if any(token in name for token in ("shell", "rce", "reverse")):
        cost += 0.20
    if any(token in name for token in ("ruby", "perl", "java")):
        cost += 0.15
    if not exploit.get("file_path"):
        cost += 0.20
    return round(cost, 3)


def _match_hypothesis(exploit: dict[str, Any], hypotheses: list[dict[str, Any]]) -> dict[str, Any]:
    candidate_id = exploit.get("candidate_id")
    if candidate_id:
        for hyp in hypotheses:
            if hyp.get("candidate_id") == candidate_id:
                return hyp
    ex_name = str(exploit.get("name", "")).upper()
    for hyp in hypotheses:
        cve_id = str(hyp.get("cve_id", "")).upper()
        if cve_id and cve_id in ex_name:
            return hyp
    return {}


def _assessment_map(state: PentestState) -> dict[str, dict[str, Any]]:
    bundle = state.get("retrieval_bundle", {}) or {}
    return {item.get("candidate_id"): item for item in bundle.get("assessments", []) if item.get("candidate_id")}


def _proposal_from_shortlist(state: PentestState) -> dict[str, Any]:
    shortlist = list((state.get("retrieval_bundle", {}) or {}).get("shortlist", []))
    app_name = state.get("app_name", "")
    app_version = state.get("app_version", "")
    keyword = state.get("keyword", app_name or state.get("target_ip", "target"))
    return {
        "keyword": keyword,
        "app_name": app_name,
        "app_version": app_version,
        "selected_candidates": [item.get("candidate_id") for item in shortlist if item.get("candidate_id")][:5],
        "cve_list": [item.get("cve_id") for item in shortlist if item.get("cve_id")][:5],
        "exploit_summary": "Fallback ordering based on retrieval shortlist.",
        "done": True,
    }


def _failed_attempts_text(state: PentestState) -> str:
    em = EpisodicMemory.from_list(state.get("episodic_memory", []))
    dm = DecisionMemory.from_list(state.get("decision_memory", []))
    lines: list[str] = []
    failed = [episode for episode in em.by_phase("execution") if episode.outcome in ("error", "fail", "blocked")]
    for episode in failed[-5:]:
        lines.append(f"FAILED: {episode.command[:80]} -> {episode.outcome}")
    invalidated = [decision for decision in dm.get_by_phase("planning") if decision.outcome == "invalidated"]
    for decision in invalidated[-5:]:
        lines.append(f"INVALIDATED: {decision.chosen}")
    repeats = em.count_repeats()
    if repeats:
        lines.append(f"Repeated actions detected: {repeats}")
    return "\n".join(lines) if lines else "No prior failed attempts recorded."


def _invoke_llm_json(system_prompt: str, human_prompt: str, model_name: str) -> tuple[dict[str, Any] | None, int, int]:
    cfg = get_config()
    llm = cfg.get_llm(model_name)
    response = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=human_prompt),
    ], stream=False)
    tokens_in, tokens_out = extract_token_usage(response)
    parsed = extract_json(response.content or "")
    return parsed if isinstance(parsed, dict) else None, tokens_in, tokens_out


def planner_node(state: PentestState) -> dict[str, Any]:
    cfg = get_config()
    plan_cfg = cfg.planning
    llm_model = plan_cfg["model"]

    ws = WorldState.from_dict(state.get("world_state", {}))
    shortlist = list((state.get("retrieval_bundle", {}) or {}).get("shortlist", []))
    recon_summary = ws.to_summary() or json.dumps(state.get("port_services", {}), indent=2)
    shortlist_summary = json.dumps(shortlist[:5], indent=2)
    debate_history = list(state.get("debate_history", []))
    app_name = state.get("app_name", plan_cfg.get("app", ""))
    app_version = state.get("app_version", plan_cfg.get("version", ""))
    keyword = state.get("keyword", plan_cfg.get("keyword", app_name))

    timeout_payload = _timeout_payload(state, phase="planning")
    if timeout_payload:
        return timeout_payload

    proposal = None
    t_in = t_out = 0
    if shortlist:
        prompt = (
            f"Recon findings:\n{recon_summary}\n\n"
            f"Shortlist:\n{shortlist_summary}\n\n"
            f"Target app: {app_name or 'unknown'} version {app_version or 'unknown'}.\n"
        )
        if debate_history:
            prompt += f"\nPrevious debate feedback:\n{debate_history[-1]}\n"
        try:
            proposal, t_in, t_out = _invoke_llm_json(_PLANNER_SYSTEM, prompt, llm_model)
        except Exception as exc:
            logger.warning("Planner LLM error, falling back to shortlist ordering: %s", exc)

    if not proposal:
        proposal = _proposal_from_shortlist(state)
    proposal["keyword"] = proposal.get("keyword") or keyword
    proposal["app_name"] = proposal.get("app_name") or app_name
    proposal["app_version"] = proposal.get("app_version") or app_version

    update = {
        "current_proposal": proposal,
        "total_tokens_in": state.get("total_tokens_in", 0) + t_in,
        "total_tokens_out": state.get("total_tokens_out", 0) + t_out,
        "total_tokens": state.get("total_tokens", 0) + t_in + t_out,
        "total_llm_requests": state.get("total_llm_requests", 0) + (1 if t_in or t_out else 0),
    }
    return update


def skeptic_node(state: PentestState) -> dict[str, Any]:
    cfg = get_config()
    plan_cfg = cfg.planning
    proposal = state.get("current_proposal", {})
    shortlist = list((state.get("retrieval_bundle", {}) or {}).get("shortlist", []))
    failed_summary = _failed_attempts_text(state)
    critique = "No shortlist available."
    t_in = t_out = 0
    timeout_payload = _timeout_payload(state, phase="planning")
    if timeout_payload:
        return timeout_payload
    if shortlist:
        prompt = (
            f"Shortlist:\n{json.dumps(shortlist[:5], indent=2)}\n\n"
            f"Proposal:\n{json.dumps(proposal, indent=2)}\n\n"
            f"Prior failures:\n{failed_summary}\n\n"
        )
        try:
            llm = cfg.get_llm(plan_cfg["model"])
            response = llm.invoke([
                SystemMessage(content=_SKEPTIC_SYSTEM),
                HumanMessage(content=prompt),
            ], stream=False)
            critique = response.content or critique
            t_in, t_out = extract_token_usage(response)
            slog.node_event("skeptic", phase="planning", action="critique", tokens_in=t_in, tokens_out=t_out)
        except Exception as exc:
            critique = f"Skeptic fallback: {exc}"
    debate_history = list(state.get("debate_history", []))
    debate_history.append(f"SKEPTIC CRITIQUE:\n{critique}")
    update = {
        "debate_history": debate_history,
        "total_tokens_in": state.get("total_tokens_in", 0) + t_in,
        "total_tokens_out": state.get("total_tokens_out", 0) + t_out,
        "total_tokens": state.get("total_tokens", 0) + t_in + t_out,
        "total_llm_requests": state.get("total_llm_requests", 0) + (1 if t_in or t_out else 0),
    }
    return update


def risk_officer_node(state: PentestState) -> dict[str, Any]:
    cfg = get_config()
    llm_model = cfg.planning["model"]
    proposal = state.get("current_proposal", {})
    shortlist = list((state.get("retrieval_bundle", {}) or {}).get("shortlist", []))
    debate_history = list(state.get("debate_history", []))
    debate_round = state.get("debate_round", 0)
    latest_critique = debate_history[-1] if debate_history else "No critique."
    timeout_payload = _timeout_payload(state, phase="planning")
    if timeout_payload:
        return timeout_payload
    if debate_round >= 2:
        debate_history.append("RISK OFFICER VERDICT: APPROVE (Max rounds reached)")
        update = {
            "debate_history": debate_history,
            "debate_round": debate_round + 1,
            "current_phase": "finalize_planning",
        }
        return update

    prompt = (
        f"Shortlist:\n{json.dumps(shortlist[:5], indent=2)}\n\n"
        f"Proposal:\n{json.dumps(proposal, indent=2)}\n\n"
        f"Critique:\n{latest_critique}\n\n"
    )
    verdict = "APPROVE" if shortlist else "REJECT"
    reason = "Fallback verdict."
    t_in = t_out = 0
    try:
        parsed, t_in, t_out = _invoke_llm_json(_RISK_OFFICER_SYSTEM, prompt, llm_model)
        if parsed:
            verdict = str(parsed.get("verdict", verdict)).upper()
            reason = str(parsed.get("reason", reason))
    except Exception as exc:
        reason = f"Risk Officer fallback: {exc}"
    debate_history.append(f"RISK OFFICER VERDICT: {verdict}\nReason: {reason}")
    update = {
        "debate_history": debate_history,
        "debate_round": debate_round + 1,
        "current_phase": "finalize_planning" if verdict == "APPROVE" else "planner",
        "total_tokens_in": state.get("total_tokens_in", 0) + t_in,
        "total_tokens_out": state.get("total_tokens_out", 0) + t_out,
        "total_tokens": state.get("total_tokens", 0) + t_in + t_out,
        "total_llm_requests": state.get("total_llm_requests", 0) + (1 if t_in or t_out else 0),
    }
    return update


def route_risk_officer(state: PentestState) -> str:
    return "finalize_planning" if state.get("current_phase") == "finalize_planning" else "planner"


def _apply_candidate_priority(
    exploit_plan: list[dict[str, Any]],
    hypotheses: list[dict[str, Any]],
    state: PentestState,
) -> list[dict[str, Any]]:
    if not exploit_plan:
        return []

    repeat_penalty = state.get("total_repeated_actions", 0) * 0.03
    invalid_penalty = state.get("total_invalid_commands", 0) * 0.05
    assessments = _assessment_map(state)

    ranked: list[dict[str, Any]] = []
    for exploit in exploit_plan:
        enriched = dict(exploit)
        hypothesis = _match_hypothesis(enriched, hypotheses)
        assessment = assessments.get(str(enriched.get("candidate_id") or ""), {})
        raw_score = float(enriched.get("score", 0.0) or 0.0)
        applicability = float(assessment.get("score", hypothesis.get("confidence", 0.0) or 0.0) or 0.0)
        readiness = float(
            enriched.get("execution_readiness", hypothesis.get("execution_readiness", 0.0) or (1.0 if assessment.get("procedure_ready") else 0.35))
            or 0.0
        )
        trust = float(enriched.get("trust_score", assessment.get("trust_score", 0.0) or 0.0) or 0.0)
        expected_gain = (
            applicability * 0.55
            + readiness * 0.25
            + trust * 0.20
            + min(raw_score / 100.0, 1.0) * 0.05
        )
        candidate_cost = _estimate_candidate_cost(enriched)
        priority_score = expected_gain - (candidate_cost * 0.18) - repeat_penalty - invalid_penalty
        verdict = assessment.get("verdict", enriched.get("exploitability", "unknown"))
        if verdict == "weak":
            priority_score -= 0.05
        elif verdict == "reject":
            priority_score -= 0.25

        enriched["cve_id"] = enriched.get("cve_id") or hypothesis.get("cve_id", "")
        enriched["candidate_cost"] = candidate_cost
        enriched["expected_gain"] = round(expected_gain, 3)
        enriched["priority_score"] = round(priority_score, 3)
        enriched["applicability_confidence"] = round(applicability, 3)
        enriched["execution_readiness"] = round(readiness, 3)
        ranked.append(enriched)

    ranked.sort(key=lambda item: (item.get("priority_score", 0.0), item.get("score", 0.0)), reverse=True)
    return ranked


def _reorder_by_selected(exploit_plan: list[dict[str, Any]], selected_ids: list[str]) -> list[dict[str, Any]]:
    if not selected_ids:
        return exploit_plan
    index = {candidate_id: pos for pos, candidate_id in enumerate(selected_ids)}
    return sorted(exploit_plan, key=lambda item: (index.get(item.get("candidate_id"), 10_000), -float(item.get("score", 0.0) or 0.0)))


def finalize_planning_node(state: PentestState) -> dict[str, Any]:
    cfg = get_config()
    retrieval_bundle = dict(state.get("retrieval_bundle", {}) or {})
    proposal = dict(state.get("current_proposal", {}) or {})
    em = EpisodicMemory.from_list(state.get("episodic_memory", []))
    dm = DecisionMemory.from_list(state.get("decision_memory", []))
    phase_timestamps = dict(state.get("phase_timestamps", {}))

    timeout_payload = _timeout_payload(state, phase="planning", decision_memory=dm.to_list())
    if timeout_payload:
        return timeout_payload

    exploit_plan = build_exploit_plan_from_bundle(
        retrieval_bundle,
        economic_mode=bool(cfg.planning.get("economic_mode", True)),
    )
    selected_candidates = list(proposal.get("selected_candidates", []))
    exploit_plan = _reorder_by_selected(exploit_plan, selected_candidates)
    exploit_plan = _apply_candidate_priority(exploit_plan, state.get("vuln_hypotheses", []), state)
    exploit_plan = _reorder_by_selected(exploit_plan, selected_candidates)

    output_dir = state.get("planning_output_dir")
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        try:
            with open(os.path.join(output_dir, "exploit_plan.json"), "w", encoding="utf-8") as handle:
                json.dump(exploit_plan, handle, indent=2)
        except Exception as exc:
            logger.warning("Could not write exploit_plan.json: %s", exc)

    if exploit_plan:
        top = exploit_plan[0]
        dm.record(Decision(
            step=em.total_steps(),
            phase="planning",
            question="Which exploit path should we prioritise?",
            chosen=str(top.get("name", "")),
            alternatives=[str(item.get("name", "")) for item in exploit_plan[1:5]],
            reasoning=(
                f"Selected {top.get('name', '')} from retrieval shortlist "
                f"(priority_score={top.get('priority_score', 0)}, expected_gain={top.get('expected_gain', 0)}, "
                f"candidate_cost={top.get('candidate_cost', 0)})"
            ),
            confidence=float(top.get("execution_readiness", top.get("expected_gain", 0.0)) or 0.0),
        ))

    slog.phase_event("planning", "complete", exploits=len(exploit_plan))
    phase_timestamps["planning_complete_time"] = time.time()
    cve_list = [item.get("cve_id", "") for item in exploit_plan if item.get("cve_id")]
    current_phase = "done" if not exploit_plan else "execution"
    update = {
        "keyword": proposal.get("keyword", state.get("keyword", "")),
        "app_name": proposal.get("app_name", state.get("app_name", "")),
        "app_version": proposal.get("app_version", state.get("app_version", "")),
        "cve_list": cve_list,
        "exploit_plan": exploit_plan,
        "planning_complete": bool(exploit_plan),
        "decision_memory": dm.to_list(),
        "current_phase": current_phase,
        "phase_timestamps": phase_timestamps,
    }
    return update


def planning_node(state: PentestState) -> dict[str, Any]:
    working = dict(state)
    shortlist = list((working.get("retrieval_bundle", {}) or {}).get("shortlist", []))
    if not shortlist:
        working["current_phase"] = "done"
        working["planning_complete"] = False
        working["execution_summary"] = "No shortlist available to plan."
        return working

    for _ in range(3):
        working.update(planner_node(working))
        working.update(skeptic_node(working))
        working.update(risk_officer_node(working))
        if route_risk_officer(working) == "finalize_planning":
            break

    working.update(finalize_planning_node(working))
    return working
