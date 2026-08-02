"""
Critic node for Phase 2.
"""

from __future__ import annotations

import json
import time
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from src.config import get_config
from src.memory.decision import DecisionMemory
from src.memory.episodic import EpisodicMemory
from src.retrieval import RetrievalBundle
from src.state import PentestState, runtime_exceeded
from src.utils.json_parser import require_json
from src.utils.structured_logger import extract_token_usage, get_structured_logger

from .shared import (
    hypothesis_runtime_cfg,
    log_stage,
    persist_bundle_artifacts,
    shortlist_candidate_ids,
)

slog = get_structured_logger()

_CRITIC_SYSTEM = """You are the Critic Agent for a penetration-testing hypothesis pipeline.
Decide whether the current shortlist and derived hypotheses are good enough to send to planning.

Rules:
- Prefer pass only when the evidence is coherent and at least one candidate is actionable.
- Use need_more_recon when missing version/platform/CPE evidence is the real blocker.
- Use rework_hypothesis only when the evidence is mostly sufficient but the derived hypotheses are poorly filtered or inconsistent.
- Use best_effort_pass only when the shortlist is usable enough and budget pressure should force progress.
- Never invent candidate IDs.

Return JSON only with keys:
{
  "verdict": "pass|need_more_recon|rework_hypothesis|best_effort_pass",
  "approved_candidate_ids": ["candidate ids to keep"],
  "rejected_candidate_ids": ["candidate ids to drop"],
  "issues": ["short issue strings"],
  "recon_requests": ["specific recon asks"],
  "reason": "one short sentence"
}
"""


def _shortlist_maps(bundle: RetrievalBundle) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    shortlist = list(bundle.shortlist)
    assessments = {item.get("candidate_id", ""): item for item in bundle.assessments}
    authoritative = {item.get("cve_id", ""): item for item in bundle.authoritative_records}
    poc_by_cve: dict[str, list[dict[str, Any]]] = {}
    for item in bundle.poc_candidates:
        poc_by_cve.setdefault(item.get("cve_id", ""), []).append(item)
    return shortlist, assessments, authoritative, poc_by_cve


def _classify_shortlist(bundle: RetrievalBundle) -> dict[str, Any]:
    shortlist, assessments, authoritative, poc_by_cve = _shortlist_maps(bundle)
    strong: list[dict[str, Any]] = []
    weak: list[dict[str, Any]] = []
    version_unknown: list[dict[str, Any]] = []
    for item in shortlist:
        cve_id = item.get("cve_id", "")
        candidate_id = item.get("candidate_id", "")
        assessment = assessments.get(candidate_id, {})
        authority = authoritative.get(cve_id, {})
        source = str(authority.get("source", ""))
        has_authority = source in {"vendor", "kev", "cvemap", "nvd"}
        version_match = assessment.get("version_match", "unknown")
        hard_mismatch = "no" in {
            version_match,
            assessment.get("cpe_match", "unknown"),
            assessment.get("platform_match", "unknown"),
            assessment.get("network_match", "unknown"),
        }
        if item.get("source") == "google":
            sibling_sources = {
                entry.get("source")
                for entry in poc_by_cve.get(cve_id, [])
                if entry.get("candidate_id") != candidate_id
            }
            if sibling_sources.intersection({"github", "exploitdb"}):
                weak.append(item)
                continue
        if has_authority and assessment.get("verdict") == "strong" and version_match == "yes" and not hard_mismatch:
            strong.append(item)
        else:
            weak.append(item)
            if version_match != "yes":
                version_unknown.append(item)
    return {
        "shortlist": shortlist,
        "strong": strong,
        "weak": weak,
        "version_unknown": version_unknown,
    }


def _deterministic_fast_path(state: PentestState, bundle: RetrievalBundle) -> dict[str, Any] | None:
    hypotheses = list(state.get("vuln_hypotheses", []))
    shortlist = list(bundle.shortlist)
    shortlist_ids = shortlist_candidate_ids(shortlist)
    retrieval_status = str(state.get("retrieval_status", "") or "")
    followup_count = int(state.get("phase2_followup_count", 0) or 0)
    followup_max = int(state.get("phase2_followup_max", 2) or 2)
    service_exhausted = bool(state.get("service_exhausted", False))

    if retrieval_status == "query_invalid":
        return {
            "verdict": "exhausted",
            "approved_candidate_ids": [],
            "rejected_candidate_ids": [],
            "issues": ["retrieval_query_invalid"],
            "recon_requests": [],
            "reason": "Retrieval query construction failed. Normalized fingerprint could not produce valid search queries.",
        }

    if retrieval_status == "dataset_missing":
        return {
            "verdict": "exhausted",
            "approved_candidate_ids": [],
            "rejected_candidate_ids": [],
            "issues": ["dataset_benchmark_cache_missing"],
            "recon_requests": [],
            "reason": "Curated benchmark CVE cache not found. Check dataset configuration.",
        }

    if retrieval_status == "backend_failed":
        if shortlist:
            return {
                "verdict": "best_effort_pass",
                "approved_candidate_ids": shortlist_ids,
                "rejected_candidate_ids": [],
                "issues": ["retrieval_backend_failed"],
                "recon_requests": [],
                "reason": "Retrieval backend failed; proceeding with the current shortlist.",
            }
        # backend_failed without shortlist — rotate to next non-exhausted service
        exhausted_keys = set(state.get("phase2_exhausted_service_keys", []))
        target_services = list(state.get("target_services", []) or [])
        has_next = any(
            str(svc.get("service_key") or svc.get("name", "")) not in exhausted_keys
            for svc in target_services
        )
        if has_next:
            return {
                "verdict": "need_more_recon",
                "approved_candidate_ids": [],
                "rejected_candidate_ids": [],
                "issues": ["retrieval_backend_failed"],
                "recon_requests": [],
                "reason": "Retrieval backend failed; rotating to next service.",
            }
        return {
            "verdict": "exhausted",
            "approved_candidate_ids": [],
            "rejected_candidate_ids": [],
            "issues": ["retrieval_backend_failed"],
            "recon_requests": [],
            "reason": "Retrieval backend failed and all services exhausted.",
        }

    if service_exhausted:
        if shortlist:
            return {
                "verdict": "best_effort_pass",
                "approved_candidate_ids": shortlist_ids,
                "rejected_candidate_ids": [],
                "issues": ["service_rotation_exhausted"],
                "recon_requests": [],
                "reason": "Service follow-ups exhausted; proceeding with the current shortlist.",
            }
        return {
            "verdict": "exhausted",
            "approved_candidate_ids": [],
            "rejected_candidate_ids": [],
            "issues": ["service_rotation_exhausted"],
            "recon_requests": [],
            "reason": "All target services exhausted their follow-up budget with no usable shortlist.",
        }

    if followup_count >= followup_max:
        if shortlist:
            return {
                "verdict": "best_effort_pass",
                "approved_candidate_ids": shortlist_ids,
                "rejected_candidate_ids": [],
                "issues": ["followup_budget_exhausted"],
                "recon_requests": [],
                "reason": "Phase 2 follow-up limit reached; proceeding with the current shortlist.",
            }
        return {
            "verdict": "need_more_recon",
            "approved_candidate_ids": [],
            "rejected_candidate_ids": shortlist_ids,
            "issues": ["followup_budget_exhausted"],
            "recon_requests": ["rotate to the next target service for further investigation"],
            "reason": "Phase 2 follow-up limit reached with no usable shortlist.",
        }

    if state.get("budget_exhausted") and state.get("budget_exhaust_phase") in {"recon", "hypothesis"}:
        if shortlist:
            return {
                "verdict": "best_effort_pass",
                "approved_candidate_ids": shortlist_ids,
                "rejected_candidate_ids": [],
                "issues": ["budget_exhausted"],
                "recon_requests": [],
                "reason": "Budget exhausted during Phase 2; proceeding with the current shortlist.",
            }
        return {
            "verdict": "exhausted",
            "approved_candidate_ids": [],
            "rejected_candidate_ids": [],
            "issues": ["budget_exhausted"],
            "recon_requests": [],
            "reason": "Budget exhausted before Phase 2 produced a shortlist.",
        }
    if not hypotheses and not shortlist:
        if retrieval_status in {"empty", "no_match"}:
            return {
                "verdict": "exhausted",
                "approved_candidate_ids": [],
                "rejected_candidate_ids": [],
                "issues": ["retrieval_returned_no_cves"],
                "recon_requests": [],
                "reason": (
                    f"CVE retrieval returned no authoritative records for this target's services (status={retrieval_status}). "
                    "Additional recon cannot resolve an empty CVE database response; terminating Phase 2."
                ),
            }
        if retrieval_status == "backend_failed":
            return {
                "verdict": "need_more_recon",
                "approved_candidate_ids": [],
                "rejected_candidate_ids": [],
                "issues": ["retrieval_backend_failed_no_shortlist"],
                "recon_requests": ["retry CVE retrieval or switch to backup data source"],
                "reason": "Retrieval backend failed before Phase 2 produced a shortlist.",
            }
        return {
            "verdict": "need_more_recon",
            "approved_candidate_ids": [],
            "rejected_candidate_ids": [],
            "issues": ["no_hypotheses"],
            "recon_requests": ["collect exact version, banner, or CPE evidence for the exposed service"],
            "reason": "No vulnerability hypotheses generated. Need more recon data.",
        }

    classified = _classify_shortlist(bundle)
    strong = classified["strong"]
    classified["weak"]
    version_unknown = classified["version_unknown"]

    if shortlist and len(shortlist) == 1 and not strong:
        issue = "confirmed version evidence missing" if version_unknown else "single weak shortlist candidate"
        return {
            "verdict": "need_more_recon",
            "approved_candidate_ids": [],
            "rejected_candidate_ids": shortlist_ids,
            "issues": [issue],
            "recon_requests": ["confirm exact service version, platform, and CPE before exploit planning"],
            "reason": "The only surviving shortlist candidate is too weak to plan against.",
        }
    if not shortlist and hypotheses:
        strong_hypotheses = [
            item for item in hypotheses
            if len(item.get("evidence_chain", [])) >= 2 and float(item.get("confidence", 0.0) or 0.0) >= 0.3
        ]
        if not strong_hypotheses:
            return {
                "verdict": "need_more_recon",
                "approved_candidate_ids": [],
                "rejected_candidate_ids": [],
                "issues": ["weak_hypotheses"],
                "recon_requests": ["improve version, CPE, or platform evidence before retrying Phase 2"],
                "reason": "All derived hypotheses are weak and lack a usable shortlist.",
            }
    if shortlist and not strong and version_unknown:
        return {
            "verdict": "need_more_recon",
            "approved_candidate_ids": [],
            "rejected_candidate_ids": shortlist_ids,
            "issues": ["version_not_confirmed"],
            "recon_requests": ["confirm exact version and platform evidence for the shortlisted target service"],
            "reason": "No strong authoritative candidate with confirmed version support survived Phase 2.",
        }
    if shortlist and not strong and len(shortlist) <= 1:
        return {
            "verdict": "need_more_recon",
            "approved_candidate_ids": [],
            "rejected_candidate_ids": shortlist_ids,
            "issues": ["no_strong_candidate"],
            "recon_requests": ["collect more precise recon evidence for candidate filtering"],
            "reason": "No strong candidate survived the shortlist filter.",
        }
    if shortlist and strong and len(shortlist) == 1:
        assessments_map = {item.get("candidate_id", ""): item for item in bundle.assessments}
        single = strong[0]
        single_id = single.get("candidate_id", "")
        single_assessment = assessments_map.get(single_id, {})
        single_reasons = single_assessment.get("reasons", [])
        has_platform_conflict = any(
            r.startswith("snippet_platform=no") for r in single_reasons
        )
        if has_platform_conflict:
            return {
                "verdict": "need_more_recon",
                "approved_candidate_ids": [],
                "rejected_candidate_ids": shortlist_ids,
                "issues": ["single_candidate_platform_conflict"],
                "recon_requests": [
                    "confirm target platform before exploiting; "
                    "snippet target assumptions conflict with fingerprint",
                ],
                "reason": (
                    "The only strong candidate has a platform conflict "
                    "between snippet assumptions and target fingerprint."
                ),
            }
        return {
            "verdict": "pass",
            "approved_candidate_ids": shortlist_ids,
            "rejected_candidate_ids": [],
            "issues": [],
            "recon_requests": [],
            "reason": "A single strong authoritative candidate survived with confirmed version support.",
        }
    return None



def _llm_critic_report(
    state: PentestState,
    bundle: RetrievalBundle,
    max_rework_rounds: int,
) -> tuple[dict[str, Any] | None, int, int]:
    cfg = get_config()
    runtime_cfg = hypothesis_runtime_cfg(state)
    critic_model = runtime_cfg["critic"]["model"]
    llm = cfg.get_llm(critic_model)
    normalized = json.dumps(bundle.normalized_evidence[:10], indent=2)
    hypotheses = json.dumps(state.get("vuln_hypotheses", [])[:10], indent=2)
    shortlist = json.dumps(bundle.shortlist[:10], indent=2)
    response = llm.invoke([
        SystemMessage(content=_CRITIC_SYSTEM),
        HumanMessage(content=(
            f"Current rework count: {int(state.get('hypothesis_rework_count', 0) or 0)} / {max_rework_rounds}\n\n"
            f"Shortlist:\n{shortlist}\n\n"
            f"Normalized evidence:\n{normalized}\n\n"
            f"Derived hypotheses:\n{hypotheses}\n"
        )),
    ], stream=False)
    tokens_in, tokens_out = extract_token_usage(response)
    parsed, error = require_json(
        getattr(response, "content", "") or "",
        keys=["verdict", "approved_candidate_ids", "rejected_candidate_ids", "issues", "recon_requests", "reason"],
    )
    if parsed is None:
        parsed = {
            "verdict": "need_more_recon",
            "approved_candidate_ids": [],
            "rejected_candidate_ids": shortlist_candidate_ids(bundle.shortlist),
            "issues": [error or "critic_parse_failed"],
            "recon_requests": ["collect more target evidence before planning"],
            "reason": "Critic response was invalid JSON; defaulting to conservative recon request.",
        }
    return parsed, tokens_in, tokens_out


def _sanitize_report(
    report: dict[str, Any],
    bundle: RetrievalBundle,
    state: PentestState,
    *,
    classified: dict[str, Any],
    max_rework_rounds: int,
) -> dict[str, Any]:
    valid_ids = set(shortlist_candidate_ids(bundle.shortlist))
    strong_ids = {item.get("candidate_id", "") for item in classified["strong"]}
    shortlist_ids = shortlist_candidate_ids(bundle.shortlist)
    approved = [item for item in report.get("approved_candidate_ids", []) if item in valid_ids]
    rejected = [item for item in report.get("rejected_candidate_ids", []) if item in valid_ids]
    verdict = str(report.get("verdict", "need_more_recon"))

    if verdict not in {"pass", "need_more_recon", "rework_hypothesis", "best_effort_pass", "exhausted"}:
        verdict = "need_more_recon"
    if verdict in {"pass", "best_effort_pass"} and not approved:
        approved = [item for item in shortlist_ids if item in strong_ids] or shortlist_ids
    if verdict == "need_more_recon" and not rejected:
        rejected = shortlist_ids

    rework_count = int(state.get("hypothesis_rework_count", 0) or 0)
    if verdict == "rework_hypothesis" and rework_count >= max_rework_rounds:
        verdict = "best_effort_pass" if shortlist_ids else "need_more_recon"
        if verdict == "best_effort_pass" and not approved:
            approved = shortlist_ids

    return {
        "verdict": verdict,
        "approved_candidate_ids": approved,
        "rejected_candidate_ids": rejected,
        "issues": list(report.get("issues", []))[:8],
        "recon_requests": list(report.get("recon_requests", []))[:6],
        "reason": str(report.get("reason", "") or "No reason provided."),
    }


def _next_non_exhausted_service(
    target_services: list[dict], current_index: int, exhausted_keys: list[str],
) -> int | None:
    """Find the next service whose key is not in exhausted_keys. Returns None if all exhausted."""
    exhausted = set(exhausted_keys)
    for offset in range(1, len(target_services) + 1):
        idx = (current_index + offset) % len(target_services)
        svc = target_services[idx]
        key = str(svc.get("service_key") or svc.get("name", ""))
        if key not in exhausted:
            return idx
    return None


def _phase2_stop_reason(base_reason: str, *, terminal_reason: str | None = None) -> str:
    """Compose a human-readable terminal reason for Phase 2 exits."""
    summary = (terminal_reason or base_reason or "Phase 2 terminated.").strip()
    base = (base_reason or "").strip()
    if base and base not in summary:
        return f"{summary} Last critic reason: {base}"
    return summary


def _apply_critic_report(
    state: PentestState,
    bundle: RetrievalBundle,
    report: dict[str, Any],
    llm_tokens_in: int,
    llm_tokens_out: int,
    llm_used: bool,
) -> dict[str, Any]:
    em = EpisodicMemory.from_list(state.get("episodic_memory", []))
    dm = DecisionMemory.from_list(state.get("decision_memory", []))
    vlog = list(state.get("verification_log", []))
    phase_timestamps = dict(state.get("phase_timestamps", {}))
    latest = dm.get_latest()
    hypotheses = list(state.get("vuln_hypotheses", []))

    approved_ids = set(report.get("approved_candidate_ids", []))
    if approved_ids:
        bundle.shortlist = [item for item in bundle.shortlist if item.get("candidate_id") in approved_ids]
        hypotheses = [item for item in hypotheses if item.get("candidate_id") in approved_ids]

    report["approved_candidate_ids"] = shortlist_candidate_ids(bundle.shortlist)
    bundle.critic_report = {
        **report,
        "llm_used": llm_used,
        "tokens_in": llm_tokens_in,
        "tokens_out": llm_tokens_out,
        "timestamp": time.time(),
    }

    log_stage(
        em,
        "critic_review",
        f"{report['verdict']} with {len(report['approved_candidate_ids'])} approved candidate(s)",
        action_type="verifier_check",
    )
    verdict_entry = {
        "verdict": report["verdict"],
        "reason": report["reason"],
        "phase": "hypothesis",
        "issues": list(report.get("issues", [])),
        "recon_requests": list(report.get("recon_requests", [])),
        "approved_candidate_ids": list(report.get("approved_candidate_ids", [])),
        "rejected_candidate_ids": list(report.get("rejected_candidate_ids", [])),
        "timestamp": time.time(),
    }
    vlog.append(verdict_entry)

    update: dict[str, Any] = {
        "retrieval_bundle": bundle.to_dict(),
        "vuln_hypotheses": hypotheses,
        "cve_list": [item.get("cve_id", "") for item in hypotheses],
        "verification_log": vlog,
        "episodic_memory": em.to_list(),
        "decision_memory": dm.to_list(),
        "phase_timestamps": phase_timestamps,
        "spent_steps": em.total_steps(),
        "phase2_route": "",
        "current_phase": "hypothesis",
        "total_tokens_in": int(state.get("total_tokens_in", 0) or 0) + llm_tokens_in,
        "total_tokens_out": int(state.get("total_tokens_out", 0) or 0) + llm_tokens_out,
        "total_tokens": int(state.get("total_tokens", 0) or 0) + llm_tokens_in + llm_tokens_out,
        "total_llm_requests": int(state.get("total_llm_requests", 0) or 0) + (1 if llm_used else 0),
    }

    if report["verdict"] in {"pass", "best_effort_pass"}:
        if latest and latest.phase == "hypothesis":
            dm.mark_outcome(latest.step, "validated")
            update["decision_memory"] = dm.to_list()
        phase_timestamps["hypothesis_complete_time"] = time.time()
        update["phase_timestamps"] = phase_timestamps
        update["hypothesis_complete"] = bool(bundle.shortlist)
        update["phase2_route"] = "planning"
        update["current_phase"] = "planning"
        return update

    if report["verdict"] == "need_more_recon":
        if latest and latest.phase == "hypothesis":
            dm.mark_outcome(latest.step, "invalidated")
            update["decision_memory"] = dm.to_list()

        target_services = list(state.get("target_services", []) or [])
        current_index = int(state.get("current_service_index", 0) or 0)
        exhausted_keys = list(state.get("phase2_exhausted_service_keys", []))
        retrieval_status = str(state.get("retrieval_status", "") or "")
        shortlist = list(bundle.shortlist)

        # Force rotation without consuming followup budget when retrieval
        # backend_failed for the active service with no usable shortlist.
        if retrieval_status == "backend_failed" and not shortlist:
            if target_services:
                current_key = str(target_services[current_index].get("service_key") or target_services[current_index].get("name", ""))
                if current_key and current_key not in exhausted_keys:
                    exhausted_keys.append(current_key)
            update["phase2_exhausted_service_keys"] = exhausted_keys

            next_index = _next_non_exhausted_service(target_services, current_index, exhausted_keys)
            if next_index is None:
                update["phase2_route"] = "end"
                update["current_phase"] = "done"
                update["execution_summary"] = _phase2_stop_reason(
                    str(report.get("reason", "") or ""),
                    terminal_reason=(
                        "Phase 2 stopped after retrieval backend failures exhausted all target services."
                    ),
                )
                phase_timestamps["hypothesis_complete_time"] = time.time()
                update["phase_timestamps"] = phase_timestamps
                update["hypothesis_complete"] = False
                update["hypothesis_verifier_blocks"] = int(state.get("hypothesis_verifier_blocks", 0) or 0) + 1
                return update

            update["current_service_index"] = next_index
            update["phase2_followup_count"] = 0
            next_svc = target_services[next_index]
            update["phase2_target_service_key"] = str(next_svc.get("service_key", ""))
            update["phase2_target_port"] = int(next_svc.get("port", 0) or 0)
            update["phase2_target_product"] = str(next_svc.get("name", ""))
            update["keyword"] = str(next_svc.get("name", ""))
            update["app_name"] = str(next_svc.get("name", ""))
            update["app_version"] = str(next_svc.get("version", ""))
            update["phase2_route"] = "hypothesis"
            update["current_phase"] = "hypothesis"
            phase_timestamps["hypothesis_complete_time"] = time.time()
            update["phase_timestamps"] = phase_timestamps
            update["hypothesis_complete"] = False
            update["hypothesis_verifier_blocks"] = int(state.get("hypothesis_verifier_blocks", 0) or 0) + 1
            return update

        # Normal need_more_recon: increment followup count and manage rotation
        phase2_followup_count = int(state.get("phase2_followup_count", 0) or 0) + 1
        phase2_followup_max = int(state.get("phase2_followup_max", 2) or 2)
        update["phase2_followup_count"] = phase2_followup_count

        # Stamp current service identity into phase2_target_* fields
        if target_services:
            svc = target_services[current_index]
            update["phase2_target_service_key"] = str(svc.get("service_key", ""))
            update["phase2_target_port"] = int(svc.get("port", 0) or 0)
            update["phase2_target_product"] = str(svc.get("name", ""))

        if phase2_followup_count >= phase2_followup_max:
            # Mark current service as exhausted
            exhausted_keys = list(state.get("phase2_exhausted_service_keys", []))
            if target_services:
                current_svc = target_services[current_index]
                current_key = str(current_svc.get("service_key") or current_svc.get("name", ""))
                if current_key and current_key not in exhausted_keys:
                    exhausted_keys.append(current_key)
            update["phase2_exhausted_service_keys"] = exhausted_keys
            update["phase2_followup_count"] = 0

            # Find next non-exhausted service
            next_index = _next_non_exhausted_service(target_services, current_index, exhausted_keys)
            if next_index is None:
                # All services exhausted — terminate Phase 2
                update["phase2_route"] = "end"
                update["current_phase"] = "done"
                update["execution_summary"] = _phase2_stop_reason(
                    str(report.get("reason", "") or ""),
                    terminal_reason=(
                        "Phase 2 stopped because all target services exhausted their follow-up budget with no usable shortlist."
                    ),
                )
                phase_timestamps["hypothesis_complete_time"] = time.time()
                update["phase_timestamps"] = phase_timestamps
                update["hypothesis_complete"] = False
                update["hypothesis_verifier_blocks"] = int(state.get("hypothesis_verifier_blocks", 0) or 0) + 1
                return update

            # Rotate to next non-exhausted service
            update["current_service_index"] = next_index
            next_svc = target_services[next_index]
            update["phase2_target_service_key"] = str(next_svc.get("service_key", ""))
            update["phase2_target_port"] = int(next_svc.get("port", 0) or 0)
            update["phase2_target_product"] = str(next_svc.get("name", ""))
            # Recompute keyword/app_name/app_version from the next service
            update["keyword"] = str(next_svc.get("name", ""))
            update["app_name"] = str(next_svc.get("name", ""))
            update["app_version"] = str(next_svc.get("version", ""))
            update["phase2_route"] = "hypothesis"
            update["current_phase"] = "hypothesis"
        else:
            # Still have follow-up budget — request targeted recon
            update["phase2_route"] = "recon"
            update["current_phase"] = "recon"

        phase_timestamps["hypothesis_complete_time"] = time.time()
        update["phase_timestamps"] = phase_timestamps
        update["hypothesis_complete"] = False
        update["hypothesis_verifier_blocks"] = int(state.get("hypothesis_verifier_blocks", 0) or 0) + 1
        return update

    if report["verdict"] == "rework_hypothesis":
        update["hypothesis_complete"] = False
        update["hypothesis_rework_count"] = int(state.get("hypothesis_rework_count", 0) or 0) + 1
        return update

    if latest and latest.phase == "hypothesis":
        dm.mark_outcome(latest.step, "invalidated")
        update["decision_memory"] = dm.to_list()
    update["hypothesis_complete"] = False
    update["phase2_route"] = "end"
    update["current_phase"] = "done"
    update["execution_summary"] = _phase2_stop_reason(str(report.get("reason", "") or ""))
    return update


def critic_agent_node(state: PentestState) -> dict[str, Any]:
    get_config()
    runtime_cfg = hypothesis_runtime_cfg(state)
    max_rework_rounds = int(runtime_cfg["critic"]["max_rework_rounds"] or 0)
    bundle = RetrievalBundle.from_dict(state.get("retrieval_bundle", {}) or {})

    timed_out, timeout_reason = runtime_exceeded(state)
    if timed_out:
        return {
            "phase2_route": "end",
            "current_phase": "done",
            "timeout_exceeded": True,
            "execution_summary": timeout_reason,
        }

    fast_path = _deterministic_fast_path(state, bundle)
    tokens_in = 0
    tokens_out = 0
    llm_used = False

    if fast_path is None:
        parsed, tokens_in, tokens_out = _llm_critic_report(state, bundle, max_rework_rounds)
        fast_path = parsed or {}
        llm_used = True
        slog.node_event(
            "critic_agent",
            phase="hypothesis",
            action="llm_critic_review",
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            outcome="ok",
        )

    classified = _classify_shortlist(bundle)
    report = _sanitize_report(
        fast_path,
        bundle,
        state,
        classified=classified,
        max_rework_rounds=max_rework_rounds,
    )
    update = _apply_critic_report(state, bundle, report, tokens_in, tokens_out, llm_used)
    if state.get("planning_output_dir"):
        persist_bundle_artifacts(state["planning_output_dir"], bundle)
    return update


def route_critic_agent(state: PentestState) -> str:
    bundle = RetrievalBundle.from_dict(state.get("retrieval_bundle", {}) or {})
    verdict = str(bundle.critic_report.get("verdict", ""))
    if verdict == "rework_hypothesis" and not state.get("phase2_route"):
        return "hypothesis_agent"
    return "end"
