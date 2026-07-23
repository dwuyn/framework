"""
Retrieval node for Phase 2.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from src.config import get_config
from src.memory.episodic import EpisodicMemory
from src.memory.world_state import WorldState
from src.retrieval import (
    RetrievalBundle,
    apply_cpe_updates,
    build_fingerprints,
    collect_authoritative_records,
    collect_poc_candidates,
    extract_procedure_snippets,
)
from src.state import PentestState, runtime_exceeded
from src.utils.structured_logger import get_structured_logger

from .shared import (
    emit_budget_event,
    hypothesis_runtime_cfg,
    keyword_from_fingerprints,
    log_stage,
    output_dir,
    persist_bundle_artifacts,
)
from src.state import service_target_key

logger = logging.getLogger(__name__)
slog = get_structured_logger()


def retrieval_agent_node(state: PentestState) -> dict[str, Any]:
    cfg = get_config()
    runtime_cfg = hypothesis_runtime_cfg(state)
    retrieval_cfg = runtime_cfg["retrieval"]
    ws = WorldState.from_dict(state.get("world_state", {}))
    em = EpisodicMemory.from_list(state.get("episodic_memory", []))
    phase_timestamps = dict(state.get("phase_timestamps", {}))
    shortlist = list((state.get("retrieval_bundle", {}) or {}).get("shortlist", []))
    phase_timestamps.setdefault("hypothesis_start_time", time.time())
    retrieval_started_at = time.time()

    timed_out, timeout_reason = runtime_exceeded(state)
    if timed_out:
        return {
            "hypothesis_complete": False,
            "phase2_route": "end",
            "current_phase": "done",
            "timeout_exceeded": True,
            "execution_summary": timeout_reason,
            "phase_timestamps": phase_timestamps,
            "episodic_memory": em.to_list(),
        }

    fingerprints = build_fingerprints(ws, top_services=int(retrieval_cfg.get("top_services", 5)), state=state)
    logger.info(
        "Phase 2 retrieval: starting with %d fingerprint(s) from recon",
        len(fingerprints),
    )
    log_stage(em, "fingerprint_normalize", f"normalized {len(fingerprints)} fingerprint(s)")
    ws = apply_cpe_updates(ws, fingerprints)

    # Select the active fingerprint: prefer the one whose IP+port matches
    # phase2_target_service_key; fall back to the first fingerprint.
    phase2_target_key = str(state.get("phase2_target_service_key", "") or "")
    phase2_target_port = int(state.get("phase2_target_port", 0) or 0)
    active_fp = None
    if phase2_target_port and fingerprints:
        for fp in fingerprints:
            if fp.port == phase2_target_port and fp.target_ip == state.get("target_ip", ""):
                active_fp = fp
                break
    if active_fp is None and fingerprints:
        active_fp = fingerprints[0]

    keyword, app_name, app_version = keyword_from_fingerprints(
        [active_fp] if active_fp else fingerprints, state,
    )
    # Build stable, non-nesting artifact path from target IP and active service key.
    # Use phase2_target_service_key if set (matches the target_services inventory);
    # otherwise derive from the active fingerprint.
    svc_key = phase2_target_key
    if not svc_key and active_fp is not None:
        svc_key = service_target_key(active_fp.target_ip, active_fp.port, active_fp.product)
    path = output_dir(state.get("target_ip", "target"), svc_key, retrieval_cfg)

    errors: list[str] = []
    backend_errors: list[str] = []
    retrieval_status = "ok"
    logger.info(
        "Phase 2 retrieval: collecting authoritative records for keyword '%s'",
        keyword or app_name or "target",
    )

    # Bounded retry for backend_failed using live_retrieval_retry_max
    max_retries = max(int(state.get("live_retrieval_retry_max", 1) or 1), 0)
    for attempt in range(1 + max_retries):
        errors.clear()
        try:
            records, retrieval_status = collect_authoritative_records(fingerprints, retrieval_cfg, errors)
        except Exception as exc:
            logger.error("Phase 2 retrieval backend failure (attempt %d/%d): %s",
                         attempt + 1, 1 + max_retries, exc)
            retrieval_status = "backend_failed"
            backend_errors.append(str(exc))
            records = []

        if retrieval_status != "backend_failed":
            break
        if attempt < max_retries:
            logger.info(
                "Retrying retrieval (attempt %d/%d) after backend_failed",
                attempt + 2, 1 + max_retries,
            )
            continue

    if retrieval_status != "backend_failed":
        if not records:
            if retrieval_status not in {"ok", "no_match", "query_invalid", "dataset_missing", "empty"}:
                retrieval_status = "empty" if not errors else "no_match"
        elif errors and retrieval_status == "ok":
            retrieval_status = "ok"
    else:
        logger.warning("Retrieval backend failed after %d attempt(s)", 1 + max_retries)
    logger.info(
        "Phase 2 retrieval: collected %d authoritative record(s), status=%s",
        len(records),
        retrieval_status,
    )
    log_stage(em, "authoritative_retrieve",
              f"collected {len(records)} authoritative record(s), status={retrieval_status}"
              + (f" after {1 + max_retries} attempts" if retrieval_status == "backend_failed" else ""))

    logger.info(
        "Phase 2 retrieval: collecting PoC candidates from authoritative records",
    )
    candidates = collect_poc_candidates(records, path, retrieval_cfg, errors)
    logger.info(
        "Phase 2 retrieval: collected %d PoC candidate(s)",
        len(candidates),
    )
    log_stage(em, "poc_collect", f"collected {len(candidates)} poc candidate(s)")

    logger.info(
        "Phase 2 retrieval: extracting procedure snippets for %d candidate(s)",
        len(candidates),
    )
    snippets = extract_procedure_snippets(
        candidates,
        economic_mode=runtime_cfg["economic_mode"],
        allow_llm_fallback=False,
    )
    logger.info(
        "Phase 2 retrieval: extracted %d procedure snippet(s) in %.1fs",
        len(snippets),
        time.time() - retrieval_started_at,
    )
    log_stage(em, "procedure_extract", f"extracted {len(snippets)} procedure snippet(s)")

    bundle = RetrievalBundle(
        fingerprints=[item.to_dict() for item in fingerprints],
        authoritative_records=[item.to_dict() for item in records],
        poc_candidates=[item.to_dict() for item in candidates],
        procedure_snippets=[item.to_dict() for item in snippets],
        assessments=[],
        normalized_evidence=[],
        shortlist=[],
        critic_report={},
        errors=errors,
        generated_at=time.time(),
    )
    persist_bundle_artifacts(path, bundle)

    slog.node_event(
        "retrieval_agent",
        phase="hypothesis",
        action=f"raw retrieval records={len(records)} candidates={len(candidates)}",
        outcome="ok" if (records or candidates) else "no_candidates",
    )
    update = {
        "keyword": keyword,
        "app_name": app_name,
        "app_version": app_version,
        "planning_output_dir": path,
        "world_state": ws.to_dict(),
        "retrieval_bundle": bundle.to_dict(),
        "retrieval_status": retrieval_status,
        "retrieval_errors": backend_errors,
        "hypothesis_complete": False,
        "hypothesis_rework_count": 0,
        "episodic_memory": em.to_list(),
        "phase_timestamps": phase_timestamps,
        "phase2_route": "",
        "current_phase": "hypothesis",
    }
    # Stamp Phase 2 target identity from the active fingerprint.
    # Use phase2_target_service_key if already set (matches target_services inventory);
    # otherwise derive from the active fingerprint's normalized fields.
    if active_fp is not None:
        update["phase2_target_service_key"] = phase2_target_key or service_target_key(
            active_fp.target_ip, active_fp.port, active_fp.product,
        )
        update["phase2_target_port"] = active_fp.port
        update["phase2_target_product"] = active_fp.product
    return update
