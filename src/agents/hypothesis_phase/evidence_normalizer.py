"""
Evidence normalization node for Phase 2.
"""

from __future__ import annotations

import time
from typing import Any

from src.config import get_config
from src.memory.episodic import EpisodicMemory
from src.memory.world_state import WorldState
from src.retrieval import (
    ApplicabilityAssessment,
    AuthoritativeRecord,
    PocCandidate,
    ProcedureSnippet,
    ProductFingerprint,
    RetrievalBundle,
    assess_candidates,
    build_shortlist,
)
from src.state import PentestState, runtime_exceeded
from src.utils.structured_logger import get_structured_logger

from .shared import emit_budget_event, hypothesis_runtime_cfg, log_stage, persist_bundle_artifacts

slog = get_structured_logger()


def _dedupe_shortlist(shortlist: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, int, str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for item in shortlist:
        key = (
            str(item.get("target_ip", "")),
            int(item.get("port", 0) or 0),
            str(item.get("cve_id", "")),
            str(item.get("candidate_id", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _normalize_evidence(
    fingerprints: list[ProductFingerprint],
    records: list[AuthoritativeRecord],
    candidates: list[PocCandidate],
    snippets: list[ProcedureSnippet],
    assessments: list[ApplicabilityAssessment],
) -> list[dict[str, Any]]:
    record_map = {record.cve_id: record for record in records}
    candidate_map = {candidate.candidate_id: candidate for candidate in candidates}
    snippet_map = {snippet.candidate_id: snippet for snippet in snippets}
    candidate_by_cve: dict[str, list[PocCandidate]] = {}
    for candidate in candidates:
        candidate_by_cve.setdefault(candidate.cve_id, []).append(candidate)

    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str, str]] = set()
    for assessment in assessments:
        record = record_map.get(assessment.cve_id)
        candidate = candidate_map.get(assessment.candidate_id)
        snippet = snippet_map.get(assessment.candidate_id)
        if record is None or candidate is None:
            continue
        text = (record.title + " " + record.description).lower()
        fp = next(
            (
                item for item in fingerprints
                if item.product.lower() in text or item.raw_service.lower() in text
            ),
            fingerprints[0] if fingerprints else None,
        )
        if fp is None:
            continue
        key = (fp.target_ip, fp.port, assessment.cve_id, assessment.candidate_id)
        if key in seen:
            continue
        seen.add(key)
        sibling_sources = sorted({
            item.source for item in candidate_by_cve.get(assessment.cve_id, [])
            if item.candidate_id != assessment.candidate_id
        })
        normalized.append({
            "target_ip": fp.target_ip,
            "port": fp.port,
            "service": fp.raw_service,
            "vendor": fp.vendor,
            "product": fp.product,
            "version": fp.version,
            "cve_id": assessment.cve_id,
            "candidate_id": assessment.candidate_id,
            "source": candidate.source,
            "path": candidate.path,
            "locator": candidate.locator,
            "title": record.title,
            "version_match": assessment.version_match,
            "cpe_match": assessment.cpe_match,
            "platform_match": assessment.platform_match,
            "auth_match": assessment.auth_match,
            "network_match": assessment.network_match,
            "procedure_ready": assessment.procedure_ready,
            "hard_mismatch": "no" in {
                assessment.version_match,
                assessment.cpe_match,
                assessment.platform_match,
                assessment.network_match,
            },
            "version_unknown": assessment.version_match != "yes",
            "google_only": candidate.source == "google" and not {"github", "exploitdb"}.intersection(sibling_sources),
            "sibling_sources": sibling_sources,
            "trust_score": assessment.trust_score,
            "estimated_cost": assessment.estimated_cost,
            "score": assessment.score,
            "verdict": assessment.verdict,
            "commands": list((snippet.commands if snippet else [])[:5]),
            "dependencies": list((snippet.dependencies if snippet else [])[:5]),
            "reasons": list(assessment.reasons),
        })
    normalized.sort(key=lambda item: (item["verdict"] == "strong", item["score"], item["trust_score"]), reverse=True)
    return normalized


def evidence_normalizer_node(state: PentestState) -> dict[str, Any]:
    cfg = get_config()
    runtime_cfg = hypothesis_runtime_cfg(state)
    retrieval_cfg = runtime_cfg["retrieval"]
    ws = WorldState.from_dict(state.get("world_state", {}))
    em = EpisodicMemory.from_list(state.get("episodic_memory", []))
    bundle = RetrievalBundle.from_dict(state.get("retrieval_bundle", {}) or {})

    timed_out, timeout_reason = runtime_exceeded(state)
    if timed_out:
        return {
            "phase2_route": "end",
            "current_phase": "done",
            "timeout_exceeded": True,
            "execution_summary": timeout_reason,
            "episodic_memory": em.to_list(),
        }

    fingerprints = [ProductFingerprint.from_dict(item) for item in bundle.fingerprints]
    records = [AuthoritativeRecord.from_dict(item) for item in bundle.authoritative_records]
    candidates = [PocCandidate.from_dict(item) for item in bundle.poc_candidates]
    snippets = [ProcedureSnippet.from_dict(item) for item in bundle.procedure_snippets]

    assessments = assess_candidates(ws, fingerprints, records, candidates, snippets)
    log_stage(em, "applicability_assess", f"computed {len(assessments)} assessment(s)")

    shortlist = build_shortlist(
        fingerprints,
        records,
        candidates,
        snippets,
        assessments,
        top_cves=int(retrieval_cfg.get("top_cves", 5)),
    )
    shortlist = _dedupe_shortlist(shortlist)
    log_stage(em, "shortlist_build", f"shortlisted {len(shortlist)} candidate(s)")

    normalized = _normalize_evidence(fingerprints, records, candidates, snippets, assessments)
    bundle.assessments = [item.to_dict() for item in assessments]
    bundle.normalized_evidence = normalized
    bundle.shortlist = shortlist
    bundle.generated_at = bundle.generated_at or time.time()

    if state.get("planning_output_dir"):
        persist_bundle_artifacts(state["planning_output_dir"], bundle)

    slog.node_event(
        "evidence_normalizer",
        phase="hypothesis",
        action=f"normalize evidence shortlist={len(shortlist)}",
        outcome="ok" if shortlist else "no_hypotheses",
    )
    update = {
        "retrieval_bundle": bundle.to_dict(),
        "hypothesis_complete": False,
        "episodic_memory": em.to_list(),
        "phase2_route": "",
        "current_phase": "hypothesis",
    }
    return update
