"""
Legacy sequential compatibility wrapper for Phase 2.

The runtime graph now uses src.agents.hypothesis_phase, which splits Phase 2 into
retrieval, normalization, hypothesis synthesis, and critic nodes. This module is
kept for direct imports and legacy tests during the transition window.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from src.agents.hypothesis_phase.shared import (
    keyword_from_fingerprints as _shared_keyword_from_fingerprints,
)
from src.config import get_config
from src.memory.decision import Decision, DecisionMemory
from src.memory.episodic import Episode, EpisodicMemory
from src.memory.world_state import WorldState
from src.retrieval import (
    RetrievalBundle,
    apply_cpe_updates,
    assess_candidates,
    build_fingerprints,
    build_shortlist,
    collect_authoritative_records,
    collect_poc_candidates,
    extract_procedure_snippets,
)
from src.retrieval.models import (
    ApplicabilityAssessment,
    AuthoritativeRecord,
    PocCandidate,
    ProcedureSnippet,
    ProductFingerprint,
)
from src.state import PentestState, runtime_exceeded, service_target_key
from src.utils.structured_logger import get_structured_logger

logger = logging.getLogger(__name__)
slog = get_structured_logger()

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@dataclass
class VulnHypothesis:
    service: str
    version: str
    port: int = 0
    cve_id: str = ""
    cve_description: str = ""
    cvss_score: float = 0.0
    evidence_chain: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    prerequisites_status: dict[str, Any] = field(default_factory=dict)
    version_in_range: bool = False
    auth_required: bool = False
    confidence: float = 0.0
    execution_readiness: float = 0.0
    candidate_id: str = ""
    candidate_path: str = ""
    source: str = ""
    assessment_verdict: str = "reject"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _retrieval_cfg(state: PentestState) -> dict[str, Any]:
    cfg = get_config()
    planning = cfg.planning
    defaults = {
        "top_services": 5,
        "per_service_cve_limit": 8,
        "top_cves": 5,
        "github_search_limit": 12,
        "github_clone_top_k": 2,
        "exploitdb_copy_top_k": 2,
        "google_fallback_top_k": 1,
        "enable_google_fallback": True,
        "enable_vendor_refs": True,
        "kev_cache_path": "data/kev/known_exploited_vulnerabilities.json",
        "candidate_cache_dir": "data/retrieval_candidates",
    }
    retrieval = dict(defaults)
    retrieval.update(planning.get("retrieval", {}))
    return retrieval


def _log_stage(em: EpisodicMemory, action: str, summary: str, outcome: str = "success") -> None:
    em.log(Episode(
        step=em.total_steps() + 1,
        timestamp=time.time(),
        phase="hypothesis",
        action_type="retrieval_stage",
        command=action,
        args={},
        output_summary=summary[:500],
        outcome=outcome,
    ))


def _keyword_from_fingerprints(fingerprints: list[ProductFingerprint], state: PentestState) -> tuple[str, str, str]:
    """Legacy wrapper — delegates to the shared scoring logic."""
    return _shared_keyword_from_fingerprints(fingerprints, state)


def _output_dir(target_ip: str, service_key: str, retrieval_cfg: dict[str, Any]) -> str:
    """Build stable, non-nesting artifact path: data/retrieval_candidates/<ip>/<service-key>."""
    safe_ip = "".join(ch if ch.isalnum() or ch in "-._" else "-" for ch in (target_ip or "target"))
    safe_svc = "".join(ch if ch.isalnum() or ch in "-._" else "-" for ch in (service_key or "default"))
    base = retrieval_cfg.get("candidate_cache_dir") or os.path.join("data", "retrieval_candidates")
    if os.path.isabs(base):
        root = base
    else:
        root = os.path.join(_ROOT, base)
    path = os.path.join(root, safe_ip, safe_svc)
    os.makedirs(path, exist_ok=True)
    return path


def _write_json(path: str, payload: Any) -> None:
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
    except Exception as exc:
        logger.warning("Could not write %s: %s", path, exc)





def _derive_hypotheses(
    fingerprints: list[ProductFingerprint],
    records: list[AuthoritativeRecord],
    candidates: list[PocCandidate],
    snippets: list[ProcedureSnippet],
    assessments: list[ApplicabilityAssessment],
    shortlist: list[dict[str, Any]],
) -> list[VulnHypothesis]:
    record_map = {record.cve_id: record for record in records}
    candidate_map = {candidate.candidate_id: candidate for candidate in candidates}
    snippet_map = {snippet.candidate_id: snippet for snippet in snippets}
    assessment_map = {assessment.candidate_id: assessment for assessment in assessments}
    hypotheses: list[VulnHypothesis] = []

    for item in shortlist:
        record = record_map.get(item["cve_id"])
        candidate = candidate_map.get(item["candidate_id"])
        snippet = snippet_map.get(item["candidate_id"])
        assessment = assessment_map.get(item["candidate_id"])
        if record is None or candidate is None or assessment is None:
            continue
        fp = next(
            (
                fingerprint for fingerprint in fingerprints
                if fingerprint.port == item.get("port") and fingerprint.target_ip == item.get("target_ip")
            ),
            fingerprints[0] if fingerprints else None,
        )
        evidence = []
        if fp is not None:
            evidence.extend(fp.evidence[:3])
        evidence.extend(record.evidence[:3])
        evidence.extend(candidate.evidence[:2])
        if snippet is not None and snippet.commands:
            evidence.append(f"Procedure commands extracted: {snippet.commands[0]}")
        prereq_status = {
            "version_match": assessment.version_match,
            "cpe_match": assessment.cpe_match,
            "platform_match": assessment.platform_match,
            "auth_match": assessment.auth_match,
            "network_match": assessment.network_match,
        }
        hypotheses.append(VulnHypothesis(
            service=item.get("service", ""),
            version=item.get("version", ""),
            port=int(item.get("port", 0) or 0),
            cve_id=item["cve_id"],
            cve_description=record.description[:300],
            cvss_score=record.cvss_score,
            evidence_chain=evidence,
            prerequisites=list((snippet.target_assumptions if snippet else [])[:8]),
            prerequisites_status=prereq_status,
            version_in_range=assessment.version_match == "yes",
            auth_required=record.auth_hint == "required",
            confidence=float(item.get("score", assessment.score)),
            execution_readiness=round(float(item.get("score", assessment.score)) * (0.9 if assessment.procedure_ready else 0.6), 3),
            candidate_id=candidate.candidate_id,
            candidate_path=candidate.path,
            source=candidate.source,
            assessment_verdict=assessment.verdict,
        ))
    return hypotheses


def hypothesis_node(state: PentestState) -> dict[str, Any]:
    cfg = get_config()
    retrieval_cfg = _retrieval_cfg(state)
    ws = WorldState.from_dict(state.get("world_state", {}))
    em = EpisodicMemory.from_list(state.get("episodic_memory", []))
    dm = DecisionMemory.from_list(state.get("decision_memory", []))
    phase_timestamps = dict(state.get("phase_timestamps", {}))
    shortlist = list((state.get("retrieval_bundle", {}) or {}).get("shortlist", []))

    timed_out, timeout_reason = runtime_exceeded(state)
    if timed_out:
        return {
            "hypothesis_complete": False,
            "current_phase": "done",
            "timeout_exceeded": True,
            "execution_summary": timeout_reason,
            "phase_timestamps": phase_timestamps,
            "decision_memory": dm.to_list(),
            "episodic_memory": em.to_list(),
        }

    fingerprints = build_fingerprints(ws, top_services=int(retrieval_cfg.get("top_services", 5)), state=state)
    _log_stage(em, "fingerprint_normalize", f"normalized {len(fingerprints)} fingerprint(s)")
    ws = apply_cpe_updates(ws, fingerprints)

    keyword, app_name, app_version = _keyword_from_fingerprints(fingerprints, state)
    svc_key = ""
    if fingerprints:
        fp0 = fingerprints[0]
        svc_key = service_target_key(fp0.target_ip, fp0.port, fp0.product)
    output_dir = _output_dir(state.get("target_ip", "target"), svc_key, retrieval_cfg)

    records, retrieval_status = collect_authoritative_records(fingerprints, retrieval_cfg)
    _log_stage(em, "authoritative_retrieve", f"collected {len(records)} authoritative record(s)")

    candidates = collect_poc_candidates(records, output_dir, retrieval_cfg)
    _log_stage(em, "poc_collect", f"collected {len(candidates)} poc candidate(s)")

    snippets = extract_procedure_snippets(candidates, economic_mode=bool(cfg.planning.get("economic_mode", True)))
    _log_stage(em, "procedure_extract", f"extracted {len(snippets)} procedure snippet(s)")

    assessments = assess_candidates(ws, fingerprints, records, candidates, snippets)
    _log_stage(em, "applicability_assess", f"computed {len(assessments)} assessment(s)")

    shortlist = build_shortlist(
        fingerprints,
        records,
        candidates,
        snippets,
        assessments,
        top_cves=int(retrieval_cfg.get("top_cves", 5)),
    )
    _log_stage(em, "shortlist_build", f"shortlisted {len(shortlist)} candidate(s)")

    bundle = RetrievalBundle(
        fingerprints=[item.to_dict() for item in fingerprints],
        authoritative_records=[item.to_dict() for item in records],
        poc_candidates=[item.to_dict() for item in candidates],
        procedure_snippets=[item.to_dict() for item in snippets],
        assessments=[item.to_dict() for item in assessments],
        shortlist=shortlist,
        generated_at=time.time(),
    )

    hypotheses = _derive_hypotheses(fingerprints, records, candidates, snippets, assessments, shortlist)
    if hypotheses:
        top = hypotheses[0]
        dm.record(Decision(
            step=em.total_steps(),
            phase="hypothesis",
            question="Which vulnerabilities to investigate?",
            chosen=top.cve_id,
            alternatives=[item.cve_id for item in hypotheses[1:5]],
            reasoning=(
                f"Selected {top.cve_id} from retrieval shortlist "
                f"(score={top.confidence}, readiness={top.execution_readiness}, source={top.source})"
            ),
            confidence=top.confidence,
        ))

    _write_json(os.path.join(output_dir, "fingerprints.json"), bundle.fingerprints)
    _write_json(os.path.join(output_dir, "authoritative_records.json"), bundle.authoritative_records)
    _write_json(os.path.join(output_dir, "poc_manifest.json"), bundle.poc_candidates)
    _write_json(os.path.join(output_dir, "procedure_manifest.json"), bundle.procedure_snippets)
    _write_json(os.path.join(output_dir, "retrieval_bundle.json"), bundle.to_dict())

    slog.node_event(
        "hypothesis",
        phase="hypothesis",
        action=f"retrieval shortlist {len(shortlist)}",
        outcome="ok" if shortlist else "no_hypotheses",
    )
    phase_timestamps["hypothesis_complete_time"] = time.time()

    update = {
        "keyword": keyword,
        "app_name": app_name,
        "app_version": app_version,
        "planning_output_dir": output_dir,
        "world_state": ws.to_dict(),
        "retrieval_bundle": bundle.to_dict(),
        "vuln_hypotheses": [item.to_dict() for item in hypotheses],
        "hypothesis_complete": True,
        "episodic_memory": em.to_list(),
        "decision_memory": dm.to_list(),
        "cve_list": [item.cve_id for item in hypotheses],
        "phase_timestamps": phase_timestamps,
    }
    return update
