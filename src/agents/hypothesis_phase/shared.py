"""
Shared helpers for the modular Phase 2 hypothesis pipeline.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from src.config import get_config
from src.memory.decision import Decision, DecisionMemory
from src.memory.episodic import Episode, EpisodicMemory
from src.retrieval.models import (
    ApplicabilityAssessment,
    AuthoritativeRecord,
    PocCandidate,
    ProcedureSnippet,
    ProductFingerprint,
    RetrievalBundle,
)
from src.state import PentestState
from src.utils.structured_logger import get_structured_logger

logger = logging.getLogger(__name__)
slog = get_structured_logger()

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

DEFAULT_RETRIEVAL_CFG: dict[str, Any] = {
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

LOW_SIGNAL_LABELS = {
    "",
    "unknown",
    "generic",
    "tcpwrapped",
    "ssl http",
    "ssl/http",
    "ssl-http",
    "http",
    "https",
    "https-alt",
    "https alt",
    "http-alt",
    "http-proxy",
    "http proxy",
    "socks5",
    "socks4",
    "upnp",
    "n a",
    "n/a",
    "none",
    "sip",
    # Nmap IANA service-name database artifacts — not real product names
    "zeus-admin",
    "zeus_admin",
    "radan-http",
    "radan_http",
    "radan http",
    "blackice-icecap",
    "blackice icecap",
    "icecast",
    "vnc-http",
    "vnc http",
    "sun-answerbook",
    "hp-webadmin",
}
# Backward-compat alias
_GENERIC_LABELS = LOW_SIGNAL_LABELS
_LOW_SIGNAL_PRODUCTS = {"openssh", "ssh"}


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


def hypothesis_runtime_cfg(state: PentestState) -> dict[str, Any]:
    cfg = get_config()
    hypothesis_cfg = dict(cfg.hypothesis or {})
    retrieval = dict(DEFAULT_RETRIEVAL_CFG)
    retrieval.update(cfg.planning.get("retrieval", {}))
    retrieval.update(hypothesis_cfg.get("retrieval", {}))
    if state.get("benchmark_cve_cache_path"):
        retrieval["benchmark_cve_cache_path"] = state["benchmark_cve_cache_path"]

    critic_cfg = dict(hypothesis_cfg.get("critic", {}))
    return {
        "retrieval": retrieval,
        "critic": {
            "model": critic_cfg.get("model") or cfg.verifier["model"],
            "max_rework_rounds": max(int(critic_cfg.get("max_rework_rounds", 1) or 1), 0),
        },
        "economic_mode": bool(cfg.planning.get("economic_mode", True)),
    }


def log_stage(
    em: EpisodicMemory,
    action: str,
    summary: str,
    *,
    outcome: str = "success",
    action_type: str = "retrieval_stage",
) -> None:
    em.log(Episode(
        step=em.total_steps() + 1,
        timestamp=time.time(),
        phase="hypothesis",
        action_type=action_type,
        command=action,
        args={},
        output_summary=summary[:500],
        outcome=outcome,
    ))


def keyword_from_fingerprints(
    fingerprints: list[ProductFingerprint],
    state: PentestState,
) -> tuple[str, str, str]:
    def _normalize_label(value: str) -> str:
        return " ".join((value or "").strip().lower().replace("/", " ").split())

    def _is_useful_label(value: str) -> bool:
        return _normalize_label(value) not in LOW_SIGNAL_LABELS

    def _fingerprint_score(item: ProductFingerprint) -> tuple[float, float, float, float, float]:
        raw_service = _normalize_label(item.raw_service)
        product = _normalize_label(item.product)
        version = _normalize_label(item.version)
        useful_raw = 0.0 if raw_service in LOW_SIGNAL_LABELS else 1.0
        useful_product = 0.0 if product in LOW_SIGNAL_LABELS else 1.0
        non_ssh = 0.0 if product in _LOW_SIGNAL_PRODUCTS or raw_service in _LOW_SIGNAL_PRODUCTS else 1.0
        useful_version = 0.0 if version in LOW_SIGNAL_LABELS else 1.0
        non_default_port = 0.0 if int(item.port or 0) == 22 else 1.0
        return (
            useful_product,
            non_ssh,
            useful_raw,
            useful_version,
            non_default_port + float(item.confidence or 0.0),
        )

    if fingerprints:
        best = max(fingerprints, key=_fingerprint_score)
        # Don't use low-signal raw_service as fallback product name
        if _is_useful_label(best.product):
            fallback_name = best.product
        elif _is_useful_label(best.raw_service):
            fallback_name = best.raw_service
        else:
            fallback_name = best.vendor or "target"
        fallback_name = fallback_name or "target"

        app_name = state.get("app_name") if _is_useful_label(state.get("app_name", "")) else fallback_name
        version = state.get("app_version") if _is_useful_label(state.get("app_version", "")) else (best.version or "")
        keyword = state.get("keyword") if _is_useful_label(state.get("keyword", "")) else app_name
        return keyword, app_name, version
    return (
        state.get("keyword", "") or state.get("target_ip", "target"),
        state.get("app_name", ""),
        state.get("app_version", ""),
    )


def output_dir(target_ip: str, service_key: str, retrieval_cfg: dict[str, Any]) -> str:
    """Build stable, non-nesting artifact path: data/retrieval_candidates/<ip>/<service-key>."""
    safe_ip = "".join(ch if ch.isalnum() or ch in "-._" else "-" for ch in (target_ip or "target"))
    safe_svc = "".join(ch if ch.isalnum() or ch in "-._" else "-" for ch in (service_key or "default"))
    base = retrieval_cfg.get("candidate_cache_dir") or os.path.join("data", "retrieval_candidates")
    root = base if os.path.isabs(base) else os.path.join(_ROOT, base)
    path = os.path.join(root, safe_ip, safe_svc)
    os.makedirs(path, exist_ok=True)
    return path


def write_json(path: str, payload: Any) -> None:
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
    except Exception as exc:
        logger.warning("Could not write %s: %s", path, exc)


def persist_bundle_artifacts(path: str, bundle: RetrievalBundle | dict[str, Any]) -> None:
    payload = bundle.to_dict() if isinstance(bundle, RetrievalBundle) else dict(bundle)
    write_json(os.path.join(path, "fingerprints.json"), payload.get("fingerprints", []))
    write_json(os.path.join(path, "authoritative_records.json"), payload.get("authoritative_records", []))
    write_json(os.path.join(path, "poc_manifest.json"), payload.get("poc_candidates", []))
    write_json(os.path.join(path, "procedure_manifest.json"), payload.get("procedure_snippets", []))
    write_json(os.path.join(path, "normalized_evidence.json"), payload.get("normalized_evidence", []))
    write_json(os.path.join(path, "critic_report.json"), payload.get("critic_report", {}))
    write_json(os.path.join(path, "retrieval_bundle.json"), payload)


def emit_budget_event(update: dict[str, Any], event_phase: str) -> None:
    pass


def derive_hypotheses(
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
            execution_readiness=round(
                float(item.get("score", assessment.score)) * (0.9 if assessment.procedure_ready else 0.6),
                3,
            ),
            candidate_id=candidate.candidate_id,
            candidate_path=candidate.path,
            source=candidate.source,
            assessment_verdict=assessment.verdict,
        ))
    return hypotheses


def record_hypothesis_decision(
    dm: DecisionMemory,
    em: EpisodicMemory,
    hypotheses: list[VulnHypothesis],
) -> None:
    if not hypotheses:
        return
    top = hypotheses[0]
    dm.record(Decision(
        step=max(em.total_steps(), 1),
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


def shortlist_candidate_ids(shortlist: list[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in shortlist:
        candidate_id = str(item.get("candidate_id", ""))
        if not candidate_id or candidate_id in seen:
            continue
        seen.add(candidate_id)
        ordered.append(candidate_id)
    return ordered
