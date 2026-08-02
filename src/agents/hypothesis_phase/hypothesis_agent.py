"""
Hypothesis synthesis node for Phase 2.
"""

from __future__ import annotations

from typing import Any

from src.config import get_config
from src.memory.decision import DecisionMemory
from src.memory.episodic import EpisodicMemory
from src.retrieval import (
    ApplicabilityAssessment,
    AuthoritativeRecord,
    PocCandidate,
    ProcedureSnippet,
    ProductFingerprint,
    RetrievalBundle,
)
from src.state import PentestState, runtime_exceeded
from src.utils.structured_logger import get_structured_logger

from .shared import derive_hypotheses, log_stage, record_hypothesis_decision

slog = get_structured_logger()


def hypothesis_agent_node(state: PentestState) -> dict[str, Any]:
    get_config()
    em = EpisodicMemory.from_list(state.get("episodic_memory", []))
    dm = DecisionMemory.from_list(state.get("decision_memory", []))
    bundle = RetrievalBundle.from_dict(state.get("retrieval_bundle", {}) or {})

    timed_out, timeout_reason = runtime_exceeded(state)
    if timed_out:
        return {
            "phase2_route": "end",
            "current_phase": "done",
            "timeout_exceeded": True,
            "execution_summary": timeout_reason,
            "decision_memory": dm.to_list(),
            "episodic_memory": em.to_list(),
        }

    fingerprints = [ProductFingerprint.from_dict(item) for item in bundle.fingerprints]
    records = [AuthoritativeRecord.from_dict(item) for item in bundle.authoritative_records]
    candidates = [PocCandidate.from_dict(item) for item in bundle.poc_candidates]
    snippets = [ProcedureSnippet.from_dict(item) for item in bundle.procedure_snippets]
    assessments = [ApplicabilityAssessment.from_dict(item) for item in bundle.assessments]
    shortlist = list(bundle.shortlist)

    hypotheses = derive_hypotheses(fingerprints, records, candidates, snippets, assessments, shortlist)
    log_stage(em, "hypothesis_derive", f"derived {len(hypotheses)} hypothesis record(s)", action_type="analysis_stage")
    record_hypothesis_decision(dm, em, hypotheses)

    slog.node_event(
        "hypothesis_agent",
        phase="hypothesis",
        action=f"derive hypotheses {len(hypotheses)}",
        outcome="ok" if hypotheses else "no_hypotheses",
    )
    update = {
        "vuln_hypotheses": [item.to_dict() for item in hypotheses],
        "cve_list": [item.cve_id for item in hypotheses],
        "decision_memory": dm.to_list(),
        "episodic_memory": em.to_list(),
        "hypothesis_complete": False,
        "phase2_route": "",
        "current_phase": "hypothesis",
    }
    return update
