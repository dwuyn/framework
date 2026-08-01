"""
src/agents/verifier_pipeline.py
────────────────────────────────
Evidence-gated verifier that controls the execution loop.

The verifier decides after each step:
- ``collect_evidence`` — more reconnaissance or retrieval needed
- ``replan`` — current plan is flawed; send back to planner
- ``execute`` — ready to run the next candidate
- ``stop`` — no further progress possible

Every verdict must cite specific state keys and evidence IDs.
"""

from __future__ import annotations

import logging
import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from src.pipeline.candidates import ExploitCandidate, is_executable
from src.pipeline.evidence import Fingerprint
from src.pipeline.ledger import EventLedger
from src.pipeline.oracle import OracleResult, ProofArtifact
from src.pipeline.queue import CandidateQueue, RankedCandidate
from src.pipeline.runner import ExecutionResult

logger = logging.getLogger(__name__)


# ── Data structures ──────────────────────────────────────────────────────────


@dataclass
class VerifierDecision:
    """Output from the Pipeline Verifier agent."""

    action: str                          # collect_evidence | replan | execute | stop
    reason: str = ""
    cited_state_keys: list[str] = field(default_factory=list)
    cited_evidence_ids: list[str] = field(default_factory=list)
    target_candidate_id: str = ""        # candidate to execute (action=execute)
    proposal_id: str = ""
    approved_for_execution: bool = False
    new_evidence_request: dict | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "reason": self.reason,
            "cited_state_keys": list(self.cited_state_keys),
            "cited_evidence_ids": list(self.cited_evidence_ids),
            "target_candidate_id": self.target_candidate_id,
            "proposal_id": self.proposal_id,
            "approved_for_execution": bool(self.approved_for_execution),
            "new_evidence_request": self.new_evidence_request,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "VerifierDecision":
        return cls(
            action=str(data.get("action", "stop")),
            reason=str(data.get("reason", "")),
            cited_state_keys=list(data.get("cited_state_keys") or []),
            cited_evidence_ids=list(data.get("cited_evidence_ids") or []),
            target_candidate_id=str(data.get("target_candidate_id", "")),
            proposal_id=str(data.get("proposal_id", "")),
            approved_for_execution=bool(data.get("approved_for_execution", False)),
            new_evidence_request=data.get("new_evidence_request"),
        )


# ── Verifier Agent ───────────────────────────────────────────────────────────


class PipelineVerifierAgent:
    """Evidence-gated verifier that controls the multi-agent execution loop.

    Decisions:
    - ``collect_evidence`` — Need more recon/retrieval data before proceeding
    - ``replan`` — Current plan is flawed; send back to planner
    - ``execute`` — Ready to execute the next candidate
    - ``stop`` — No further progress possible

    Requirements:
    - Must cite specific state keys and evidence IDs
    - Must reference the ledger for prior outcomes
    - Never unconstrained shell prose
    """

    def __init__(
        self,
        llm: Any | None = None,
        *,
        ledger: EventLedger | None = None,
    ) -> None:
        self.llm = llm
        self.ledger = ledger

    def decide(
        self,
        *,
        fingerprint: Fingerprint | None,
        ranked_queue: CandidateQueue,
        executed_candidates: list[ExploitCandidate] | None = None,
        executed_ids: set[str] | None = None,
        prior_verifier_decisions: list[VerifierDecision] | None = None,
        planner_proposals: list[Any] | None = None,
        critic_verdicts: list[Any] | None = None,
        last_execution_result: ExecutionResult | None = None,
        last_proof: ProofArtifact | None = None,
        prior_failures: list[str] | None = None,
        catalog_exhausted: bool = False,
        loop_count: int = 0,
        loop_max: int = 5,
    ) -> VerifierDecision:
        """Make the next action decision."""
        executed_ids = executed_ids or set()
        prior_failures = prior_failures or []
        prior_verifier_decisions = prior_verifier_decisions or []

        cited_keys: list[str] = []
        cited_evidence: list[str] = []

        # ── 1. Loop cap guard ─────────────────────────────────────────────────
        if loop_count >= loop_max:
            return VerifierDecision(
                action="stop",
                reason=f"Planner loop cap reached ({loop_count}/{loop_max}).",
                cited_state_keys=["planner_loop_count", "planner_loop_max"],
            )

        # Captured stdout is an artifact, not a success decision.  The graph
        # reaches the independent oracle only after the lifecycle finishes.

        if not ranked_queue.ranked and not planner_proposals:
            return VerifierDecision(action="stop", reason="No candidates or planner proposals.",
                                    cited_state_keys=["exploit_candidates"])

        # ── 4. Check for repeated/failed actions ──────────────────────────────
        if last_execution_result and last_execution_result.returncode != 0:
            # Last execution failed.  Try next candidate or replan.
            if prior_failures and len(prior_failures) >= 3:
                # Multiple failures — replan.
                return VerifierDecision(
                    action="replan",
                    reason=f"Multiple execution failures ({len(prior_failures)}). "
                           f"Requesting replan.",
                    cited_state_keys=["prior_failures"],
                    cited_evidence_ids=cited_evidence,
                )

        # ── 4. Find next unexecuted candidate in queue. ───────────────────────
        next_candidate = None
        for rc in ranked_queue.ranked:
            cand_id = rc.candidate.candidate_id
            if cand_id not in executed_ids:
                next_candidate = rc.candidate
                break

        if next_candidate:
            cited_keys.append("exploit_candidates")
            trust = next_candidate.provenance.trust
            reason = f"Next candidate: {next_candidate.kind}/{next_candidate.cve_id} (trust={trust})"

            proposal = _proposal_for_candidate(planner_proposals, next_candidate.candidate_id)
            if planner_proposals and proposal is None:
                return VerifierDecision(action="replan", reason="Candidate lacks a planner proposal.",
                                        cited_state_keys=["planner_proposals"])
            proposal_id = str((proposal or {}).get("proposal_id") or f"plan-{next_candidate.candidate_id}")
            if trust == "llm_provisional" and proposal is None:
                if not _critic_approved(critic_verdicts, next_candidate.candidate_id):
                    return VerifierDecision(action="replan", reason="Critic did not approve guided procedure.",
                                            cited_state_keys=["critic_verdicts"])
            if proposal is not None and not _critic_approved(critic_verdicts, proposal_id):
                return VerifierDecision(action="replan", reason="Critic did not approve this proposal.",
                                        cited_state_keys=["critic_verdicts", "planner_proposals"],
                                        proposal_id=proposal_id)

            return VerifierDecision(
                action="execute",
                reason=reason,
                cited_state_keys=cited_keys,
                cited_evidence_ids=cited_evidence,
                target_candidate_id=next_candidate.candidate_id,
                proposal_id=proposal_id,
                approved_for_execution=True,
            )

        # ── 5. Queue exhausted but planner has proposals ──────────────────────
        if planner_proposals:
            latest = planner_proposals[-1]
            proposal_dict = latest if isinstance(latest, dict) else latest.to_dict()
            cand = proposal_dict.get("candidate") or {}
            cand_id = cand.get("candidate_id", "")
            proposal_id = str(proposal_dict.get("proposal_id") or f"plan-{cand_id}")
            if cand_id and cand_id not in executed_ids and _critic_approved(critic_verdicts, proposal_id):
                return VerifierDecision(
                    action="execute",
                    reason=f"Executing planner proposal for {proposal_dict.get('cve_id', 'unknown')}.",
                    cited_state_keys=["planner_proposals"],
                    cited_evidence_ids=cited_evidence,
                    target_candidate_id=cand_id,
                    proposal_id=proposal_id,
                    approved_for_execution=True,
                )

        # ── 6. All candidates exhausted ───────────────────────────────────────
        if not catalog_exhausted:
            # Catalog hasn't been fully tried — collect more evidence.
            return VerifierDecision(
                action="collect_evidence",
                reason="All current candidates exhausted but catalog not fully tried. "
                       "Requesting additional evidence.",
                cited_state_keys=["exploit_candidates", "catalog_exhausted"],
                cited_evidence_ids=cited_evidence,
                new_evidence_request={"reason": "catalog_not_exhausted"},
            )

        # ── 8. Fully exhausted ────────────────────────────────────────────────
        return VerifierDecision(
            action="stop",
            reason="All candidates exhausted (catalog + planner proposals). "
                   "No further progress possible.",
            cited_state_keys=["exploit_candidates", "planner_proposals", "catalog_exhausted"],
            cited_evidence_ids=cited_evidence,
        )


    def decide_after_execution(self, **kwargs: Any) -> VerifierDecision:
        """Post-execution entry point; the same gate handles both phases."""
        return self.decide(**kwargs)

    def review(self, decision: VerifierDecision) -> VerifierDecision:
        """LLM may veto or request evidence; it cannot create an execution approval."""
        if self.llm is None:
            return decision
        prompt = (
            "You are the verifier. Review this deterministic safety decision. "
            "Return JSON {\"action\": \"execute|collect_evidence|replan|stop\", \"reason\": \"...\"}. "
            "You may veto execute, but may not turn a non-execute decision into execute.\n"
            f"Decision: {json.dumps(decision.to_dict(), sort_keys=True)}"
        )
        try:
            text = str(getattr(self.llm.invoke(prompt), "content", "") or "")
            parsed = json.loads(text[text.find("{"):text.rfind("}") + 1])
            action = str(parsed.get("action") or decision.action)
            if action == "execute" and decision.action != "execute":
                return decision
            if action in {"collect_evidence", "replan", "stop"}:
                decision.action = action
                decision.reason = str(parsed.get("reason") or decision.reason)
                if action != "execute":
                    decision.approved_for_execution = False
                    decision.target_candidate_id = ""
            return decision
        except Exception as exc:
            logger.warning("Verifier LLM review failed: %s", exc)
            return decision


def _proposal_for_candidate(proposals: list[Any] | None, candidate_id: str) -> dict[str, Any] | None:
    for raw in reversed(proposals or []):
        proposal = raw if isinstance(raw, dict) else raw.to_dict()
        if (proposal.get("candidate") or {}).get("candidate_id") == candidate_id:
            return proposal
    return None


def _critic_approved(verdicts: list[Any] | None, proposal_id: str) -> bool:
    for raw in reversed(verdicts or []):
        verdict = raw if isinstance(raw, dict) else raw.to_dict()
        if verdict.get("proposal_id") == proposal_id:
            return bool(verdict.get("approved", False))
    return False
