"""
src/agents/critic.py
────────────────────
Critic agent that challenges planner proposals before the verifier commits.

The critic checks:
- Unsupported assumptions in the proposal rationale
- Missing authentication / preconditions not met by the fingerprint
- Invalid parameters: unresolved placeholders, scope violations,
  placeholder injection
- Better alternative methods already in the catalog that weren't tried
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from src.pipeline.candidates import (
    ExploitCandidate,
    PLACEHOLDER_RE,
    substitute_placeholders,
    SUPPORTED_KINDS,
)
from src.pipeline.evidence import Fingerprint, constraint_matches
from src.pipeline.ledger import EventLedger
from src.pipeline.manifest import Scope
from src.pipeline.scope import ScopeValidator

logger = logging.getLogger(__name__)


# ── Data structures ──────────────────────────────────────────────────────────


@dataclass
class CriticVerdict:
    """Output from the Critic agent."""

    proposal_id: str
    challenges: list[str]
    missing_preconditions: list[str]
    invalid_parameters: list[str]
    better_alternatives: list[str]
    severity: str = "info"            # "fatal" | "warning" | "info"
    approved: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "challenges": list(self.challenges),
            "missing_preconditions": list(self.missing_preconditions),
            "invalid_parameters": list(self.invalid_parameters),
            "better_alternatives": list(self.better_alternatives),
            "severity": self.severity,
            "approved": bool(self.approved),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CriticVerdict":
        return cls(
            proposal_id=str(data.get("proposal_id", "")),
            challenges=list(data.get("challenges") or []),
            missing_preconditions=list(data.get("missing_preconditions") or []),
            invalid_parameters=list(data.get("invalid_parameters") or []),
            better_alternatives=list(data.get("better_alternatives") or []),
            severity=str(data.get("severity", "info")),
            approved=bool(data.get("approved", True)),
        )


# ── Critic Agent ─────────────────────────────────────────────────────────────


class CriticAgent:
    """Challenges planner proposals before the verifier commits.

    Runs deterministic checks first (scope, placeholders, fingerprint match)
    and optionally uses an LLM for deeper assumption analysis.
    """

    def __init__(
        self,
        llm: Any | None = None,
        *,
        scope: Scope | None = None,
        ledger: EventLedger | None = None,
    ) -> None:
        self.llm = llm
        self.scope = scope
        self.ledger = ledger

    def evaluate(
        self,
        proposal: Any,
        *,
        fingerprint: Fingerprint | None,
        executed_candidates: list[ExploitCandidate] | None = None,
        catalog_candidates: list[ExploitCandidate] | None = None,
    ) -> CriticVerdict:
        """Evaluate a planner proposal and return a verdict.

        ``proposal`` can be a :class:`PlannerProposal` or a raw dict.
        """
        from src.agents.planner import PlannerProposal

        if isinstance(proposal, dict):
            proposal = PlannerProposal.from_dict(proposal)

        challenges: list[str] = []
        missing_preconditions: list[str] = []
        invalid_params: list[str] = []
        better_alternatives: list[str] = []

        candidate = proposal.candidate

        # ── 1. Fingerprint consistency ────────────────────────────────────────
        if fingerprint:
            if candidate.product_evidence and fingerprint.product.parsed \
                    and candidate.product_evidence.lower() != fingerprint.product.parsed.lower():
                challenges.append(
                    f"product_mismatch: proposal targets '{candidate.product_evidence}' "
                    f"but fingerprint says '{fingerprint.product.parsed}'"
                )

            if candidate.version_evidence and fingerprint.version.parsed \
                    and candidate.version_evidence.lower() != fingerprint.version.parsed.lower():
                grade = constraint_matches(candidate.constraint, fingerprint)
                if grade == "mismatch":
                    challenges.append(
                        f"version_mismatch: proposal targets version "
                        f"'{candidate.version_evidence}' but fingerprint says "
                        f"'{fingerprint.version.parsed}'"
                    )

            if not fingerprint.product.parsed or fingerprint.product.parsed == "unknown":
                missing_preconditions.append("fingerprint_unknown_product")
        else:
            missing_preconditions.append("no_fingerprint")

        # ── 2. Missing preconditions ──────────────────────────────────────────
        if candidate.auth_required == "yes":
            if not fingerprint or fingerprint.auth_hint not in {"provided", "unknown"}:
                missing_preconditions.append("auth_required_but_not_met")

        for prereq in candidate.network_prereqs:
            if prereq == "outbound" and not candidate.requires_callback:
                continue
            missing_preconditions.append(f"network_prereq:{prereq}")

        # ── 3. Parameter validation ───────────────────────────────────────────
        for step in candidate.procedure:
            _, unresolved = substitute_placeholders(step.argv, {}, strict=True)
            if unresolved:
                # These are expected placeholders (TARGET_IP etc.) that get
                # resolved at render time — only flag truly unusual ones.
                unexpected = [p for p in unresolved
                              if not _is_expected_placeholder(p)]
                if unexpected:
                    invalid_params.append(
                        f"unresolved:{step.stage}:{unexpected}"
                    )

        # Scope validation.
        if self.scope and candidate.procedure and candidate.kind != "guided_procedure":
            validator = ScopeValidator(self.scope)
            for step in candidate.procedure:
                dec = validator.validate_args(step.argv, stage=step.stage)
                if not dec:
                    invalid_params.append(f"scope:{step.stage}:{dec.reason}")

        # ── 4. Better alternatives ────────────────────────────────────────────
        if catalog_candidates:
            for cat_cand in catalog_candidates:
                if cat_cand.candidate_id == candidate.candidate_id:
                    continue
                if cat_cand.kind == "guided_procedure":
                    continue
                if cat_cand.cve_id != candidate.cve_id:
                    continue
                if cat_cand.provenance.trust in ("trusted", "lab_approved"):
                    better_alternatives.append(
                        f"{cat_cand.kind}:{cat_cand.candidate_id} "
                        f"(trust={cat_cand.provenance.trust})"
                    )

        # ── 5. LLM-based deeper analysis ──────────────────────────────────────
        if self.llm is not None:
            llm_challenges = self._llm_challenge(proposal, fingerprint)
            challenges.extend(llm_challenges)

        # ── 6. Determine severity and approval ────────────────────────────────
        fatal = bool(challenges) or bool(missing_preconditions) or bool(invalid_params)
        severity = "fatal" if fatal else ("warning" if better_alternatives else "info")
        approved = not fatal

        verdict = CriticVerdict(
            proposal_id=proposal.proposal_id or f"plan-{proposal.candidate.candidate_id}",
            challenges=challenges,
            missing_preconditions=missing_preconditions,
            invalid_parameters=invalid_params,
            better_alternatives=better_alternatives,
            severity=severity,
            approved=approved,
        )

        if self.ledger:
            self.ledger.record(
                phase="critic", stage="policy_decision",
                cve_id=proposal.cve_id,
                candidate_id=proposal.candidate.candidate_id,
                method="guided_procedure",
                outcome="blocked_by_policy" if not approved else "",
                failure_class="policy_block" if not approved else "",
                detail=f"severity={severity}",
                payload={"verdict": verdict.to_dict(), "proposal_id": verdict.proposal_id},
            )

        return verdict

    def _llm_challenge(
        self,
        proposal: Any,
        fingerprint: Fingerprint | None,
    ) -> list[str]:
        """Use the LLM to find deeper assumption issues."""
        if not self.llm:
            return []

        product = fingerprint.product.parsed if fingerprint else "unknown"
        version = fingerprint.version.parsed if fingerprint else "unknown"

        prompt = (
            f"You are a security critic.  Review this exploitation proposal:\n\n"
            f"CVE: {proposal.cve_id}\n"
            f"Target: {product} {version}\n"
            f"Rationale: {proposal.rationale}\n"
            f"Procedure steps: {len(proposal.candidate.procedure)}\n\n"
            f"Identify any unsupported assumptions, missing preconditions, "
            f"or invalid parameters.  Return a JSON array of challenge strings, "
            f"or an empty array if the proposal is sound."
        )

        try:
            response = self.llm.invoke(prompt)
            text = str(getattr(response, "content", response) or "")
            return _parse_challenges(text)
        except Exception as exc:
            logger.warning("Critic LLM call failed: %s", exc)
            return []


def _is_expected_placeholder(placeholder: str) -> bool:
    """Check if a placeholder is one of the standard expected ones."""
    expected_prefixes = {
        "TARGET_IP", "RHOST", "RHOSTS", "RPORT", "LHOST", "LPORT",
        "PRODUCT", "VENDOR", "VERSION", "TARGET",
        "MSF_RC", "NUCLEI_OUTPUT", "FRAMEWORK_COMMAND",
    }
    clean = placeholder.strip("${}<>()__")
    return clean in expected_prefixes


def _parse_challenges(text: str) -> list[str]:
    """Parse a JSON array of challenge strings from LLM output."""
    import json
    import re

    match = re.search(r"\[.*\]", text, re.DOTALL)
    if not match:
        return []
    try:
        items = json.loads(match.group(0))
    except json.JSONDecodeError:
        return []
    return [str(item) for item in items if isinstance(item, str)]
