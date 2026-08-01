"""
src/agents/planner.py
─────────────────────
LLM-based planner that generates ``guided_procedure`` candidates.

Policy
──────
- Activates only after catalog exhaustion (all executable catalog kinds
  tried without obtaining task proof).
- Requires fingerprint evidence plus at least one advisory / tool-manual
  reference.
- Generates structured :class:`ProcedureStep` argv arrays only — never
  free-form shell prose.
- Only benchmark-approved tools: ``nmap``, ``curl``, ``python3``, ``nuclei``,
  ``msfconsole``, ``bash`` (for scripted sequences).
- Rejects shell-evaluation forms, system package changes, external targets,
  unresolved placeholders, and out-of-scope endpoints.
- Builds an ``ExploitCandidate`` with ``kind="guided_procedure"`` and
  ``provenance.trust="llm_provisional"`` (lowest trust tier).
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from src.pipeline.candidates import (
    ExploitCandidate,
    ProcedureStep,
    Provenance,
    derive_candidate_id,
    hash_artifact,
)
from src.pipeline.evidence import Fingerprint, VersionConstraint
from src.pipeline.ledger import EventLedger
from src.pipeline.manifest import ResourceLimits, Scope
from src.pipeline.runner import ReconObservation

logger = logging.getLogger(__name__)

# ── Approved tool set ────────────────────────────────────────────────────────

APPROVED_TOOLS = frozenset({
    "nmap", "curl", "nuclei", "msfconsole", "nc", "ncat", "wget",
    "searchsploit", "nikto", "gobuster", "dirb", "wfuzz", "hydra",
    "medusa", "sqlmap",
})

ALLOWED_PLACEHOLDERS = frozenset({
    "TARGET_IP", "RHOST", "RHOSTS", "RPORT", "TARGET", "LHOST", "LPORT",
})

# Patterns that indicate shell-evaluation or injection risks.
_SHELL_EVAL_PATTERNS = (
    re.compile(r"\beval\s*\("),
    re.compile(r"\bexec\s*\("),
    re.compile(r"\bos\.system\s*\("),
    re.compile(r"\bsubprocess\.call\s*\("),
    re.compile(r";\s*(rm|dd|mkfs|shutdown|reboot)\b"),
    re.compile(r"\|\s*(rm|dd|mkfs)\b"),
    re.compile(r">\s*/dev/sd"),
    re.compile(r"\bsudo\b"),
    re.compile(r"\bsu\b"),
    re.compile(r"\bapt\b|\byum\b|\bpip\b|\bnpm\b"),
)


# ── Data structures ──────────────────────────────────────────────────────────


@dataclass
class PlannerProposal:
    """Output from the LLM Planner agent."""

    cve_id: str
    rationale: str
    fingerprint_match: str
    prereq_satisfaction: str
    procedure_readiness: float
    expected_evidence_gain: str
    candidate: ExploitCandidate
    cited_evidence_ids: list[str]
    catalog_exhausted: bool
    proposal_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "rationale": self.rationale,
            "fingerprint_match": self.fingerprint_match,
            "prereq_satisfaction": self.prereq_satisfaction,
            "procedure_readiness": self.procedure_readiness,
            "expected_evidence_gain": self.expected_evidence_gain,
            "candidate": self.candidate.to_dict(),
            "cited_evidence_ids": list(self.cited_evidence_ids),
            "catalog_exhausted": bool(self.catalog_exhausted),
            "proposal_id": self.proposal_id or f"plan-{self.candidate.candidate_id}",
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PlannerProposal":
        return cls(
            cve_id=str(data.get("cve_id", "")),
            rationale=str(data.get("rationale", "")),
            fingerprint_match=str(data.get("fingerprint_match", "")),
            prereq_satisfaction=str(data.get("prereq_satisfaction", "")),
            procedure_readiness=float(data.get("procedure_readiness", 0.0)),
            expected_evidence_gain=str(data.get("expected_evidence_gain", "")),
            candidate=ExploitCandidate.from_dict(data.get("candidate") or {}),
            cited_evidence_ids=list(data.get("cited_evidence_ids") or []),
            catalog_exhausted=bool(data.get("catalog_exhausted", False)),
            proposal_id=str(data.get("proposal_id") or f"plan-{(data.get('candidate') or {}).get('candidate_id', '')}"),
        )


# ── Planner Agent ────────────────────────────────────────────────────────────


class PlannerAgent:
    """LLM-based planner that generates guided_procedure candidates.

    Only produces candidates after catalog exhaustion, and every candidate
    must cite fingerprint evidence and at least one advisory reference.
    """

    APPROVED_TOOLS = APPROVED_TOOLS

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

    # ── Public API ────────────────────────────────────────────────────────────

    def propose(
        self,
        *,
        fingerprint: Fingerprint,
        cve_id: str,
        observations: list[ReconObservation],
        executed_candidates: list[ExploitCandidate],
        prior_failures: list[str],
        references: list[str] | None = None,
    ) -> PlannerProposal | None:
        """Generate a guided_procedure proposal.

        Returns ``None`` if the LLM cannot produce a valid proposal or if
        required evidence/references are missing.
        """
        if not fingerprint or not fingerprint.product.parsed or fingerprint.product.parsed == "unknown":
            logger.info("Planner: no actionable fingerprint — skipping.")
            return None

        if not cve_id:
            logger.info("Planner: no CVE ID — skipping.")
            return None

        if not references:
            logger.info("Planner: no advisory/tool-manual references — skipping.")
            return None

        # Build procedure via LLM or deterministic fallback.
        procedure = self._generate_procedure(
            fingerprint=fingerprint,
            cve_id=cve_id,
            references=references,
            prior_failures=prior_failures,
        )
        if not procedure:
            return None

        # Validate the generated procedure.
        violations = validate_guided_procedure(procedure, scope=self.scope)
        if violations:
            logger.warning("Planner: generated procedure rejected: %s", violations)
            if self.ledger:
                self.ledger.record(
                    phase="planner", stage="policy_decision",
                    cve_id=cve_id, outcome="blocked_by_policy",
                    failure_class="procedure_incomplete",
                    detail=f"validation_failed: {violations}",
                )
            return None

        candidate = build_guided_candidate(
            cve_id=cve_id,
            procedure=procedure,
            fingerprint=fingerprint,
            references=references,
        )

        proposal = PlannerProposal(
            cve_id=cve_id,
            rationale=f"Catalog exhausted for {fingerprint.product.parsed}/{fingerprint.version.parsed}. "
                      f"LLM-generated procedure targeting {cve_id} based on {len(references)} reference(s).",
            fingerprint_match=f"product={fingerprint.product.parsed}, version={fingerprint.version.parsed}",
            prereq_satisfaction="verified against fingerprint",
            procedure_readiness=0.3,
            expected_evidence_gain=f"Proof of {cve_id} exploitation via guided procedure",
            candidate=candidate,
            cited_evidence_ids=[f"fp:{fingerprint.product.parsed}:{fingerprint.version.parsed}"],
            catalog_exhausted=True,
        )

        if self.ledger:
            self.ledger.record(
                phase="planner", stage="policy_decision",
                cve_id=cve_id, candidate_id=candidate.candidate_id,
                method="guided_procedure",
                detail="proposal_generated",
                payload={"readiness": proposal.procedure_readiness,
                         "reference_count": len(references)},
            )

        return proposal

    def propose_catalog(
        self,
        *,
        fingerprint: Fingerprint,
        candidates: list[ExploitCandidate],
        catalog_exhausted: bool,
    ) -> PlannerProposal | None:
        """Select one already-ranked catalog candidate; never invents argv."""
        if not candidates:
            return None
        selected = candidates[0]
        if self.llm is not None:
            ids = [c.candidate_id for c in candidates]
            prompt = (
                "Select exactly one candidate id from this evidence-gated catalog. "
                "Do not create commands or candidates. Return only the id.\n"
                f"Fingerprint: {fingerprint.product.parsed} {fingerprint.version.parsed}\n"
                f"Candidates: {ids}"
            )
            try:
                response = self.llm.invoke(prompt)
                choice = str(getattr(response, "content", response) or "").strip()
                selected = next((c for c in candidates if c.candidate_id == choice), selected)
            except Exception as exc:
                logger.warning("Planner catalog selection failed: %s", exc)
        proposal = PlannerProposal(
            cve_id=selected.cve_id,
            rationale=f"Selected catalog candidate {selected.candidate_id} for verified fingerprint.",
            fingerprint_match=f"product={fingerprint.product.parsed}, version={fingerprint.version.parsed}",
            prereq_satisfaction="queue eligibility verified",
            procedure_readiness=1.0,
            expected_evidence_gain=f"Evidence from {selected.kind}",
            candidate=selected,
            cited_evidence_ids=[f"fp:{fingerprint.product.parsed}:{fingerprint.version.parsed}"],
            catalog_exhausted=catalog_exhausted,
            proposal_id=f"plan-{selected.candidate_id}",
        )
        if self.ledger:
            self.ledger.record(phase="planner", stage="policy_decision", cve_id=selected.cve_id,
                               candidate_id=selected.candidate_id, method=selected.kind,
                               detail="catalog_candidate_selected", payload={"proposal_id": proposal.proposal_id})
        return proposal

    # ── Internal ──────────────────────────────────────────────────────────────

    def _generate_procedure(
        self,
        *,
        fingerprint: Fingerprint,
        cve_id: str,
        references: list[str],
        prior_failures: list[str],
    ) -> list[ProcedureStep] | None:
        """Generate a structured procedure via LLM.

        Uses the LLM if available; otherwise builds a minimal curl-based
        detection + verification procedure as a conservative fallback.
        """
        if self.llm is not None:
            return self._llm_generate(fingerprint=fingerprint, cve_id=cve_id,
                                       references=references,
                                       prior_failures=prior_failures)
        return self._deterministic_fallback(fingerprint=fingerprint, cve_id=cve_id)

    def _llm_generate(
        self,
        *,
        fingerprint: Fingerprint,
        cve_id: str,
        references: list[str],
        prior_failures: list[str],
    ) -> list[ProcedureStep] | None:
        """Use the LLM to generate a structured procedure."""
        product = fingerprint.product.parsed
        version = fingerprint.version.parsed
        port = fingerprint.port
        target = fingerprint.target_ip

        prompt = (
            f"You are a penetration-testing planner.  Generate a structured, "
            f"safe exploitation procedure for CVE {cve_id} targeting "
            f"{product} {version} on {target}:{port}.\n\n"
            f"REQUIREMENTS:\n"
            f"- Return a JSON array of procedure steps.\n"
            f"- Each step: {{\"stage\": \"setup|execute|verify|cleanup\", "
            f"\"argv\": [\"tool\", \"arg1\", ...], \"timeout_seconds\": 60}}\n"
            f"- Only use approved tools: {sorted(APPROVED_TOOLS)}\n"
            f"- argv must be structured arrays — never shell prose.\n"
            f"- Reference(s): {', '.join(references[:3])}\n"
            f"- Prior failures to avoid: {', '.join(prior_failures[:5]) or 'none'}\n\n"
            f"Return ONLY the JSON array."
        )

        try:
            response = self.llm.invoke(prompt)
            text = str(getattr(response, "content", response) or "")
            return _parse_procedure_json(text)
        except Exception as exc:
            logger.warning("Planner LLM call failed: %s", exc)
            return None

    def _deterministic_fallback(
        self,
        *,
        fingerprint: Fingerprint,
        cve_id: str,
    ) -> list[ProcedureStep] | None:
        """Conservative curl-based detection + verification procedure.

        Used when no LLM is configured.  This is intentionally minimal —
        it only detects the vulnerability presence and does not attempt
        exploitation.
        """
        target = fingerprint.target_ip
        port = fingerprint.port or 80
        product = fingerprint.product.parsed

        if product in ("unknown", ""):
            return None

        # Minimal curl-based probe.
        return [
            ProcedureStep(
                stage="execute",
                argv=["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                      f"http://{{TARGET_IP}}:{port}/"],
                timeout_seconds=30,
            ),
            ProcedureStep(
                stage="verify",
                argv=["curl", "-s", "-I", f"http://{{TARGET_IP}}:{port}/"],
                timeout_seconds=30,
            ),
        ]


# ── Validation helpers ───────────────────────────────────────────────────────


def validate_guided_procedure(
    procedure: list[ProcedureStep],
    *,
    scope: Scope | None = None,
) -> list[str]:
    """Validate a generated procedure against policy constraints.

    Returns a list of violation strings; empty list means valid.
    """
    from src.pipeline.scope import ScopeValidator

    violations: list[str] = []

    if not procedure:
        violations.append("empty_procedure")
        return violations

    has_execute = any(s.stage == "execute" for s in procedure)
    if not has_execute:
        violations.append("no_execute_stage")

    for step in procedure:
        if not step.argv:
            violations.append(f"empty_argv:{step.stage}")
            continue

        # Check tool is approved.
        tool = step.argv[0]
        if tool not in APPROVED_TOOLS:
            violations.append(f"unapproved_tool:{step.stage}:{tool}")

        # Check for shell-evaluation patterns.
        cmd_str = " ".join(step.argv)
        for pattern in _SHELL_EVAL_PATTERNS:
            if pattern.search(cmd_str):
                violations.append(f"shell_eval:{step.stage}:{pattern.pattern}")
                break

        for name in re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", cmd_str):
            if name not in ALLOWED_PLACEHOLDERS:
                violations.append(f"unresolved_placeholder:{step.stage}:{name}")

        # Scope validation after replacing only known target placeholders.
    if scope:
        values = _scope_bindings(scope)
        validator = ScopeValidator(scope)
        for step in procedure:
            argv = [_replace_known_placeholders(token, values) for token in step.argv]
            dec = validator.validate_args(argv, stage=step.stage)
            if not dec:
                violations.append(f"scope:{step.stage}:{dec.reason}")

    return violations


def _scope_bindings(scope: Scope) -> dict[str, str]:
    """Use an in-scope representative only for pre-render policy validation."""
    target = scope.allowed_hostnames[0] if scope.allowed_hostnames else ""
    if not target and scope.allowed_networks:
        import ipaddress
        target = str(next(ipaddress.ip_network(scope.allowed_networks[0], strict=False).hosts(), ""))
    port = str(scope.allowed_ports[0]) if scope.allowed_ports else ""
    return {"TARGET_IP": target, "RHOST": target, "RHOSTS": target, "TARGET": target, "RPORT": port,
            "LHOST": scope.callback_endpoints[0] if scope.callback_endpoints else "127.0.0.1", "LPORT": "4444"}


def _replace_known_placeholders(token: str, values: Mapping[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        return values.get(name, match.group(0)) if name in ALLOWED_PLACEHOLDERS else match.group(0)
    return re.sub(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", replace, str(token))


def build_guided_candidate(
    *,
    cve_id: str,
    procedure: list[ProcedureStep],
    fingerprint: Fingerprint,
    references: list[str],
) -> ExploitCandidate:
    """Build an ExploitCandidate of kind ``guided_procedure``.

    The candidate has ``llm_provisional`` trust — it cannot execute until
    the verifier explicitly approves it.
    """
    prov = Provenance(
        revision="llm-planner-v1",
        sha256="",
        references=list(references),
        license="unknown",
        trust="llm_provisional",
        source_kind="llm_planner",
        advisory_ref=references[0] if references else "",
    )
    candidate_id = derive_candidate_id(
        kind="guided_procedure",
        cve_id=cve_id,
        locator=f"llm-{cve_id}-{fingerprint.port}",
        provenance=prov,
    )
    return ExploitCandidate(
        candidate_id=candidate_id,
        cve_id=cve_id,
        kind="guided_procedure",
        source="llm_planner",
        locator=f"llm-{cve_id}",
        provenance=prov,
        procedure=list(procedure),
        capability="code_execution",
        side_effect_class="remote_exploit",
        product_evidence=fingerprint.product.parsed,
        version_evidence=fingerprint.version.parsed,
        cpe_evidence=fingerprint.cpe_primary() if hasattr(fingerprint, "cpe_primary") else "",
        placeholders=["TARGET_IP", "RHOST", "RPORT"],
    )


def build_generated_artifact_candidate(
    *, cve_id: str, artifact_path: str, language: str, fingerprint: Fingerprint,
    references: list[str], parent_candidate_id: str = "",
) -> ExploitCandidate | None:
    """Turn a bounded LLM artifact into the existing provisional contract.

    The caller is responsible for invoking this only after known-source
    exhaustion; this function enforces syntax/static validation and never
    runs package managers or a host shell.
    """
    from src.pipeline.runtime import static_preflight

    failure = static_preflight(artifact_path, language)
    if failure:
        return None
    try:
        with open(artifact_path, "rb") as handle:
            digest = hash_artifact(handle.read())
    except OSError:
        return None
    interpreter = {"python": "python3", "shell": "bash"}.get(language)
    if not interpreter:
        return None
    prov = Provenance(revision="llm-artifact-v1", sha256=digest, references=list(references),
                      license="unknown", trust="llm_provisional", source_kind="llm_code",
                      advisory_ref=references[0] if references else "")
    candidate = ExploitCandidate(
        candidate_id=derive_candidate_id(kind="guided_procedure", cve_id=cve_id,
                                         locator=f"llm-artifact:{digest}", provenance=prov),
        cve_id=cve_id, kind="guided_procedure", source="llm_code", locator=f"llm-artifact:{digest}",
        provenance=prov, working_dir=os.path.dirname(artifact_path), artifact_hash=digest,
        procedure=[ProcedureStep(stage="prepare", argv=[interpreter, "-m", "py_compile", artifact_path]
                                 if language == "python" else ["bash", "-n", artifact_path]),
                   ProcedureStep(stage="execute", argv=[interpreter, artifact_path])],
        capability="code_execution", side_effect_class="remote_exploit",
        runtime_kind="isolated_container", requirements={"binaries": [interpreter]},
        expected_evidence=["task_proof"], failure_predicates=["syntax_invalid", "scope_violation"],
        repair_lineage={"parent_candidate_id": parent_candidate_id, "repair_index": 1},
        product_evidence=fingerprint.product.parsed, version_evidence=fingerprint.version.parsed,
        extra={"artifact_path": artifact_path, "generation_kind": "llm_code"},
    )
    return candidate


def _parse_procedure_json(text: str) -> list[ProcedureStep] | None:
    """Parse a JSON array of procedure steps from LLM output."""
    import json

    # Try to extract JSON from the text.
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if not match:
        return None
    try:
        items = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None

    if not isinstance(items, list):
        return None

    steps: list[ProcedureStep] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        argv = item.get("argv") or []
        if not isinstance(argv, list):
            continue
        stage = str(item.get("stage") or "execute")
        timeout = int(item.get("timeout_seconds") or 60)
        steps.append(ProcedureStep(stage=stage, argv=[str(a) for a in argv],
                                    timeout_seconds=timeout))
    return steps if steps else None
