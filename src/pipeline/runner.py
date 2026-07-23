"""
src/pipeline/runner.py
──────────────────────
Pipeline runner.

Wires:

    recon -> evidence normalization -> CVE source collection ->
    candidate collection -> deterministic queue -> policy preflight ->
    method execution -> independent oracle -> cleanup

The runner executes a single target-condition run inside a ``RunContext``.
It never falls back to free-form shell improvisation and never fabricates
proof: every outcome flows through the ``BenchmarkOracle`` via structured
proof artifacts captured during execution.
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from src.pipeline.budget import BudgetExceeded, ResourceBudget
from src.pipeline.candidates import ExploitCandidate, is_executable, substitute_placeholders
from src.pipeline.evidence import (
    Fingerprint, ServiceObservation, fingerprint_service,
)
from src.pipeline.ledger import Event, EventLedger
from src.pipeline.manifest import (
    ResourceLimits, RunManifest, Scope, new_manifest,
)
from src.pipeline.oracle import (
    BenchmarkOracle, Oracle, OracleResult, ProofArtifact,
)
from src.pipeline.queue import (
    CandidateQueue, RankedCandidate, rank_candidates, shortlist,
)
from src.pipeline.renderers import RenderedStep, RenderError, render_procedure
from src.pipeline.scope import ScopeDecision, ScopeValidator
from src.pipeline.sources import (
    BaseAdapter, CveListV5Adapter, NvdAdapter, VulnxAdapter,
    SourceRegistry, RawCveRecord,
)

# ── Hooks for testing/dry-run ─────────────────────────────────────────────────


@dataclass
class ReconObservation:
    target_ip: str
    port: int
    protocol: str = "tcp"
    service_name: str = ""
    banner: str = ""
    version: str = ""
    observed_cpe: str = ""


@dataclass
class RunnerHooks:
    """Pluggable hooks for testing or offline runs.

    All defaults are offline-friendly: no network, no real subprocesses.
    """

    recon: Callable[["PipelineRunner"], list[ReconObservation]] = None  # type: ignore[assignment]
    fingerprint: Callable[..., Fingerprint] = fingerprint_service
    execute_step: Callable[[RenderedStep, "PipelineRunner"],
                              "ExecutionResult"] = None  # type: ignore[assignment]
    cleanup_step: Callable[[RenderedStep, "PipelineRunner"],
                             "ExecutionResult"] = None  # type: ignore[assignment]


@dataclass
class ExecutionResult:
    returncode: int
    stdout: str
    stderr: str
    duration_ms: float
    content_hash: str = ""

    @property
    def output(self) -> str:
        return self.stdout or self.stderr or ""


# ── PipelineRunner ──────────────────────────────────────────────────────────


class PipelineRunner:
    """One-shot execution of the evidence-driven pipeline for a single target."""

    def __init__(self, *, manifest: RunManifest, ledger: EventLedger,
                 budget: ResourceBudget, scope: Scope,
                 oracle: Oracle | None = None,
                 sources: SourceRegistry | None = None,
                 hooks: RunnerHooks | None = None,
                 ) -> None:
        self.manifest = manifest
        self.ledger = ledger
        self.budget = budget
        self.scope = scope
        self.oracle = oracle or BenchmarkOracle()
        self.sources = sources or SourceRegistry(
            [NvdAdapter(mode="snapshot", ledger=ledger, snapshot_dir=""),
             CveListV5Adapter(mode="snapshot", ledger=ledger, snapshot_dir=""),
             VulnxAdapter(mode="snapshot", ledger=ledger, snapshot_dir="")],
            ledger=ledger,
        )
        self.hooks = hooks or RunnerHooks()
        self.validator = ScopeValidator(scope)
        self.msf_cfgroot = ""
        self.nuclei_output_dir = ""
        self.working_dir = ""
        if manifest.run_dir:
            self.working_dir = manifest.run_dir
            self.msf_cfgroot = os.path.join(manifest.run_dir, "msf_cfgroot")
            self.nuclei_output_dir = os.path.join(manifest.run_dir, "nuclei_out")
            os.makedirs(self.msf_cfgroot, exist_ok=True)
            os.makedirs(self.nuclei_output_dir, exist_ok=True)
        self._proofs: list[ProofArtifact] = []

    # ── Phases ─────────────────────────────────────────────────────────────────
    def recon(self) -> list[ReconObservation]:
        self.ledger.record(phase="recon", stage="applicability", detail="begin")
        if self.hooks.recon:
            obs = self.hooks.recon(self) or []
        else:
            obs = []
        self.ledger.record(phase="recon", stage="applicability",
                            detail=f"recon produced {len(obs)} observation(s)")
        return obs

    def evidence(self, observations: list[ReconObservation]) -> list[Fingerprint]:
        fps: list[Fingerprint] = []
        for obs in observations:
            so = ServiceObservation(target_ip=obs.target_ip, port=obs.port,
                                      protocol=obs.protocol, service_name=obs.service_name,
                                      banner=obs.banner, version=obs.version,
                                      observed_cpe=obs.observed_cpe, source="recon",
                                      timestamp=time.time())
            hook = self.hooks.fingerprint
            if hook is fingerprint_service:
                fp = hook(so)
            else:
                fp = hook(so, None)
            fps.append(fp)
        return fps

    def retrieve(self, fp: Fingerprint) -> list[RawCveRecord]:
        records = self.sources.collect_cves(fp.product.parsed, fp.vendor.parsed, fp.version.parsed)
        priority = self.sources.collect_priority(fp.product.parsed, fp.vendor.parsed, fp.version.parsed)
        # Priority never changes applicability; record for diagnostics.
        for cve_id, sig in priority.items():
            self.ledger.record(phase="retrieval", stage="applicability",
                                cve_id=cve_id, detail="priority-only",
                                payload={"in_kev": sig.in_kev, "epss": sig.epss_score})
        return records

    def build_queue(self, *, fp: Fingerprint,
                     candidates: list[ExploitCandidate]) -> CandidateQueue:
        ranked = rank_candidates(candidates, fingerprint=fp,
                                  proof_capability=self.manifest.oracle_spec.get("capability", "code_execution"),
                                  ledger=self.ledger, scope=self.scope)
        return shortlist(ranked, limits=ResourceLimits(**self.manifest.limits))

    # ── Execution ──────────────────────────────────────────────────────────────
    def _execute_or_cleanup(self, *, candidate: ExploitCandidate,
                              values: Mapping[str, str], stage_filter: set[str],
                              mode: str) -> list[ExecutionResult]:
        results: list[ExecutionResult] = []
        try:
            steps = render_procedure(candidate, values=values,
                                       working_dir=self.working_dir,
                                       msf_cfgroot=self.msf_cfgroot,
                                       nuclei_output_dir=self.nuclei_output_dir,
                                       ledger=self.ledger)
        except RenderError as exc:
            self.ledger.record(
                phase="execution", stage="execution_failure",
                candidate_id=candidate.candidate_id, method=candidate.kind,
                cve_id=candidate.cve_id,
                outcome="execution_failed", failure_class="procedure_incomplete",
                detail=str(exc),
            )
            return results
        for step in steps:
            if step.stage not in stage_filter:
                continue
            self.budget.record_tool_call()
            dec = self.validator.validate_args(step.argv, stage=step.stage)
            if not dec:
                self.ledger.record(
                    phase="execution", stage="execution_failure",
                    candidate_id=candidate.candidate_id, method=candidate.kind,
                    cve_id=candidate.cve_id,
                    outcome="blocked_by_policy", failure_class="scope_violation",
                    scope_decision="blocked",
                    detail=dec.reason,
                )
                continue
            try:
                self.budget.record_command()
            except BudgetExceeded:
                self.ledger.record(phase="execution", stage="execution_failure",
                                    candidate_id=candidate.candidate_id,
                                    outcome="execution_failed",
                                    failure_class="budget_exceeded")
                return results
            self.ledger.record(
                phase="execution", stage=stage_filter_for_outcome(step.stage, mode),
                candidate_id=candidate.candidate_id, method=candidate.kind,
                cve_id=candidate.cve_id, scope_decision="allowed",
                policy_decision="execute", detail="step render",
                payload={"executed_command": True, "argv": step.argv},
            )
            hook = self.hooks.execute_step if mode == "execute" else self.hooks.cleanup_step
            if hook is not None:
                res = hook(step, self)
            else:
                res = self._default_execute(step, candidate)
            results.append(res)
            if mode == "execute" and res.stdout:
                self._record_proof(res, candidate, step.stage)
        return results

    def _record_proof(self, res: ExecutionResult, candidate: ExploitCandidate,
                       stage: str) -> None:
        if not res.stdout:
            return
        proof = ProofArtifact(
            kind="command_output" if stage == "execute" else "detection_output",
            content=res.stdout,
            path=os.path.join(self.working_dir, "proofs",
                                f"{candidate.candidate_id}-{stage}.txt"),
        )
        self._proofs.append(proof)
        self.ledger.record(
            phase="oracle", stage="task_proof" if stage == "execute" else "vulnerability_confirmation",
            candidate_id=candidate.candidate_id, method=candidate.kind,
            cve_id=candidate.cve_id, proof_ref=proof.path,
            detail=f"proof-captured:{proof.content_hash[:12]}",
            payload={"content_hash": proof.content_hash, "stage": stage},
        )

    def _default_execute(self, step: RenderedStep, candidate: ExploitCandidate) -> ExecutionResult:
        try:
            env = dict(os.environ)
            if step.env:
                env.update(step.env)
            start = time.time()
            proc = subprocess.run(
                step.argv,
                cwd=self.working_dir or None,
                env=env,
                capture_output=True,
                text=True,
                timeout=step.timeout_seconds,
                check=False,
            )
            duration_ms = round((time.time() - start) * 1000.0, 3)
            return ExecutionResult(returncode=proc.returncode, stdout=proc.stdout,
                                     stderr=proc.stderr, duration_ms=duration_ms)
        except subprocess.TimeoutExpired as exc:
            return ExecutionResult(returncode=124, stdout=exc.stdout or "",
                                     stderr=(exc.stderr or "") + "\n[timeout]",
                                     duration_ms=float(step.timeout_seconds) * 1000.0)
        except FileNotFoundError as exc:
            return ExecutionResult(returncode=127, stdout="", stderr=str(exc),
                                     duration_ms=0.0)
        except Exception as exc:                          # noqa: BLE001
            return ExecutionResult(returncode=1, stdout="", stderr=f"[render-error] {exc}",
                                     duration_ms=0.0)

    # ── Top-level ──────────────────────────────────────────────────────────────
    def run(self, *, recon_obs: list[ReconObservation] | None = None,
            candidates: list[ExploitCandidate] | None = None) -> OracleResult:
        observations = recon_obs if recon_obs is not None else self.recon()
        fps = self.evidence(observations)
        if not fps:
            self.ledger.record(phase="execution", stage="execution_failure",
                                outcome="execution_failed",
                                failure_class="identity_mismatch",
                                detail="no fingerprints produced")
            return OracleResult(outcome="execution_failed", reason="no fingerprints")
        proofs: list[ProofArtifact] = []
        for fp in fps:
            self.ledger.record(phase="evidence", stage="applicability",
                                detail=fp.applicability_grade())
            records = self.retrieve(fp)
            relevant = [r for r in records if r.product and r.product == fp.product.parsed]
            for rec in relevant:
                self.ledger.record(phase="retrieval", stage="applicability",
                                    cve_id=rec.cve_id, detail="raw",
                                    payload=rec.to_dict())
            candidates_for_fp = [c for c in (candidates or []) if not fp.vendor.parsed
                                  or fp.vendor.parsed == "unknown"
                                  or c.constraint.vendor == fp.vendor.parsed]
            queue = self.build_queue(fp=fp, candidates=candidates_for_fp)
            for rc in queue.ranked:
                proofs.extend(self._execute_one(rc, fp))
            # Cleanup pass.
            for rc in queue.ranked:
                self._cleanup_one(rc, fp)
        proofs.extend(self._proofs)
        target_cve = self.manifest.oracle_spec.get("cve_id", "")
        truth = self.manifest.oracle_spec.get("truth")
        if truth is None:
            self.ledger.record(phase="oracle", stage="task_proof",
                                outcome="execution_failed",
                                failure_class="oracle_reject",
                                detail="no truth supplied")
            return OracleResult(outcome="execution_failed", reason="no truth supplied")
        for cve in ([target_cve] if target_cve else [r.cve_id for r in (records or [])]):
            for proof in proofs:
                res = self.oracle.evaluate_proof(cve, proof, truth)
                if res.task_proof:
                    self.ledger.record(
                        phase="oracle", stage="task_proof",
                        cve_id=cve, proof_ref=proof.path,
                        outcome="task_proof_obtained", detail="oracle-accepted",
                        payload={"evidence_used": res.evidence_used},
                    )
                    return res
        # Fall through: no oracle-accepted proof.
        self.ledger.record(phase="oracle", stage="task_proof",
                            outcome="execution_failed",
                            failure_class="oracle_reject",
                            detail="no oracle-accepted proof")
        return OracleResult(outcome="execution_failed", reason="no proof accepted")

    def _execute_one(self, rc: RankedCandidate, fp: Fingerprint) -> list[ProofArtifact]:
        cand = rc.candidate
        if not is_executable(cand, manifest_approved_lab_ids={"*"}
                              if cand.provenance.trust == "lab_approved" else None):
            self.ledger.record(phase="execution", stage="policy_decision",
                                candidate_id=cand.candidate_id, cve_id=cand.cve_id,
                                policy_decision="blocked",
                                outcome="blocked_by_policy",
                                failure_class="policy_block",
                                detail=f"trust={cand.provenance.trust}")
            return []
        if not rc.capability_match and not rc.procedure_complete:
            self.ledger.record(phase="execution", stage="execution_failure",
                                candidate_id=cand.candidate_id, cve_id=cand.cve_id,
                                outcome="not_executable",
                                failure_class="procedure_incomplete",
                                detail="missing capability/procedure",
                                payload={"reasons": rc.rejection_reasons})
            return []
        values = _values_from_fingerprint(fp)
        results = self._execute_or_cleanup(
            candidate=cand, values=values,
            stage_filter={"execute", "verify"}, mode="execute")
        # If all executed steps produced no output, record not_applicable.
        if not any(r.stdout for r in results):
            self.ledger.record(phase="execution", stage="execution_failure",
                                candidate_id=cand.candidate_id, cve_id=cand.cve_id,
                                outcome="execution_failed",
                                failure_class="procedure_incomplete",
                                detail="no output")
        return [ProofArtifact(kind="command_output", content=r.stdout, path="")
                for r in results if r.stdout]

    def _cleanup_one(self, rc: RankedCandidate, fp: Fingerprint) -> None:
        cand = rc.candidate
        values = _values_from_fingerprint(fp)
        cleanup_steps = self._execute_or_cleanup(
            candidate=cand, values=values,
            stage_filter={"cleanup"}, mode="cleanup")
        if cleanup_steps:
            self.ledger.record(phase="cleanup", stage="cleanup",
                                candidate_id=cand.candidate_id, cve_id=cand.cve_id,
                                outcome="task_proof_obtained", detail="cleanup-best-effort")


def stage_filter_for_outcome(stage: str, mode: str) -> str:
    """Map a renderer stage + runner mode to a ledger stage."""
    if mode == "cleanup":
        return "cleanup"
    return {
        "execute": "task_proof",
        "verify": "vulnerability_confirmation",
        "setup": "execution_failure",
        "cleanup": "cleanup",
    }.get(stage, "execution_failure")


def _values_from_fingerprint(fp: Fingerprint) -> dict[str, str]:
    return {
        "RHOST": fp.target_ip,
        "RHOSTS": fp.target_ip,
        "RPORT": str(fp.port),
        "TARGET": fp.target_ip,
        "LHOST": "127.0.0.1",
        "LPORT": "4444",
        "PRODUCT": fp.product.parsed,
        "VENDOR": fp.vendor.parsed,
        "VERSION": fp.version.parsed,
    }
