"""
tests/test_guided_procedure.py
──────────────────────────────
Tests for guided_procedure candidate kind, procedure rejection,
verifier routing, and benchmark isolation.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.critic import CriticAgent, CriticVerdict
from src.agents.planner import (
    PlannerProposal,
    build_guided_candidate,
    validate_guided_procedure,
)
from src.agents.verifier_pipeline import PipelineVerifierAgent, VerifierDecision
from src.pipeline.candidates import (
    SUPPORTED_KINDS,
    SUPPORTED_TRUST,
    ExploitCandidate,
    ProcedureStep,
    Provenance,
    derive_candidate_id,
    evaluate_trust,
    is_executable,
)
from src.pipeline.evidence import Fingerprint, IdentityField
from src.pipeline.manifest import Scope
from src.pipeline.queue import CandidateQueue, RankedCandidate

# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_fingerprint(product="apache", version="2.4.49", port=80,
                      target_ip="10.0.0.1") -> Fingerprint:
    def _field(val, observed=True, confidence="high"):
        return IdentityField(raw=val, parsed=val, source="test", timestamp=0.0,
                              observed=observed, confidence=confidence, reason="")
    return Fingerprint(
        target_ip=target_ip,
        port=port,
        protocol="tcp",
        product=_field(product),
        vendor=_field("apache"),
        version=_field(version),
        platform_hints=["linux"],
        auth_hint="none",
    )


def _make_procedure(steps=None) -> list[ProcedureStep]:
    if steps is None:
        steps = [
            ProcedureStep(stage="execute",
                          argv=["curl", "-s", "http://{TARGET_IP}:80/"],
                          timeout_seconds=30),
            ProcedureStep(stage="verify",
                          argv=["curl", "-s", "-I", "http://{TARGET_IP}:80/"],
                          timeout_seconds=30),
        ]
    return steps


def _make_guided_candidate(cve_id="CVE-2021-41773", procedure=None,
                           fingerprint=None) -> ExploitCandidate:
    if procedure is None:
        procedure = _make_procedure()
    if fingerprint is None:
        fingerprint = _make_fingerprint()
    return build_guided_candidate(
        cve_id=cve_id,
        procedure=procedure,
        fingerprint=fingerprint,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    )


def _make_catalog_candidate(cve_id="CVE-2021-41773", kind="metasploit") -> ExploitCandidate:
    prov = Provenance(trust="trusted", source_kind=kind)
    return ExploitCandidate(
        candidate_id=derive_candidate_id(kind=kind, cve_id=cve_id,
                                          locator=f"test-{kind}", provenance=prov),
        cve_id=cve_id, kind=kind, source="test",
        locator=f"test-{kind}",
        provenance=prov,
        procedure=[ProcedureStep(stage="execute", argv=["nmap", "{TARGET_IP}"])],
    )


# ── Test: guided_procedure kind normalization ────────────────────────────────


class TestGuidedProcedureNormalization(unittest.TestCase):

    def test_supported_kinds_includes_guided_procedure(self):
        self.assertIn("guided_procedure", SUPPORTED_KINDS)

    def test_supported_trust_includes_llm_provisional(self):
        self.assertIn("llm_provisional", SUPPORTED_TRUST)

    def test_guided_procedure_candidate_creation(self):
        cand = _make_guided_candidate()
        self.assertEqual(cand.kind, "guided_procedure")
        self.assertEqual(cand.provenance.trust, "llm_provisional")
        self.assertEqual(cand.provenance.source_kind, "llm_planner")
        self.assertTrue(cand.candidate_id.startswith("cand-guided_procedure-"))

    def test_guided_procedure_has_references(self):
        cand = _make_guided_candidate()
        self.assertTrue(len(cand.provenance.references) > 0)

    def test_guided_procedure_has_structured_argv(self):
        cand = _make_guided_candidate()
        for step in cand.procedure:
            self.assertIsInstance(step.argv, list)
            self.assertTrue(len(step.argv) > 0)
            # Each argv token is a string, not shell prose.
            for tok in step.argv:
                self.assertIsInstance(tok, str)

    def test_guided_procedure_has_placeholders(self):
        cand = _make_guided_candidate()
        self.assertIn("TARGET_IP", cand.placeholders)


# ── Test: trust policy for llm_provisional ───────────────────────────────────


class TestGuidedProcedureTrust(unittest.TestCase):

    def test_llm_provisional_not_executable_by_default(self):
        cand = _make_guided_candidate()
        self.assertFalse(is_executable(cand))

    def test_llm_provisional_executable_with_verifier_approval(self):
        cand = _make_guided_candidate()
        self.assertTrue(is_executable(cand, verifier_approved=True))

    def test_llm_provisional_blocked_without_verifier_approval(self):
        cand = _make_guided_candidate()
        trust = evaluate_trust(cand)
        self.assertEqual(trust, "llm_provisional")

    def test_trusted_still_executable(self):
        cand = _make_catalog_candidate()
        self.assertTrue(is_executable(cand))

    def test_blocked_never_executable(self):
        prov = Provenance(trust="blocked")
        cand = ExploitCandidate(
            candidate_id="test", cve_id="CVE-2021-41773",
            kind="poc", source="test", locator="test",
            provenance=prov,
        )
        self.assertFalse(is_executable(cand))
        self.assertFalse(is_executable(cand, verifier_approved=True))


# ── Test: procedure rejection ────────────────────────────────────────────────


class TestProcedureRejection(unittest.TestCase):

    def test_valid_procedure_accepted(self):
        violations = validate_guided_procedure(_make_procedure())
        self.assertEqual(violations, [])

    def test_empty_procedure_rejected(self):
        violations = validate_guided_procedure([])
        self.assertIn("empty_procedure", violations)

    def test_no_execute_stage_rejected(self):
        steps = [ProcedureStep(stage="verify", argv=["curl", "-s", "http://example.com/"])]
        violations = validate_guided_procedure(steps)
        self.assertIn("no_execute_stage", violations)

    def test_empty_argv_rejected(self):
        steps = [ProcedureStep(stage="execute", argv=[])]
        violations = validate_guided_procedure(steps)
        self.assertTrue(any("empty_argv" in v for v in violations))

    def test_unapproved_tool_rejected(self):
        steps = [ProcedureStep(stage="execute", argv=["metasploit_pro", "exploit"])]
        violations = validate_guided_procedure(steps)
        self.assertTrue(any("unapproved_tool" in v for v in violations))

    def test_shell_eval_form_rejected(self):
        steps = [ProcedureStep(stage="execute",
                                argv=["bash", "-c", "eval(malicious_code)"])]
        violations = validate_guided_procedure(steps)
        self.assertTrue(any("shell_eval" in v for v in violations))

    def test_sudo_rejected(self):
        steps = [ProcedureStep(stage="execute",
                                argv=["bash", "-c", "sudo apt install something"])]
        violations = validate_guided_procedure(steps)
        self.assertTrue(any("shell_eval" in v for v in violations))

    def test_package_install_rejected(self):
        steps = [ProcedureStep(stage="execute",
                                argv=["bash", "-c", "apt install evil"])]
        violations = validate_guided_procedure(steps)
        self.assertTrue(any("shell_eval" in v for v in violations))

    def test_scope_violation_rejected(self):
        scope = Scope(
            allowed_networks=["10.0.0.0/24"],
            allowed_ports=[80],
            allowed_schemes=["http"],
        )
        steps = [ProcedureStep(stage="execute",
                                argv=["curl", "-s", "http://192.168.1.1:8080/"])]
        violations = validate_guided_procedure(steps, scope=scope)
        self.assertTrue(any("scope" in v for v in violations))

    def test_approved_tools_accepted(self):
        for tool in ["nmap", "curl", "nuclei", "msfconsole", "nc", "wget"]:
            steps = [ProcedureStep(stage="execute", argv=[tool, "--help"])]
            violations = validate_guided_procedure(steps)
            tool_violations = [v for v in violations if "unapproved_tool" in v]
            self.assertEqual(tool_violations, [], f"Tool '{tool}' should be approved")

    def test_generated_shell_and_interpreter_are_rejected(self):
        for tool in ["bash", "sh", "python", "python3"]:
            violations = validate_guided_procedure([ProcedureStep(stage="execute", argv=[tool, "-c", "echo test"])])
            self.assertTrue(any("unapproved_tool" in value for value in violations))


# ── Test: critic evaluation ──────────────────────────────────────────────────


class TestCriticEvaluation(unittest.TestCase):

    def test_critic_approves_valid_proposal(self):
        proposal = PlannerProposal(
            cve_id="CVE-2021-41773",
            rationale="Catalog exhausted for apache/2.4.49",
            fingerprint_match="product=apache, version=2.4.49",
            prereq_satisfaction="verified",
            procedure_readiness=0.3,
            expected_evidence_gain="proof of CVE-2021-41773",
            candidate=_make_guided_candidate(),
            cited_evidence_ids=["fp:apache:2.4.49"],
            catalog_exhausted=True,
        )
        critic = CriticAgent()
        verdict = critic.evaluate(proposal, fingerprint=_make_fingerprint())
        self.assertTrue(verdict.approved)
        self.assertEqual(verdict.severity, "info")

    def test_critic_rejects_product_mismatch(self):
        proposal = PlannerProposal(
            cve_id="CVE-2021-41773",
            rationale="test",
            fingerprint_match="product=nginx",
            prereq_satisfaction="verified",
            procedure_readiness=0.3,
            expected_evidence_gain="proof",
            candidate=_make_guided_candidate(),
            cited_evidence_ids=[],
            catalog_exhausted=True,
        )
        critic = CriticAgent()
        fp = _make_fingerprint(product="nginx")
        verdict = critic.evaluate(proposal, fingerprint=fp)
        self.assertFalse(verdict.approved)
        self.assertTrue(any("product_mismatch" in c for c in verdict.challenges))

    def test_critic_identifies_better_alternatives(self):
        proposal = PlannerProposal(
            cve_id="CVE-2021-41773",
            rationale="test",
            fingerprint_match="product=apache",
            prereq_satisfaction="verified",
            procedure_readiness=0.3,
            expected_evidence_gain="proof",
            candidate=_make_guided_candidate(),
            cited_evidence_ids=[],
            catalog_exhausted=True,
        )
        catalog = [_make_catalog_candidate(kind="metasploit")]
        critic = CriticAgent()
        verdict = critic.evaluate(proposal, fingerprint=_make_fingerprint(),
                                   catalog_candidates=catalog)
        self.assertTrue(len(verdict.better_alternatives) > 0)

    def test_critic_verdict_serialization(self):
        verdict = CriticVerdict(
            proposal_id="test-123",
            challenges=["product_mismatch"],
            missing_preconditions=[],
            invalid_parameters=[],
            better_alternatives=[],
            severity="fatal",
            approved=False,
        )
        d = verdict.to_dict()
        restored = CriticVerdict.from_dict(d)
        self.assertEqual(restored.proposal_id, "test-123")
        self.assertFalse(restored.approved)
        self.assertEqual(restored.severity, "fatal")


# ── Test: verifier routing ───────────────────────────────────────────────────


class TestVerifierRouting(unittest.TestCase):

    def _make_verifier_decision(self, action="execute", target_id="cand-test"):
        return VerifierDecision(
            action=action,
            reason="test",
            cited_state_keys=["exploit_candidates"],
            cited_evidence_ids=["fp:apache:2.4.49"],
            target_candidate_id=target_id,
        )

    def test_verifier_decide_execute_with_queue(self):
        cand = _make_catalog_candidate()
        queue = CandidateQueue(ranked=[
            RankedCandidate(candidate=cand, applicability="exact",
                            capability_match=True, procedure_complete=True,
                            score=100.0)
        ])
        verifier = PipelineVerifierAgent()
        decision = verifier.decide(fingerprint=_make_fingerprint(), ranked_queue=queue)
        self.assertEqual(decision.action, "execute")
        self.assertEqual(decision.target_candidate_id, cand.candidate_id)

    def test_verifier_decide_stop_when_empty(self):
        queue = CandidateQueue(ranked=[])
        verifier = PipelineVerifierAgent()
        decision = verifier.decide(fingerprint=_make_fingerprint(), ranked_queue=queue)
        self.assertEqual(decision.action, "stop")

    def test_verifier_decide_stop_at_loop_cap(self):
        queue = CandidateQueue(ranked=[])
        verifier = PipelineVerifierAgent()
        decision = verifier.decide(
            fingerprint=_make_fingerprint(), ranked_queue=queue,
            loop_count=5, loop_max=5,
        )
        self.assertEqual(decision.action, "stop")

    def test_verifier_decide_execute_skips_executed(self):
        cand1 = _make_catalog_candidate(kind="metasploit")
        cand2 = _make_catalog_candidate(kind="nuclei")
        queue = CandidateQueue(ranked=[
            RankedCandidate(candidate=cand1, applicability="exact",
                            capability_match=True, procedure_complete=True,
                            score=100.0),
            RankedCandidate(candidate=cand2, applicability="exact",
                            capability_match=True, procedure_complete=True,
                            score=90.0),
        ])
        verifier = PipelineVerifierAgent()
        decision = verifier.decide(
            fingerprint=_make_fingerprint(), ranked_queue=queue,
            executed_ids={cand1.candidate_id},
        )
        self.assertEqual(decision.action, "execute")
        self.assertEqual(decision.target_candidate_id, cand2.candidate_id)

    def test_verifier_does_not_stop_on_unverified_stdout(self):
        from src.pipeline.oracle import ProofArtifact
        # Queue with one already-executed candidate, plus a proof.
        cand = _make_catalog_candidate()
        queue = CandidateQueue(ranked=[
            RankedCandidate(candidate=cand, applicability="exact",
                            capability_match=True, procedure_complete=True,
                            score=100.0)
        ])
        verifier = PipelineVerifierAgent()
        proof = ProofArtifact(kind="command_output", content="uid=0(root)")
        decision = verifier.decide(
            fingerprint=_make_fingerprint(), ranked_queue=queue,
            last_proof=proof,
            executed_ids={cand.candidate_id},
            loop_count=4, loop_max=5,
        )
        self.assertNotEqual(decision.action, "stop")

    def test_verifier_decide_replan_after_failures(self):
        guided = _make_guided_candidate()
        guided_dict = guided.to_dict()
        queue = CandidateQueue(ranked=[])
        verifier = PipelineVerifierAgent()
        # All candidates exhausted (executed) + 3 failures → should stop.
        decision = verifier.decide(
            fingerprint=_make_fingerprint(), ranked_queue=queue,
            planner_proposals=[{"cve_id": "CVE-2021-41773",
                                "candidate": guided_dict}],
            prior_failures=["timeout", "command_invalid", "scope_violation"],
            catalog_exhausted=True,
            executed_ids={guided.candidate_id},
        )
        self.assertEqual(decision.action, "stop")

    def test_verifier_cites_state_keys(self):
        cand = _make_catalog_candidate()
        queue = CandidateQueue(ranked=[
            RankedCandidate(candidate=cand, applicability="exact",
                            capability_match=True, procedure_complete=True,
                            score=100.0)
        ])
        verifier = PipelineVerifierAgent()
        decision = verifier.decide(fingerprint=_make_fingerprint(), ranked_queue=queue)
        self.assertTrue(len(decision.cited_state_keys) > 0)

    def test_verifier_decision_serialization(self):
        decision = VerifierDecision(
            action="execute",
            reason="test",
            cited_state_keys=["exploit_candidates"],
            cited_evidence_ids=["fp:apache:2.4.49"],
            target_candidate_id="cand-test-123",
        )
        d = decision.to_dict()
        restored = VerifierDecision.from_dict(d)
        self.assertEqual(restored.action, "execute")
        self.assertEqual(restored.target_candidate_id, "cand-test-123")

    def test_verifier_guided_procedure_needs_critic_approval(self):
        guided = _make_guided_candidate()
        queue = CandidateQueue(ranked=[
            RankedCandidate(candidate=guided, applicability="partial",
                            capability_match=True, procedure_complete=True,
                            score=50.0)
        ])
        critic_verdict = CriticVerdict(
            proposal_id=guided.candidate_id,
            challenges=["some issue"],
            missing_preconditions=[],
            invalid_parameters=[],
            better_alternatives=[],
            severity="fatal",
            approved=False,
        )
        verifier = PipelineVerifierAgent()
        decision = verifier.decide(
            fingerprint=_make_fingerprint(), ranked_queue=queue,
            critic_verdicts=[critic_verdict.to_dict()],
        )
        self.assertEqual(decision.action, "replan")


# ── Test: benchmark isolation ────────────────────────────────────────────────


class TestBenchmarkIsolation(unittest.TestCase):

    def test_oracle_rejects_guided_procedure_without_accepted_evidence(self):
        from src.pipeline.oracle import BenchmarkOracle, ProofArtifact, ProofSpec, TargetTruth
        oracle = BenchmarkOracle()
        truth = TargetTruth(
            target_id="test",
            applicable_cves=["CVE-2021-41773"],
            proof_specs={"CVE-2021-41773": ProofSpec(
                capability="code_execution",
                accepted_evidence=["uid=0", "root@"],
            )},
        )
        proof = ProofArtifact(kind="command_output", content="some output without markers")
        result = oracle.evaluate_proof("CVE-2021-41773", proof, truth)
        self.assertFalse(result.task_proof)
        self.assertEqual(result.outcome, "execution_failed")

    def test_oracle_accepts_guided_procedure_with_accepted_evidence(self):
        from src.pipeline.oracle import BenchmarkOracle, ProofArtifact, ProofSpec, TargetTruth
        oracle = BenchmarkOracle()
        truth = TargetTruth(
            target_id="test",
            applicable_cves=["CVE-2021-41773"],
            proof_specs={"CVE-2021-41773": ProofSpec(
                capability="code_execution",
                accepted_evidence=["uid=0", "root@"],
            )},
        )
        proof = ProofArtifact(kind="command_output", content="uid=0(root) gid=0(root)")
        result = oracle.evaluate_proof("CVE-2021-41773", proof, truth)
        self.assertTrue(result.task_proof)

    def test_textual_markers_never_override_oracle(self):
        from src.pipeline.oracle import (
            BenchmarkOracle,
            ProofArtifact,
            ProofSpec,
            TargetTruth,
            TextualMarkerChecker,
        )
        checker = TextualMarkerChecker()
        # Textual markers detect success...
        self.assertTrue(checker.matches("uid=0(root)"))
        # ...but oracle still requires accepted_evidence in the proof.
        oracle = BenchmarkOracle()
        truth = TargetTruth(
            target_id="test",
            applicable_cves=["CVE-2021-41773"],
            proof_specs={"CVE-2021-41773": ProofSpec(
                capability="code_execution",
                accepted_evidence=["specific_marker_xyz"],
            )},
        )
        proof = ProofArtifact(kind="command_output", content="uid=0(root)")
        result = oracle.evaluate_proof("CVE-2021-41773", proof, truth)
        # Oracle rejects because "specific_marker_xyz" is not in the proof.
        self.assertFalse(result.task_proof)

    def test_patched_control_cannot_succeed(self):
        from src.pipeline.oracle import BenchmarkOracle, ProofArtifact, ProofSpec, TargetTruth
        oracle = BenchmarkOracle()
        truth = TargetTruth(
            target_id="test-patched",
            applicable_cves=["CVE-2021-41773"],
            proof_specs={"CVE-2021-41773": ProofSpec(
                capability="code_execution",
                accepted_evidence=["uid=0"],
            )},
            is_patched_control=True,
        )
        proof = ProofArtifact(kind="command_output", content="uid=0(root)")
        result = oracle.evaluate_proof("CVE-2021-41773", proof, truth)
        self.assertEqual(result.outcome, "not_applicable")


# ── Test: planner proposal serialization ─────────────────────────────────────


class TestPlannerProposalSerialization(unittest.TestCase):

    def test_round_trip(self):
        proposal = PlannerProposal(
            cve_id="CVE-2021-41773",
            rationale="test rationale",
            fingerprint_match="product=apache",
            prereq_satisfaction="verified",
            procedure_readiness=0.3,
            expected_evidence_gain="proof",
            candidate=_make_guided_candidate(),
            cited_evidence_ids=["fp:apache:2.4.49"],
            catalog_exhausted=True,
        )
        d = proposal.to_dict()
        restored = PlannerProposal.from_dict(d)
        self.assertEqual(restored.cve_id, "CVE-2021-41773")
        self.assertEqual(restored.procedure_readiness, 0.3)
        self.assertTrue(restored.catalog_exhausted)
        self.assertEqual(restored.candidate.kind, "guided_procedure")


if __name__ == "__main__":
    unittest.main()
