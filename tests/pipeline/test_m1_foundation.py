"""
Golden tests for the M1 measurement foundation: manifest, ledger, budget,
scope validation, oracle, and evaluator.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from src.pipeline.budget import BudgetExceeded, ResourceBudget, ResourceLimits
from src.pipeline.evaluator import Evaluator
from src.pipeline.ledger import EventLedger
from src.pipeline.manifest import (
    RunContext,
    Scope,
    config_hash,
    load_manifest,
    new_manifest,
    redact_secrets,
)
from src.pipeline.oracle import (
    BenchmarkOracle,
    ProofArtifact,
    ProofSpec,
    TargetTruth,
    TextualMarkerChecker,
)
from src.pipeline.scope import ScopeValidator


class TestManifest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp()

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_run_dir_not_reused(self) -> None:
        m = new_manifest("t1", variant="1", condition="clean")
        ctx = RunContext(m, root=self.root)
        ctx.write_json("a.json", {"x": 1})
        published = ctx.publish()
        self.assertTrue(os.path.isdir(published))
        self.assertEqual(load_manifest(published).run_id, m.run_id)
        # A second run with the same id must not reuse the directory.
        m2 = RunContext.__new__(RunContext)
        m2.__init__(m, root=self.root)  # fresh staging
        with self.assertRaises(RuntimeError):
            m2.publish()  # same run_id -> final dir exists -> reuse blocked

    def test_config_hash_redacts_secrets(self) -> None:
        h1 = config_hash({"api_key": "secret", "model": "gemini-2.5-flash", "nested": {"token": "t"}})
        h2 = config_hash({"api_key": "different", "model": "gemini-2.5-flash", "nested": {"token": "x"}})
        # Secrets redacted -> identical hash for same non-secret fields.
        self.assertEqual(h1, h2)
        self.assertNotIn("secret", json.dumps(redact_secrets({"api_key": "secret"})))

    def test_manifest_schema_and_fields(self) -> None:
        m = new_manifest("t1", variant="1", scope=Scope(allowed_networks=["10.0.0.0/24"]))
        self.assertEqual(m.schema_version, "1.0.0")
        self.assertTrue(m.run_id.startswith("run-"))
        self.assertEqual(m.limits["max_cves_per_service"], 5)
        self.assertEqual(m.scope["allowed_networks"], ["10.0.0.0/24"])


class TestLedger(unittest.TestCase):
    def test_append_validates_outcomes(self) -> None:
        ledger = EventLedger("run-1")
        ledger.record(phase="execution", outcome="task_proof_obtained")
        with self.assertRaises(ValueError):
            ledger.record(phase="execution", outcome="bogus")
        self.assertEqual(len(ledger.events), 1)

    def test_repeated_action_detection(self) -> None:
        ledger = EventLedger("run-1")
        params = "rhost=10.0.0.5 lport=4444"
        ledger.record(candidate_id="c1", outcome="execution_failed",
                      payload={"rendered_params": params})
        self.assertFalse(ledger.is_repeated_action("c1", params))
        ledger.record(candidate_id="c1", outcome="execution_failed",
                      payload={"rendered_params": params})
        self.assertTrue(ledger.is_repeated_action("c1", params))

    def test_alternate_method_rescue(self) -> None:
        ledger = EventLedger("run-1")
        ledger.record(cve_id="CVE-2024-1", candidate_id="c1", method="metasploit",
                      outcome="execution_failed")
        ledger.record(cve_id="CVE-2024-1", candidate_id="c2", method="nuclei",
                      outcome="task_proof_obtained")
        self.assertTrue(ledger.alternate_method_rescue("CVE-2024-1"))
        # Same method failing then succeeding is NOT a rescue.
        ledger2 = EventLedger("run-2")
        ledger2.record(cve_id="CVE-2024-1", method="metasploit", outcome="execution_failed")
        ledger2.record(cve_id="CVE-2024-1", method="metasploit", outcome="task_proof_obtained")
        self.assertFalse(ledger2.alternate_method_rescue("CVE-2024-1"))


class TestBudget(unittest.TestCase):
    def test_hard_gates(self) -> None:
        limits = ResourceLimits(max_tool_calls=2, max_executed_commands=2,
                                max_cves_per_service=2, max_methods_per_cve=1,
                                max_executed_candidates=1, max_attempts_per_candidate=1)
        b = ResourceBudget(limits)
        b.record_tool_call()
        b.record_tool_call()
        with self.assertRaises(BudgetExceeded):
            b.record_tool_call()

    def test_attempts_per_candidate(self) -> None:
        b = ResourceBudget(ResourceLimits(max_attempts_per_candidate=2))
        b.record_attempt("c1")
        b.record_attempt("c1")
        with self.assertRaises(BudgetExceeded):
            b.record_attempt("c1")


class TestScope(unittest.TestCase):
    def scope(self, **kw) -> ScopeValidator:
        base = dict(allowed_networks=["10.0.0.0/24"], allowed_ports=[80, 443, 4444],
                    allowed_schemes=["http", "https"], callback_endpoints=["10.0.0.99"],
                    allowed_hostnames=["victim.lab"])
        base.update(kw)
        return ScopeValidator(Scope(**base),
                              resolver=lambda h: ["10.0.0.5"] if h == "victim.lab" else ["203.0.113.5"])

    def test_in_scope_ipv4(self) -> None:
        dec = self.scope().validate_args(["nmap", "-sV", "-p", "80", "10.0.0.5"], stage="execute")
        self.assertTrue(dec)

    def test_foreign_ipv4_blocked(self) -> None:
        dec = self.scope().validate_args(["nmap", "8.8.8.8"], stage="execute")
        self.assertFalse(dec)
        self.assertIn("8.8.8.8", dec.blocked_endpoints)

    def test_foreign_hostname_blocked(self) -> None:
        dec = self.scope().validate_args(["curl", "evil.example.com"], stage="execute")
        self.assertFalse(dec)

    def test_allowed_hostname_resolves_in_scope(self) -> None:
        dec = self.scope().validate_args(["curl", "victim.lab"], stage="execute")
        self.assertTrue(dec)

    def test_hostname_resolving_out_of_scope_blocked(self) -> None:
        sv = ScopeValidator(Scope(allowed_networks=["10.0.0.0/24"],
                                   allowed_hostnames=["victim.lab"]),
                            resolver=lambda h: ["8.8.8.8"])
        dec = sv.validate_args(["curl", "victim.lab"], stage="execute")
        self.assertFalse(dec)

    def test_ipv6_in_scope_and_blocked(self) -> None:
        sv = ScopeValidator(Scope(allowed_networks=["2001:db8::/32"]))
        self.assertTrue(sv.validate_args(["curl", "http://[2001:db8::1]"]))
        dec = sv.validate_args(["curl", "http://[2001:dead::1]"])
        self.assertFalse(dec)

    def test_url_scheme_and_port(self) -> None:
        dec = self.scope().validate_args(["curl", "http://10.0.0.5:80/"])
        self.assertTrue(dec)
        dec = self.scope().validate_args(["curl", "ftp://10.0.0.5/"])
        self.assertFalse(dec)
        dec = self.scope().validate_args(["curl", "http://10.0.0.5:9999/"])
        self.assertFalse(dec)

    def test_callback_endpoint_allowed(self) -> None:
        dec = self.scope().validate_args(["bash", "-c", "nc 10.0.0.99 4444"], stage="execute")
        self.assertTrue(dec)

    def test_foreign_callback_blocked(self) -> None:
        dec = self.scope().validate_args(["nc", "10.0.1.50", "4444"], stage="execute")
        self.assertFalse(dec)

    def test_unresolved_placeholder_blocked(self) -> None:
        dec = self.scope().validate_args(["nmap", "-p", "80", "{RHOST}"], stage="execute")
        self.assertFalse(dec)
        self.assertTrue(dec.unresolved_placeholders)

    def test_all_stages_validated(self) -> None:
        sv = self.scope()
        results = sv.validate_procedure(
            setup=[["nc", "-lvnp", "4444", "10.0.0.99"]],
            execute=[["nmap", "-p", "80", "10.0.0.5"]],
            verify=[["curl", "http://10.0.0.5/"]],
            cleanup=[["rm", "/tmp/payload"]],
        )
        self.assertTrue(all(results.values()))


class TestOracle(unittest.TestCase):
    def test_detection_cannot_satisfy_rce(self) -> None:
        truth = TargetTruth("t1", applicable_cves=["CVE-2024-1"],
                            proof_specs={"CVE-2024-1": ProofSpec(capability="code_execution",
                                                                 accepted_evidence=["uid=0"])})
        oracle = BenchmarkOracle()
        proof = ProofArtifact(kind="detection_output", content="vulnerable: true")
        res = oracle.evaluate_proof("CVE-2024-1", proof, truth)
        self.assertNotEqual(res.outcome, "task_proof_obtained")

    def test_textual_marker_cannot_override(self) -> None:
        truth = TargetTruth("t1", applicable_cves=["CVE-2024-1"],
                            proof_specs={"CVE-2024-1": ProofSpec(capability="code_execution",
                                                                 accepted_evidence=["uid=0"])})
        oracle = BenchmarkOracle()
        # Output full of markers but no accepted evidence -> rejected.
        proof = ProofArtifact(kind="command_output", content="root@victim:~# pwned access granted")
        res = oracle.evaluate_proof("CVE-2024-1", proof, truth)
        self.assertFalse(res.task_proof)
        self.assertTrue(TextualMarkerChecker().matches("uid=0 root@"))

    def test_nonempty_output_insufficient(self) -> None:
        truth = TargetTruth("t1", applicable_cves=["CVE-2024-1"],
                            proof_specs={"CVE-2024-1": ProofSpec(capability="code_execution",
                                                                 accepted_evidence=["uid=0"])})
        oracle = BenchmarkOracle()
        proof = ProofArtifact(kind="command_output", content="some nonempty but meaningless output")
        res = oracle.evaluate_proof("CVE-2024-1", proof, truth)
        self.assertFalse(res.task_proof)

    def test_patched_control_cannot_succeed(self) -> None:
        truth = TargetTruth("t1", applicable_cves=["CVE-2024-1"], is_patched_control=True,
                            proof_specs={"CVE-2024-1": ProofSpec(capability="code_execution",
                                                                 accepted_evidence=["uid=0"])})
        oracle = BenchmarkOracle()
        proof = ProofArtifact(kind="command_output", content="uid=0(root)")
        res = oracle.evaluate_proof("CVE-2024-1", proof, truth)
        self.assertEqual(res.outcome, "not_applicable")

    def test_accepted_evidence_yields_task_proof(self) -> None:
        truth = TargetTruth("t1", applicable_cves=["CVE-2024-1"],
                            proof_specs={"CVE-2024-1": ProofSpec(capability="code_execution",
                                                                 accepted_evidence=["uid=0"])})
        oracle = BenchmarkOracle()
        proof = ProofArtifact(kind="command_output", content="uid=0(root) gid=0(root)")
        res = oracle.evaluate_proof("CVE-2024-1", proof, truth)
        self.assertTrue(res.task_proof)


class TestEvaluator(unittest.TestCase):
    def test_evaluator_independent_adjudication(self) -> None:
        truth = TargetTruth("t1", applicable_cves=["CVE-2024-1"],
                            proof_specs={"CVE-2024-1": ProofSpec(capability="code_execution",
                                                                 accepted_evidence=["uid=0"])})
        manifest = new_manifest("t1", variant="4", condition="clean")
        manifest.oracle_spec = {"cve_id": "CVE-2024-1"}

        def runner(m, ledger, budget, truth):
            ledger.record(phase="execution", candidate_id="c1", cve_id="CVE-2024-1",
                         outcome="execution_failed", failure_class="procedure_incomplete",
                         payload={"executed_command": True})
            ledger.record(phase="execution", candidate_id="c2", cve_id="CVE-2024-1",
                         outcome="task_proof_obtained", payload={"executed_command": True})
            return [ProofArtifact(kind="command_output", content="uid=0(root)")]

        row = Evaluator().evaluate(manifest=manifest, truth=truth, runner=runner)
        self.assertEqual(row.outcome, "task_proof_obtained")
        self.assertTrue(row.vulnerability_confirmed is False)  # task_proof, not just confirm
        self.assertEqual(row.executed_commands, 2)
        self.assertFalse(row.success_at_1)  # first candidate failed


if __name__ == "__main__":
    unittest.main()
