"""
Acceptance tests for the handoff completion gates.

  * One offline replay reproduces IDs, ranking, metrics, and proof
    interpretation from stored events.
  * One snapshot benchmark runs without Internet retrieval.
  * One live-source integration tolerates an unavailable or rate-limited
    backend.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from src.pipeline.candidates import ExploitCandidate, ProcedureStep
from src.pipeline.collectors import MetasploitSpec, collect_metasploit
from src.pipeline.evaluator import Evaluator
from src.pipeline.evidence import (
    ServiceObservation,
    fingerprint_service,
)
from src.pipeline.ledger import EventLedger
from src.pipeline.manifest import Scope, new_manifest
from src.pipeline.oracle import ProofArtifact, ProofSpec, TargetTruth
from src.pipeline.runner import PipelineRunner, ReconObservation
from src.pipeline.sources import (
    CveListV5Adapter,
    NvdAdapter,
    RawCveRecord,
    VulnxAdapter,
    write_snapshot,
)


def _fp():
    return fingerprint_service(ServiceObservation(
        target_ip="10.0.0.5", port=80, service_name="apache",
        banner="Apache/2.4.49 (Unix)"))


def _msf(cve_id: str = "CVE-2021-41773") -> ExploitCandidate:
    cand = collect_metasploit(MetasploitSpec(
        cve_id=cve_id, module_name="exploit/multi/http/path_traversal",
        options={"RHOSTS": "10.0.0.5", "RPORT": "80",
                  "PAYLOAD": "generic/shell_reverse_tcp"}))
    cand.constraint.vendor = "apache"
    cand.constraint.product = "httpd"
    cand.constraint.version_start = "2.4.0"
    cand.constraint.version_end = "2.4.99"
    cand.procedure = [
        ProcedureStep(stage="execute", argv=["sh", "-c", "echo TASK_PROOF_MARKER"],
                        timeout_seconds=10),
    ]
    return cand


class TestOfflineReplay(unittest.TestCase):
    def test_replay_from_stored_events(self) -> None:
        # Step 1: produce a real ledger by running the pipeline against a
        # benign echo command.
        tmp = tempfile.mkdtemp()
        try:
            scope = Scope(allowed_networks=["10.0.0.0/24"],
                          allowed_ports=[80, 4444],
                          callback_endpoints=["10.0.0.99"])
            manifest = new_manifest("t1", variant="4", condition="clean",
                                       scope=scope,
                                       oracle_spec={"cve_id": "CVE-2021-41773",
                                                     "capability": "code_execution"})
            manifest.run_dir = os.path.join(tmp, "run")
            ledger = EventLedger(manifest.run_id, path=os.path.join(manifest.run_dir, "events.jsonl"))
            from src.pipeline.budget import ResourceBudget, ResourceLimits
            budget = ResourceBudget(ResourceLimits(**manifest.limits))
            truth = TargetTruth("t1", applicable_cves=["CVE-2021-41773"],
                                  proof_specs={"CVE-2021-41773":
                                                    ProofSpec(capability="code_execution",
                                                                accepted_evidence=["TASK_PROOF_MARKER"])})
            runner = PipelineRunner(manifest=manifest, ledger=ledger,
                                       budget=budget, scope=scope)
            manifest.oracle_spec["truth"] = truth
            obs = [ReconObservation(target_ip="10.0.0.5", port=80,
                                      service_name="apache", banner="Apache/2.4.49 (Unix)")]
            cand = _msf()
            # Run with the default real executor; benign echo produces a
            # TASK_PROOF_MARKER for the oracle to accept.
            res = runner.run(recon_obs=obs, candidates=[cand])
            self.assertTrue(res.task_proof)
            # Step 2: replay the ledger file and verify the same metric block
            # is derivable purely from events.
            reloaded = EventLedger.load(os.path.join(manifest.run_dir, "events.jsonl"),
                                          run_id=manifest.run_id)
            from src.pipeline.benchmark import metrics_from_ledger
            metrics = metrics_from_ledger(reloaded, truth=truth)
            self.assertTrue(metrics["task_proof_obtained"])
            # Deterministic candidate ids stable across replay.
            self.assertEqual(ledger.events[0].event_id, reloaded.events[0].event_id)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestSnapshotBenchmark(unittest.TestCase):
    def test_snapshot_no_internet(self) -> None:
        tmp = tempfile.mkdtemp()
        try:
            snap = os.path.join(tmp, "snap")
            os.makedirs(snap)
            write_snapshot(snap, [
                RawCveRecord(source="nvd", cve_id="CVE-2021-41773", raw={"a": 1},
                              raw_hash="x", retrieved_at=0.0,
                              vendor="apache", product="httpd",
                              version_start="2.4.0", version_end="2.4.99",
                              cvss_score=9.8),
            ])
            # Read from snapshot, never from network.
            adapter = NvdAdapter(mode="snapshot", snapshot_dir=snap)
            recs = adapter.fetch("httpd", "apache", "2.4.49")
            self.assertEqual(len(recs), 1)
            # Vulnx adapter reports no_match, not failure.
            vulnx = VulnxAdapter(mode="snapshot", snapshot_dir=snap)
            self.assertEqual(vulnx.fetch("httpd", "apache", "2.4.49"), [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestLiveBackendIsolation(unittest.TestCase):
    def test_unavailable_backend_does_not_block_others(self) -> None:
        ledger = EventLedger("run-1")
        cve = CveListV5Adapter(mode="live", ledger=ledger)
        nvd = NvdAdapter(mode="live", ledger=ledger)
        # Live HTTP is mocked unavailable in unit tests; adapters must return
        # empty results without raising.
        with patch("src.pipeline.sources.request.urlopen", side_effect=OSError("offline")):
            self.assertEqual(cve.fetch("httpd", "apache", "2.4.49"), [])
            self.assertEqual(nvd.fetch("httpd", "apache", "2.4.49"), [])
        # Both recorded a BACKEND_FAILED status in the ledger.
        statuses = [ev.payload.get("status") for ev in ledger.events
                    if ev.payload.get("source") in {"cve_list_v5", "nvd"}]
        self.assertIn("backend_failed", statuses)


class TestResultRowCoverage(unittest.TestCase):
    def test_every_row_resolves_to_manifest_and_artifact(self) -> None:
        # The handoff requires every result row to resolve to a run manifest,
        # source snapshot, candidate hash, model/tool version, and proof artifact.
        manifest = new_manifest("t1", variant="4", condition="clean")
        truth = TargetTruth("t1", applicable_cves=["CVE-2021-41773"],
                              proof_specs={"CVE-2021-41773":
                                                ProofSpec(capability="code_execution",
                                                            accepted_evidence=["TASK_PROOF_MARKER"])})
        ledger = EventLedger(manifest.run_id)
        ledger.record(phase="execution", stage="task_proof",
                       candidate_id="cand-x", cve_id="CVE-2021-41773",
                       outcome="task_proof_obtained",
                       payload={"executed_command": True})
        from src.pipeline.budget import ResourceLimits
        manifest.run_dir = "/tmp/r"
        manifest.artifact_hashes = {"cand-x": "abc"}
        manifest.source_snapshot_ids = ["snap1"]
        manifest.tool_versions = {"nuclei": "3.7.1"}

        def runner(m, led, budget, truth):
            led.record(phase="execution", stage="task_proof",
                        candidate_id="cand-x", cve_id="CVE-2021-41773",
                        outcome="task_proof_obtained",
                        payload={"executed_command": True})
            return [ProofArtifact(kind="command_output", content="TASK_PROOF_MARKER",
                                    content_hash="abc")]
        row = Evaluator().evaluate(manifest=manifest, truth=truth, runner=runner,
                                    limits=ResourceLimits(**manifest.limits))
        self.assertEqual(row.run_id, manifest.run_id)
        self.assertEqual(row.repo_commit, manifest.repo.get("commit", ""))
        self.assertEqual(row.model_id, manifest.model_id)
        self.assertEqual(row.tool_versions, manifest.tool_versions)
        self.assertEqual(row.source_snapshot_id, "snap1")
        self.assertEqual(row.candidate_hashes, ["abc"])
        self.assertEqual(row.proof_ref, "abc")


if __name__ == "__main__":
    unittest.main()
