import inspect
import os
import shutil
import tempfile
import unittest

from src import graph as active_graph
from src.pipeline.candidates import ExploitCandidate, ProcedureStep, Provenance
from src.pipeline.evidence import VersionConstraint
from src.pipeline.manifest import Scope, new_manifest
from src.pipeline.oracle import ProofSpec, TargetTruth
from src.pipeline.sources import RawCveRecord, write_snapshot
from src.state import initial_state


class TestActiveGraphPipeline(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_build_graph_default_wiring_omits_legacy_nodes(self) -> None:
        # build_graph delegates to _build_v6_graph where the actual wiring lives.
        src = inspect.getsource(active_graph._build_v6_graph)
        self.assertIn("pipeline_prepare", src)
        self.assertIn("pipeline_oracle", src)
        self.assertIn("pipeline_planner", src)
        self.assertIn("pipeline_critic", src)
        self.assertIn("pipeline_verifier", src)
        # Legacy node names must not appear as standalone graph nodes.
        # Use add_node("name", ...) pattern to check for legacy wiring.
        for legacy in (
            "collect_poc_candidates",
            "maintain_access",
            "build_hypothesis_phase_graph",
        ):
            self.assertNotIn(legacy, src)
        # The legacy planner/skeptic/risk_officer nodes should not be wired
        # as standalone graph nodes (they'd appear as add_node("planner", ...)
        # not add_node("pipeline_planner", ...)).
        self.assertNotIn('"planner"', src.split("pipeline_planner")[0] if "pipeline_planner" in src else src)
        self.assertNotIn('"skeptic"', src)
        self.assertNotIn('"risk_officer"', src)

    def test_pipeline_nodes_snapshot_dry_run_variant_4(self) -> None:
        snap = os.path.join(self.tmp, "snap")
        write_snapshot(snap, [
            RawCveRecord(source="nvd", cve_id="CVE-2021-41773", raw={"x": 1},
                          raw_hash="abc", retrieved_at=0.0,
                          vendor="apache", product="httpd",
                          version_start="2.4.0", version_end="2.4.99"),
        ])
        truth = TargetTruth(
            target_id="t1",
            applicable_cves=["CVE-2021-41773"],
            proof_specs={"CVE-2021-41773": ProofSpec(
                capability="code_execution",
                accepted_evidence=["TASK_PROOF_MARKER"],
            )},
        )
        scope = Scope(allowed_networks=["10.0.0.0/24"], allowed_ports=[80])
        manifest = new_manifest("t1", variant="4", condition="clean", scope=scope,
                                  oracle_spec={"cve_id": "CVE-2021-41773",
                                                "capability": "code_execution",
                                                "truth": truth.to_dict()})
        manifest.run_dir = os.path.join(self.tmp, "run")
        cand = ExploitCandidate(
            candidate_id="cand-echo",
            cve_id="CVE-2021-41773",
            kind="metasploit",
            source="metasploit",
            locator="exploit/test",
            provenance=Provenance(trust="trusted"),
            constraint=VersionConstraint(vendor="apache", product="httpd",
                                         version_start="2.4.0", version_end="2.4.99"),
            procedure=[ProcedureStep(stage="execute",
                                     argv=["sh", "-c", "echo TASK_PROOF_MARKER"],
                                     timeout_seconds=10)],
            capability="code_execution",
        )
        state = initial_state("10.0.0.5", target_port="80")
        state.update({
            "recon_complete": True,
            "retrieval_mode": "snapshot",
            "source_snapshot_dir": snap,
            "pipeline_manifest": manifest.to_dict(),
            "oracle_truth": truth.to_dict(),
            "pipeline_recon_observations": [{
                "target_ip": "10.0.0.5",
                "port": 80,
                "service_name": "apache",
                "banner": "Apache/2.4.49 (Unix)",
            }],
            "exploit_candidates": [cand.to_dict()],
            "verifier_decisions": [{"action": "execute", "target_candidate_id": "cand-echo",
                                    "approved_for_execution": True}],
        })

        for node in (
            active_graph.pipeline_prepare_node,
            active_graph.pipeline_retrieve_node,
            active_graph.pipeline_queue_node,
            active_graph.pipeline_execute_node,
            active_graph.pipeline_oracle_node,
        ):
            state.update(node(state))

        # A public graph manifest has had its evaluator truth removed and has
        # no attacker container configuration, so it must not fall back to a
        # host shell merely because this fixture contains a benign command.
        self.assertFalse(state["execution_success"])
        self.assertNotEqual(state["pipeline_result"]["outcome"], "task_proof_obtained")
        self.assertTrue(os.path.exists(state["pipeline_ledger_path"]))


if __name__ == "__main__":
    unittest.main()
