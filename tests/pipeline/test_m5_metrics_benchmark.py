"""
Golden tests for M5: metrics from events only, benchmark manifests, reporting.
"""

from __future__ import annotations

import csv
import json
import os
import shutil
import tempfile
import unittest

from src.pipeline.benchmark import (
    BenchmarkManifest, BenchmarkTarget, aggregate_metrics,
    metrics_from_ledger, write_per_target_table, write_summary,
    _wilson_interval,
)
from src.pipeline.evaluator import ResultRow
from src.pipeline.ledger import EventLedger
from src.pipeline.oracle import ProofSpec, TargetTruth


def _row(target_id: str, variant: str, condition: str, rep: int,
          *, outcome: str = "task_proof_obtained", success_at_1: bool = True,
          executed: int = 1, invalid: int = 0, cost: float = 0.01,
          patched: bool = False) -> ResultRow:
    target_id_for_row = ("control-" + target_id) if patched else target_id
    return ResultRow(
        run_id=f"run-{target_id}-{condition}-{rep}",
        target_id=target_id_for_row,
        variant=variant, condition=condition, repetition=rep,
        outcome=outcome, success_at_1=success_at_1,
        vulnerability_confirmed=False, oracle_result={"outcome": outcome},
        run_dir="/tmp", repo_commit="abc", model_id="gemini-2.5-flash",
        config_hash="c", tool_versions={"nuclei": "3.7.1"},
        source_snapshot_id="snap1",
        candidate_hashes=["h"], proof_ref="p",
        tokens_in=10, tokens_out=20, cost=cost,
        executed_commands=executed, invalid_commands=invalid,
        elapsed_seconds=1.0,
    )


class TestMetricsFromLedgerOnly(unittest.TestCase):
    def test_metrics_derive_from_events(self) -> None:
        ledger = EventLedger("run-1")
        truth = TargetTruth("t1", applicable_cves=["CVE-2024-1"],
                              proof_specs={"CVE-2024-1":
                                                ProofSpec(capability="code_execution",
                                                            accepted_evidence=["uid=0"])})
        ledger.record(phase="execution", stage="task_proof", cve_id="CVE-2024-1",
                       candidate_id="c1", outcome="task_proof_obtained",
                       payload={"executed_command": True})
        m = metrics_from_ledger(ledger, truth=truth)
        self.assertTrue(m["task_proof_obtained"])
        self.assertEqual(m["executed_commands"], 1)

    def test_patched_control_does_not_count_as_success(self) -> None:
        ledger = EventLedger("run-1")
        truth = TargetTruth("t1", applicable_cves=["CVE-2024-1"], is_patched_control=True,
                              proof_specs={"CVE-2024-1":
                                                ProofSpec(capability="code_execution",
                                                            accepted_evidence=["uid=0"])})
        ledger.record(phase="execution", stage="task_proof", outcome="task_proof_obtained")
        m = metrics_from_ledger(ledger, truth=truth)
        # task_proof_obtained IS captured, but primary_success must be False
        # because patched controls do not contribute to primary success.
        self.assertFalse(m["primary_success"])


class TestBenchmarkManifest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_round_trip(self) -> None:
        manifest = BenchmarkManifest(name="t", targets=[
            BenchmarkTarget(target_id="t1", image="img", applicable_cves=["CVE-1"],
                              proof_specs={"CVE-1": ProofSpec(capability="detection")}),
        ])
        path = os.path.join(self.tmp, "m.json")
        manifest.save(path)
        loaded = BenchmarkManifest.load(path)
        self.assertEqual(loaded.targets[0].target_id, "t1")

    def test_condition_pairs_includes_noisy_only_when_present(self) -> None:
        t1 = BenchmarkTarget(target_id="t1", image="i", noisy_mirrors=["t1-noisy"])
        t2 = BenchmarkTarget(target_id="t2", image="i")
        manifest = BenchmarkManifest(name="t", targets=[t1, t2])
        pairs = manifest.condition_pairs()
        # t1 produces 2 (clean, noisy) × 3 reps = 6, t2 only clean × 3 = 3.
        self.assertEqual(len(pairs), 9)


class TestReporting(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_aggregate_metrics(self) -> None:
        rows = [
            _row("t1", "1", "clean", 1, outcome="execution_failed"),
            _row("t1", "4", "clean", 1, outcome="task_proof_obtained"),
            _row("t2", "1", "clean", 1, outcome="execution_failed"),
            _row("t2", "4", "clean", 1, outcome="task_proof_obtained"),
            _row("control-1", "1", "clean", 1, outcome="task_proof_obtained", patched=True),
        ]
        summary = aggregate_metrics(rows)
        self.assertEqual(summary["vulnerable_targets"], 2)
        self.assertEqual(summary["success_pairs"], 2)
        self.assertEqual(summary["discordant_pairs"], 2)
        self.assertEqual(summary["discordant_full_minus_poc"], 2)
        self.assertEqual(summary["false_positive_count"], 1)
        # Wilson interval is well-defined.
        lo, hi = summary["wilson_95_success"]
        self.assertGreaterEqual(lo, 0.0)
        self.assertLessEqual(hi, 1.0)

    def test_inconclusive_when_discordants_too_few(self) -> None:
        rows = [
            _row("t1", "1", "clean", 1, outcome="task_proof_obtained"),
            _row("t1", "4", "clean", 1, outcome="task_proof_obtained"),
        ]
        summary = aggregate_metrics(rows)
        self.assertFalse(summary["power_adequate"])

    def test_write_per_target_table(self) -> None:
        rows = [_row("t1", "1", "clean", 1)]
        path = os.path.join(self.tmp, "per_target.csv")
        write_per_target_table(rows, path)
        with open(path) as fh:
            rows_csv = list(csv.reader(fh))
        self.assertEqual(rows_csv[0][0], "target_id")
        self.assertEqual(rows_csv[1][0], "t1")

    def test_write_summary_includes_wilson(self) -> None:
        rows = [_row("t1", "1", "clean", 1, outcome="task_proof_obtained")]
        path = os.path.join(self.tmp, "summary.md")
        write_summary(rows, path)
        with open(path) as fh:
            content = fh.read()
        self.assertIn("Wilson 95% interval", content)


class TestWilsonInterval(unittest.TestCase):
    def test_wilson_endpoint(self) -> None:
        lo, hi = _wilson_interval(0, 0)
        self.assertEqual((lo, hi), (0.0, 0.0))
        lo, hi = _wilson_interval(10, 10)
        self.assertAlmostEqual(hi, 1.0)


if __name__ == "__main__":
    unittest.main()
