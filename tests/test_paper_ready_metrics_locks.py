from __future__ import annotations

import pytest

from src.pipeline.dataset_lock import validate_dataset_lock
from src.pipeline.ledger import EventLedger
from src.pipeline.matrix import generate_matrix, matrix_hash
from src.planning.policy_lock import build_policy_lock, tree_hash, validate_policy_lock, weight_grid
from src.scoring.paper_metrics import compute_paper_metrics


def _train_cases() -> list[dict]:
    severities = ["critical", "high", "medium", "low"]
    capabilities = ["code_execution", "file_read", "auth_bypass", "xss", "ssrf"]
    return [
        {
            "case_id": f"vp-train-{i + 1:04d}",
            "severity": severities[i % len(severities)],
            "capability": capabilities[i % len(capabilities)],
        }
        for i in range(40)
    ]


def test_paper_metrics_golden_fixture() -> None:
    ledger = EventLedger("run")
    ledger.record(
        phase="recon",
        stage="service_observation",
        payload={"event_type": "service_observation", "service_key": "host:80:tcp:marimo"},
    )
    ledger.record(
        phase="planner",
        stage="ranked_vulnerability_proposal",
        cve_id="CVE-2026-0000",
        payload={"event_type": "ranked_vulnerability_proposal", "cve_id": "CVE-2026-0000"},
    )
    ledger.record(
        phase="planner",
        stage="ranked_vulnerability_proposal",
        cve_id="CVE-2026-39987",
        payload={"event_type": "ranked_vulnerability_proposal", "cve_id": "CVE-2026-39987"},
    )
    ledger.record(
        phase="planner",
        stage="ranked_exploit_proposal",
        cve_id="CVE-2026-39987",
        candidate_id="exp-1",
        payload={
            "event_type": "ranked_exploit_proposal",
            "cve_id": "CVE-2026-39987",
            "candidate_id": "exp-1",
        },
    )
    ledger.record(
        phase="execution",
        stage="command",
        failure_class="command_invalid",
        payload={"event_type": "command", "validator_rejected": True},
    )
    ledger.record(phase="execution", stage="command", payload={"event_type": "command"})
    ledger.record(
        phase="execution",
        stage="repeated_action",
        payload={"event_type": "repeated_action", "signature": "curl /login"},
    )
    ledger.record(
        phase="execution",
        stage="execution_failure",
        outcome="execution_failed",
        failure_class="runtime_error",
    )
    ledger.record(
        phase="execution",
        stage="recovery",
        payload={"event_type": "recovery", "milestone_reached": True},
    )
    ledger.record(
        phase="llm",
        stage="llm_usage",
        payload={
            "event_type": "llm_usage",
            "input_tokens": 10,
            "cached_input_tokens": 2,
            "output_tokens": 5,
            "thinking_tokens": 3,
            "usd": 0.0001,
            "model_revision": "rev-a",
        },
    )
    ledger.record(
        phase="oracle",
        stage="proof_submission",
        outcome="task_proof_obtained",
        payload={"event_type": "proof_submission", "accepted": True},
    )
    ledger.record(
        phase="maintain",
        stage="session_continuity",
        payload={"event_type": "session_continuity", "verified": True},
    )

    metrics = compute_paper_metrics(
        ledger,
        truth={
            "applicable_cves": ["CVE-2026-39987"],
            "service": {"service_key": "host:80:tcp:marimo"},
        },
    ).to_dict()
    assert metrics["OSR"] == 1.0
    assert metrics["SSR_Recon"] == 1.0
    assert metrics["SSR_Vuln"] == 1.0
    assert metrics["SSR_Exploit"] == 1.0
    assert metrics["SSR_Maintain"] == 1.0
    assert metrics["Correct-CVE@1"] is False
    assert metrics["Correct-CVE@3"] is True
    assert metrics["invalid_command_rate"] == 0.5
    assert metrics["recovery_rate"] == 1.0
    assert metrics["total_tokens"] == 20
    assert metrics["llm_calls_by_revision"] == {"rev-a": 1}


def test_policy_lock_is_deterministic_and_validates_hashes() -> None:
    cases = _train_cases()
    scores = [
        {
            "weights": weights.to_dict(),
            "osr": 0.5 if weights.w_success < 1 else 0.6,
            "exploit_applicability_precision": 0.9,
            "tokens_per_success": 100,
            "hfr": 0.1,
        }
        for weights in weight_grid()
    ]
    feature_schema = {"features": ["remaining_budget", "evidence_confidence"]}
    train_tree = {"cases": cases}
    lock = build_policy_lock(cases, feature_schema, scores, train_tree=train_tree)
    assert [len(fold) for fold in lock["folds"]] == [8, 8, 8, 8, 8]
    validate_policy_lock(
        lock,
        dataset_train_hash=tree_hash(train_tree),
        feature_schema_hash=tree_hash(feature_schema),
    )
    with pytest.raises(ValueError, match="train hash"):
        validate_policy_lock(lock, dataset_train_hash="bad", feature_schema_hash=tree_hash(feature_schema))


def test_matrix_generator_produces_3807_unique_cells() -> None:
    cells = generate_matrix(
        test_cases=[f"vp-test-{i + 1:04d}" for i in range(27)],
        robustness_cases=[f"vp-test-{i + 1:04d}" for i in range(9)],
        frameworks=["VeriPlanPT", "PentestGPT", "PentestAgent", "VulnBot", "HackSynth"],
        models=[
            {"logical_label": "gemini-3.5-flash", "resource_revision": "rev-35"},
            {"logical_label": "gemini-3.6-flash", "resource_revision": "rev-36"},
            {"logical_label": "gemma-4-26b-a4b-it", "resource_revision": "rev-gemma"},
        ],
        dataset_lock_hash="dataset",
        framework_sha="framework",
    )
    assert len(cells) == 3807
    assert matrix_hash(cells) == matrix_hash(cells)


def test_dataset_lock_validator_requires_freeze_contract() -> None:
    lock = {
        "schema_version": "2.0.0",
        "locked_at": "2026-08-01T00:00:00Z",
        "snapshot_cutoff": "2026-08-01T00:00:00Z",
        "constructed_before_freeze": True,
        "tree_hash": "tree",
        "file_hashes": {},
        "train_cases": [f"vp-train-{i + 1:04d}" for i in range(40)],
        "test_cases": [f"vp-test-{i + 1:04d}" for i in range(27)],
        "model_profiles": [
            {"logical_label": "gemini-3.5-flash", "resource_revision": "rev-35"},
            {"logical_label": "gemini-3.6-flash", "resource_revision": "rev-36"},
            {"logical_label": "gemma-4-26b-a4b-it", "resource_revision": "rev-gemma"},
        ],
        "policy_hash": "policy",
        "matrix_hash": "matrix",
        "replacement_cases": [
            {"product": "Marimo", "vulnerable_version": "0.20.4", "fixed_version": "0.23.0"},
            {"product": "Quarkus", "vulnerable_version": "3.34.6", "fixed_version": "3.34.7"},
            {"product": "Kirby", "vulnerable_version": "5.4.0", "fixed_version": "5.4.1"},
            {"product": "FUXA", "vulnerable_version": "1.3.0", "fixed_version": "1.3.1"},
        ],
    }
    validate_dataset_lock(lock)
    lock["test_cases"][0] = "CVE-2026-39987"
    with pytest.raises(ValueError, match="opaque IDs"):
        validate_dataset_lock(lock)
