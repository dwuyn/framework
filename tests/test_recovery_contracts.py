from __future__ import annotations

from pathlib import Path

import pytest

from src.pipeline.approval import verify_approval
from src.pipeline.matrix import generate_matrix
from src.pipeline.readiness_evidence import validate_smoke_evidence


def _digest(value: int) -> str:
    return f"{value:064x}"


def test_official_evidence_rehash_rejects_hash_only_records(tmp_path: Path) -> None:
    record = {"status": "passed", "evidence_sha256": _digest(1)}
    with pytest.raises(ValueError, match="artifact_path"):
        validate_smoke_evidence(
            {
                "schema_version": "2.0.0", "generated_at": "2026-08-04T00:00:00Z",
                "base_case_fixed_controls": [{
                    "case_id": f"vp-base-{index:04d}",
                    "vulnerable": {"docker": {**record, "image_digest": "sha256:" + _digest(1)}, "oracle": record},
                    "fixed": {"docker": {**record, "image_digest": "sha256:" + _digest(2)}, "oracle": {**record, "status": "expected_failure"}},
                } for index in range(1, 95)],
                "robustness": [], "vertex_canaries": [], "framework_model_smokes": [],
            },
            base_case_ids=[f"vp-base-{index:04d}" for index in range(1, 95)],
            mode="dataset-freeze", artifact_root=tmp_path,
        )


def test_approval_rejects_wrong_scope_before_signature() -> None:
    approval = {
        "schema_version": "2.0.0", "scope": "canary_smoke", "plan_hash": _digest(1),
        "cell_count": 3, "issued_at": "2026-08-04T00:00:00Z",
        "expires_at": "2026-08-05T00:00:00Z", "cost_ceiling_usd": 10,
        "approver_key_id": "recovery-approver",
    }
    with pytest.raises(ValueError, match="scope mismatch"):
        verify_approval(approval, scope="sweep", plan_hash=_digest(1), cell_count=3, cost_ceiling_usd=150)


def test_strict_matrix_rejects_placeholder_provenance() -> None:
    with pytest.raises(ValueError, match="real dataset"):
        generate_matrix(
            test_cases=[f"vp-test-{i:04d}" for i in range(1, 28)],
            robustness_cases=[f"vp-test-{i:04d}" for i in range(1, 10)],
            frameworks=[{"name": name, "commit": "placeholder", "image_digest": "sha256:placeholder"} for name in ["VeriPlanPT", "PentestGPT", "VulnBot", "HackSynth", "PentestAgent"]],
            models=[{"logical_label": label, "resource_id": "resource", "resource_revision": "revision"} for label in ["gemini-3.5-flash", "gemini-3.6-flash", "gemma-4-26b-a4b-it"]],
            dataset_lock_hash="placeholder", policy_lock_hash="placeholder", evaluator_commit="placeholder", strict=True,
        )
