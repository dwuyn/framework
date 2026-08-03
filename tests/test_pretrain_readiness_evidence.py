from __future__ import annotations

import copy
import importlib.util
import os
from pathlib import Path

import pytest

from src.pipeline.readiness_evidence import validate_smoke_evidence

BASE_CASE_IDS = [f"vp-base-{index:04d}" for index in range(1, 95)]
MODEL_LABELS = ["gemini-3.5-flash", "gemini-3.6-flash", "gemma-4-26b-a4b-it"]


def _digest(value: int) -> str:
    return f"{value:064x}"


def _passed(value: int) -> dict[str, str]:
    return {"status": "passed", "evidence_sha256": _digest(value)}


def _control(case_id: str, value: int) -> dict[str, object]:
    return {
        "case_id": case_id,
        "vulnerable": {
            "docker": {**_passed(value), "image_digest": f"sha256:{_digest(value)}"},
            "oracle": _passed(value + 1),
        },
        "fixed": {
            "docker": {**_passed(value + 2), "image_digest": f"sha256:{_digest(value + 2)}"},
            "oracle": {"status": "expected_failure", "evidence_sha256": _digest(value + 3)},
        },
    }


def _evidence() -> dict[str, object]:
    robustness = []
    strata = ("semantic_preserving",) * 3 + ("environmental",) * 3 + ("deceptive_noise",) * 3
    for index, stratum in enumerate(strata):
        robustness.append({
            "variant_id": f"vp-robustness-{index + 1:04d}",
            "base_case_id": BASE_CASE_IDS[index],
            "stratum": stratum,
            "transformation": "fixture",
            "semantic_validity": _passed(500 + index * 2),
            "smoke": _passed(501 + index * 2),
        })
    return {
        "schema_version": "2.0.0",
        "generated_at": "2026-08-03T00:00:00Z",
        "base_case_fixed_controls": [_control(case_id, index * 4 + 1) for index, case_id in enumerate(BASE_CASE_IDS)],
        "robustness": robustness,
        "vertex_canaries": [
            {**_passed(700 + index), "model_label": label, "resource_id": f"resource/{index}", "resource_revision": f"revision/{index}"}
            for index, label in enumerate(MODEL_LABELS)
        ],
        "framework_model_smokes": [
            {**_passed(800 + index), "framework": framework, "model_label": model, "smoke_id": f"smoke-{index:02d}"}
            for index, (framework, model) in enumerate(
                (framework, model)
                for framework in ("VeriPlanPT", "PentestGPT", "VulnBot", "HackSynth", "PentestAgent")
                for model in MODEL_LABELS
            )
        ],
    }


def test_readiness_evidence_requires_every_locked_base_case() -> None:
    summary = validate_smoke_evidence(_evidence(), base_case_ids=BASE_CASE_IDS, model_labels=MODEL_LABELS, mode="pretrain")
    assert summary == {
        "base_case_fixed_controls": 94,
        "robustness": 9,
        "vertex_canaries": 3,
        "framework_model_smokes": 15,
    }


def test_readiness_evidence_rejects_fixed_oracle_that_does_not_fail() -> None:
    evidence = copy.deepcopy(_evidence())
    evidence["base_case_fixed_controls"][0]["fixed"]["oracle"]["status"] = "passed"  # type: ignore[index]
    with pytest.raises(ValueError, match="expected_failure"):
        validate_smoke_evidence(evidence, base_case_ids=BASE_CASE_IDS, model_labels=MODEL_LABELS, mode="pretrain")


def test_readiness_evidence_rejects_missing_robustness_stratum() -> None:
    evidence = copy.deepcopy(_evidence())
    evidence["robustness"][0]["stratum"] = "environmental"  # type: ignore[index]
    with pytest.raises(ValueError, match="three records per required stratum"):
        validate_smoke_evidence(evidence, base_case_ids=BASE_CASE_IDS, model_labels=MODEL_LABELS, mode="pretrain")


def test_dataset_freeze_requires_empty_runtime_evidence() -> None:
    evidence = _evidence()
    evidence["vertex_canaries"] = []
    evidence["framework_model_smokes"] = []
    summary = validate_smoke_evidence(evidence, base_case_ids=BASE_CASE_IDS, mode="dataset-freeze")
    assert summary["vertex_canaries"] == 0


def test_dataset_checkout_accepts_the_same_golden_evidence() -> None:
    dataset_root = Path(os.environ.get("VERIPLANPT_DATASET_ROOT", "../veriplanpt-dataset"))
    contract_path = dataset_root / "scripts" / "readiness_evidence.py"
    if not contract_path.exists():
        pytest.skip("dataset checkout is not available")
    spec = importlib.util.spec_from_file_location("dataset_readiness_evidence", contract_path)
    assert spec and spec.loader
    dataset_contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dataset_contract)
    evidence = _evidence()
    assert dataset_contract.validate_smoke_evidence(
        evidence, base_case_ids=BASE_CASE_IDS, model_labels=MODEL_LABELS, mode="pretrain"
    ) == validate_smoke_evidence(evidence, base_case_ids=BASE_CASE_IDS, model_labels=MODEL_LABELS, mode="pretrain")
    evidence["framework_model_smokes"][1]["model_label"] = MODEL_LABELS[0]  # type: ignore[index]
    with pytest.raises(ValueError, match="pairs must be unique"):
        dataset_contract.validate_smoke_evidence(
            evidence, base_case_ids=BASE_CASE_IDS, model_labels=MODEL_LABELS, mode="pretrain"
        )
    with pytest.raises(ValueError, match="pairs must be unique"):
        validate_smoke_evidence(evidence, base_case_ids=BASE_CASE_IDS, model_labels=MODEL_LABELS, mode="pretrain")
