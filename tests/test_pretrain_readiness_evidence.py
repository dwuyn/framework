from __future__ import annotations

import copy

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
    kinds = ("semantic_preserving",) * 3 + ("environmental",) * 3 + ("deceptive_noise",) * 3
    for index, kind in enumerate(kinds):
        robustness.append({
            "variant_id": f"vp-robustness-{index + 1:04d}",
            "base_case_id": BASE_CASE_IDS[index],
            "kind": kind,
            "semantic_validity": _passed(500 + index * 2),
            "smoke": _passed(501 + index * 2),
        })
    return {
        "schema_version": "1.0.0",
        "generated_at": "2026-08-03T00:00:00Z",
        "base_case_fixed_controls": [_control(case_id, index * 4 + 1) for index, case_id in enumerate(BASE_CASE_IDS)],
        "robustness": robustness,
        "vertex_canaries": [
            {**_passed(700 + index), "model_label": label, "resource_id": f"resource/{index}", "resource_revision": f"revision/{index}"}
            for index, label in enumerate(MODEL_LABELS)
        ],
        "baseline_smokes": [
            {**_passed(800 + index), "framework": ("PentestGPT", "VulnBot", "HackSynth", "PentestAgent")[index % 4], "model_label": MODEL_LABELS[index % 3], "smoke_id": f"smoke-{index:02d}"}
            for index in range(15)
        ],
    }


def test_readiness_evidence_requires_every_locked_base_case() -> None:
    summary = validate_smoke_evidence(_evidence(), base_case_ids=BASE_CASE_IDS, model_labels=MODEL_LABELS)
    assert summary == {
        "base_case_fixed_controls": 94,
        "robustness": 9,
        "vertex_canaries": 3,
        "baseline_smokes": 15,
    }


def test_readiness_evidence_rejects_fixed_oracle_that_does_not_fail() -> None:
    evidence = copy.deepcopy(_evidence())
    evidence["base_case_fixed_controls"][0]["fixed"]["oracle"]["status"] = "passed"  # type: ignore[index]
    with pytest.raises(ValueError, match="expected_failure"):
        validate_smoke_evidence(evidence, base_case_ids=BASE_CASE_IDS, model_labels=MODEL_LABELS)


def test_readiness_evidence_rejects_missing_robustness_stratum() -> None:
    evidence = copy.deepcopy(_evidence())
    evidence["robustness"][0]["kind"] = "environmental"  # type: ignore[index]
    with pytest.raises(ValueError, match="three records per required stratum"):
        validate_smoke_evidence(evidence, base_case_ids=BASE_CASE_IDS, model_labels=MODEL_LABELS)
