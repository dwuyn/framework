"""Validation for the single pre-training smoke-evidence contract.

The evidence is recorded by the dataset/build workflow, but the framework
validates it before accepting a paid training run. This module validates
evidence structure and immutable digests only; it never fabricates success.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA_VERSION = "1.0.0"
BASE_CASE_COUNT = 94
ROBUSTNESS_COUNT = 9
VERTEX_CANARY_COUNT = 3
BASELINE_SMOKE_COUNT = 15
ROBUSTNESS_KINDS = frozenset({"semantic_preserving", "environmental", "deceptive_noise"})
BASELINE_FRAMEWORKS = frozenset({"PentestGPT", "VulnBot", "HackSynth", "PentestAgent"})
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def load_smoke_evidence(path: str | Path) -> dict[str, Any]:
    """Load the one canonical readiness evidence file."""
    with Path(path).open(encoding="utf-8") as handle:
        evidence = json.load(handle)
    if not isinstance(evidence, dict):
        raise ValueError("smoke evidence must be a JSON object")
    return evidence


def _records(value: Any, name: str, expected: int) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or len(value) != expected:
        raise ValueError(f"smoke evidence requires exactly {expected} {name} records")
    if not all(isinstance(record, Mapping) for record in value):
        raise ValueError(f"smoke evidence {name} records must be objects")
    return value


def _digest(value: Any, name: str) -> None:
    if not SHA256.fullmatch(str(value)):
        raise ValueError(f"{name} must be a SHA-256 digest")


def _passed(record: Mapping[str, Any], name: str) -> None:
    if record.get("status") != "passed":
        raise ValueError(f"{name} must have status='passed'")
    _digest(record.get("evidence_sha256"), f"{name}.evidence_sha256")


def _validate_control(case: Mapping[str, Any], name: str, *, oracle_status: str) -> None:
    docker = case.get("docker")
    oracle = case.get("oracle")
    if not isinstance(docker, Mapping) or not isinstance(oracle, Mapping):
        raise ValueError(f"{name} requires docker and oracle records")
    _passed(docker, f"{name}.docker")
    if not str(docker.get("image_digest", "")).startswith("sha256:"):
        raise ValueError(f"{name}.docker.image_digest must be an immutable image digest")
    if oracle.get("status") != oracle_status:
        raise ValueError(f"{name}.oracle must have status={oracle_status!r}")
    _digest(oracle.get("evidence_sha256"), f"{name}.oracle.evidence_sha256")


def validate_smoke_evidence(
    evidence: Mapping[str, Any],
    *,
    base_case_ids: Sequence[str],
    model_labels: Sequence[str],
) -> dict[str, int]:
    """Validate paired controls, robustness, canaries, and baseline smokes."""
    required = {
        "schema_version", "generated_at", "base_case_fixed_controls", "robustness",
        "vertex_canaries", "baseline_smokes",
    }
    missing = sorted(required.difference(evidence))
    if missing:
        raise ValueError(f"smoke evidence missing field(s): {', '.join(missing)}")
    unexpected = sorted(set(evidence).difference(required))
    if unexpected:
        raise ValueError(f"smoke evidence has unexpected field(s): {', '.join(unexpected)}")
    if evidence["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"smoke evidence schema_version must be {SCHEMA_VERSION}")
    if not str(evidence["generated_at"]).endswith("Z"):
        raise ValueError("smoke evidence generated_at must be UTC")

    expected_cases = set(base_case_ids)
    if len(expected_cases) != BASE_CASE_COUNT:
        raise ValueError(f"readiness requires exactly {BASE_CASE_COUNT} locked base cases")
    controls = _records(evidence["base_case_fixed_controls"], "base-case fixed-control", BASE_CASE_COUNT)
    control_ids = {str(record.get("case_id", "")) for record in controls}
    if control_ids != expected_cases:
        raise ValueError("base-case fixed-control evidence must cover exactly the locked base cases")
    for record in controls:
        case_id = str(record["case_id"])
        _validate_control(record.get("vulnerable", {}), f"{case_id}.vulnerable", oracle_status="passed")
        _validate_control(record.get("fixed", {}), f"{case_id}.fixed", oracle_status="expected_failure")

    robustness = _records(evidence["robustness"], "robustness", ROBUSTNESS_COUNT)
    variant_ids: set[str] = set()
    kinds: list[str] = []
    for record in robustness:
        variant_id = str(record.get("variant_id", ""))
        if not variant_id or variant_id in variant_ids:
            raise ValueError("robustness variant_id must be present and unique")
        variant_ids.add(variant_id)
        if str(record.get("base_case_id", "")) not in expected_cases:
            raise ValueError(f"robustness {variant_id} references an unlocked base case")
        kinds.append(str(record.get("kind", "")))
        _passed(record.get("semantic_validity", {}), f"{variant_id}.semantic_validity")
        _passed(record.get("smoke", {}), f"{variant_id}.smoke")
    if {kind for kind in kinds} != ROBUSTNESS_KINDS or any(kinds.count(kind) != 3 for kind in ROBUSTNESS_KINDS):
        raise ValueError("robustness evidence requires three records per required stratum")

    expected_models = set(model_labels)
    if len(expected_models) != VERTEX_CANARY_COUNT:
        raise ValueError("readiness requires exactly three locked model labels")
    canaries = _records(evidence["vertex_canaries"], "Vertex canary", VERTEX_CANARY_COUNT)
    canary_labels = {str(record.get("model_label", "")) for record in canaries}
    if canary_labels != expected_models:
        raise ValueError("Vertex canaries must cover exactly the locked model labels")
    for record in canaries:
        _passed(record, f"Vertex canary {record.get('model_label', '')}")
        if not str(record.get("resource_id", "")).strip() or not str(record.get("resource_revision", "")).strip():
            raise ValueError("Vertex canary requires a pinned resource_id and resource_revision")

    baselines = _records(evidence["baseline_smokes"], "baseline smoke", BASELINE_SMOKE_COUNT)
    baseline_ids: set[tuple[str, str]] = set()
    for record in baselines:
        framework = str(record.get("framework", ""))
        model = str(record.get("model_label", ""))
        smoke_id = str(record.get("smoke_id", ""))
        if framework not in BASELINE_FRAMEWORKS:
            raise ValueError(f"unsupported baseline framework {framework!r}")
        if model not in expected_models or not smoke_id:
            raise ValueError("baseline smoke requires a locked model_label and smoke_id")
        identifier = (framework, smoke_id)
        if identifier in baseline_ids:
            raise ValueError("baseline smoke framework/smoke_id pairs must be unique")
        baseline_ids.add(identifier)
        _passed(record, f"baseline smoke {framework}/{smoke_id}")

    return {
        "base_case_fixed_controls": len(controls),
        "robustness": len(robustness),
        "vertex_canaries": len(canaries),
        "baseline_smokes": len(baselines),
    }
