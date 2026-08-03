"""Canonical VeriPlanPT readiness-evidence contract shared with the dataset."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA_VERSION = "2.0.0"
BASE_CASE_COUNT = 94
ROBUSTNESS_COUNT = 9
VERTEX_CANARY_COUNT = 3
FRAMEWORK_MODEL_SMOKE_COUNT = 15
ROBUSTNESS_STRATA = frozenset({"semantic_preserving", "environmental", "deceptive_noise"})
FRAMEWORKS = frozenset({"VeriPlanPT", "PentestGPT", "VulnBot", "HackSynth", "PentestAgent"})
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def dataset_owned_evidence(evidence: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": evidence.get("schema_version"),
        "base_case_fixed_controls": evidence.get("base_case_fixed_controls"),
        "robustness": evidence.get("robustness"),
    }


def dataset_owned_evidence_hash(evidence: Mapping[str, Any]) -> str:
    return canonical_hash(dataset_owned_evidence(evidence))


def load_smoke_evidence(path: str | Path) -> dict[str, Any]:
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
    model_labels: Sequence[str] = (),
    robustness_base_case_ids: Sequence[str] | None = None,
    mode: str,
) -> dict[str, int]:
    """Validate dataset-freeze or pretrain evidence without fabricating results."""
    if mode not in {"dataset-freeze", "pretrain"}:
        raise ValueError("smoke evidence mode must be 'dataset-freeze' or 'pretrain'")
    required = {
        "schema_version", "generated_at", "base_case_fixed_controls", "robustness",
        "vertex_canaries", "framework_model_smokes",
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
    if {str(record.get("case_id", "")) for record in controls} != expected_cases:
        raise ValueError("base-case fixed-control evidence must cover exactly the locked base cases")
    for record in controls:
        case_id = str(record["case_id"])
        _validate_control(record.get("vulnerable", {}), f"{case_id}.vulnerable", oracle_status="passed")
        _validate_control(record.get("fixed", {}), f"{case_id}.fixed", oracle_status="expected_failure")

    robustness = _records(evidence["robustness"], "robustness", ROBUSTNESS_COUNT)
    allowed_bases = set(robustness_base_case_ids or base_case_ids)
    variant_ids: set[str] = set()
    bases: set[str] = set()
    strata: list[str] = []
    for record in robustness:
        variant_id = str(record.get("variant_id", ""))
        base_case_id = str(record.get("base_case_id", ""))
        if not variant_id or variant_id in variant_ids:
            raise ValueError("robustness variant_id must be present and unique")
        if not base_case_id or base_case_id in bases:
            raise ValueError("robustness base_case_id must be present and unique")
        if base_case_id not in allowed_bases:
            raise ValueError(f"robustness {variant_id} references an unlocked base case")
        if not str(record.get("transformation", "")).strip():
            raise ValueError(f"robustness {variant_id} requires a transformation")
        variant_ids.add(variant_id)
        bases.add(base_case_id)
        strata.append(str(record.get("stratum", "")))
        _passed(record.get("semantic_validity", {}), f"{variant_id}.semantic_validity")
        _passed(record.get("smoke", {}), f"{variant_id}.smoke")
    if set(strata) != ROBUSTNESS_STRATA or any(strata.count(stratum) != 3 for stratum in ROBUSTNESS_STRATA):
        raise ValueError("robustness evidence requires three records per required stratum")

    canaries = evidence["vertex_canaries"]
    smokes = evidence["framework_model_smokes"]
    if mode == "dataset-freeze":
        if canaries != [] or smokes != []:
            raise ValueError("dataset-freeze evidence requires empty runtime evidence sections")
        return {
            "base_case_fixed_controls": len(controls),
            "robustness": len(robustness),
            "vertex_canaries": 0,
            "framework_model_smokes": 0,
        }

    expected_models = set(model_labels)
    if len(expected_models) != VERTEX_CANARY_COUNT:
        raise ValueError("readiness requires exactly three locked model labels")
    canary_records = _records(canaries, "Vertex canary", VERTEX_CANARY_COUNT)
    if {str(record.get("model_label", "")) for record in canary_records} != expected_models:
        raise ValueError("Vertex canaries must cover exactly the locked model labels")
    for record in canary_records:
        _passed(record, f"Vertex canary {record.get('model_label', '')}")
        if not str(record.get("resource_id", "")).strip() or not str(record.get("resource_revision", "")).strip():
            raise ValueError("Vertex canary requires a pinned resource_id and resource_revision")

    smoke_records = _records(smokes, "framework-model smoke", FRAMEWORK_MODEL_SMOKE_COUNT)
    expected_pairs = {(framework, model) for framework in FRAMEWORKS for model in expected_models}
    pairs: set[tuple[str, str]] = set()
    for record in smoke_records:
        framework = str(record.get("framework", ""))
        model = str(record.get("model_label", ""))
        if not str(record.get("smoke_id", "")).strip():
            raise ValueError("framework-model smoke requires smoke_id")
        pair = (framework, model)
        if pair in pairs:
            raise ValueError("framework-model smoke pairs must be unique")
        pairs.add(pair)
        _passed(record, f"framework-model smoke {framework}/{model}")
    if pairs != expected_pairs:
        raise ValueError("framework-model smokes must cover exactly every framework/model pair")
    return {
        "base_case_fixed_controls": len(controls),
        "robustness": len(robustness),
        "vertex_canaries": len(canary_records),
        "framework_model_smokes": len(smoke_records),
    }
