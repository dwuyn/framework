from __future__ import annotations

import hashlib
import json

import pytest

from scripts.collect_modelgarden_metadata import _gemma_endpoint_snapshot, _resource, _select
from src.pipeline.framework_adapter import ModelProfile
from src.pipeline.runtime_readiness import build_canary_smoke_plan, worst_case_cost_usd


def _profile(label: str) -> ModelProfile:
    gemma = label == "gemma-4-26b-a4b-it"
    return ModelProfile.from_dict({
        "logical_label": label, "location": "global",
        "resource_id": f"projects/p/locations/global/publishers/google/models/{label}",
        "resource_revision": "001" if gemma else "default",
        "resolution_mode": "immutable" if gemma else "provider_alias",
        "resolution_evidence_hash": "a" * 64, "resolution_resolved_at": "2026-08-05T00:00:00Z",
        "endpoint_url": "https://global-aiplatform.googleapis.com/v1" if gemma else "",
        "pricing": {"input_per_million": 1.5, "cached_input_per_million": 0.15, "output_per_million": 7.5},
        "pricing_effective_at": "2026-08-05T00:00:00Z",
        "usage_semantics": {"input_includes_cached": "true", "total_formula": "input+output", "output_includes_reasoning": "true"},
    })


def test_model_garden_selection_requires_exact_name_and_version() -> None:
    records = [
        {"name": "publishers/google/models/gemini-3.5-flash", "versionId": "default"},
        {"name": "publishers/google/models/gemini-3.5-flash-lite", "versionId": "default"},
        {"name": "publishers/google/models/gemini-3.5-flash", "versionId": "002"},
    ]
    assert _select(records, catalog_name="publishers/google/models/gemini-3.5-flash", version="default") == records[0]
    with pytest.raises(RuntimeError, match="exactly one"):
        _select(records, catalog_name="publishers/google/models/gemini-3.5-flash", version="001")


def test_publisher_template_becomes_global_project_resource() -> None:
    assert _resource(
        "projects/{project}/locations/{location}/publishers/google/models/gemini-3.5-flash",
        project="runtime-project", model_id="gemini-3.5-flash",
    ) == "projects/runtime-project/locations/global/publishers/google/models/gemini-3.5-flash"


def test_gemma_endpoint_snapshot_uses_public_model_id(tmp_path) -> None:
    document = tmp_path / "gemma.source"
    document.write_text("official source", encoding="utf-8")
    snapshot = tmp_path / "gemma.json"
    snapshot.write_text(json.dumps({
        "schema_version": "1.0.0",
        "model_id": "gemma-4-26b-a4b-it-maas",
        "endpoint_url": "https://aiplatform.googleapis.com/v1/projects/p/locations/global/endpoints/openapi/chat/completions",
        "source_url": "https://docs.cloud.google.com/example",
        "retrieved_at": "2026-08-06T00:00:00Z",
        "source_sha256": hashlib.sha256(document.read_bytes()).hexdigest(),
    }), encoding="utf-8")
    assert _gemma_endpoint_snapshot(snapshot, document)["model_id"] == "gemma-4-26b-a4b-it-maas"


def test_strict_reservation_uses_pricing_and_two_attempts() -> None:
    profiles = [_profile(label) for label in sorted(ModelProfile.ALLOWED_MODELS)]
    images = {name: "sha256:" + "2" * 64 for name in ("VeriPlanPT", "PentestGPT", "VulnBot", "HackSynth", "PentestAgent")}
    plan = build_canary_smoke_plan(
        profiles=profiles, dataset_lock_hash="a" * 64, baseline_identity_hash="b" * 64,
        native_identity_hash="c" * 64, model_resolution_lock_hash="d" * 64,
        evaluator_hash="e" * 64, oracle_hash="f" * 64, image_digests=images,
        target_runtime_lock_hash="1" * 64, source_snapshot_hash="3" * 64,
        max_input_tokens=100, max_output_tokens=10,
        max_llm_calls=40, retry_policy={"max_attempts": 2}, strict=True,
    )
    expected = worst_case_cost_usd(
        profiles[0], max_input_tokens=100, max_output_tokens=10,
        max_llm_calls=40, max_attempts=2,
    )
    assert plan["cells"][0]["cell_worst_case_cost_usd"] == expected
