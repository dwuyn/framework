from __future__ import annotations

import pytest

from src.pipeline.framework_adapter import ModelProfile
from src.pipeline.llm_budget import normalize_usage
from src.pipeline.model_resolution import validate_resolution_lock
from src.pipeline.runtime_readiness import build_canary_smoke_plan
from src.pipeline.vertex_gateway import GatewayError, VertexGateway, serve_gateway
from src.pipeline.vertex_runtime import (
    GeminiExecutor,
    GemmaMaaSExecutor,
    ModelResolver,
    PricingSnapshot,
    VertexContractError,
)


def _profile(label: str, resource_id: str = "projects/p/locations/global/publishers/google/models/x") -> ModelProfile:
    return ModelProfile.from_dict(
        {
            "logical_label": label,
            "location": "global",
            "resource_id": resource_id,
            "resource_revision": "v20260805",
            "pricing": {
                "input_per_million": 1.0,
                "cached_input_per_million": 0.5,
                "output_per_million": 2.0,
                "thinking_per_million": 2.0,
            },
            "pricing_effective_at": "2026-08-05T00:00:00Z",
            "usage_semantics": {
                "input_includes_cached": "true",
                "total_formula": "input+output+thinking",
            },
        }
    )


def _metadata(label: str) -> dict[str, str]:
    model_id = label if label != "gemma-4-26b-a4b-it" else "google/gemma-4-26b-a4b-it-maas"
    api_family = "vertex_openai_compatible" if label == "gemma-4-26b-a4b-it" else "google_genai"
    return {
        "model_id": model_id,
        "resource_id": f"projects/p/locations/global/publishers/google/models/{label}",
        "resource_revision": "v20260805",
        "location": "global",
        "api_family": api_family,
    }


def test_resolver_requires_exact_locked_inventory() -> None:
    resolved = ModelResolver().resolve_all({label: _metadata(label) for label in ModelResolver().catalog})
    assert [item.logical_label for item in resolved] == sorted(ModelResolver().catalog)
    assert all(len(item.metadata_hash) == 64 for item in resolved)


def test_resolver_rejects_alias_and_fake_resource() -> None:
    metadata = _metadata("gemini-3.6-flash")
    metadata["resource_revision"] = "latest"
    with pytest.raises(VertexContractError, match="not immutable"):
        ModelResolver().resolve("gemini-3.6-flash", metadata)


def test_resolver_allows_explicit_gemini_provider_alias() -> None:
    metadata = _metadata("gemini-3.6-flash")
    metadata.update({
        "resource_revision": "default",
        "resolution_mode": "provider_alias",
        "resolution_evidence_hash": "a" * 64,
        "resolution_resolved_at": "2026-08-05T00:00:00Z",
    })
    resolved = ModelResolver().resolve("gemini-3.6-flash", metadata)
    assert resolved.resolution_mode == "provider_alias"
    profile = resolved.to_model_profile(
        {"input_per_million": 1.0, "cached_input_per_million": 0.5,
         "output_per_million": 2.0, "thinking_per_million": 2.0},
        pricing_effective_at="2026-08-05T00:00:00Z",
    )
    assert profile.resolution_mode == "provider_alias"


def test_resolver_rejects_alias_without_explicit_exception() -> None:
    metadata = _metadata("gemini-3.6-flash")
    metadata["resource_revision"] = "default"
    with pytest.raises(VertexContractError, match="provider_alias"):
        ModelResolver().resolve("gemini-3.6-flash", metadata)
    metadata["resource_revision"] = "v20260805"
    metadata["resource_id"] = "gemini-3.6-flash"
    with pytest.raises(VertexContractError, match="full Vertex resource"):
        ModelResolver().resolve("gemini-3.6-flash", metadata)


def test_resolver_rejects_model_surface_mismatch() -> None:
    metadata = _metadata("gemini-3.6-flash")
    metadata["api_family"] = "vertex_openai_compatible"
    with pytest.raises(VertexContractError, match="provider surface"):
        ModelResolver().resolve("gemini-3.6-flash", metadata)


def test_resolver_rejects_tampered_metadata_hash() -> None:
    metadata = _metadata("gemini-3.6-flash")
    metadata["metadata_hash"] = "0" * 64
    with pytest.raises(VertexContractError, match="metadata_hash"):
        ModelResolver().resolve("gemini-3.6-flash", metadata)


def test_pricing_snapshot_is_hashable_and_profile_ready() -> None:
    snapshot = PricingSnapshot(
        source_url="https://cloud.google.com/vertex-ai/generative-ai/pricing",
        retrieved_at="2026-08-05T00:00:00Z",
        effective_at="2026-08-05T00:00:00Z",
        model_prices={
            "gemini-3.6-flash": {
                "input_per_million": 1.0,
                "cached_input_per_million": 0.5,
                "output_per_million": 2.0,
                "thinking_per_million": 2.0,
            }
        },
    )
    profile = ModelResolver().resolve("gemini-3.6-flash", _metadata("gemini-3.6-flash"))
    built = profile.to_model_profile(
        snapshot.pricing_for("gemini-3.6-flash"),
        pricing_effective_at=snapshot.effective_at,
    )
    assert built.profile_hash
    assert len(snapshot.snapshot_hash) == 64


class _GeminiTransport:
    def generate(self, *, model_id, contents, generation_parameters):
        assert model_id == "gemini-3.6-flash"
        assert contents == "ping"
        assert generation_parameters == {}
        return {"text": "pong", "usage": {"input_tokens": 4, "output_tokens": 2}}


class _GemmaTransport:
    def generate(self, *, model_id, messages, generation_parameters):
        assert model_id == "google/gemma-4-26b-a4b-it-maas"
        assert messages == [{"role": "user", "content": "ping"}]
        assert generation_parameters == {}
        return {
            "choices": [{"message": {"content": "pong"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3},
        }


def test_gemini_executor_normalizes_fake_response() -> None:
    result = GeminiExecutor(_GeminiTransport()).invoke(_profile("gemini-3.6-flash"), "ping")
    assert result.text == "pong"
    assert result.usage.input_tokens == 4
    assert result.usage.output_tokens == 2
    assert result.model_id == "gemini-3.6-flash"
    assert len(result.response_hash) == 64


def test_gemma_executor_normalizes_openai_response() -> None:
    result = GemmaMaaSExecutor(_GemmaTransport()).invoke(
        _profile("gemma-4-26b-a4b-it"), [{"role": "user", "content": "ping"}]
    )
    assert result.text == "pong"
    assert result.usage.total_tokens == 8
    assert result.model_id == "google/gemma-4-26b-a4b-it-maas"


def test_standard_pricing_counts_reasoning_once_in_billable_output() -> None:
    profile = ModelProfile.from_dict({
        **_profile("gemini-3.6-flash").to_dict(),
        "usage_semantics": {
            "input_includes_cached": "true",
            "total_formula": "input+output",
            "output_includes_reasoning": "true",
        },
        "pricing": {
            "input_per_million": 1.5,
            "cached_input_per_million": 0.15,
            "output_per_million": 7.5,
        },
    })
    usage = normalize_usage({
        "usage_metadata": {
            "prompt_token_count": 10,
            "cached_content_token_count": 2,
            "candidates_token_count": 3,
            "thoughts_token_count": 4,
        },
    }, profile)
    assert usage.output_tokens == 7
    assert usage.thinking_tokens == 4
    assert usage.total_tokens == 17
    assert usage.usd == pytest.approx(((8 * 1.5) + (2 * 0.15) + (7 * 7.5)) / 1_000_000)


def test_resolution_lock_rehashes_alias_catalog_evidence(tmp_path) -> None:
    metadata = tmp_path / "models/gemini-3.6-flash.json"
    metadata.parent.mkdir()
    metadata.write_text('{"name":"gemini-3.6-flash"}\n', encoding="utf-8")
    digest = __import__("hashlib").sha256(metadata.read_bytes()).hexdigest()
    profile = ModelProfile.from_dict({
        **_profile("gemini-3.6-flash").to_dict(),
        "resource_revision": "default",
        "resolution_mode": "provider_alias",
        "resolution_resolved_at": "2026-08-05T00:00:00Z",
        "resolution_evidence_hash": digest,
    })
    lock = {
        "schema_version": "1.0.0", "generated_at": "2026-08-05T00:00:00Z",
        "models": [{
            "logical_label": profile.logical_label,
            "resource_id": profile.resource_id,
            "resource_revision": profile.resource_revision,
            "resolution_mode": profile.resolution_mode,
            "resolution_evidence_hash": digest,
            "resolution_resolved_at": profile.resolution_resolved_at,
            "metadata_path": "models/gemini-3.6-flash.json",
        }],
    }
    validate_resolution_lock(lock, profiles=[profile], artifact_root=tmp_path)
    metadata.write_text('{"name":"tampered"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="metadata hash"):
        validate_resolution_lock(lock, profiles=[profile], artifact_root=tmp_path)


def test_executor_rejects_wrong_provider_surface() -> None:
    with pytest.raises(VertexContractError, match="Gemini"):
        GeminiExecutor(_GeminiTransport()).invoke(_profile("gemma-4-26b-a4b-it"), "ping")


def test_gateway_rejects_unapproved_run_and_profile() -> None:
    profile = _profile("gemini-3.6-flash")
    gateway = VertexGateway(
        profiles=[profile], allowed_run_ids={"run-1"}, token="test-token",
        gemini=GeminiExecutor(_GeminiTransport()), gemma=GemmaMaaSExecutor(_GemmaTransport()),
    )
    result = gateway.invoke({
        "run_id": "run-1", "model_label": profile.logical_label,
        "profile_hash": profile.profile_hash, "contents": "ping",
    }, token="test-token")
    assert result.text == "pong"
    with pytest.raises(GatewayError, match="not approved"):
        gateway.invoke({
            "run_id": "run-2", "model_label": profile.logical_label,
            "profile_hash": profile.profile_hash, "contents": "ping",
        }, token="test-token")


def test_runtime_readiness_plan_has_exactly_eighteen_cells() -> None:
    profiles = [_profile(label) for label in sorted(ModelProfile.ALLOWED_MODELS)]
    costs = {name: 0.1 for name in ("VeriPlanPT", "PentestGPT", "VulnBot", "HackSynth", "PentestAgent")}
    plan = build_canary_smoke_plan(profiles=profiles, framework_costs=costs, canary_cost=0.01)
    assert plan["cell_count"] == 18
    assert len(plan["cells"]) == 18
    assert len({cell["run_id"] for cell in plan["cells"]}) == 18


def test_gateway_refuses_non_local_bind_address() -> None:
    profile = _profile("gemini-3.6-flash")
    gateway = VertexGateway(
        profiles=[profile], allowed_run_ids={"run-1"}, token="test-token",
        gemini=GeminiExecutor(_GeminiTransport()), gemma=GemmaMaaSExecutor(_GemmaTransport()),
    )
    with pytest.raises(GatewayError, match="bind address"):
        serve_gateway(gateway, host="example.test", port=8080)
