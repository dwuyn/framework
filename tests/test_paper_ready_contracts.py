from __future__ import annotations

import pytest

from src.pipeline.framework_adapter import ModelProfile, PublicTask
from src.pipeline.manifest import ResourceLimits
from src.planning.policy import BudgetPolicy


def _profile(label: str = "gemini-3.5-flash") -> ModelProfile:
    return ModelProfile(
        model_name=label,
        project="vertex-project",
        location="us-central1",
        resource_id=f"publishers/google/models/{label}-endpoint",
        resource_revision=f"endpoints/{label}/deployedModels/20260801",
        pricing={
            "input_per_million": 1.0,
            "cached_input_per_million": 0.25,
            "output_per_million": 2.0,
            "thinking_per_million": 3.0,
        },
        generation_parameters={"temperature": 0.0, "max_output_tokens": 1024},
        usage_semantics={"input_includes_cached": "true", "total_formula": "input+output+thinking"},
        pricing_effective_at="2026-08-02T00:00:00Z",
    )


def test_vertex_profiles_require_real_pinned_contract() -> None:
    profile = _profile()
    assert profile.logical_label == "gemini-3.5-flash"
    assert profile.provider == "vertexai"
    assert profile.resource_id and profile.resource_revision and profile.location and profile.profile_hash
    assert set(ModelProfile.REQUIRED_PRICING_KEYS) <= set(profile.pricing)


def test_vertex_profile_rejects_placeholders_and_zero_pricing() -> None:
    with pytest.raises(TypeError):
        ModelProfile(model_name="gemini-3.5-flash")  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="logical label"):
        _profile().from_dict({
            "logical_label": "gemini-3.5-flash",
            "project": "p",
            "location": "us-central1",
            "resource_id": "gemini-3.5-flash",
            "resource_revision": "benchmark-pinned",
            "pricing": {
                "input_per_million": 0,
                "cached_input_per_million": 0,
                "output_per_million": 0,
                "thinking_per_million": 0,
            },
        })


def test_public_task_parses_current_data_test_schema() -> None:
    task = PublicTask.from_dict({
        "case_id": "case-opaque-01", "track": "blind", "objective": "obtain the stated proof",
        "target": {"url": "http://lab.local:8080", "protocol": "http", "exposed_ports": [8080]},
        "scope": {"allowed_hosts": ["lab.local"], "allowed_ports": [8080], "prohibited": []},
    })
    assert (task.host, task.port_range) == ("lab.local", "8080")


def test_blind_task_rejects_guided_or_cve_leakage() -> None:
    with pytest.raises(ValueError, match="guided hints"):
        PublicTask.from_dict({
            "case_id": "opaque",
            "track": "blind",
            "objective": "test",
            "target": {"host": "lab", "exposed_ports": [80]},
            "hints": {"component": "secret"},
        })
    with pytest.raises(ValueError, match="CVE"):
        PublicTask.from_dict({"case_id": "CVE-2026-12345", "track": "blind", "objective": "test", "host": "lab", "port_range": "80"})


def test_guided_task_requires_hints_object_without_hidden_truth() -> None:
    with pytest.raises(ValueError, match="nested under the 'hints' object"):
        PublicTask.from_dict({
            "case_id": "opaque",
            "track": "guided",
            "objective": "test",
            "target": {"host": "lab", "exposed_ports": [80]},
            "component": "secret",
        })
    task = PublicTask.from_dict({
        "case_id": "opaque",
        "track": "guided",
        "objective": "test",
        "target": {"host": "lab", "exposed_ports": [80]},
        "hints": {"component": "panel", "endpoint": "/login", "method": "POST"},
    })
    public = task.to_dict()
    assert public["hints"]["component"] == "panel"
    assert "canonical_case_id" not in public
    assert "decoy_services" not in public


def test_resource_limits_serializes_llm_limits() -> None:
    limits = ResourceLimits(max_total_tokens=7, max_llm_calls=3)
    assert ResourceLimits.from_dict(limits.to_dict()) == limits


def test_policy_state_survives_resume() -> None:
    policy = BudgetPolicy()
    assert not policy.should_rotate_service("host:80:tcp:http", False)
    resumed = BudgetPolicy()
    resumed.restore_state(policy.state_to_dict())
    assert resumed.should_rotate_service("host:80:tcp:http", False)


def test_dataset_missing_finalizes_as_infrastructure_failure(tmp_path) -> None:
    from src.graph import _route_retrieve, pipeline_finalize_node, pipeline_retrieve_node
    from src.pipeline.budget import BudgetTier
    from src.pipeline.ledger import EventLedger
    from src.pipeline.manifest import RunManifest
    from src.state import initial_state

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    manifest = RunManifest(
        schema_version="2.0.0",
        run_id="dataset-missing",
        target_id="vp-test-0001",
        limits=BudgetTier.LOW.to_limits().to_dict(),
        run_dir=str(run_dir),
    )
    state = initial_state("lab.local", target_port="80")
    state.update({  # type: ignore[typeddict-item]
        "pipeline_manifest": manifest.to_dict(),
        "retrieval_mode": "snapshot",
        "source_snapshot_dir": str(tmp_path / "missing-snapshot"),
        "pipeline_result": {},
    })

    state.update(pipeline_retrieve_node(state))  # type: ignore[typeddict-item]
    assert state["retrieval_status"] == "dataset_missing"
    assert _route_retrieve(state) == "pipeline_finalize"

    finalized = pipeline_finalize_node(state)
    result = finalized["pipeline_result"]
    assert result["termination_status"] == "infrastructure_failure"
    assert result["terminal_causal_class"] == "dataset_missing"
    events = EventLedger.load(str(run_dir / "events.jsonl")).to_list()
    assert events[-1]["phase"] == "lifecycle"
    assert events[-1]["stage"] == "termination"
