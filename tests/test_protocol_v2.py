from __future__ import annotations

import pytest

from src.pipeline.budget import ResourceBudget
from src.pipeline.framework_adapter import ModelProfile
from src.pipeline.ledger import EventLedger
from src.pipeline.llm_budget import UsageMetadataMissing, normalize_usage
from src.pipeline.manifest import ResourceLimits, Scope
from src.pipeline.runner import ExecutionResult
from src.pipeline.runtime import ExecutionGateway, RuntimeResult
from src.pipeline.train import training_cells


def _profile(label: str) -> dict[str, object]:
    profile = ModelProfile(
        model_name=label,
        location="us-central1",
        resource_id=f"projects/p/locations/us-central1/endpoints/{label}",
        resource_revision=f"endpoints/{label}/deployedModels/123",
        pricing={"input_per_million": 1.0, "cached_input_per_million": 0.25,
                 "output_per_million": 2.0, "thinking_per_million": 3.0},
        generation_parameters={"temperature": 0.0},
        usage_semantics={"input_includes_cached": "true", "total_formula": "input+output+thinking"},
        pricing_effective_at="2026-08-02T00:00:00Z",
    )
    return profile.to_dict()


def test_training_plan_has_exact_locked_cell_counts() -> None:
    cases = [
        {"case_id": f"vp-train-{number:04d}", "severity": f"s{number % 4}", "capability": f"c{number % 5}"}
        for number in range(1, 41)
    ]
    profiles = [_profile(label) for label in sorted(ModelProfile.ALLOWED_MODELS)]
    cells = training_cells(cases, profiles)
    assert len(cells) == 4560
    assert sum(cell.phase == "sweep" for cell in cells) == 4200
    assert sum(cell.phase == "confirmation" for cell in cells) == 360
    assert len({cell.run_id for cell in cells}) == 4560
    assert all(cell.track == "blind" and cell.budget_tier == "medium" for cell in cells)


def test_usage_requires_provider_metadata_and_never_counts_cache_twice() -> None:
    profile = ModelProfile.from_dict(_profile("gemini-3.5-flash"))
    with pytest.raises(UsageMetadataMissing):
        normalize_usage({"content": "missing"}, profile)
    usage = normalize_usage({"usage": {"input_tokens": 10, "cached_input_tokens": 4,
                                         "output_tokens": 5, "thinking_tokens": 2}}, profile)
    assert usage.total_tokens == 17
    assert usage.usd == pytest.approx((6 + 1 + 10 + 6) / 1_000_000)


class _Runtime:
    def run(self, argv: list[str], *, timeout: int) -> RuntimeResult:
        return RuntimeResult(ExecutionResult(0, "ok", "", 1.0))


def test_execution_gateway_rejects_unstructured_or_out_of_scope_before_runtime() -> None:
    ledger = EventLedger("run")
    scope = Scope(allowed_hostnames=["lab.local"], allowed_ports=[443])
    gateway = ExecutionGateway(runtime=_Runtime(), scope=scope, budget=ResourceBudget(ResourceLimits()), ledger=ledger)  # type: ignore[arg-type]
    invalid = gateway.execute([], timeout=1, stage="execute")
    assert invalid.failure_class == "command_invalid"
    blocked = gateway.execute(["curl", "https://outside.invalid"], timeout=1, stage="execute")
    assert blocked.failure_class == "scope_violation"
    assert len(ledger.events) == 2
