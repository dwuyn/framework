from __future__ import annotations

import pytest

from src.pipeline.budget import BudgetExceeded, ResourceBudget
from src.pipeline.framework_adapter import ModelProfile
from src.pipeline.ledger import EventLedger
from src.pipeline.llm_budget import BudgetedLLM
from src.pipeline.manifest import ResourceLimits


def _profile() -> ModelProfile:
    return ModelProfile(
        model_name="gemini-3.5-flash",
        project="vertex-project",
        location="us-central1",
        resource_id="projects/p/locations/us-central1/endpoints/123",
        resource_revision="endpoints/123/deployedModels/456",
        pricing={
            "input_per_million": 1.0,
            "cached_input_per_million": 0.25,
            "output_per_million": 2.0,
            "thinking_per_million": 3.0,
        },
        generation_parameters={"temperature": 0.0},
        usage_semantics={"input_includes_cached": "true", "total_formula": "input+output+thinking"},
        pricing_effective_at="2026-08-02T00:00:00Z",
    )


class FakeLLM:
    def invoke(self, prompt: str):
        return {
            "content": f"ok:{prompt}",
            "usage": {
                "input_tokens": 10,
                "cached_input_tokens": 4,
                "output_tokens": 5,
                "thinking_tokens": 2,
            },
        }


def test_budgeted_llm_records_usage_cost_and_revision() -> None:
    ledger = EventLedger("run")
    budget = ResourceBudget(ResourceLimits(max_llm_calls=2, max_total_tokens=100))
    response = BudgetedLLM(
        FakeLLM(),
        budget=budget,
        ledger=ledger,
        model_profile=_profile(),
        role="planner",
    ).invoke("x", estimated_tokens=20)

    assert response["content"] == "ok:x"
    event = ledger.events[-1]
    assert event.phase == "llm"
    assert event.stage == "llm_usage"
    assert event.payload["event_type"] == "llm_usage"
    assert event.payload["model_revision"] == "endpoints/123/deployedModels/456"
    assert event.payload["total_tokens"] == 17
    assert event.payload["usd"] > 0
    assert budget.state.llm_calls == 1


def test_budgeted_llm_preflight_blocks_before_call() -> None:
    ledger = EventLedger("run")
    budget = ResourceBudget(ResourceLimits(max_llm_calls=1, max_total_tokens=100))
    budget.record_llm_usage(input_tokens=1)
    with pytest.raises(BudgetExceeded):
        BudgetedLLM(
            FakeLLM(),
            budget=budget,
            ledger=ledger,
            model_profile=_profile(),
            role="planner",
        ).invoke("x")
    assert ledger.events[-1].payload["event_type"] == "budget_exhausted"
    assert ledger.events[-1].failure_class == "budget_exceeded"
