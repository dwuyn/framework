from __future__ import annotations

import json

from src.baselines import HackSynthAdapter, PentestAgentAdapter, PentestGPTAdapter, VulnBotAdapter
from src.pipeline.budget import BudgetTier
from src.pipeline.framework_adapter import ModelProfile, PublicTask


def _profile() -> ModelProfile:
    return ModelProfile.from_dict({
        "logical_label": "gemini-3.5-flash", "location": "us-central1", "resource_id": "endpoint/123",
        "resource_revision": "endpoint/123/deployed/456",
        "pricing": {"input_per_million": 1, "cached_input_per_million": 1,
                    "output_per_million": 1, "thinking_per_million": 1},
        "usage_semantics": {"input_includes_cached": "true", "total_formula": "input+output+thinking"},
        "pricing_effective_at": "2026-08-04T00:00:00Z",
    })


def test_all_baseline_adapters_create_pinned_cli_invocations(tmp_path) -> None:
    task = PublicTask.from_dict({"case_id": "vp-validation-0001", "track": "blind", "objective": "proof",
                                 "target": {"host": "lab.local", "exposed_ports": [80]}})
    for adapter in (PentestGPTAdapter(), PentestAgentAdapter(), VulnBotAdapter(), HackSynthAdapter()):
        run_dir = tmp_path / adapter.name
        invocation = adapter.build_invocation(public_task=task, model_profile=_profile(), budget_tier=BudgetTier.MEDIUM,
                                              run_context={"stage": "canary_smoke"}, run_dir=run_dir)
        assert invocation.argv[0:1] == ("python",)
        assert _profile().resource_id not in invocation.argv
        assert invocation.env["VERIPLANPT_PROVIDER_SHIM"] == "veriplanpt-vertex"
        assert json.loads(invocation.env["VERIPLANPT_BUDGET_JSON"])["max_llm_calls"] > 0
        assert json.loads((run_dir / "public-task.json").read_text())["case_id"] == task.case_id
        assert (run_dir / "adapter-config.json").is_file()


def test_hacksynth_adapter_writes_the_upstream_config_shape(tmp_path) -> None:
    task = PublicTask.from_dict({"case_id": "vp-validation-0001", "track": "blind", "objective": "proof",
                                 "target": {"host": "lab.local", "exposed_ports": [80]}})
    run_dir = tmp_path / "nested" / "run"
    HackSynthAdapter().build_invocation(public_task=task, model_profile=_profile(), budget_tier=BudgetTier.LOW,
                                        run_context={}, run_dir=run_dir)
    config = json.loads((run_dir / "hacksynth-config.json").read_text())
    benchmark = json.loads((run_dir / "hacksynth-benchmark.json").read_text())
    assert config["llm"]["model_id"] == _profile().logical_label
    assert task.case_id in benchmark
