"""Pinned, non-invasive adapters for the four external baseline CLIs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.pipeline.budget import BudgetTier
from src.pipeline.framework_adapter import ModelProfile, PublicTask


@dataclass(frozen=True)
class BaselineInvocation:
    argv: tuple[str, ...]
    env: dict[str, str]


def _limits(tier: BudgetTier) -> dict[str, int]:
    limits = tier.to_limits()
    return {"max_llm_calls": limits.max_llm_calls, "max_total_tokens": limits.max_total_tokens,
            "max_runtime_seconds": limits.max_runtime_seconds, "max_tool_calls": limits.max_tool_calls}


class ExternalBaselineAdapter:
    """Build an upstream CLI invocation without modifying the upstream tree."""

    name = ""

    def build_invocation(self, *, public_task: PublicTask, model_profile: ModelProfile,
                         budget_tier: BudgetTier, run_context: Mapping[str, Any], run_dir: str | Path) -> BaselineInvocation:
        if not self.name:
            raise ValueError("adapter name is required")
        root = Path(run_dir).resolve()
        root.mkdir(parents=True, exist_ok=True)
        task_path = root / "public-task.json"
        profile_path = root / "model-profile.json"
        task_path.write_text(json.dumps(public_task.to_dict(), sort_keys=True) + "\n", encoding="utf-8")
        profile_path.write_text(json.dumps(model_profile.to_dict(), sort_keys=True) + "\n", encoding="utf-8")
        config_path = root / "adapter-config.json"
        config_path.write_text(
            json.dumps(
                {
                    "framework": self.name,
                    "public_task_path": str(task_path),
                    "model_profile_path": str(profile_path),
                    "provider_shim": "veriplanpt-vertex",
                    "model_label": model_profile.logical_label,
                    "model_resource_id": model_profile.resource_id,
                    "budget": _limits(budget_tier),
                    "run_context": dict(run_context),
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        env = {
            "VERIPLANPT_PUBLIC_TASK_PATH": str(task_path),
            "VERIPLANPT_MODEL_PROFILE_PATH": str(profile_path),
            "VERIPLANPT_ADAPTER_CONFIG_PATH": str(config_path),
            "VERIPLANPT_PROVIDER_SHIM": "veriplanpt-vertex",
            "VERIPLANPT_MODEL_LABEL": model_profile.logical_label,
            "VERIPLANPT_MODEL_RESOURCE": model_profile.resource_id,
            "VERIPLANPT_MODEL_REVISION": model_profile.resource_revision,
            "VERIPLANPT_TRACK": public_task.track,
            "VERIPLANPT_BUDGET_JSON": json.dumps(_limits(budget_tier), sort_keys=True),
            "VERIPLANPT_RUN_CONTEXT_JSON": json.dumps(dict(run_context), sort_keys=True),
            "VERIPLANPT_RUN_DIR": str(root),
        }
        return BaselineInvocation(tuple(self._argv(root, model_profile, budget_tier)), env)

    def _argv(self, run_dir: Path, model_profile: ModelProfile, budget_tier: BudgetTier) -> Sequence[str]:
        raise NotImplementedError


class PentestGPTAdapter(ExternalBaselineAdapter):
    name = "PentestGPT"

    def _argv(self, run_dir: Path, model_profile: ModelProfile, budget_tier: BudgetTier) -> Sequence[str]:
        return ("python", "-m", "pentestgpt.main", "--log_dir", str(run_dir / "upstream-logs"),
                "--reasoning_model", model_profile.logical_label, "--parsing_model", model_profile.logical_label)


class PentestAgentAdapter(ExternalBaselineAdapter):
    name = "PentestAgent"

    def _argv(self, run_dir: Path, model_profile: ModelProfile, budget_tier: BudgetTier) -> Sequence[str]:
        # Upstream has no unified CLI: its documented first stage is the recon
        # entrypoint. The Vertex resource is supplied through the provider shim
        # environment, never through an upstream model-name argument.
        return ("python", "agents/recon_agent.py")


class VulnBotAdapter(ExternalBaselineAdapter):
    name = "VulnBot"

    def _argv(self, run_dir: Path, model_profile: ModelProfile, budget_tier: BudgetTier) -> Sequence[str]:
        return ("python", "cli.py", "vulnbot", "--max_interactions", str(budget_tier.to_limits().max_llm_calls))


class HackSynthAdapter(ExternalBaselineAdapter):
    name = "HackSynth"

    def _argv(self, run_dir: Path, model_profile: ModelProfile, budget_tier: BudgetTier) -> Sequence[str]:
        benchmark = run_dir / "hacksynth-benchmark.json"
        config = run_dir / "hacksynth-config.json"
        task = json.loads((run_dir / "public-task.json").read_text(encoding="utf-8"))
        benchmark.write_text(
            json.dumps(
                {
                    task["case_id"]: {
                        "description": task["objective"],
                        "target": task["target"].get("host", ""),
                        "flag": "__veriplanpt_oracle__",
                        "category": "veriplanpt",
                    }
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        limits = _limits(budget_tier)
        config.write_text(
            json.dumps(
                {
                    "attackbox": f"veriplanpt-{task['case_id']}",
                    "target_text": "Perform the approved benchmark task: {target}",
                    "llm": {
                        "model_id": model_profile.logical_label,
                        "model_local": False,
                        "base_url": "http://gateway-relay:8080/v1",
                        "temperature": 0,
                        "top_p": 1,
                        "max_new_tokens": limits["max_total_tokens"],
                        "prompt_chaining": False,
                        "do_sample": False,
                    },
                    "planner": {"system_prompt": "", "user_prompt": ""},
                    "summarizer": {"system_prompt": "", "user_prompt": ""},
                    "timeout_duration": limits["max_runtime_seconds"],
                    "new_observation_length_limit": 2000,
                    "max_tries": limits["max_llm_calls"],
                    "neptune": {"project": "veriplanpt/offline"},
                    "veriplanpt": {
                        "public_task_path": str(run_dir / "public-task.json"),
                        "model_profile_path": str(run_dir / "model-profile.json"),
                        "provider_shim": "veriplanpt-vertex",
                        "budget": limits,
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return ("python", "run_bench.py", "-b", str(benchmark), "-c", str(config))
