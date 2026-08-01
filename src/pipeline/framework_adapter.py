"""
src/pipeline/framework_adapter.py
──────────────────────────────────
Public interface for running VeriPlanPT on a benchmark task.

Defines the three locked interfaces:
  - PublicTask  : what the framework receives (blind or guided)
  - BudgetTier  : re-exported from budget.py
  - RunArtifact : what the framework returns

FrameworkAdapter.run() is the single entry point for all benchmark runs.
The external evaluator calls this and receives a RunArtifact; it never reads
the internal state or the evaluator truth directly.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import time
from dataclasses import dataclass, field
from typing import Any

from src.pipeline.budget import BudgetTier
from src.pipeline.ledger import EventLedger

# Re-export BudgetTier so importers only need this module.
__all__ = [
    "BudgetTier",
    "ModelProfile",
    "PublicTask",
    "RunArtifact",
    "FrameworkAdapter",
]


@dataclass
class ModelProfile:
    """Identifies the model configuration for a run.

    model_name must be one of the three preregistered models:
        gemini-3.5-flash, gemini-3.6-flash, gemma-4-26b-a4b-it
    """
    model_name: str
    # Vertex AI endpoint/resource revision — must be pinned before run matrix
    resource_revision: str = ""
    location: str = "us-central1"

    ALLOWED_MODELS = frozenset({
        "gemini-3.5-flash",
        "gemini-3.6-flash",
        "gemma-4-26b-a4b-it",
    })

    def __post_init__(self) -> None:
        if self.model_name not in self.ALLOWED_MODELS:
            raise ValueError(
                f"ModelProfile.model_name {self.model_name!r} is not in the preregistered set "
                f"{sorted(self.ALLOWED_MODELS)}"
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "model_name": self.model_name,
            "resource_revision": self.resource_revision,
            "location": self.location,
        }


@dataclass
class PublicTask:
    """What the framework receives from the benchmark harness.

    Two schemas:
    - blind:  scope, host, port_range and general objective only.
              No product, CVE, version, endpoint or method hints.
    - guided: blind fields PLUS component, endpoint, method hints.
              No hidden truth.

    The harness constructs this from the public half of the lab manifest.
    """
    case_id: str
    track: str               # "blind" | "guided"
    objective: str           # general attack objective, no CVE/version hints
    host: str
    port_range: str          # e.g. "1-65535" or "80,443,8080"
    # Optional fields (guided track only)
    component: str = ""
    endpoint: str = ""
    method_hint: str = ""
    # Hard-noise / alias metadata (populated by harness)
    decoy_services: list[str] = field(default_factory=list)
    is_alias: bool = False
    canonical_case_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "track": self.track,
            "objective": self.objective,
            "host": self.host,
            "port_range": self.port_range,
            "component": self.component,
            "endpoint": self.endpoint,
            "method_hint": self.method_hint,
            "decoy_services": list(self.decoy_services),
            "is_alias": self.is_alias,
            "canonical_case_id": self.canonical_case_id,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PublicTask":
        return cls(
            case_id=str(d.get("case_id", "")),
            track=str(d.get("track", "blind")),
            objective=str(d.get("objective", "")),
            host=str(d.get("host", "") or d.get("target", {}).get("host", "")),
            port_range=str(d.get("port_range", "1-65535")),
            component=str(d.get("component", "")),
            endpoint=str(d.get("endpoint", "")),
            method_hint=str(d.get("method_hint", "")),
            decoy_services=list(d.get("decoy_services", [])),
            is_alias=bool(d.get("is_alias", False)),
            canonical_case_id=str(d.get("canonical_case_id", "")),
        )


@dataclass
class EnvironmentManifest:
    """Immutable record of the execution environment."""
    python_version: str = ""
    platform_info: str = ""
    framework_commit: str = ""
    framework_dirty: bool = False
    snapshot_hash: str = ""
    snapshot_cutoff: str = "2026-08-01T00:00:00Z"
    created_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "python_version": self.python_version,
            "platform_info": self.platform_info,
            "framework_commit": self.framework_commit,
            "framework_dirty": self.framework_dirty,
            "snapshot_hash": self.snapshot_hash,
            "snapshot_cutoff": self.snapshot_cutoff,
            "created_at": self.created_at,
        }


@dataclass
class RunArtifact:
    """What FrameworkAdapter.run() returns to the external harness.

    This is the complete, normalised output of one framework run.
    The harness uploads this to the evaluator; the framework never sees
    the evaluator's verdict.
    """
    case_id: str
    repetition: int
    track: str
    model_profile: ModelProfile
    budget_tier: BudgetTier
    run_id: str = ""
    run_dir: str = ""
    # Outcome as reported by the internal oracle (without hidden truth).
    internal_outcome: str = ""
    budget_termination_reason: str = ""
    # Normalised transcript (list of {role, event} dicts from EventLedger)
    transcript: list[dict[str, Any]] = field(default_factory=list)
    # Proof submissions for the external evaluator
    proof_submissions: list[dict[str, Any]] = field(default_factory=list)
    # Token/cost usage summary
    usage: dict[str, Any] = field(default_factory=dict)
    # Environment snapshot
    env_manifest: EnvironmentManifest = field(default_factory=EnvironmentManifest)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "repetition": self.repetition,
            "track": self.track,
            "model_profile": self.model_profile.to_dict(),
            "budget_tier": self.budget_tier.value,
            "run_id": self.run_id,
            "run_dir": self.run_dir,
            "internal_outcome": self.internal_outcome,
            "budget_termination_reason": self.budget_termination_reason,
            "transcript": self.transcript,
            "proof_submissions": self.proof_submissions,
            "usage": self.usage,
            "env_manifest": self.env_manifest.to_dict(),
        }

    def save(self, path: str) -> None:
        """Write the artifact to a JSON file."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, sort_keys=True, default=str)


def _capture_env(snapshot_dir: str = "") -> EnvironmentManifest:
    """Capture immutable environment metadata at run time."""
    import subprocess
    commit = ""
    dirty = False
    try:
        repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        commit = subprocess.run(
            ["git", "-C", repo, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        dirty = bool(subprocess.run(
            ["git", "-C", repo, "status", "--porcelain"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip())
    except Exception:
        pass

    snap_hash = ""
    if snapshot_dir and os.path.isdir(snapshot_dir):
        digest = hashlib.sha256()
        for root, _, names in os.walk(snapshot_dir):
            for name in sorted(names):
                try:
                    with open(os.path.join(root, name), "rb") as fh:
                        digest.update(fh.read())
                except OSError:
                    pass
        snap_hash = digest.hexdigest()

    return EnvironmentManifest(
        python_version=sys.version,
        platform_info=platform.platform(),
        framework_commit=commit,
        framework_dirty=dirty,
        snapshot_hash=snap_hash,
        created_at=time.time(),
    )


class FrameworkAdapter:
    """Entry point for all benchmark runs.

    Usage:
        adapter = FrameworkAdapter(results_root="/path/to/results")
        artifact = adapter.run(task, model_profile, budget_tier, repetition=1)
    """

    def __init__(
        self,
        results_root: str = "",
        snapshot_dir: str = "",
    ) -> None:
        self.results_root = results_root or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "data", "runs",
        )
        self.snapshot_dir = snapshot_dir

    def run(
        self,
        task: PublicTask,
        model_profile: ModelProfile,
        budget_tier: BudgetTier,
        repetition: int = 1,
    ) -> RunArtifact:
        """Execute one benchmark run and return the normalised RunArtifact.

        The framework graph is invoked; the external evaluator never accesses
        the internal oracle truth during this call.
        """
        from src.graph import build_graph
        from src.state import initial_state

        env = _capture_env(self.snapshot_dir)
        run_dir = os.path.join(
            self.results_root, task.case_id,
            f"{model_profile.model_name}_{budget_tier.value}_rep{repetition:02d}",
        )
        os.makedirs(run_dir, exist_ok=True)

        limits = budget_tier.to_limits()
        thread_id = f"{task.case_id}-{model_profile.model_name}-{budget_tier.value}-{repetition}"
        graph, config = build_graph(thread_id)

        # Parse first port from port_range for initial state.
        ports = []
        for part in task.port_range.replace(",", " ").split():
            if "-" in part:
                try:
                    ports.append(int(part.split("-")[0]))
                except ValueError:
                    pass
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    pass
        target_port = str(ports[0]) if ports else "80"

        state = initial_state(
            target_ip=task.host,
            target_port=target_port,
            max_runtime_seconds=limits.max_runtime_seconds,
        )
        state.update({
            "public_task": task.to_dict(),
            "model_profile": model_profile.model_name,
            "budget_tier": budget_tier.value,
            "retrieval_mode": "snapshot",
            "source_snapshot_dir": self.snapshot_dir,
            "pipeline_result": {"run_dir": run_dir},
        })
        if task.component:
            state["app_name"] = task.component

        final = graph.invoke(state, config=config)
        result = dict(final.get("pipeline_result") or {})
        actual_run_dir = str(result.get("run_dir") or run_dir)

        # Build transcript from ledger.
        ledger_path = result.get("ledger_path") or os.path.join(actual_run_dir, "events.jsonl")
        transcript: list[dict[str, Any]] = []
        if ledger_path and os.path.exists(ledger_path):
            ledger = EventLedger.load(ledger_path)
            transcript = [
                {"role": e.phase, "event": {k: v for k, v in vars(e).items() if v is not None}}
                for e in ledger.events
            ]

        # Collect proof submissions.
        proofs_path = result.get("proofs_path") or os.path.join(actual_run_dir, "proofs.json")
        proof_submissions: list[dict[str, Any]] = []
        if proofs_path and os.path.exists(proofs_path):
            with open(proofs_path, encoding="utf-8") as fh:
                proof_submissions = json.load(fh)

        # Usage summary from final state.
        usage = {
            "total_tokens": int(final.get("total_tokens") or 0),
            "total_input_tokens": int(final.get("total_input_tokens") or 0),
            "total_cached_input_tokens": int(final.get("total_cached_input_tokens") or 0),
            "total_output_tokens": int(final.get("total_output_tokens") or 0),
            "total_thinking_tokens": int(final.get("total_thinking_tokens") or 0),
            "total_llm_requests": int(final.get("total_llm_requests") or 0),
            "total_usd": float(final.get("total_usd") or 0.0),
        }
        # Also capture from budget_state if available.
        budget_state = dict(final.get("budget_state") or {})
        if budget_state:
            usage.update({
                "budget_tool_calls": budget_state.get("tool_calls", 0),
                "budget_commands": budget_state.get("executed_commands", 0),
                "budget_llm_calls": budget_state.get("llm_calls", 0),
            })

        artifact = RunArtifact(
            case_id=task.case_id,
            repetition=repetition,
            track=task.track,
            model_profile=model_profile,
            budget_tier=budget_tier,
            run_id=thread_id,
            run_dir=actual_run_dir,
            internal_outcome=str(result.get("outcome") or ""),
            budget_termination_reason=str(result.get("budget_termination_reason") or ""),
            transcript=transcript,
            proof_submissions=proof_submissions,
            usage=usage,
            env_manifest=env,
        )

        artifact.save(os.path.join(actual_run_dir, "run_artifact.json"))
        return artifact
