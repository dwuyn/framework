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
from typing import Any, ClassVar, Mapping, cast
from urllib.parse import urlparse

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
    """Pinned, reproducible Vertex profile; credentials stay in the environment."""
    model_name: str
    location: str
    resource_id: str
    resource_revision: str
    pricing: dict[str, float]
    provider: str = "vertexai"
    # Compatibility-only runtime input. It is intentionally not serialized;
    # benchmark project selection comes from Vertex environment credentials.
    project: str = field(default="", repr=False)
    generation_parameters: dict[str, Any] = field(default_factory=dict)
    usage_semantics: dict[str, str] = field(default_factory=dict)
    pricing_currency: str = "USD"
    pricing_effective_at: str = ""
    pricing_billing_basis: str = "per_million_tokens"

    ALLOWED_MODELS: ClassVar[frozenset[str]] = frozenset({
        "gemini-3.5-flash",
        "gemini-3.6-flash",
        "gemma-4-26b-a4b-it",
    })
    REQUIRED_PRICING_KEYS: ClassVar[frozenset[str]] = frozenset({
        "input_per_million", "cached_input_per_million", "output_per_million", "thinking_per_million",
    })

    def __post_init__(self) -> None:
        if self.model_name not in self.ALLOWED_MODELS:
            raise ValueError(
                f"ModelProfile.model_name {self.model_name!r} is not in the preregistered set "
                f"{sorted(self.ALLOWED_MODELS)}"
            )
        if self.provider != "vertexai":
            raise ValueError("VeriPlanPT benchmark profiles must use provider='vertexai'")
        missing_fields = [name for name in ("location", "resource_id", "resource_revision")
                          if not str(getattr(self, name, "")).strip()]
        if missing_fields:
            raise ValueError(f"ModelProfile missing required field(s): {', '.join(missing_fields)}")
        if self.resource_id == self.model_name:
            raise ValueError("ModelProfile.resource_id must be the real Vertex resource ID, not the logical label")
        if self.resource_revision.lower() in {"benchmark-pinned", "latest", "default", "unknown"}:
            raise ValueError("ModelProfile.resource_revision must be an immutable Vertex revision/endpoint ID")
        missing_prices = self.REQUIRED_PRICING_KEYS.difference(self.pricing)
        if missing_prices:
            raise ValueError(f"ModelProfile.pricing missing key(s): {', '.join(sorted(missing_prices))}")
        zero_prices = [
            key for key in self.REQUIRED_PRICING_KEYS
            if float(self.pricing.get(key, 0.0)) <= 0.0
        ]
        if zero_prices:
            raise ValueError(f"ModelProfile.pricing must be positive for: {', '.join(sorted(zero_prices))}")
        if self.pricing_currency != "USD":
            raise ValueError("ModelProfile pricing_currency must be USD")
        if not self.pricing_effective_at:
            raise ValueError("ModelProfile requires pricing_effective_at")
        if self.pricing_billing_basis != "per_million_tokens":
            raise ValueError("ModelProfile pricing_billing_basis must be per_million_tokens")
        required_usage = {"input_includes_cached", "total_formula"}
        missing_usage = required_usage.difference(self.usage_semantics)
        if missing_usage:
            raise ValueError(f"ModelProfile usage_semantics missing key(s): {', '.join(sorted(missing_usage))}")
        if self.usage_semantics["input_includes_cached"] != "true":
            raise ValueError("ModelProfile usage must declare input_includes_cached=true")
        if self.usage_semantics["total_formula"] != "input+output+thinking":
            raise ValueError("ModelProfile usage total_formula must be input+output+thinking")

    @property
    def logical_label(self) -> str:
        return self.model_name

    @property
    def profile_hash(self) -> str:
        return self.profile_hash_without_self()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ModelProfile":
        label = data.get("logical_label") or data.get("model_name")
        if not label:
            raise ValueError("ModelProfile requires logical_label or model_name")
        return cls(
            model_name=str(label),
            provider=str(data.get("provider", "vertexai")),
            location=str(data.get("location", "")),
            resource_id=str(data.get("resource_id", "")),
            resource_revision=str(data.get("resource_revision") or data.get("endpoint_id") or ""),
            pricing={str(k): float(v) for k, v in dict(data.get("pricing") or {}).items()},
            generation_parameters=dict(data.get("generation_parameters") or {}),
            usage_semantics={str(k): str(v) for k, v in dict(data.get("usage_semantics") or {}).items()},
            pricing_currency=str(data.get("pricing_currency") or "USD"),
            pricing_effective_at=str(data.get("pricing_effective_at") or ""),
            pricing_billing_basis=str(data.get("pricing_billing_basis") or "per_million_tokens"),
        )

    @classmethod
    def from_json_file(cls, path: str) -> "ModelProfile":
        with open(path, encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))

    def to_dict(self) -> dict[str, Any]:
        return {
            "logical_label": self.model_name,
            "model_name": self.model_name,
            "provider": self.provider,
            "resource_id": self.resource_id,
            "resource_revision": self.resource_revision,
            "location": self.location,
            "pricing": dict(self.pricing),
            "generation_parameters": dict(self.generation_parameters),
            "usage_semantics": dict(self.usage_semantics),
            "pricing_currency": self.pricing_currency,
            "pricing_effective_at": self.pricing_effective_at,
            "pricing_billing_basis": self.pricing_billing_basis,
            "profile_hash": self.profile_hash_without_self(),
        }

    def profile_hash_without_self(self) -> str:
        data = {
            "logical_label": self.model_name,
            "provider": self.provider,
            "resource_id": self.resource_id,
            "resource_revision": self.resource_revision,
            "location": self.location,
            "pricing": self.pricing,
            "generation_parameters": self.generation_parameters,
            "usage_semantics": self.usage_semantics,
            "pricing_currency": self.pricing_currency,
            "pricing_effective_at": self.pricing_effective_at,
            "pricing_billing_basis": self.pricing_billing_basis,
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass
class PublicTask:
    """What the framework receives from the benchmark harness.

    PublicTask v2 exposes opaque case identity, track, objective, target,
    scope, and optional guided hints.  Hidden truth, CVE/version metadata,
    alias metadata, and decoy metadata are not part of this contract.

    The harness constructs this from the public half of the lab manifest.
    """
    case_id: str
    track: str               # "blind" | "guided"
    objective: str           # general attack objective, no CVE/version hints
    host: str = ""
    port_range: str = "1-65535"          # e.g. "1-65535" or "80,443,8080"
    target: dict[str, Any] = field(default_factory=dict)
    scope: dict[str, Any] = field(default_factory=dict)
    hints: dict[str, str] = field(default_factory=dict)

    FORBIDDEN_PUBLIC_KEYS: ClassVar[frozenset[str]] = frozenset({
        "canonical_case_id",
        "cve",
        "cve_id",
        "hidden_version",
        "version",
        "alias",
        "aliases",
        "alias_metadata",
        "decoy",
        "decoys",
        "decoy_services",
        "decoy_metadata",
    })
    TOP_LEVEL_HINT_KEYS: ClassVar[frozenset[str]] = frozenset({
        "component", "endpoint", "method", "method_hint",
    })
    ALLOWED_HINT_KEYS: ClassVar[frozenset[str]] = frozenset({
        "component", "endpoint", "method",
    })

    def __post_init__(self) -> None:
        if not self.target and self.host:
            self.target = {"host": self.host}
            if self.port_range:
                ports = [
                    int(part) for part in self.port_range.replace(",", " ").split()
                    if part.isdigit()
                ]
                if ports:
                    self.target["exposed_ports"] = ports
        self.validate_public_surface()

    def to_dict(self) -> dict[str, Any]:
        target = dict(self.target)
        if self.host and "host" not in target:
            target["host"] = self.host
        if self.port_range and "exposed_ports" not in target and "port" not in target:
            target["exposed_ports"] = [
                int(part) for part in self.port_range.replace(",", " ").split()
                if part.isdigit()
            ]
        out: dict[str, Any] = {
            "case_id": self.case_id,
            "track": self.track,
            "objective": self.objective,
            "target": target,
            "scope": dict(self.scope),
        }
        if self.track == "guided" and self.hints:
            out["hints"] = dict(self.hints)
        return out

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PublicTask":
        forbidden = cls.FORBIDDEN_PUBLIC_KEYS.intersection(d)
        if forbidden:
            raise ValueError(f"public task contains forbidden hidden metadata: {', '.join(sorted(forbidden))}")
        top_level_hints = cls.TOP_LEVEL_HINT_KEYS.intersection(d)
        if top_level_hints:
            raise ValueError("guided hints must be nested under the 'hints' object")
        target = cast(dict[str, Any], d.get("target") if isinstance(d.get("target"), dict) else {})
        for key in cls.FORBIDDEN_PUBLIC_KEYS.intersection(target):
            raise ValueError(f"public task target contains forbidden hidden metadata: {key}")
        url = str(target.get("url") or "")
        parsed = urlparse(url)
        host = str(d.get("host") or target.get("host") or parsed.hostname or "")
        ports = d.get("port_range") or target.get("exposed_ports") or target.get("port") or parsed.port
        if isinstance(ports, list):
            port_range = ",".join(str(port) for port in ports)
        else:
            port_range = str(ports or "1-65535")
        scope = d.get("scope") if isinstance(d.get("scope"), dict) else {}
        if scope.get("allowed_hosts") and host not in {str(v) for v in scope["allowed_hosts"]}:
            raise ValueError("public task host is outside its declared scope")
        hints = cast(dict[str, Any], d.get("hints") if isinstance(d.get("hints"), dict) else {})
        unknown_hints = set(hints).difference(cls.ALLOWED_HINT_KEYS)
        if unknown_hints:
            raise ValueError(f"unsupported guided hint key(s): {', '.join(sorted(unknown_hints))}")
        task = cls(
            case_id=str(d.get("case_id", "")),
            track=str(d.get("track", "blind")),
            objective=str(d.get("objective", "")),
            host=host,
            port_range=port_range,
            target=dict(target),
            scope=dict(scope),
            hints={str(k): str(v) for k, v in hints.items()},
        )
        task.validate_public_surface()
        return task

    def validate_public_surface(self) -> None:
        """Reject accidental disclosure in a blind task before a run starts."""
        if self.track not in {"blind", "guided"}:
            raise ValueError("public task track must be 'blind' or 'guided'")
        if not self.case_id or not self.objective or not self.host:
            raise ValueError("public task requires case_id, objective and target host")
        if self.track == "blind" and self.hints:
            raise ValueError("blind public task must not include guided hints")
        if self.track == "guided" and set(self.hints).difference(self.ALLOWED_HINT_KEYS):
            raise ValueError("guided task contains unsupported hint keys")
        import re
        visible = json.dumps(self.to_dict(), sort_keys=True, default=str)
        if re.search(r"\bCVE-\d{4}-\d+\b", visible, flags=re.IGNORECASE):
            raise ValueError("public task leaks a CVE identifier")
        if re.search(r"\b(?:version|v)\s*\d+\.\d+(?:\.\d+)?\b", visible, flags=re.IGNORECASE):
            raise ValueError("public task leaks a version")


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
    schema_version: str = "2.0.0"
    run_id: str = ""
    run_dir: str = ""
    condition: str = ""
    termination_status: str = ""
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
        termination_status = self.termination_status or self.internal_outcome or "unknown"
        budget_limits = self.budget_tier.to_limits().to_dict()
        return {
            "schema_version": self.schema_version,
            "run_identity": {
                "run_id": self.run_id,
                "case_id": self.case_id,
                "track": self.track,
                "condition": self.condition,
                "repetition": self.repetition,
            },
            "case_id": self.case_id,
            "repetition": self.repetition,
            "track": self.track,
            "condition": self.condition,
            "model_profile": self.model_profile.to_dict(),
            "model_revision": self.model_profile.resource_revision,
            "budget_tier": self.budget_tier.value,
            "budget": {
                "tier": self.budget_tier.value,
                "limits": budget_limits,
                "usage": dict(self.usage),
            },
            "run_id": self.run_id,
            "run_dir": self.run_dir,
            "termination_status": termination_status,
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
        self.snapshot_dir = snapshot_dir or os.environ.get("VERIPLANPT_DATASET_ROOT", "")

    def run(
        self,
        task: PublicTask,
        model_profile: ModelProfile,
        budget_tier: BudgetTier,
        repetition: int = 1,
        run_dir: str = "",
        condition: str = "",
    ) -> RunArtifact:
        """Execute one benchmark run and return the normalised RunArtifact.

        The framework graph is invoked; the external evaluator never accesses
        the internal oracle truth during this call.
        """
        from src.graph import build_graph
        from src.pipeline.manifest import RunManifest, Scope
        from src.state import initial_state

        env = _capture_env(self.snapshot_dir)
        selected_run_dir = run_dir or os.path.join(
            self.results_root, task.case_id,
            f"{model_profile.model_name}_{budget_tier.value}_rep{repetition:02d}",
        )
        os.makedirs(selected_run_dir, exist_ok=True)

        limits = budget_tier.to_limits()
        identity_blob = json.dumps({
            "framework_commit": env.framework_commit,
            "case_id": task.case_id,
            "model_revision": model_profile.resource_revision,
            "budget_tier": budget_tier.value,
            "track": task.track,
            "condition": condition,
            "repetition": repetition,
        }, sort_keys=True)
        thread_id = "vp-" + hashlib.sha256(identity_blob.encode("utf-8")).hexdigest()[:24]
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
        scope = Scope(
            allowed_hostnames=[str(v) for v in task.scope.get("allowed_hosts", [])],
            allowed_ports=[
                int(v) for v in task.scope.get("allowed_ports", [])
                if str(v).isdigit()
            ],
        )
        manifest = RunManifest(
            schema_version="2.0.0",
            run_id=thread_id,
            created_at=time.time(),
            target_id=task.case_id,
            lab_id=task.case_id,
            repetition=repetition,
            condition=condition,
            variant=task.track,
            scope=scope.to_dict(),
            limits=limits.to_dict(),
            repo={
                "commit": env.framework_commit,
                "dirty": env.framework_dirty,
            },
            model_provider=model_profile.provider,
            model_id=model_profile.resource_id,
            run_dir=selected_run_dir,
        )
        state.update({
            "public_task": task.to_dict(),
            "model_profile": model_profile.model_name,
            "budget_tier": budget_tier.value,
            "retrieval_mode": "snapshot",
            "source_snapshot_dir": self.snapshot_dir,
            "pipeline_manifest": manifest.to_dict(),
            "pipeline_result": {"run_dir": selected_run_dir},
        })
        state["model_profile_contract"] = model_profile.to_dict()  # type: ignore[typeddict-unknown-key]
        if task.hints.get("component"):
            state["app_name"] = task.hints["component"]

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
            condition=condition,
            termination_status=str(result.get("termination_status") or result.get("outcome") or ""),
            internal_outcome=str(result.get("outcome") or ""),
            budget_termination_reason=str(result.get("budget_termination_reason") or ""),
            transcript=transcript,
            proof_submissions=proof_submissions,
            usage=usage,
            env_manifest=env,
        )

        artifact.save(os.path.join(actual_run_dir, "run_artifact.json"))
        return artifact
