#!/usr/bin/env python3
"""Strict container boundary for the 3+15 runtime readiness probe.

Paid study stages intentionally fail closed until a framework-specific
automation adapter is installed.  A readiness probe verifies the locked image,
public invocation, model profile, relay path, and evidence writer without
pretending that a provider smoke is a benchmark run.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping


class RuntimeBoundaryError(ValueError):
    pass


def _canonical(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeBoundaryError(f"{name} is required")
    return value


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RuntimeBoundaryError(f"{name} must be an object")
    return dict(value)


def _load_public_invocation() -> dict[str, Any]:
    try:
        value = json.load(sys.stdin)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeBoundaryError("stdin is not a public invocation JSON object") from exc
    invocation = _object(value, "public invocation")
    run_id = _required_env("VERIPLANPT_RUN_ID")
    if invocation.get("run_id") != run_id:
        raise RuntimeBoundaryError("public invocation run ID differs from the approved environment")
    if invocation.get("model_label") != _required_env("VERIPLANPT_MODEL_LABEL"):
        raise RuntimeBoundaryError("public invocation model label differs from the approved environment")
    profile = _object(invocation.get("model_profile"), "model profile")
    if profile.get("profile_hash") != _required_env("VERIPLANPT_PROFILE_HASH"):
        raise RuntimeBoundaryError("public invocation model profile hash differs from the approved environment")
    if invocation.get("framework") != _required_env("VERIPLANPT_FRAMEWORK_NAME"):
        raise RuntimeBoundaryError("public invocation framework differs from the approved environment")
    if str(invocation.get("track", "")) not in {"blind", "guided"}:
        raise RuntimeBoundaryError("public invocation track is invalid")
    _object(invocation.get("task"), "public task")
    return invocation


def _provider_probe(invocation: Mapping[str, Any]) -> Mapping[str, Any]:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from provider_shim import request  # type: ignore[import-not-found]

    task = _object(invocation["task"], "public task")
    prompt = {
        "purpose": "runtime-readiness",
        "case_id": invocation["case_id"],
        "objective": task.get("objective", "Verify the controlled model path."),
        "target": task.get("target", {}),
    }
    return request({"contents": json.dumps(prompt, sort_keys=True)})


def _artifact(invocation: Mapping[str, Any], response: Mapping[str, Any]) -> dict[str, Any]:
    usage_value = response.get("usage")
    usage = _object(usage_value, "gateway usage")
    required_usage = ("input_tokens", "output_tokens", "total_tokens", "usd")
    if any(key not in usage for key in required_usage):
        raise RuntimeBoundaryError("gateway response has incomplete normalized usage")
    event_ledger = [{
        "role": "runtime_boundary",
        "event": {
            "event_type": "controlled_provider_probe",
            "request_sha256": _canonical(invocation["task"]),
            "response_sha256": str(response.get("response_hash") or _canonical(response)),
        },
    }]
    proof = [{"status": "ready", "kind": "controlled_provider_path"}]
    provenance = _object(invocation.get("provenance"), "provenance")
    framework = str(invocation["framework"])
    return {
        "schema_version": "2.1.0",
        "run_id": invocation["run_id"],
        "run_identity": {
            "run_id": invocation["run_id"],
            "case_id": invocation["case_id"],
            "track": invocation["track"],
            "condition": invocation["condition"],
            "repetition": int(invocation.get("repetition", 1)),
        },
        "case_id": invocation["case_id"],
        "track": invocation["track"],
        "condition": invocation["condition"],
        "repetition": int(invocation.get("repetition", 1)),
        "budget_tier": str(invocation.get("budget_tier", "medium")),
        "model_profile": dict(invocation["model_profile"]),
        "framework_identity": {
            "name": framework,
            "repository_url": str(provenance.get("framework_repository_url", "")),
            "commit": str(provenance.get("framework_commit", "")),
            "image_digest": str(provenance.get("framework_image_digest", "")),
            "adapter_version": "runtime-boundary-2.2",
        },
        "run_context": {
            "dataset_lock_hash": str(provenance.get("dataset_lock_hash", "")),
            "training_protocol_hash": str(provenance.get("protocol_hash", "")),
            "policy_lock_hash": str(provenance.get("policy_lock_hash", "")),
            "matrix_hash": str(provenance.get("matrix_hash", "")),
            "gateway_relay_lock_hash": _required_env("VERIPLANPT_GATEWAY_RELAY_LOCK_HASH"),
            "framework_commit": str(provenance.get("framework_commit", "")),
            "evaluator_commit": str(provenance.get("evaluator_commit", "")),
            "stage": "canary_smoke",
            "control_condition": "runtime",
        },
        "transcript": event_ledger,
        "proof_submissions": proof,
        "usage": {
            "input_tokens": int(usage["input_tokens"]),
            "output_tokens": int(usage["output_tokens"]),
            "total_tokens": int(usage["total_tokens"]),
            "total_usd": float(usage["usd"]),
        },
        "event_ledger_hash": _canonical(event_ledger),
        "proof_hash": _canonical(proof),
        "termination_status": "completed",
        "internal_outcome": "runtime_ready",
        "budget_termination_reason": "",
    }


def main() -> int:
    if _required_env("VERIPLANPT_STAGE") != "canary_smoke":
        raise RuntimeBoundaryError(
            "paid stage requires a locked framework-specific automation adapter"
        )
    invocation = _load_public_invocation()
    artifact = _artifact(invocation, _provider_probe(invocation))
    output = Path(_required_env("VERIPLANPT_OUTPUT_DIR"))
    if not output.is_dir() or output.is_symlink():
        raise RuntimeBoundaryError("runtime output directory is not a real mounted directory")
    destination = output / "run_artifact.json"
    if destination.exists():
        raise RuntimeBoundaryError("refusing to overwrite an existing RunArtifact")
    destination.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeBoundaryError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(78) from exc
