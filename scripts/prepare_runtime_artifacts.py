#!/usr/bin/env python3
"""Materialize a new runtime artifact root from already verified inputs.

This command never contacts Vertex and never signs an approval.  Model Garden
metadata must have been collected by an operator using service-account
impersonation, and the cloud admin must sign the generated approval separately.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from src.pipeline.dataset_lock import load_dataset_lock, lock_hash, validate_dataset_lock
from src.pipeline.framework_adapter import ModelProfile
from src.pipeline.model_resolution import validate_resolution_lock
from src.pipeline.protocol import (
    git_state,
    hash_lock_file,
    validate_baseline_lock,
    write_json_atomically,
)
from src.pipeline.runtime_contract import LOCKED_MODEL_LABELS, sha256_file
from src.pipeline.runtime_readiness import build_canary_smoke_plan
from src.pipeline.vertex_runtime import ModelResolver, PricingSnapshot

ROOT = Path(__file__).resolve().parents[1]
FRAMEWORKS = ("VeriPlanPT", "PentestGPT", "VulnBot", "HackSynth", "PentestAgent")


def _copy(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise ValueError(f"required runtime input is missing: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise ValueError(f"refusing to overwrite runtime artifact: {destination}")
    shutil.copyfile(source, destination)


def _git_commit(path: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True, check=False,
    )
    if result.returncode or not result.stdout.strip():
        raise ValueError(f"cannot read Git commit for {path}")
    return result.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--freeze-manifest", required=True, help="verified FREEZE-MANIFEST.json")
    parser.add_argument("--metadata-dir", required=True, help="three metadata snapshots collected with impersonation")
    parser.add_argument("--pricing-snapshot", required=True, help="official Google pricing snapshot")
    parser.add_argument("--baseline-lock", required=True)
    parser.add_argument("--native-identity", required=True)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--impersonate-service-account", required=True)
    parser.add_argument("--evaluator-commit", required=True)
    parser.add_argument("--evaluator-bundle-hash", required=True)
    parser.add_argument("--oracle-bundle-hash", required=True)
    parser.add_argument("--evaluator-image-digest", required=True)
    parser.add_argument("--feature-schema-hash", required=True)
    parser.add_argument("--max-input-tokens", type=int, default=4096)
    parser.add_argument("--max-output-tokens", type=int, default=1024)
    parser.add_argument("--reservation-ceiling-usd", type=float, required=True)
    args = parser.parse_args(argv)

    import re
    if not re.fullmatch(r"[0-9a-f]{40}", args.evaluator_commit):
        raise SystemExit("evaluator commit must be a full Git SHA")
    if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in (args.evaluator_bundle_hash, args.oracle_bundle_hash)):
        raise SystemExit("evaluator and oracle bundle hashes must be SHA-256")
    dataset_root = Path(args.dataset_root).resolve()
    artifact_root = Path(args.artifact_root).resolve()
    if artifact_root.exists() and any(artifact_root.iterdir()):
        raise SystemExit(f"runtime artifact root must be new and empty: {artifact_root}")
    artifact_root.mkdir(parents=True, exist_ok=True)
    lock = load_dataset_lock(dataset_root / "dataset.lock.json")
    validate_dataset_lock(lock, dataset_root=dataset_root, strict=True)
    dataset_hash = lock_hash(lock)
    freeze_manifest = Path(args.freeze_manifest).resolve()
    if freeze_manifest.name != "FREEZE-MANIFEST.json":
        raise SystemExit("--freeze-manifest must point to FREEZE-MANIFEST.json")
    _copy(freeze_manifest, artifact_root / "FREEZE-MANIFEST.json")

    baseline_source = Path(args.baseline_lock).resolve()
    baseline = json.loads(baseline_source.read_text(encoding="utf-8"))
    if not isinstance(baseline, dict):
        raise SystemExit("baseline lock must be a JSON object")
    validate_baseline_lock(baseline, strict=True)
    _copy(baseline_source, artifact_root / "baseline.lock.json")
    baseline_hash = hash_lock_file(artifact_root / "baseline.lock.json")

    native_source = Path(args.native_identity).resolve()
    native_identity = json.loads(native_source.read_text(encoding="utf-8"))
    if not isinstance(native_identity, dict) or not str(native_identity.get("image", {}).get("image_digest", "")).startswith("sha256:"):
        raise SystemExit("native identity must contain an observed immutable image digest")
    _copy(native_source, artifact_root / "native-veriplanpt-identity.json")
    native_hash = sha256_file(artifact_root / "native-veriplanpt-identity.json")
    image_digests = {str(item["name"]): str(item["image_digest"]) for item in baseline["baselines"]}
    image_digests["VeriPlanPT"] = str(native_identity["image"]["image_digest"])

    metadata_root = Path(args.metadata_dir).resolve()
    metadata: dict[str, dict[str, Any]] = {}
    model_dir = artifact_root / "models"
    for label in LOCKED_MODEL_LABELS:
        source = metadata_root / f"{label}.json"
        try:
            value = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"metadata snapshot missing or invalid for {label}: {source}") from exc
        if not isinstance(value, dict):
            raise SystemExit(f"metadata snapshot must be an object for {label}")
        metadata[label] = value
        _copy(source, model_dir / source.name)
    for name in ("gemma-maas-endpoint.json", "gemma-maas-endpoint.source"):
        _copy(metadata_root / name, model_dir / name)

    resolved = ModelResolver().resolve_all(metadata)
    pricing_source = Path(args.pricing_snapshot).resolve()
    pricing = PricingSnapshot.from_dict(json.loads(pricing_source.read_text(encoding="utf-8")))
    if set(pricing.model_prices) != set(LOCKED_MODEL_LABELS):
        raise SystemExit("pricing snapshot must cover exactly the three locked model labels")
    _copy(pricing_source, artifact_root / "pricing-snapshot.json")
    pricing_ref = {"artifact_path": "pricing-snapshot.json", "sha256": sha256_file(artifact_root / "pricing-snapshot.json")}

    profiles: list[ModelProfile] = []
    resolution_entries: list[dict[str, Any]] = []
    for item in resolved:
        profile = item.to_model_profile(pricing.pricing_for(item.logical_label), pricing_effective_at=pricing.effective_at)
        profiles.append(profile)
        metadata_path = model_dir / f"{item.logical_label}.json"
        resolution_entries.append({
            **item.to_dict(),
            "metadata_path": f"models/{item.logical_label}.json",
            "metadata_sha256": sha256_file(metadata_path),
        })
        if item.logical_label == "gemma-4-26b-a4b-it":
            resolution_entries[-1].update({
                "endpoint_snapshot_path": "models/gemma-maas-endpoint.json",
                "endpoint_snapshot_sha256": sha256_file(model_dir / "gemma-maas-endpoint.json"),
                "endpoint_source_path": "models/gemma-maas-endpoint.source",
                "endpoint_source_sha256": sha256_file(model_dir / "gemma-maas-endpoint.source"),
            })
    resolution = {
        "schema_version": "2.0.0",
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "dataset_lock_hash": dataset_hash,
        "models": resolution_entries,
    }
    write_json_atomically(artifact_root / "model-resolution.lock.json", resolution, refuse_existing=True)
    resolution_hash = sha256_file(artifact_root / "model-resolution.lock.json")
    validate_resolution_lock(resolution, profiles=profiles, artifact_root=artifact_root, strict=True)

    alias_exception = {
        "schema_version": "1.0.0", "project": args.project, "dataset_lock_hash": dataset_hash,
        "model_labels": list(LOCKED_MODEL_LABELS),
        "expires_at": (datetime.now(UTC) + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        "reason": "Gemini @default is the approved provider alias while Model Garden revisions are not immutable.",
    }
    write_json_atomically(artifact_root / "alias-exception.json", alias_exception, refuse_existing=True)
    alias_ref = {
        "artifact_path": "alias-exception.json", "sha256": sha256_file(artifact_root / "alias-exception.json"),
        "signature_path": "signatures/alias-exception.json.minisig",
    }

    plan = build_canary_smoke_plan(
        profiles=profiles,
        dataset_lock_hash=dataset_hash, baseline_identity_hash=baseline_hash,
        model_resolution_lock_hash=resolution_hash, evaluator_hash=args.evaluator_bundle_hash,
        oracle_hash=args.oracle_bundle_hash, image_digests=image_digests, native_identity_hash=native_hash,
        max_input_tokens=args.max_input_tokens, max_output_tokens=args.max_output_tokens,
        retry_policy={"max_attempts": 2, "retryable": ["408", "429", "500", "502", "503", "504"]}, strict=True,
    )
    reserved_cost = sum(float(cell["cell_worst_case_cost_usd"]) for cell in plan["cells"])
    if abs(reserved_cost - float(args.reservation_ceiling_usd)) > 1e-12:
        raise SystemExit("reservation ceiling must equal the pricing-derived 18-cell reservation")
    write_json_atomically(artifact_root / "canary-smoke-plan.json", plan, refuse_existing=True)
    plan_hash = str(plan["plan_hash"])
    approval = {
        "schema_version": "2.0.0", "scope": "canary_smoke", "plan_hash": plan_hash,
        "cell_count": 18, "issued_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
        "cost_ceiling_usd": float(args.reservation_ceiling_usd), "approver_key_id": "pending-cloud-admin",
    }
    write_json_atomically(artifact_root / "approval-canary-smoke.json", approval, refuse_existing=True)

    framework_state = git_state(ROOT)
    dataset_commit = _git_commit(dataset_root)
    protocol = {
        "schema_version": "3.0.0", "dataset_repository_commit": dataset_commit,
        "dataset_lock_hash": dataset_hash, "framework_commit": framework_state["commit"],
        "evaluator_commit": args.evaluator_commit, "evaluator_bundle_hash": args.evaluator_bundle_hash,
        "oracle_bundle_hash": args.oracle_bundle_hash, "evaluator_image_digest": args.evaluator_image_digest,
        "feature_schema_hash": args.feature_schema_hash, "model_profiles": [profile.to_dict() for profile in profiles],
        "budget_tiers": ["low", "medium", "high"],
        "cv": {"seed": 20260801, "folds": 5, "cases_per_fold": 8, "track": "blind", "budget_tier": "medium"},
        "baseline_lock_hash": baseline_hash, "selection_rules": {"winner": "protocol_locked"},
        "expected_training_cells": {"sweep": 4200, "confirmation": 360, "total": 4560},
        "snapshot_mode": "frozen", "cost_estimate_usd": float(args.reservation_ceiling_usd),
        "pricing_snapshot": pricing_ref,
        "dataset_freeze_manifest": {"artifact_path": "FREEZE-MANIFEST.json", "sha256": sha256_file(artifact_root / "FREEZE-MANIFEST.json")},
        "model_resolution_lock": {"artifact_path": "model-resolution.lock.json", "sha256": resolution_hash},
        "native_identity": {"artifact_path": "native-veriplanpt-identity.json", "sha256": native_hash},
        "alias_exception": alias_ref,
        "canary_smoke_plan": {"artifact_path": "canary-smoke-plan.json", "sha256": sha256_file(artifact_root / "canary-smoke-plan.json")},
        "approval_canary_smoke": {
            "artifact_path": "approval-canary-smoke.json", "sha256": sha256_file(artifact_root / "approval-canary-smoke.json"),
            "signature_path": "signatures/approval-canary-smoke.json.minisig",
        },
        "vertex_project": args.project, "impersonate_service_account": args.impersonate_service_account,
        "runtime_budgets": {
            "max_input_tokens": args.max_input_tokens, "max_output_tokens": args.max_output_tokens,
            "max_attempts": 2, "reservation_ceiling_usd": args.reservation_ceiling_usd,
            "max_workers": 2, "billing": "known_only",
        },
    }
    write_json_atomically(artifact_root / "training_protocol.json", protocol, refuse_existing=True)
    print(json.dumps({
        "artifact_root": str(artifact_root), "dataset_lock_hash": dataset_hash,
        "model_resolution_lock_sha256": resolution_hash, "canary_plan_hash": plan_hash,
        "approval": "unsigned-pending-cloud-admin", "vertex_calls": 0,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
