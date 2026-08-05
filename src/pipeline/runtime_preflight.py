"""Verify live-runtime authority without reading smoke evidence or invoking Vertex."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Sequence

from src.pipeline.approval import verify_approval
from src.pipeline.dataset_lock import load_dataset_lock, lock_hash, validate_dataset_lock
from src.pipeline.framework_adapter import ModelProfile
from src.pipeline.model_resolution import validate_resolution_lock
from src.pipeline.protocol import (
    git_state,
    hash_lock_file,
    load_json,
    validate_baseline_lock,
    validate_training_protocol,
)
from src.pipeline.runtime_contract import (
    validate_lock_reference,
    verify_alias_exception,
    verify_impersonated_adc,
)
from src.pipeline.runtime_readiness import _canonical_hash, validate_canary_smoke_plan


def runtime_preflight(*, dataset_root: str | Path, artifact_root: str | Path,
                      approver_public_key: str, project: str | None = None) -> dict[str, Any]:
    root, artifacts = Path(dataset_root).resolve(), Path(artifact_root).resolve()
    lock = load_dataset_lock(root / "dataset.lock.json")
    validate_dataset_lock(lock, dataset_root=root, strict=True)
    protocol = load_json(artifacts / "training_protocol.json")
    state = git_state(Path(__file__).resolve().parents[2])
    if state["dirty"]:
        raise ValueError("runtime preflight requires a clean framework worktree")
    validate_training_protocol(
        protocol, dataset_hash=lock_hash(lock), framework_commit=str(state["commit"]),
        evaluator_commit=str(protocol["evaluator_commit"]), artifact_root=artifacts, strict_runtime=True,
    )
    baseline_path = artifacts / "baseline.lock.json"
    validate_baseline_lock(load_json(baseline_path), strict=True)
    if hash_lock_file(baseline_path) != str(protocol["baseline_lock_hash"]):
        raise ValueError("baseline lock does not match training protocol")
    profiles = [ModelProfile.from_dict(item) for item in protocol["model_profiles"]]
    resolution_ref = protocol["model_resolution_lock"]
    resolution_path = artifacts / Path(str(resolution_ref["artifact_path"]))
    validate_resolution_lock(load_json(resolution_path), profiles=profiles, artifact_root=artifacts, strict=True)
    alias_ref = protocol["alias_exception"]
    validate_lock_reference(alias_ref, name="alias_exception", artifact_root=artifacts)
    verify_alias_exception(
        load_json(artifacts / Path(str(alias_ref["artifact_path"]))),
        signature_path=artifacts / str(alias_ref["signature_path"]), public_key=approver_public_key,
        project=project or str(protocol["vertex_project"]), dataset_lock_hash=lock_hash(lock),
    )
    plan_ref, approval_ref = protocol["canary_smoke_plan"], protocol["approval_canary_smoke"]
    validate_lock_reference(plan_ref, name="canary_smoke_plan", artifact_root=artifacts)
    validate_lock_reference(approval_ref, name="approval_canary_smoke", artifact_root=artifacts)
    plan = load_json(artifacts / Path(str(plan_ref["artifact_path"])))
    validate_canary_smoke_plan(plan, profiles=profiles, strict=True)
    reservation = sum(float(cell["cell_worst_case_cost_usd"]) for cell in plan["cells"])
    verified = verify_approval(
        load_json(artifacts / Path(str(approval_ref["artifact_path"]))), scope="canary_smoke",
        plan_hash=_canonical_hash(plan), cell_count=18, cost_ceiling_usd=reservation,
        signature_path=artifacts / str(approval_ref["signature_path"]), public_key=approver_public_key,
    )
    for cell in plan["cells"]:
        image = str(cell["image_digest"])
        inspected = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", image], capture_output=True, text=True, check=False)
        if inspected.returncode or inspected.stdout.strip() != image:
            raise ValueError(f"runtime image digest unavailable: {image}")
    adc = verify_impersonated_adc(str(protocol["impersonate_service_account"]), project=project or str(protocol["vertex_project"]))
    return {"ready": True, "plan_hash": _canonical_hash(plan), "reservation_ceiling_usd": reservation,
            "approval_expires_at": verified["expires_at"], "adc": adc, "vertex_calls": 0}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--approver-public-key", required=True)
    parser.add_argument("--project")
    args = parser.parse_args(argv)
    try:
        report = runtime_preflight(**vars(args))
    except Exception as exc:
        print(json.dumps({"ready": False, "vertex_calls": 0, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
