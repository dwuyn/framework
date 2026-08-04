"""Generate an auditable, fail-closed pretraining readiness report."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Callable, Sequence

from src.pipeline.dataset_lock import load_dataset_lock, lock_hash, validate_dataset_lock
from src.pipeline.protocol import (
    git_state,
    hash_lock_file,
    load_json,
    validate_baseline_lock,
    validate_training_protocol,
)
from src.pipeline.readiness_evidence import load_smoke_evidence, validate_smoke_evidence
from src.pipeline.train import plan_training


def _check(checks: dict[str, dict[str, Any]], name: str, func: Callable[[], Any]) -> None:
    try:
        detail = func()
        checks[name] = {"passed": True, "detail": detail}
    except Exception as exc:  # Report every gate rather than stopping at the first failure.
        checks[name] = {"passed": False, "detail": str(exc)}


def _command(root: Path, args: list[str]) -> dict[str, str]:
    result = subprocess.run(args, cwd=root, check=False, capture_output=True, text=True, timeout=180)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()[-2_000:]
        raise ValueError(f"{' '.join(args)} failed: {detail}")
    return {"command": " ".join(args)}


def pretrain_check(*, dataset_root: str | Path, baseline_lock: str | Path | None = None,
                   training_protocol: str | Path | None = None, artifact_root: str | Path | None = None,
                   output: str | Path = "pretrain_readiness.json", framework_root: str | Path = ".",
                   evaluator_commit: str | None = None) -> dict[str, Any]:
    root = Path(dataset_root).resolve()
    framework = Path(framework_root).resolve()
    if artifact_root is not None:
        art_path = Path(artifact_root).resolve()
        if baseline_lock is None:
            baseline_lock = art_path / "baseline.lock.json"
        if training_protocol is None:
            training_protocol = art_path / "training_protocol.json"
    if baseline_lock is None:
        baseline_lock = root / "baseline.lock.json"
    if training_protocol is None:
        training_protocol = root / "training_protocol.json"

    checks: dict[str, dict[str, Any]] = {}
    _check(checks, "framework_clean", lambda: git_state(framework) if not git_state(framework)["dirty"]
           else (_ for _ in ()).throw(ValueError("framework repository is dirty")))
    _check(checks, "poetry_lock", lambda: _command(framework, ["poetry", "check", "--lock"]))
    _check(checks, "unit_tests", lambda: _command(framework, ["poetry", "run", "pytest", "-q"]))
    _check(checks, "ruff", lambda: _command(framework, ["poetry", "run", "ruff", "check", "src", "tests"]))
    _check(checks, "mypy", lambda: _command(framework, ["poetry", "run", "mypy", "src/pipeline/pretrain_check.py", "src/pipeline/train.py", "src/pipeline/protocol.py", "src/pipeline/dataset_lock.py", "src/pipeline/readiness_evidence.py", "--ignore-missing-imports", "--follow-imports=skip"]))
    _check(checks, "dependency_security", lambda: _command(framework, ["poetry", "run", "pip", "check"]))
    _check(checks, "dataset_clean", lambda: git_state(root) if not git_state(root)["dirty"]
           else (_ for _ in ()).throw(ValueError("dataset repository is dirty")))
    lock_path = root / "dataset.lock.json"
    dataset_lock: dict[str, Any] = {}

    def dataset_gate() -> dict[str, Any]:
        nonlocal dataset_lock
        dataset_lock = load_dataset_lock(lock_path)
        validate_dataset_lock(dataset_lock, dataset_root=root)
        return {"lock_hash": lock_hash(dataset_lock)}

    _check(checks, "dataset_lock", dataset_gate)

    def baseline_gate() -> dict[str, str]:
        validate_baseline_lock(load_json(baseline_lock))
        return {"lock_hash": hash_lock_file(baseline_lock)}

    _check(checks, "baseline_lock", baseline_gate)

    def protocol_gate() -> dict[str, Any]:
        if not dataset_lock:
            raise ValueError("dataset lock did not validate")
        protocol = load_json(training_protocol)
        state = git_state(framework)
        eval_commit = evaluator_commit or state["commit"]
        validate_training_protocol(
            protocol,
            dataset_hash=lock_hash(dataset_lock),
            framework_commit=state["commit"],
            evaluator_commit=eval_commit,
        )
        b_hash = hash_lock_file(baseline_lock)
        if str(protocol.get("baseline_lock_hash")) != b_hash:
            raise ValueError("training protocol baseline_lock_hash mismatch with baseline lock")
        return {"protocol_hash": hash_lock_file(training_protocol)}

    _check(checks, "training_protocol", protocol_gate)

    def smoke_gate() -> dict[str, Any]:
        if not dataset_lock:
            raise ValueError("dataset lock did not validate")
        protocol = load_json(training_protocol)
        profiles = protocol.get("model_profiles")
        if not isinstance(profiles, list):
            raise ValueError("training protocol model_profiles is invalid")
        return validate_smoke_evidence(
            load_smoke_evidence(root / "readiness" / "smoke-evidence.json"),
            base_case_ids=[
                *dataset_lock["train_cases"],
                *dataset_lock["validation_cases"],
                *dataset_lock["test_cases"],
            ],
            model_labels=[
                str(profile.get("logical_label") or profile.get("model_name") or "")
                for profile in profiles
                if isinstance(profile, dict)
            ],
            robustness_base_case_ids=dataset_lock["test_cases"],
            mode="pretrain",
        )

    _check(checks, "smoke_evidence", smoke_gate)

    def no_test_artifacts() -> dict[str, Any]:
        test_root = root / "cases" / "test"
        if any(test_root.rglob("run_artifact.json")):
            raise ValueError("test split has run artifacts before policy freeze")
        if (root / "policy.lock.json").exists() or (root / "matrix.json").exists() or (root / "matrix.csv").exists():
            raise ValueError("policy lock or final matrix exists before training")
        return {"test_root": str(test_root)}

    _check(checks, "test_sealed", no_test_artifacts)
    _check(checks, "train_dry_run", lambda: {
        "cells": plan_training(dataset_root=root, protocol_path=training_protocol,
                               output_path=Path(output).with_name("training_plan.preview.json"))["cell_count"]
    })
    report = {
        "schema_version": "2.0.0",
        "ready": all(item["passed"] for item in checks.values()),
        "checks": checks,
        "framework_commit": git_state(framework)["commit"],
        "dataset_lock_hash": lock_hash(dataset_lock) if dataset_lock else "",
        "baseline_lock_hash": hash_lock_file(baseline_lock) if Path(baseline_lock).exists() else "",
        "training_protocol_hash": hash_lock_file(training_protocol) if Path(training_protocol).exists() else "",
    }
    Path(output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate every gate before Vertex policy training.")
    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--artifact-root", help="Directory containing downstream artifacts (baseline.lock.json, training_protocol.json)")
    parser.add_argument("--baseline-lock")
    parser.add_argument("--training-protocol")
    parser.add_argument("--evaluator-commit")
    parser.add_argument("--output", default="pretrain_readiness.json")
    args = parser.parse_args(argv)
    report = pretrain_check(
        dataset_root=args.dataset_root,
        baseline_lock=args.baseline_lock,
        training_protocol=args.training_protocol,
        artifact_root=args.artifact_root,
        evaluator_commit=args.evaluator_commit,
        output=args.output,
    )
    print(json.dumps({"ready": report["ready"], "output": args.output}, sort_keys=True))
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
