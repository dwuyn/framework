#!/usr/bin/env python3
"""Run the 5x3 actual-driver, provider-free certification matrix."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EPOCH = ROOT.parent / "veriplanpt-epoch-r10.4-r29-20260813T130000Z"
OUTPUT = EPOCH / "mock-live-certification"
SNAPSHOT = ROOT.parent / "veriplanpt-cve-source-snapshot-20260812T182421Z-recovered"
PUBLIC_TASK = ROOT.parent / "veriplanpt-runtime-staging-20260807T123503Z/contract-smoke/public-task.json"
PROFILES = ROOT.parent / "veriplanpt-runtime-staging-20260808T034849Z/runtime-artifacts/model-profiles.json"
TARGET_LOCK = ROOT.parent / "veriplanpt-runtime-r10.2-r26-20260812T144308Z/inputs/target-runtime.lock.r10.2.json"
BASELINE_LOCK = EPOCH / "locks/baseline.lock.json"
NATIVE_IDENTITY = EPOCH / "locks/native-veriplanpt-identity.json"
RELAY_LOCK = EPOCH / "locks/gateway-relay.lock.json"
SOURCE_SNAPSHOT_HASH = "afcee65c1ec8c86517e346cdd27cba90d709abdc24547aeaa0d4929418128acf"
DATASET_LOCK_HASH = "7f1e24086fc63c9f2c7181bb9535b6c53aa6f06752c2855c7f7df8758ca0d878"
EVALUATOR_COMMIT = "ac4c472e1e2e8e8fb48f2b8b4e2e2e48c5c2f6a1"
FRAMEWORKS = ("VeriPlanPT", "PentestAgent", "PentestGPT", "VulnBot", "HackSynth")
MODELS = ("gemini-3.5-flash", "gemini-3.6-flash", "gemma-4-26b-a4b-it")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(args: list[str], *, input_bytes: bytes | None = None, timeout: int = 180) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(args, input=input_bytes, capture_output=True, text=False, timeout=timeout, check=False)


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _image_map() -> dict[str, str]:
    result: dict[str, str] = {}
    for item in _json(BASELINE_LOCK)["baselines"]:
        result[str(item["name"])] = str(item["image_digest"])
    result["VeriPlanPT"] = str(_json(NATIVE_IDENTITY)["image"]["image_digest"])
    result["gateway-relay"] = str(_json(RELAY_LOCK)["relay"]["image_digest"])
    if set(result) != set(FRAMEWORKS) | {"gateway-relay"}:
        raise ValueError("successor locks do not pin the six certification images")
    return result


def _profiles() -> dict[str, dict[str, Any]]:
    values = _json(PROFILES).get("profiles")
    if not isinstance(values, list):
        raise ValueError("model profile input has no profiles")
    result = {str(item["logical_label"]): dict(item) for item in values if isinstance(item, dict)}
    if set(result) != set(MODELS):
        raise ValueError("model profile input does not pin the three required models")
    return result


def _docker_cleanup(container: str, network: str) -> None:
    _run(["docker", "rm", "-f", container], timeout=30)
    _run(["docker", "network", "rm", network], timeout=30)


def main() -> int:
    if not SNAPSHOT.is_dir() or not PUBLIC_TASK.is_file() or not PROFILES.is_file():
        raise SystemExit("mock-live public inputs are incomplete")
    if not BASELINE_LOCK.is_file() or not NATIVE_IDENTITY.is_file() or not RELAY_LOCK.is_file():
        raise SystemExit("successor image locks are incomplete")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for child in OUTPUT.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        elif child.is_file() and not child.is_symlink():
            child.unlink()
    image_map = _image_map()
    profiles = _profiles()
    public_task = _json(PUBLIC_TASK)
    target_lock_hash = _sha(TARGET_LOCK)
    relay_lock_hash = _sha(RELAY_LOCK)
    profile_copy = OUTPUT / "model-profiles.json"
    profile_copy.write_text(json.dumps({"schema_version": "1.0.0", "profiles": list(profiles.values())}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    socket_path = OUTPUT / "gateway.sock"
    gateway_evidence = OUTPUT / "mock-gateway-evidence.json"
    server = subprocess.Popen([
        sys.executable, str(ROOT / "scripts/mock_live_gateway.py"),
        "--socket", str(socket_path), "--evidence", str(gateway_evidence), "--expected", "15",
    ])
    network = "veriplanpt-r103-mock-live"
    relay = "veriplanpt-r103-mock-relay"
    created_network = False
    results: list[dict[str, Any]] = []
    try:
        network_result = _run(["docker", "network", "create", "--internal", network], timeout=30)
        if network_result.returncode != 0:
            raise RuntimeError(network_result.stderr.decode(errors="replace"))
        created_network = True
        for _ in range(100):
            if socket_path.exists():
                break
            time.sleep(0.05)
        relay_result = _run([
            "docker", "run", "-d", "--name", relay, "--network", network,
            "--network-alias", "gateway-relay", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--mount", f"type=bind,src={socket_path},dst=/run/veriplanpt-gateway/gateway.sock,readonly",
            image_map["gateway-relay"],
        ], timeout=60)
        if relay_result.returncode != 0:
            raise RuntimeError(relay_result.stderr.decode(errors="replace"))
        time.sleep(0.5)
        for framework in FRAMEWORKS:
            for model in MODELS:
                run_id = f"mock-live-{framework}-{model}"
                profile = profiles[model]
                output = OUTPUT / run_id
                output.mkdir(parents=True, exist_ok=True)
                invocation = {
                    "schema_version": "2.0.0", "run_id": run_id, "framework": framework,
                    "model_label": model, "case_id": str(public_task["case_id"]), "track": "blind",
                    "execution_kind": "framework_model_smoke", "condition": "not_applicable",
                    "evaluation_scope": "readiness_transport", "readiness_kind": "smoke",
                    "metric_eligible": False, "task": public_task,
                    "provenance": {
                        "dataset_lock_hash": DATASET_LOCK_HASH, "protocol_hash": _sha(EPOCH / "envelopes-r10.4-r29.json"),
                        "framework_commit": str(_json(NATIVE_IDENTITY)["source"]["commit"]) if framework == "VeriPlanPT" else "unknown",
                        "framework_image_digest": image_map[framework], "framework_repository_url": "https://example.invalid/veriplanpt",
                        "evaluator_commit": EVALUATOR_COMMIT, "target_runtime_lock_hash": target_lock_hash,
                        "source_snapshot_hash": SOURCE_SNAPSHOT_HASH,
                    },
                    "labels": {"certification": "mock-live"}, "model_profile": profile,
                    "budget_tier": "medium", "repetition": 1, "parameters": {},
                }
                payload = (json.dumps(invocation, sort_keys=True, separators=(",", ":")) + "\n").encode()
                token = f"smoke~{run_id}~{profile['profile_hash']}"
                environment = {
                    "VERIPLANPT_RUN_ID": run_id, "VERIPLANPT_MODEL_LABEL": model,
                    "VERIPLANPT_PROFILE_HASH": str(profile["profile_hash"]), "VERIPLANPT_PROVIDER_TOKEN": token,
                    "VERIPLANPT_PROVIDER_TOKEN_EXPIRES_AT": (datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
                    "VERIPLANPT_GATEWAY_LIVE": "true", "VERIPLANPT_PROVIDER_URL": "http://gateway-relay:8080/v1/generate",
                    "VERIPLANPT_PROVIDER_BASE_URL": "http://gateway-relay:8080/v1", "OPENAI_BASEURL": "http://gateway-relay:8080/v1",
                    "OPENAI_API_KEY": token, "VERIPLANPT_FRAMEWORK_NAME": framework,
                    "VERIPLANPT_STAGE": "canary_smoke", "VERIPLANPT_ADAPTER_PRODUCTION": "true",
                    "VERIPLANPT_MAX_LLM_CALLS": "1", "VERIPLANPT_MAX_RUNTIME_SECONDS": "120",
                    "VERIPLANPT_RUN_DIR": "/run/veriplanpt/output", "VERIPLANPT_OUTPUT_DIR": "/run/veriplanpt/output",
                    "LOG_DIR": "/run/veriplanpt/output", "PENTEST_SOURCE_SNAPSHOT": "/run/veriplanpt/source-snapshot",
                    "PENTEST_SOURCE_SNAPSHOT_HASH": SOURCE_SNAPSHOT_HASH, "VERIPLANPT_TARGET_RUNTIME_LOCK_HASH": target_lock_hash,
                    "VERIPLANPT_GATEWAY_RELAY_LOCK_HASH": relay_lock_hash, "VERIPLANPT_DATASET_LOCK_HASH": DATASET_LOCK_HASH,
                    "VERIPLANPT_TRAINING_PROTOCOL_HASH": _sha(EPOCH / "envelopes-r10.4-r29.json"),
                    "VERIPLANPT_EVALUATOR_COMMIT": EVALUATOR_COMMIT, "VERIPLANPT_IMAGE_DIGEST": image_map[framework],
                }
                docker_args = [
                    "docker", "run", "--rm", "-i", "--name", f"{relay}-{len(results):02d}", "--network", network,
                    "--user", "1000:1000",
                    "--read-only", "--tmpfs", "/run/veriplanpt:rw,nosuid,size=256m",
                    "--mount", f"type=bind,src={output},dst=/run/veriplanpt/output",
                    "--mount", f"type=bind,src={SNAPSHOT},dst=/run/veriplanpt/source-snapshot,readonly",
                ]
                for key, value in environment.items():
                    docker_args.extend(["--env", f"{key}={value}"])
                docker_args.extend([image_map[framework], "/runner/run"])
                started = time.monotonic()
                result = _run(docker_args, input_bytes=payload, timeout=180)
                result_record: dict[str, Any] = {
                    "framework": framework, "model": model, "run_id": run_id,
                    "image_digest": image_map[framework], "exit_code": result.returncode,
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                    "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
                    "stdout_tail": result.stdout.decode(errors="replace")[-2000:],
                    "stderr_tail": result.stderr.decode(errors="replace")[-4000:],
                }
                evidence_path = output / "driver-evidence.json"
                calls_path = output / "provider-calls.jsonl"
                if evidence_path.is_file():
                    result_record["driver_evidence"] = _json(evidence_path)
                result_record["provider_call_rows"] = len(calls_path.read_text(encoding="utf-8").splitlines()) if calls_path.is_file() else 0
                result_record["generated_config_hash"] = str(result_record.get("driver_evidence", {}).get("generated_config_hash", ""))
                result_record["forbidden_generated_config_strings"] = []
                for candidate in output.glob("*config*.json"):
                    text = candidate.read_text(encoding="utf-8")
                    for forbidden in ("CVE-", "oracle", "truth", "evaluator_hint"):
                        if forbidden.lower() in text.lower():
                            result_record["forbidden_generated_config_strings"].append(forbidden)
                result_record["valid"] = bool(
                    result.returncode == 0
                    and result_record.get("driver_evidence", {}).get("mode") in {"actual-sdk-adapter", "actual-framework-driver"}
                    and int(result_record.get("driver_evidence", {}).get("provider_response_count", -1)) == 1
                    and result_record["forbidden_generated_config_strings"] == []
                )
                results.append(result_record)
                (output / "cell-result.json").write_text(
                    json.dumps(result_record, indent=2, sort_keys=True) + "\n", encoding="utf-8",
                )
        _run(["docker", "rm", "-f", relay], timeout=30)
        _run(["docker", "network", "rm", network], timeout=30)
        created_network = False
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.terminate()
            server.wait(timeout=10)
    finally:
        _docker_cleanup(relay, network) if created_network else None
        if server.poll() is None:
            server.terminate()
            server.wait(timeout=10)
    gateway = _json(gateway_evidence) if gateway_evidence.is_file() else {}
    report = {
        "schema_version": "1.0.0", "mode": "provider-free-mock-live",
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "expected_cells": 15, "valid_cells": sum(bool(item["valid"]) for item in results),
        "provider_calls": int(gateway.get("provider_calls", -1)), "vertex_calls": int(gateway.get("vertex_calls", -1)),
        "gateway": gateway, "cells": results,
        "all_passed": len(results) == 15 and all(bool(item["valid"]) for item in results)
        and gateway.get("all_cells_one_response") is True
        and gateway.get("provider_calls") == 0 and gateway.get("vertex_calls") == 0,
    }
    (OUTPUT / "certification-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUTPUT), "cells": len(results), "valid_cells": report["valid_cells"], "all_passed": report["all_passed"]}, sort_keys=True))
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
