#!/usr/bin/env python3
"""Strict container boundary for readiness and paid framework execution.

The image contains the adapter dispatch.  The caller supplies only the public
invocation and the locked relay binding; no caller-provided command, host path,
credential, or hidden case data is accepted.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping

_HEX64 = set("0123456789abcdef")


class RuntimeBoundaryError(ValueError):
    pass


def _canonical(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _redact(value: str) -> str:
    """Redact bearer/key-like values while retaining bounded diagnostics."""
    import re
    return re.sub(
        r"(?i)(bearer\s+|(?:token|api[_-]?key|secret|credential)\s*[=:]\s*)[^\s,;]+",
        r"\1[REDACTED]", value,
    )


def _driver_diagnostics(
    *, command: tuple[str, ...], returncode: int, stdout: str = "", stderr: str = "",
    error_class: str = "",
) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "argv": list(command),
        "exit_code": int(returncode),
        "error_class": error_class or ("non_zero_exit" if returncode else ""),
        "stdout": _redact(stdout)[-8192:],
        "stderr": _redact(stderr)[-8192:],
        "stdout_sha256": hashlib.sha256(stdout.encode("utf-8", errors="replace")).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode("utf-8", errors="replace")).hexdigest(),
    }


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
    if invocation.get("schema_version") != "2.0.0":
        raise RuntimeBoundaryError("public invocation schema_version must be 2.0.0")
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
    provenance = _object(invocation.get("provenance"), "provenance")
    for name in ("dataset_lock_hash", "framework_commit", "framework_image_digest", "evaluator_commit"):
        if not str(provenance.get(name, "")):
            raise RuntimeBoundaryError(f"provenance is missing {name}")
    target_hash = str(provenance.get("target_runtime_lock_hash", ""))
    if len(target_hash) != 64 or set(target_hash.lower()) - _HEX64:
        raise RuntimeBoundaryError("provenance target runtime lock hash is invalid")
    if target_hash != _required_env("VERIPLANPT_TARGET_RUNTIME_LOCK_HASH"):
        raise RuntimeBoundaryError("public invocation target runtime lock hash differs from the approved environment")
    expected_source_hash = os.environ.get("PENTEST_SOURCE_SNAPSHOT_HASH", "").strip()
    if expected_source_hash:
        if len(expected_source_hash) != 64 or set(expected_source_hash.lower()) - _HEX64:
            raise RuntimeBoundaryError("runtime source snapshot hash is invalid")
        if str(provenance.get("source_snapshot_hash", "")) != expected_source_hash:
            raise RuntimeBoundaryError("public invocation source snapshot hash differs from the approved environment")
    return invocation


def _provider_probe(invocation: Mapping[str, Any], *, phase: str = "runtime-readiness") -> Mapping[str, Any]:
    # The immutable image copies this entrypoint to /runner/run while the
    # provider shim remains in /opt/adapter.  Add both locations explicitly so
    # the public stdin boundary cannot depend on the image working directory.
    for adapter_dir in (Path(__file__).resolve().parent, Path("/opt/adapter")):
        if str(adapter_dir) not in sys.path:
            sys.path.insert(0, str(adapter_dir))
    from provider_shim import request  # type: ignore[import-not-found]

    task = _object(invocation["task"], "public task")
    prompt = {
        "purpose": phase,
        "case_id": invocation["case_id"],
        "objective": task.get("objective", "Verify the controlled model path."),
        "target": task.get("target", {}),
    }
    contents: Any = json.dumps(prompt, sort_keys=True)
    if invocation["model_label"] == "gemma-4-26b-a4b-it":
        contents = [{"role": "user", "content": contents}]
    return request({"contents": contents})


def _adapter_phases(framework: str) -> tuple[str, ...]:
    if framework == "VeriPlanPT":
        return ("recon", "planning", "execution")
    if framework == "PentestAgent":
        return ("recon", "planning", "execution")
    if framework in {"PentestGPT", "VulnBot", "HackSynth"}:
        return ("recon", "planning", "execution")
    raise RuntimeBoundaryError(f"unsupported framework adapter: {framework}")


def _run_fake_production_driver(
    invocation: Mapping[str, Any], *, phases: tuple[str, ...], output: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Offline contract driver; provider calls originate in this driver."""
    events: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = []
    for phase in phases:
        response = dict(_provider_probe(invocation, phase=phase))
        responses.append(response)
        events.append({
            "role": str(invocation["framework"]),
            "event": {
                "event_type": "production_driver_request",
                "phase": phase,
                "provider_response_hash": str(response.get("response_hash") or _canonical(response)),
                "provider_mode": "fake",
            },
        })
    output.joinpath("driver-diagnostics.json").write_text(json.dumps(_driver_diagnostics(
        command=("fake-production-driver",), returncode=0,
        stdout=json.dumps(events, sort_keys=True),
    ), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return events, responses


def _run_adapter(invocation: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], str]:
    """Run the common adapter lifecycle and return evidence plus termination."""
    framework = str(invocation["framework"])
    phases = _adapter_phases(framework)
    started = time.monotonic()
    output = Path(_required_env("VERIPLANPT_OUTPUT_DIR"))
    driver_input = output / "public-invocation.json"
    if driver_input.exists() or driver_input.is_symlink():
        raise RuntimeBoundaryError("refusing to overwrite public driver input")
    driver_input.write_text(json.dumps(dict(invocation), sort_keys=True) + "\n", encoding="utf-8")
    os.environ["VERIPLANPT_PUBLIC_INVOCATION_FILE"] = str(driver_input)
    events: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = []
    if os.environ.get("VERIPLANPT_FAKE_PROVIDER", "").lower() == "true":
        events, responses = _run_fake_production_driver(invocation, phases=phases, output=output)
        proof = [{"kind": "framework_execution", "framework": framework, "phases": list(phases)}]
        if driver_input.exists():
            driver_input.unlink()
        return events, proof, responses, "completed"
    command = (
        (sys.executable, "-m", "src.pipeline.production_driver")
        if framework == "VeriPlanPT"
        else (sys.executable, "/opt/adapter/baseline_driver.py")
    )
    completed: subprocess.CompletedProcess[str] | None = None
    try:
        completed = subprocess.run(
            command,
            # The image root and upstream checkout are read-only. The
            # image-owned driver receives the pinned source through PYTHONPATH
            # and writes logs/config/checkpoints in the per-cell output mount.
            cwd=output,
            capture_output=True,
            text=True,
            timeout=int(os.environ.get("VERIPLANPT_MAX_RUNTIME_SECONDS", "3600")),
            check=False,
        )
        diagnostics = _driver_diagnostics(
            command=command, returncode=completed.returncode,
            stdout=completed.stdout, stderr=completed.stderr,
        )
    except subprocess.TimeoutExpired as exc:
        diagnostics = _driver_diagnostics(
            command=command, returncode=124,
            stdout=str(exc.stdout or ""), stderr=str(exc.stderr or ""),
            error_class="task_timeout",
        )
    except (OSError, ValueError) as exc:
        diagnostics = _driver_diagnostics(
            command=command, returncode=127, error_class=type(exc).__name__, stderr=str(exc),
        )
    (output / "driver-diagnostics.json").write_text(
        json.dumps(diagnostics, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    events.append({
        "role": framework,
        "event": {
            "event_type": "production_driver",
            "argv": list(command),
            "returncode": int(diagnostics["exit_code"]),
            "error_class": diagnostics["error_class"],
            "stdout_sha256": diagnostics["stdout_sha256"],
            "stderr_sha256": diagnostics["stderr_sha256"],
        },
    })
    if completed is None or completed.returncode != 0:
        if driver_input.exists():
            driver_input.unlink()
        return events, [], responses, "infrastructure_failure"
    evidence_path = output / "driver-evidence.json"
    if not evidence_path.is_file() or evidence_path.is_symlink():
        raise RuntimeBoundaryError("actual driver did not emit driver-evidence.json")
    evidence = _object(json.loads(evidence_path.read_text(encoding="utf-8")), "driver evidence")
    if int(evidence.get("provider_response_count", -1)) < 0:
        raise RuntimeBoundaryError("driver evidence provider response count is invalid")
    if not str(evidence.get("public_task_hash", "")) or not str(evidence.get("generated_config_hash", "")):
        raise RuntimeBoundaryError("driver evidence is missing public-task/config hashes")
    events.append({
        "role": framework,
        "event": {
            "event_type": "driver_evidence",
            "mode": str(evidence.get("mode", "")),
            "provider_response_count": int(evidence["provider_response_count"]),
            "public_task_hash": str(evidence["public_task_hash"]),
            "generated_config_hash": str(evidence["generated_config_hash"]),
            "outcome": str(evidence.get("outcome", "")),
        },
    })
    proof = [{
        "kind": "framework_execution",
        "framework": framework,
        "phases": list(phases),
        "driver_evidence_sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }]
    if driver_input.exists():
        driver_input.unlink()
    return events, proof, responses, "completed"


def _run_canary(invocation: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], str]:
    """Perform exactly one provider response without importing the framework graph."""
    response = _provider_probe(invocation, phase="vertex-canary")
    event = {
        "role": str(invocation["framework"]),
        "event": {
            "event_type": "vertex_canary_probe",
            "provider_response_hash": str(response.get("response_hash") or _canonical(response)),
            "provider_mode": "fake" if os.environ.get("VERIPLANPT_FAKE_PROVIDER", "").lower() == "true" else "relay",
        },
    }
    return [event], [{"kind": "controlled_provider_probe", "response_count": 1}], [dict(response)], "completed"


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
    run_context = {
        "dataset_lock_hash": str(provenance.get("dataset_lock_hash", "")),
        "training_protocol_hash": str(provenance.get("protocol_hash", "")),
        "gateway_relay_lock_hash": _required_env("VERIPLANPT_GATEWAY_RELAY_LOCK_HASH"),
        "framework_commit": str(provenance.get("framework_commit", "")),
        "evaluator_commit": str(provenance.get("evaluator_commit", "")),
        "target_runtime_lock_hash": _required_env("VERIPLANPT_TARGET_RUNTIME_LOCK_HASH"),
        "stage": _required_env("VERIPLANPT_STAGE"),
        "control_condition": "runtime",
    }
    source_snapshot_hash = str(provenance.get("source_snapshot_hash", ""))
    if source_snapshot_hash:
        run_context["source_snapshot_hash"] = source_snapshot_hash
    # Readiness has no policy or matrix lock yet.  Omitting these optional
    # bindings is distinct from emitting an invalid empty string; later paid
    # stages include them in the public invocation provenance.
    for key in ("policy_lock_hash", "matrix_hash"):
        value = str(provenance.get(key, ""))
        if value:
            run_context[key] = value
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
        "execution_kind": str(invocation.get("execution_kind", "")),
        "evaluation_scope": str(invocation.get("evaluation_scope", "")),
        "readiness_kind": str(invocation.get("readiness_kind", "")),
        "repetition": int(invocation.get("repetition", 1)),
        "budget_tier": str(invocation.get("budget_tier", "medium")),
        "model_profile": dict(invocation["model_profile"]),
        "framework_identity": {
            "name": framework,
            "repository_url": str(provenance.get("framework_repository_url", "")),
            "commit": str(provenance.get("framework_commit", "")),
            "image_digest": str(provenance.get("framework_image_digest", "")),
            "adapter_version": "adapter-3.0",
        },
        "run_context": run_context,
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
        "internal_outcome": (
            "model_no_visible_text" if str(response.get("response_status", "")) == "no_visible_text"
            else "runtime_ready"
        ),
        "budget_termination_reason": "",
        "metric_eligible": str(invocation.get("evaluation_scope", "")) != "readiness_transport",
        "valid": True,
    }


def main() -> int:
    stage = _required_env("VERIPLANPT_STAGE")
    if stage not in {"canary_smoke", "sweep", "confirmation", "benchmark"}:
        raise RuntimeBoundaryError("unsupported execution stage")
    output = Path(_required_env("VERIPLANPT_OUTPUT_DIR"))
    if not output.is_dir() or output.is_symlink():
        raise RuntimeBoundaryError("runtime output directory is not a real mounted directory")
    invocation = _load_public_invocation()
    execution_kind = str(invocation.get("execution_kind", ""))
    if not execution_kind and str(invocation.get("condition", "")) in {"vertex_canary", "framework_model_smoke"}:
        # Legacy evidence remains readable; every r10.5 invocation carries
        # execution_kind explicitly and takes the branch above.
        execution_kind = str(invocation["condition"])
    if stage == "canary_smoke" and execution_kind not in {"vertex_canary", "framework_model_smoke"}:
        raise RuntimeBoundaryError("readiness invocation execution_kind is invalid")
    if os.environ.get("VERIPLANPT_FAKE_PROVIDER", "").lower() == "true":
        raise RuntimeBoundaryError(
            "VERIPLANPT_FAKE_PROVIDER is test-only and is not accepted by r10.3 production certification"
        )
    if stage == "canary_smoke" or os.environ.get("VERIPLANPT_ADAPTER_PRODUCTION", "") == "true":
        if execution_kind == "vertex_canary":
            events, proof, responses, termination = _run_canary(invocation)
        else:
            events, proof, responses, termination = _run_adapter(invocation)
        response = {
            "usage": {
                "input_tokens": sum(int(item.get("usage", {}).get("input_tokens", 0)) for item in responses),
                "output_tokens": sum(int(item.get("usage", {}).get("output_tokens", 0)) for item in responses),
                "total_tokens": sum(int(item.get("usage", {}).get("total_tokens", 0)) for item in responses),
                "usd": sum(float(item.get("usage", {}).get("usd", 0.0)) for item in responses),
            },
            "response_hash": _canonical(events),
            "response_status": (
                "no_visible_text"
                if any(str(item.get("response_status", "")) == "no_visible_text" for item in responses)
                else "ok"
            ),
        }
        candidate = output / "run_artifact.json"
        # Vertex canaries intentionally run only the controlled provider
        # probe; unlike framework/model smoke they do not invoke a production
        # driver that can emit its own RunArtifact.  Materialize the strict
        # controlled-probe artifact for that path instead of treating the
        # missing driver artifact as a post-response failure.
        is_vertex_canary = execution_kind == "vertex_canary"
        if termination == "completed" and not is_vertex_canary:
            if candidate.is_file() and not candidate.is_symlink():
                artifact = _object(json.loads(candidate.read_text(encoding="utf-8")), "production RunArtifact")
                if artifact.get("schema_version") != "2.1.0" or artifact.get("run_id") != invocation["run_id"]:
                    raise RuntimeBoundaryError("production adapter RunArtifact identity is invalid")
                context = _object(artifact.get("run_context"), "production RunArtifact context")
                context["stage"] = stage
                context["target_runtime_lock_hash"] = _required_env("VERIPLANPT_TARGET_RUNTIME_LOCK_HASH")
                context["gateway_relay_lock_hash"] = _required_env("VERIPLANPT_GATEWAY_RELAY_LOCK_HASH")
                artifact["run_context"] = context
            else:
                # The image-owned runtime wrapper materializes the official
                # wire artifact when an upstream driver only emits native
                # result files. The host ledger remains the source of usage;
                # an absent provider response is still rejected by the runner.
                artifact = _artifact(invocation, response)
        else:
            artifact = _artifact(invocation, response)
            artifact["transcript"] = events
            artifact["proof_submissions"] = proof
            artifact["event_ledger_hash"] = _canonical(events)
            artifact["proof_hash"] = _canonical(proof)
            artifact["termination_status"] = termination
            artifact["internal_outcome"] = (
                "model_no_visible_text"
                if response.get("response_status") == "no_visible_text"
                else ("adapter_completed" if termination == "completed" else termination)
            )
            if termination == "infrastructure_failure":
                artifact["metric_eligible"] = False
                artifact["valid"] = False
    else:
        raise RuntimeBoundaryError("paid stage requires VERIPLANPT_ADAPTER_PRODUCTION=true")
    destination = output / "run_artifact.json"
    if destination.exists() and (not destination.is_file() or destination.is_symlink()):
        raise RuntimeBoundaryError("refusing to overwrite an existing RunArtifact")
    if not destination.exists():
        destination.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 70 if termination == "infrastructure_failure" else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeBoundaryError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(78) from exc
