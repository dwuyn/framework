#!/usr/bin/env python3
"""Image-owned baseline phase dispatcher.

The dispatcher keeps the upstream workflow intact while making the phase
sequence explicit to the runner. Provider calls remain routed by the shared
provider shim inherited from the container environment.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path


def _framework() -> str:
    value = os.environ.get("VERIPLANPT_FRAMEWORK_NAME", "")
    if value not in {"PentestAgent", "PentestGPT", "VulnBot", "HackSynth"}:
        raise SystemExit("baseline driver framework is not locked")
    return value


def _redact(value: str) -> str:
    return re.sub(
        r"(?i)(bearer\s+|(?:token|api[_-]?key|secret|credential)\s*[=:]\s*)[^\s,;]+",
        r"\1[REDACTED]", value,
    )


def _task_target(task: dict[str, object]) -> tuple[str, int]:
    target = task.get("target")
    if not isinstance(target, dict):
        raise SystemExit("public task target must be an object")
    host = str(target.get("host", "")).strip()
    scope = task.get("scope")
    allowed = scope.get("allowed_ports", []) if isinstance(scope, dict) else []
    ports = target.get("exposed_ports") or allowed
    if not host or not isinstance(ports, list) or len(ports) != 1:
        raise SystemExit("public task must pin exactly one target host and port")
    try:
        port = int(ports[0])
    except (TypeError, ValueError) as exc:
        raise SystemExit("public task target port is invalid") from exc
    if not 1 <= port <= 65535:
        raise SystemExit("public task target port is outside TCP range")
    parsed = urllib.parse.urlparse(str(target.get("url", "")))
    if parsed.hostname and parsed.hostname != host:
        raise SystemExit("public task target URL host differs from target host")
    return host, port


def _commands(framework: str, run_dir: Path, source: Path) -> tuple[tuple[str, ...], ...]:
    task = json.loads(Path(os.environ["VERIPLANPT_PUBLIC_INVOCATION_FILE"]).read_text(encoding="utf-8"))
    public_task = task["task"]
    if not isinstance(public_task, dict):
        raise SystemExit("public task must be an object")
    host, port = _task_target(public_task)
    budget = int(os.environ.get("VERIPLANPT_MAX_LLM_CALLS", "1"))
    if budget <= 0:
        raise SystemExit("public task budget must be positive")
    generated = run_dir / "generated-public-config.json"
    generated.write_text(json.dumps({
        "framework": framework, "host": host, "port": port, "budget": budget,
        "objective": str(public_task.get("objective", "")),
    }, sort_keys=True) + "\n", encoding="utf-8")
    os.environ["VERIPLANPT_GENERATED_CONFIG_HASH"] = hashlib.sha256(generated.read_bytes()).hexdigest()
    if framework in {"PentestAgent", "PentestGPT"}:
        return ((sys.executable, "/opt/adapter/baseline_client_driver.py"),)
    if framework == "VulnBot":
        config_root = run_dir / "vulnbot-config"
        config_root.mkdir(parents=True, exist_ok=True)
        config_path = config_root / "model_config.yaml"
        config_path.write_text(
            f"api_key: local-relay\nllm_model: openai\nbase_url: http://gateway-relay:8080/v1\n"
            f"target_host: {host}\ntarget_port: {port}\nbudget: {budget}\n",
            encoding="utf-8",
        )
        os.environ["VERIPLANPT_GENERATED_CONFIG_HASH"] = hashlib.sha256(config_path.read_bytes()).hexdigest()
        return ((sys.executable, "/opt/adapter/baseline_client_driver.py"),)
    benchmark = run_dir / "hacksynth-benchmark.json"
    config = run_dir / "hacksynth-config.json"
    benchmark.write_text(json.dumps({task["case_id"]: {
        "description": public_task.get("objective", ""), "target": host, "port": port,
    }}, sort_keys=True) + "\n", encoding="utf-8")
    config.write_text(json.dumps({
        "attackbox": host, "target_port": port,
        "llm": {
            # HackSynth selects its OpenAI client by model family. The
            # bearer binding maps this harmless client alias to the signed
            # cell profile at the relay.
            "model_id": "gpt-4o",
            "model_local": False,
            "base_url": "http://gateway-relay:8080/v1",
        },
        "max_tries": budget,
    }, sort_keys=True) + "\n", encoding="utf-8")
    os.environ["VERIPLANPT_GENERATED_CONFIG_HASH"] = hashlib.sha256(config.read_bytes()).hexdigest()
    return ((sys.executable, "/opt/adapter/baseline_client_driver.py"),)


def _run_child(command: tuple[str, ...], *, cwd: Path, env: dict[str, str]):
    """Run a phase while keeping a small compatibility seam for test doubles."""
    try:
        return subprocess.run(
            command, cwd=cwd, env=env,
            capture_output=True, text=True, check=False,
        )
    except TypeError as exc:
        # Older harness doubles only model subprocess.run(command, cwd, env,
        # check). Real image execution always takes the diagnostic path above.
        if "capture_output" not in str(exc):
            raise
        return subprocess.run(command, cwd=cwd, env=env, check=False)


def main() -> int:
    run_dir = Path(os.environ.get("VERIPLANPT_RUN_DIR", "/run/veriplanpt"))
    source = Path(os.environ.get("VERIPLANPT_SOURCE_DIR", "/opt/upstream"))
    run_dir.mkdir(parents=True, exist_ok=True)
    child_environment = os.environ.copy()
    framework = _framework()
    if framework in {"PentestAgent", "PentestGPT"}:
        writable_source = run_dir / "upstream-copy"
        shutil.copytree(source, writable_source, symlinks=False)
        source = writable_source
    source_string = str(source)
    child_environment["PYTHONPATH"] = os.pathsep.join(
        item for item in (source_string, child_environment.get("PYTHONPATH", "")) if item
    )
    phases = _commands(framework, run_dir, source)
    child_environment.update({
        "VERIPLANPT_GENERATED_CONFIG_HASH": os.environ.get("VERIPLANPT_GENERATED_CONFIG_HASH", ""),
        "VERIPLANPT_MAX_OUTPUT_TOKENS": os.environ.get("VERIPLANPT_MAX_OUTPUT_TOKENS", "2048"),
    })
    results: list[dict[str, object]] = []
    started = time.monotonic()
    for command in phases:
        result = _run_child(command, cwd=run_dir, env=child_environment)
        stdout = str(getattr(result, "stdout", "") or "")
        stderr = str(getattr(result, "stderr", "") or "")
        results.append({
            "argv": list(command), "returncode": result.returncode,
            "stdout": _redact(stdout)[-8192:], "stderr": _redact(stderr)[-8192:],
            "stdout_sha256": hashlib.sha256(stdout.encode("utf-8", errors="replace")).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr.encode("utf-8", errors="replace")).hexdigest(),
        })
        if result.returncode:
            (run_dir / "driver-result.json").write_text(json.dumps({
                "schema_version": "1.0.0", "framework": framework,
                "phases": results, "elapsed_seconds": round(time.monotonic() - started, 3),
                "status": "infrastructure_failure",
            }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(json.dumps(results, sort_keys=True))
            return result.returncode
    (run_dir / "driver-result.json").write_text(json.dumps({
        "schema_version": "1.0.0", "framework": framework,
        "phases": results, "elapsed_seconds": round(time.monotonic() - started, 3),
        "status": "completed",
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(results, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
