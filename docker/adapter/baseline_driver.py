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
import subprocess
import sys
import time
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


def _commands(framework: str, run_dir: Path, source: Path) -> tuple[tuple[str, ...], ...]:
    if framework == "PentestAgent":
        return (
            (sys.executable, str(source / "agents/recon_agent.py")),
            (sys.executable, str(source / "agents/planning_agent.py")),
            (sys.executable, str(source / "agents/execution_agent.py")),
        )
    if framework == "PentestGPT":
        return ((sys.executable, "-m", "pentestgpt.main"),)
    if framework == "VulnBot":
        return ((sys.executable, str(source / "cli.py"), "vulnbot", "--max_interactions", os.environ.get("VERIPLANPT_MAX_LLM_CALLS", "1")),)
    benchmark = run_dir / "hacksynth-benchmark.json"
    config = run_dir / "hacksynth-config.json"
    task = json.loads(Path(os.environ["VERIPLANPT_PUBLIC_INVOCATION_FILE"]).read_text(encoding="utf-8"))
    benchmark.write_text(json.dumps({task["case_id"]: {"description": task["task"].get("objective", ""), "target": "lab.local"}}, sort_keys=True) + "\n", encoding="utf-8")
    config.write_text(json.dumps({
        "attackbox": "lab.local",
        "llm": {
            # HackSynth selects its OpenAI client by model family. The
            # bearer binding maps this harmless client alias to the signed
            # cell profile at the relay.
            "model_id": "gpt-4o",
            "model_local": False,
            "base_url": "http://gateway-relay:8080/v1",
        },
        "max_tries": int(os.environ.get("VERIPLANPT_MAX_LLM_CALLS", "1")),
    }, sort_keys=True) + "\n", encoding="utf-8")
    return ((sys.executable, str(source / "run_bench.py"), "-b", str(benchmark), "-c", str(config)),)


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
    source_string = str(source)
    child_environment["PYTHONPATH"] = os.pathsep.join(
        item for item in (source_string, child_environment.get("PYTHONPATH", "")) if item
    )
    framework = _framework()
    if framework == "VulnBot":
        # Keep the upstream checkout immutable while giving its settings
        # loader an image-owned, relay-pinned config envelope.
        config_root = run_dir / "vulnbot-config"
        config_root.mkdir(parents=True, exist_ok=True)
        (config_root / "model_config.yaml").write_text(
            "api_key: local-relay\n"
            "llm_model: openai\n"
            "base_url: http://gateway-relay:8080/v1\n"
            "llm_model_name: gpt-4o\n"
            "embedding_type: local\n"
            "temperature: 0\n"
            "timeout: 300\n",
            encoding="utf-8",
        )
        child_environment["PENTEST_ROOT"] = str(config_root)
    phases = _commands(framework, run_dir, source)
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
