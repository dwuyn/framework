#!/usr/bin/env python3
"""Image-owned baseline phase dispatcher.

The dispatcher keeps the upstream workflow intact while making the phase
sequence explicit to the runner. Provider calls remain routed by the shared
provider shim inherited from the container environment.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _framework() -> str:
    value = os.environ.get("VERIPLANPT_FRAMEWORK_NAME", "")
    if value not in {"PentestAgent", "PentestGPT", "VulnBot", "HackSynth"}:
        raise SystemExit("baseline driver framework is not locked")
    return value


def _commands(framework: str, run_dir: Path) -> tuple[tuple[str, ...], ...]:
    if framework == "PentestAgent":
        return (
            (sys.executable, "agents/recon_agent.py"),
            (sys.executable, "agents/planning_agent.py"),
            (sys.executable, "agents/execution_agent.py"),
        )
    if framework == "PentestGPT":
        return ((sys.executable, "-m", "pentestgpt.main"),)
    if framework == "VulnBot":
        return ((sys.executable, "cli.py", "vulnbot", "--max_interactions", os.environ.get("VERIPLANPT_MAX_LLM_CALLS", "1")),)
    benchmark = run_dir / "hacksynth-benchmark.json"
    config = run_dir / "hacksynth-config.json"
    task = json.loads(Path(os.environ["VERIPLANPT_PUBLIC_INVOCATION_FILE"]).read_text(encoding="utf-8"))
    benchmark.write_text(json.dumps({task["case_id"]: {"description": task["task"].get("objective", ""), "target": "lab.local"}}, sort_keys=True) + "\n", encoding="utf-8")
    config.write_text(json.dumps({"attackbox": "lab.local", "llm": {"model_id": task["model_label"], "model_local": False}, "max_tries": int(os.environ.get("VERIPLANPT_MAX_LLM_CALLS", "1"))}, sort_keys=True) + "\n", encoding="utf-8")
    return ((sys.executable, "run_bench.py", "-b", str(benchmark), "-c", str(config)),)


def main() -> int:
    run_dir = Path(os.environ.get("VERIPLANPT_RUN_DIR", "/run/veriplanpt"))
    source = Path(os.environ.get("VERIPLANPT_SOURCE_DIR", "/opt/upstream"))
    for command in _commands(_framework(), run_dir):
        result = subprocess.run(command, cwd=source, check=False)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
