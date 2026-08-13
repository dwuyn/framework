#!/usr/bin/env python3
"""Materialize receipt-independent r10.3/r27 dependency metadata.

The committed envelope template predates the successor worktree.  This
command emits a new metadata record with the successor framework identity,
current first-party adapter paths, and the two baseline dependency deltas.
It does not alter upstream checkouts or any historical envelope.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise SystemExit(f"successor Git query failed: {result.stderr.strip()[-1000:]}")
    return result.stdout.strip()


def _adapter_paths(framework: str) -> dict[str, str]:
    return {
        "common": str(ROOT / "docker/adapter/provider_shim.py"),
        "framework": str(ROOT / f"src/baselines/{framework}.py"),
        "runtime": str(ROOT / "docker/adapter/runtime_entrypoint.py"),
        "wrapper": str(ROOT / "src/baselines/wrapper.py"),
    }


def materialize(source: dict[str, Any]) -> dict[str, Any]:
    output = copy.deepcopy(source)
    current_commit = _git("rev-parse", "HEAD")
    current_tree = _git("rev-parse", "HEAD^{tree}")
    for item in output["envelopes"]:
        name = str(item["name"])
        source_record = item["source"]
        if name == "VeriPlanPT":
            source_record.update({
                "path": str(ROOT), "commit": current_commit, "tree_hash": current_tree,
            })
        else:
            source_record["path"] = str((ROOT.parent / Path(str(source_record["path"])).name).resolve())
        source_root = Path(str(source_record["path"]))
        item["input_hashes"] = {
            relative: _sha256(source_root / relative)
            for relative in dict(item.get("input_hashes", {}))
        }
        item["recipe_path"] = str(
            ROOT / ("docker/veriplanpt.Dockerfile" if name == "VeriPlanPT" else f"docker/baselines/{name}.Dockerfile")
        )
        item["adapter_paths"] = _adapter_paths(
            {"PentestAgent": "pentest_agent", "PentestGPT": "pentest_gpt",
             "VulnBot": "vuln_bot", "HackSynth": "hack_synth"}.get(name, "pentest_agent")
        )
        lock_path = ROOT / str(item["dependency_lock"]["path"])
        item["dependency_lock"]["sha256"] = _sha256(lock_path)
        if name == "VulnBot":
            item["build_delta"] = {"added_dependencies": ["paramiko==3.4.0"]}
        elif name == "HackSynth":
            item["build_delta"] = {"added_dependencies": ["openai==1.53.0"]}
    output["successor"] = {
        "framework_release": "veriplanpt-runtime-v0.4.0-r10.3",
        "runner_release": "v0.3.0-r27",
        "framework_commit": current_commit,
        "framework_tree": current_tree,
        "runtime_contract": "veriplanpt-runtime-v0.4.0-r10.3",
        "max_llm_calls": 1,
    }
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    source = json.loads((ROOT / "build/dependency-envelopes/envelopes.json").read_text(encoding="utf-8"))
    destination = Path(args.output).resolve()
    if destination.exists():
        raise SystemExit(f"refusing to overwrite successor metadata: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(materialize(source), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(destination), "framework_commit": _git("rev-parse", "HEAD")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
