#!/usr/bin/env python3
"""Write an observed build inventory consumed by the baseline-lock CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT_ROOT = ROOT.parent / "veriplanpt-artifacts"
IMAGES = {
    "PentestAgent": "veriplanpt/pentestagent:locked",
    "PentestGPT": "veriplanpt/pentestgpt:locked",
    "VulnBot": "veriplanpt/vulnbot:locked",
    "HackSynth": "veriplanpt/hacksynth:locked",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", default=str(ROOT / "build/dependency-envelopes/envelopes.json"))
    parser.add_argument("--artifact-root", default=str(DEFAULT_ARTIFACT_ROOT))
    parser.add_argument("--output", default=str(ROOT / "build/baselines.inventory.json"))
    args = parser.parse_args()
    metadata = json.loads(Path(args.metadata).read_text(encoding="utf-8"))
    contexts = json.loads((Path(args.artifact_root) / "baseline-build-contexts/context-manifest.json").read_text(encoding="utf-8"))["contexts"]
    entries = []
    for envelope in metadata["envelopes"]:
        name = str(envelope["name"])
        if name == "VeriPlanPT":
            continue
        context = contexts.get(name)
        if not isinstance(context, dict):
            raise SystemExit(f"missing staged context for {name}")
        entries.append({
            "name": name,
            "path": envelope["source"]["path"],
            "repo_url": envelope["source"]["remote"],
            "recipe_path": str((ROOT / "docker/baselines" / f"{name}.Dockerfile").resolve()),
            "build_context_path": context["path"],
            "image": IMAGES[name],
            "input_hashes": envelope["input_hashes"],
            "dependency_lock_path": str((ROOT / envelope["dependency_lock"]["path"]).resolve()),
            "os_package_requirements": envelope["os_package_requirements"],
            "adapter_bundle": {
                "common": str((Path(context["path"]) / "adapter/provider_shim.py").resolve()),
                "framework": str((Path(context["path"]) / "adapter" / f"framework-{name.lower().replace('pentestagent', 'pentest_agent').replace('pentestgpt', 'pentest_gpt').replace('vulnbot', 'vuln_bot').replace('hacksynth', 'hack_synth')}.py").resolve()),
                "wrapper": str((Path(context["path"]) / "adapter/wrapper-wrapper.py").resolve()),
                "runtime": str((Path(context["path"]) / "adapter/runtime_entrypoint.py").resolve()),
                "contract_version": "adapter-3.0",
            },
        })
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"schema_version": "1.0.0", "baselines": entries}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "baselines": len(entries)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
