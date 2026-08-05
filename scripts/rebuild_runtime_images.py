#!/usr/bin/env python3
"""Rebuild all five locked images and emit observed identity inputs.

Builds are network-disabled and use staged wheelhouses.  The command refuses
to substitute a digest when Docker cannot produce one.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.pipeline.baseline_lock import _adapter_bundle_hash

ROOT = Path(__file__).resolve().parents[1]
IMAGES = {
    "PentestAgent": "veriplanpt/pentestagent:locked",
    "PentestGPT": "veriplanpt/pentestgpt:locked",
    "VulnBot": "veriplanpt/vulnbot:locked",
    "HackSynth": "veriplanpt/hacksynth:locked",
    "VeriPlanPT": "veriplanpt/veriplanpt:locked",
}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed for {root}")
    return result.stdout.strip()


def _inspect(image: str) -> tuple[str, dict[str, str]]:
    result = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{json .}}", image],
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise RuntimeError(f"Docker image inspect failed for {image}")
    value = json.loads(result.stdout)
    digest = str(value.get("Id", ""))
    labels = value.get("Config", {}).get("Labels", {})
    if not digest.startswith("sha256:") or not isinstance(labels, dict):
        raise RuntimeError(f"Docker did not return an immutable identity for {image}")
    return digest, {str(key): str(item) for key, item in labels.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staging-root", required=True)
    parser.add_argument("--output-baseline-lock", required=True)
    parser.add_argument("--output-native-identity", required=True)
    args = parser.parse_args(argv)
    staging_root = Path(args.staging_root).resolve()
    if shutil.disk_usage(staging_root).free < 50 * 1024 ** 3:
        raise SystemExit("runtime image rebuild requires at least 50 GiB free disk")
    contexts = json.loads((staging_root / "baseline-build-contexts/context-manifest.json").read_text(encoding="utf-8"))["contexts"]
    envelopes = json.loads((ROOT / "build/dependency-envelopes/envelopes.json").read_text(encoding="utf-8"))["envelopes"]
    by_name = {str(item["name"]): item for item in envelopes}
    observed: list[dict[str, Any]] = []
    native: dict[str, Any] = {}
    for name, image in IMAGES.items():
        context = Path(str(contexts[name]["path"])).resolve()
        recipe = ROOT / ("docker/veriplanpt.Dockerfile" if name == "VeriPlanPT" else f"docker/baselines/{name}.Dockerfile")
        envelope = by_name[name]
        source = Path(str(envelope["source"]["path"])).resolve()
        adapter_paths = {
            "common": context / "adapter/provider_shim.py",
            "framework": next(context.joinpath("adapter").glob("framework-*.py")),
            "wrapper": context / "adapter/wrapper-wrapper.py",
        }
        adapter_hash = _adapter_bundle_hash({key: str(path) for key, path in adapter_paths.items()}, "adapter-2.1")
        dependency_hash = _sha(next((context / "envelope").iterdir()))
        recipe_hash = _sha(recipe)
        commit = _git(source, "rev-parse", "HEAD")
        tree_hash = _git(source, "rev-parse", "HEAD^{tree}")
        args_for_build = {
            "DEPENDENCY_LOCK_HASH": dependency_hash,
            "RECIPE_HASH": recipe_hash,
            "ADAPTER_BUNDLE_HASH": adapter_hash,
            "GIT_TREE_HASH": tree_hash,
        }
        if name == "VeriPlanPT":
            args_for_build["FRAMEWORK_COMMIT"] = commit
        else:
            args_for_build["UPSTREAM_COMMIT"] = commit
        command = ["docker", "build", "--network=none", "--tag", image, "--file", str(recipe)]
        for key, value in sorted(args_for_build.items()):
            command.extend(["--build-arg", f"{key}={value}"])
        command.append(str(context))
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode:
            detail = (result.stderr or result.stdout).strip()[-4000:]
            raise RuntimeError(f"Docker build failed for {name}: {detail}")
        digest, labels = _inspect(image)
        identity = {
            "name": name, "image": image, "image_id": digest, "image_digest": digest,
            "adapter_bundle_hash": adapter_hash, "adapter_contract_version": "adapter-2.1",
            "dependency_lock_hash": dependency_hash, "recipe_hash": recipe_hash,
            "source_commit": commit, "source_tree_hash": tree_hash, "image_labels": labels,
        }
        if name == "VeriPlanPT":
            native = {
                "schema_version": "2.0.0", "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "name": name, "source": {"path": str(source), "commit": commit, "tree_hash": tree_hash},
                "recipe": {"path": str(recipe), "sha256": recipe_hash},
                "adapter_bundle": {"sha256": adapter_hash, "contract_version": "adapter-2.1"},
                "dependency_lock": {"path": str(context / "envelope" / next((context / "envelope").iterdir()).name), "sha256": dependency_hash},
                "image": identity,
            }
        else:
            observed.append({
                "name": name, "path": str(source), "repo_url": str(envelope["source"]["remote"]),
                "recipe_path": str(recipe), "build_context_path": str(context), "image": image,
                "input_hashes": envelope.get("input_hashes", {}),
                "dependency_lock_path": str(context / "envelope" / next((context / "envelope").iterdir()).name),
                "os_package_requirements": envelope.get("os_package_requirements", []),
                "adapter_bundle": {"common": str(adapter_paths["common"]), "framework": str(adapter_paths["framework"]),
                                   "wrapper": str(adapter_paths["wrapper"]), "contract_version": "adapter-2.1"},
            })
    Path(args.output_native_identity).write_text(json.dumps(native, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    inventory = Path(args.output_baseline_lock).with_suffix(".inventory.json")
    inventory.write_text(json.dumps({"schema_version": "1.0.0", "baselines": observed}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"images": len(IMAGES), "inventory": str(inventory), "native_identity": str(args.output_native_identity)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
