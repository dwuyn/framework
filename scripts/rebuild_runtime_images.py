#!/usr/bin/env python3
"""Rebuild the r10.4/r29 runtime images and emit observed identities.

Builds are network-disabled and use staged wheelhouses.  The command refuses
to substitute a digest when Docker cannot produce one.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.pipeline.baseline_lock import _adapter_bundle_hash, generate_baseline_lock

ROOT = Path(__file__).resolve().parents[1]
IMAGES = {
    "PentestAgent": "veriplanpt/pentestagent:locked",
    "PentestGPT": "veriplanpt/pentestgpt:locked",
    "VulnBot": "veriplanpt/vulnbot:locked",
    "HackSynth": "veriplanpt/hacksynth:locked",
    "VeriPlanPT": "veriplanpt/veriplanpt:locked",
}
RELAY_IMAGE = "veriplanpt/gateway-relay:locked"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def _build(command: list[str], image: str) -> None:
    """Build one image, accepting timeout only after the image ID changes."""
    before = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image],
        capture_output=True, text=True, check=False,
    )
    previous_id = before.stdout.strip() if before.returncode == 0 else ""
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=900)
    except subprocess.TimeoutExpired:
        # The legacy Docker builder can commit/tag the image and leave the
        # client waiting for a final stream flush. A pre-existing tag is never
        # accepted as evidence of this build.
        after = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image],
            capture_output=True, text=True, check=False,
        )
        if after.returncode == 0 and after.stdout.strip() != previous_id:
            return
        raise RuntimeError(f"Docker build timed out before producing {image}") from None
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()[-4000:]
        raise RuntimeError(f"Docker build failed for {image}: {detail}")


def _context_manifest(staging_root: Path, metadata_path: Path) -> tuple[dict[str, Any], str]:
    manifest_path = staging_root / "baseline-build-contexts/context-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    metadata_sha256 = _sha(metadata_path)
    if manifest.get("metadata_sha256") != metadata_sha256:
        raise RuntimeError("metadata/context SHA-256 mismatch")
    metadata_record = manifest.get("metadata")
    if not isinstance(metadata_record, dict) or metadata_record.get("sha256") != metadata_sha256:
        raise RuntimeError("metadata/context SHA-256 mismatch")
    contexts = manifest.get("contexts")
    if not isinstance(contexts, dict):
        raise RuntimeError("context manifest does not contain contexts")
    return contexts, metadata_sha256


def _dependency_lock(context: Mapping[str, Any], envelope: Mapping[str, Any]) -> tuple[Path, str]:
    lock_path = Path(str(context.get("dependency_lock", ""))).resolve()
    expected = str(envelope["dependency_lock"]["sha256"])
    if not lock_path.is_file():
        raise RuntimeError(f"staged dependency lock is missing: {lock_path}")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise RuntimeError("metadata dependency lock hash is invalid")
    if context.get("dependency_lock_sha256") != expected:
        raise RuntimeError("metadata/context dependency-lock hash mismatch")
    if lock_path.name != Path(str(envelope["dependency_lock"]["path"])).name:
        raise RuntimeError("metadata/context dependency-lock path mismatch")
    return lock_path, expected


def _os_package_envelope(context: Path, envelope: Mapping[str, Any]) -> tuple[str, list[tuple[str, str]]]:
    spec = envelope.get("os_package_envelope")
    if not isinstance(spec, Mapping):
        raise RuntimeError("PentestAgent OS package envelope is missing")
    lock_path = context / "os-packages.lock.json"
    expected_lock_sha256 = str(spec["lock_sha256"])
    if not lock_path.is_file() or _sha(lock_path) != expected_lock_sha256:
        raise RuntimeError("PentestAgent OS package lock hash mismatch")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    aggregate = str(lock.get("aggregate_lock_hash", ""))
    body = dict(lock)
    body.pop("aggregate_lock_hash", None)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != aggregate:
        raise RuntimeError("PentestAgent aggregate OS package lock hash mismatch")
    package_dir = context / "os-packages"
    packages = lock.get("packages")
    if not package_dir.is_dir() or not isinstance(packages, list):
        raise RuntimeError("PentestAgent OS package context is incomplete")
    expected_files = {str(item["filename"]) for item in packages}
    actual_files = {path.name for path in package_dir.glob("*.deb")}
    if actual_files != expected_files:
        raise RuntimeError("PentestAgent OS package file set mismatch")
    versions: list[tuple[str, str]] = []
    for item in packages:
        path = package_dir / str(item["filename"])
        if path.stat().st_size != int(item["size_bytes"]) or _sha(path) != str(item["sha256"]):
            raise RuntimeError(f"PentestAgent OS package checksum mismatch: {path.name}")
        versions.append((str(item["name"]), str(item["version"])))
    return aggregate, versions


def _build_arguments(
    name: str,
    envelope: Mapping[str, Any],
    *,
    dependency_hash: str,
    recipe_hash: str,
    adapter_hash: str,
) -> tuple[str, str, dict[str, str]]:
    source = envelope.get("source")
    if not isinstance(source, Mapping):
        raise RuntimeError(f"metadata source is invalid for {name}")
    commit = str(source["commit"])
    tree_hash = str(source["tree_hash"])
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{40}", tree_hash):
        raise RuntimeError(f"metadata source identity is invalid for {name}")
    args_for_build = {
        "ADAPTER_BUNDLE_HASH": adapter_hash,
        "DEPENDENCY_LOCK_HASH": dependency_hash,
        "GIT_TREE_HASH": tree_hash,
        "RECIPE_HASH": recipe_hash,
    }
    args_for_build["FRAMEWORK_COMMIT" if name == "VeriPlanPT" else "UPSTREAM_COMMIT"] = commit
    return commit, tree_hash, args_for_build


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", required=True, help="receipt-scoped envelope metadata")
    parser.add_argument("--staging-root", required=True)
    parser.add_argument("--output-baseline-lock", required=True)
    parser.add_argument("--output-native-identity", required=True)
    parser.add_argument("--output-relay-lock", default="")
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="reuse an already-tagged successor image after revalidating its labels",
    )
    args = parser.parse_args(argv)
    staging_root = Path(args.staging_root).resolve()
    if shutil.disk_usage(staging_root).free < 50 * 1024 ** 3:
        raise SystemExit("runtime image rebuild requires at least 50 GiB free disk")
    metadata_path = Path(args.metadata).resolve()
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    contexts, metadata_sha256 = _context_manifest(staging_root, metadata_path)
    envelopes = metadata["envelopes"]
    by_name = {str(item["name"]): item for item in envelopes}
    observed: list[dict[str, Any]] = []
    native: dict[str, Any] = {}
    for name, image in IMAGES.items():
        context = Path(str(contexts[name]["path"])).resolve()
        recipe = ROOT / ("docker/veriplanpt.Dockerfile" if name == "VeriPlanPT" else f"docker/baselines/{name}.Dockerfile")
        envelope = by_name[name]
        context_record = contexts[name]
        if context_record.get("source_commit") != envelope["source"]["commit"] or context_record.get("source_tree_hash") != envelope["source"]["tree_hash"]:
            raise RuntimeError(f"metadata/context source identity mismatch for {name}")
        adapter_paths = {
            "common": context / "adapter/provider_shim.py",
            "framework": next(context.joinpath("adapter").glob("framework-*.py")),
            "wrapper": context / "adapter/wrapper-wrapper.py",
            "runtime": context / "adapter/runtime_entrypoint.py",
            "client_driver": context / "adapter/baseline_client_driver.py",
            "readiness_transport": context / "adapter/readiness_transport_driver.py",
        }
        adapter_hash = _adapter_bundle_hash({key: str(path) for key, path in adapter_paths.items()}, "adapter-3.0")
        _lock_path, dependency_hash = _dependency_lock(context_record, envelope)
        recipe_hash = _sha(recipe)
        commit, tree_hash, args_for_build = _build_arguments(
            name, envelope, dependency_hash=dependency_hash, recipe_hash=recipe_hash, adapter_hash=adapter_hash,
        )
        os_package_hash = ""
        os_package_versions: list[tuple[str, str]] = []
        if name == "PentestAgent":
            os_package_hash, os_package_versions = _os_package_envelope(context, envelope)
            args_for_build["OS_PACKAGE_LOCK_HASH"] = os_package_hash
        command = ["docker", "build", "--network=none", "--pull=false", "--tag", image, "--file", str(recipe)]
        for key, value in sorted(args_for_build.items()):
            command.extend(["--build-arg", f"{key}={value}"])
        command.append(str(context))
        expected_labels = {
            "com.veriplanpt.upstream-commit": commit,
            "com.veriplanpt.git-tree-hash": tree_hash,
            "com.veriplanpt.adapter-bundle-hash": adapter_hash,
            "com.veriplanpt.dependency-lock-hash": dependency_hash,
            "com.veriplanpt.recipe-hash": recipe_hash,
        }
        if name == "PentestAgent":
            expected_labels["com.veriplanpt.os-package-lock-hash"] = os_package_hash
        existing = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            text=True,
            check=False,
        )
        reuse_existing = False
        if args.skip_existing and existing.returncode == 0:
            _, existing_labels = _inspect(image)
            reuse_existing = all(existing_labels.get(key) == value for key, value in expected_labels.items())
        if not reuse_existing:
            _build(command, image)
        digest, labels = _inspect(image)
        commit_label = labels.get("com.veriplanpt.upstream-commit")
        tree_label = labels.get("com.veriplanpt.git-tree-hash")
        if commit_label != commit or tree_label != tree_hash:
            raise RuntimeError(f"Docker labels do not match receipt-scoped metadata for {name}")
        for label_name, expected_value in expected_labels.items():
            if labels.get(label_name) != expected_value:
                raise RuntimeError(f"Docker label {label_name} does not match staged inputs for {name}")
        if name == "PentestAgent":
            expected = " ".join(f"{package}={version}" for package, version in os_package_versions)
            contract = (
                "set -eu; test -z \"$(dpkg --audit)\"; "
                f"for spec in {expected}; do package=\"${{spec%%=*}}\"; version=\"${{spec#*=}}\"; "
                "test \"$(dpkg-query -W -f='${Version}' \"$package\")\" = \"$version\"; done; "
                "git --version; work=$(mktemp -d); mkdir \"$work/src\"; "
                "git init \"$work/src\" >/dev/null; printf ok >\"$work/src/file\"; "
                "git -C \"$work/src\" -c user.name=offline -c user.email=offline@example.invalid add file; "
                "git -C \"$work/src\" -c user.name=offline -c user.email=offline@example.invalid commit -m offline >/dev/null; "
                "git clone \"file://$work/src\" \"$work/clone\" >/dev/null; test -f \"$work/clone/file\""
            )
            package_contract = subprocess.run(
                ["docker", "run", "--rm", "--network", "none", "--entrypoint", "/bin/sh", image, "-c", contract],
                capture_output=True, text=True, check=False,
            )
            if package_contract.returncode:
                raise RuntimeError(f"PentestAgent offline OS package contract failed: {(package_contract.stderr or package_contract.stdout).strip()[-2000:]}")
        identity = {
            "name": name, "image": image, "image_id": digest, "image_digest": digest,
            "adapter_bundle_hash": adapter_hash, "adapter_contract_version": "adapter-3.0",
            "dependency_lock_hash": dependency_hash, "recipe_hash": recipe_hash,
            "source_commit": commit, "source_tree_hash": tree_hash, "image_labels": labels,
            "metadata_sha256": metadata_sha256,
        }
        if name == "PentestAgent":
            identity["os_package_lock_hash"] = os_package_hash
        if name == "VeriPlanPT":
            native = {
                "schema_version": "2.0.0", "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "name": name, "source": {"path": str(envelope["source"]["path"]), "commit": commit, "tree_hash": tree_hash},
                "recipe": {"path": str(recipe), "sha256": recipe_hash},
                "adapter_bundle": {"sha256": adapter_hash, "contract_version": "adapter-3.0"},
                "dependency_lock": {"path": str(context / "envelope" / next((context / "envelope").iterdir()).name), "sha256": dependency_hash},
                "metadata_sha256": metadata_sha256, "image": identity,
            }
        else:
            observed.append({
                "name": name, "path": str(envelope["source"]["path"]), "repo_url": str(envelope["source"]["remote"]),
                "recipe_path": str(recipe), "build_context_path": str(context), "image": image,
                "input_hashes": envelope.get("input_hashes", {}),
                "dependency_lock_path": str(context / "envelope" / next((context / "envelope").iterdir()).name),
                "dependency_lock_hash": dependency_hash,
                "os_package_requirements": envelope.get("os_package_requirements", []),
                "adapter_bundle": {"common": str(adapter_paths["common"]), "framework": str(adapter_paths["framework"]),
                                   "wrapper": str(adapter_paths["wrapper"]), "runtime": str(adapter_paths["runtime"]),
                                   "client_driver": str(adapter_paths["client_driver"]),
                                   "contract_version": "adapter-3.0"},
            })
    relay_context = Path(str(contexts["gateway-relay"]["path"])).resolve()
    relay_recipe = relay_context / "Dockerfile"
    relay_source = relay_context / "relay/relay.py"
    relay_recipe_hash = _sha(relay_recipe)
    relay_source_hash = _sha(relay_source)
    relay_build = [
        "docker", "build", "--network=none", "--pull=false", "--tag", RELAY_IMAGE,
        "--file", str(relay_recipe), "--build-arg", f"HOST_UID={os.geteuid()}",
        "--build-arg", f"HOST_GID={os.getegid()}",
        "--build-arg", f"RECIPE_HASH={relay_recipe_hash}",
        "--build-arg", f"SOURCE_HASH={relay_source_hash}", str(relay_context),
    ]
    relay_existing = subprocess.run(
        ["docker", "image", "inspect", RELAY_IMAGE],
        capture_output=True,
        text=True,
        check=False,
    )
    if not (args.skip_existing and relay_existing.returncode == 0):
        _build(relay_build, RELAY_IMAGE)
    relay_digest, _relay_labels = _inspect(RELAY_IMAGE)
    relay_lock_path = Path(args.output_relay_lock or (staging_root / "gateway-relay.lock.json"))
    relay_lock_path.parent.mkdir(parents=True, exist_ok=True)
    relay_lock = {
        "schema_version": "1.0.0",
        "uid_policy": "host_euid_nonroot",
        "relay": {
            "image": RELAY_IMAGE, "image_digest": relay_digest,
            "alias": "gateway-relay", "endpoint": "http://gateway-relay:8080/v1/generate",
            "run_as": "host_uid_gid_nonroot",
            "recipe": {"path": str(relay_recipe.relative_to(staging_root)), "sha256": relay_recipe_hash},
            "source": {"path": str(relay_source.relative_to(staging_root)), "sha256": relay_source_hash},
        },
        "socket": {
            "path": "/run/veriplanpt-gateway/gateway.sock", "mode": "0600",
            "parent_mode": "0700", "mount_read_only": True,
        },
        "network": {"mode": "internal", "alias": "gateway-relay"},
        "baseline_socket_mount": False,
        "baseline_credentials": False,
    }
    relay_lock_path.write_text(json.dumps(relay_lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    Path(args.output_native_identity).write_text(json.dumps(native, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    inventory = Path(args.output_baseline_lock).with_suffix(".inventory.json")
    inventory.write_text(json.dumps({"schema_version": "1.0.0", "baselines": observed}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # The inventory is useful for audit, but it is not a lock.  Materialise the
    # strict lock requested by the caller only after all four baseline images
    # have been observed successfully.
    baseline_lock_path = Path(args.output_baseline_lock)
    baseline_specs = [item for item in observed if item["name"] != "VeriPlanPT"]
    baseline_lock = generate_baseline_lock(baseline_specs, output=baseline_lock_path)
    print(json.dumps({"images": len(IMAGES) + 1, "baseline_lock": str(baseline_lock_path), "baseline_count": len(baseline_lock["baselines"]), "inventory": str(inventory), "native_identity": str(args.output_native_identity), "relay_lock": str(relay_lock_path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
