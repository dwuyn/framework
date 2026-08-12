#!/usr/bin/env python3
"""Materialize dependency envelopes scoped to a verified source receipt.

The committed envelope is a template for dependency and recipe inputs.  A
receipt-scoped envelope replaces only source identities and local framework
paths.  Dependency-lock records are copied byte-for-byte so a source receipt
cannot silently select a different wheelhouse.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RECEIPT_SOURCES = {
    "VeriPlanPT": "framework",
    "PentestAgent": "PentestAgent",
    "PentestGPT": "PentestGPT",
    "VulnBot": "VulnBot",
    "HackSynth": "HackSynth",
}
REQUIRED_RECEIPT_SOURCES = {"framework", "runner", "dataset", "PentestAgent", "PentestGPT", "VulnBot", "HackSynth"}
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RECEIPT_SIGNING_KEY_ID = "3AEFBE29F67BC545"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _canonical_receipt_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    schema_version = str(value["schema_version"])
    payload: dict[str, Any] = {
        "schema_version": schema_version,
        "sources": {
            str(name): {
                "remote": str(source["remote"]), "tag_or_ref": str(source["tag_or_ref"]),
                "commit": str(source["commit"]), "tree": str(source["tree"]),
            }
            for name, source in dict(value["sources"]).items()
        },
        "dataset_freeze_manifest_hash": str(value["dataset_freeze_manifest_hash"]),
        "evaluator": {
            field: str(value["evaluator"][field])
            for field in (
                "release_root_hash", "evaluator_bundle_hash", "oracle_bundle_hash", "commit",
                "evaluator_image_digest", "oracle_image_digest", "feature_schema_hash",
            )
        },
        "signing_key_id": str(value["signing_key_id"]),
        "verification_results": {
            str(name): bool(result) for name, result in dict(value["verification_results"]).items()
        },
    }
    if schema_version == "2.1.0":
        payload.update({
            "source_snapshot_hash": str(value["source_snapshot_hash"]),
            "source_snapshot_manifest_hash": str(value["source_snapshot_manifest_hash"]),
            "source_snapshot_signature_hash": str(value["source_snapshot_signature_hash"]),
        })
    return payload


def _require_hash(value: Any, pattern: re.Pattern[str], name: str) -> str:
    result = str(value)
    if not pattern.fullmatch(result):
        raise ValueError(f"{name} has an invalid hash")
    return result


def validate_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the runner's canonical receipt shape without importing runner code."""
    schema_version = str(value.get("schema_version", ""))
    if schema_version not in {"2.0.0", "2.1.0"}:
        raise ValueError("source receipt schema_version must be 2.0.0 or 2.1.0")
    raw_sources = value.get("sources")
    if not isinstance(raw_sources, Mapping) or set(raw_sources) != REQUIRED_RECEIPT_SOURCES:
        raise ValueError("source receipt source set is incomplete or contains extra sources")
    for name, raw_source in raw_sources.items():
        if not isinstance(raw_source, Mapping):
            raise TypeError(f"source identity is not an object: {name}")
        remote = str(raw_source.get("remote", ""))
        ref = str(raw_source.get("tag_or_ref", ""))
        if not remote.startswith(("https://", "git@")) or not ref or any(char.isspace() for char in ref):
            raise ValueError(f"source identity has an invalid remote/ref: {name}")
        _require_hash(raw_source.get("commit"), SHA1, f"{name} commit")
        _require_hash(raw_source.get("tree"), SHA1, f"{name} tree")
    _require_hash(value.get("dataset_freeze_manifest_hash"), SHA256, "dataset freeze manifest hash")
    evaluator = value.get("evaluator")
    if not isinstance(evaluator, Mapping):
        raise TypeError("source receipt evaluator identity must be an object")
    for field in ("release_root_hash", "evaluator_bundle_hash", "oracle_bundle_hash", "feature_schema_hash"):
        _require_hash(evaluator.get(field), SHA256, f"evaluator {field}")
    _require_hash(evaluator.get("commit"), SHA1, "evaluator commit")
    _require_hash(evaluator.get("evaluator_image_digest"), IMAGE_DIGEST, "evaluator image digest")
    _require_hash(evaluator.get("oracle_image_digest"), IMAGE_DIGEST, "oracle image digest")
    results = value.get("verification_results")
    if not isinstance(results, Mapping) or not results or not all(item is True for item in results.values()):
        raise ValueError("source receipt requires successful verification results")
    if str(value.get("signing_key_id", "")) != RECEIPT_SIGNING_KEY_ID:
        raise ValueError(f"source receipt must use signing key {RECEIPT_SIGNING_KEY_ID}")
    if schema_version == "2.1.0":
        for field in (
            "source_snapshot_hash", "source_snapshot_manifest_hash", "source_snapshot_signature_hash",
        ):
            _require_hash(value.get(field), SHA256, f"source receipt {field}")
    expected = value.get("receipt_hash")
    actual = canonical_hash(_canonical_receipt_payload(value))
    if expected is not None and _require_hash(expected, SHA256, "source receipt hash") != actual:
        raise ValueError("source receipt hash mismatch")
    return dict(value)


def verify_detached_signature(receipt: Path, signature: Path, public_key: Path) -> None:
    if not signature.is_file() or not public_key.is_file():
        raise ValueError("receipt signature and public key must be regular files")
    minisign = shutil.which("minisign")
    if minisign is None:
        raise ValueError("minisign is required to verify the source receipt signature")
    result = subprocess.run(
        [minisign, "-Vm", str(receipt), "-p", str(public_key), "-x", str(signature)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()[-1000:]
        raise ValueError(f"source receipt signature verification failed: {detail}")


def _rebase_framework_path(path: str, old_framework_root: Path, framework_root: Path) -> str:
    candidate = Path(path)
    try:
        relative = candidate.resolve().relative_to(old_framework_root.resolve())
    except ValueError:
        return path
    return str((framework_root / relative).resolve())


def materialize_receipt_scoped_metadata(
    metadata: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    framework_root: Path = ROOT,
) -> dict[str, Any]:
    """Return metadata with receipt-pinned source identities and unchanged locks."""
    validated_receipt = validate_receipt(receipt)
    envelopes = metadata.get("envelopes")
    expected_names = set(RECEIPT_SOURCES)
    if not isinstance(envelopes, list) or {str(item.get("name")) for item in envelopes} != expected_names:
        raise ValueError("envelope metadata must contain exactly five runtime envelopes")
    framework_item = next(item for item in envelopes if str(item["name"]) == "VeriPlanPT")
    old_framework_root = Path(str(framework_item["source"]["path"])).resolve()
    output = copy.deepcopy(dict(metadata))
    for envelope in output["envelopes"]:
        name = str(envelope["name"])
        receipt_name = RECEIPT_SOURCES[name]
        source = envelope.get("source")
        if not isinstance(source, dict):
            raise ValueError(f"envelope source is not an object: {name}")
        receipt_source = validated_receipt["sources"][receipt_name]
        lock = envelope.get("dependency_lock")
        if not isinstance(lock, dict) or not SHA256.fullmatch(str(lock.get("sha256", ""))):
            raise ValueError(f"dependency lock hash is missing or invalid: {name}")
        original_lock = copy.deepcopy(lock)
        source.update({
            "remote": receipt_source["remote"],
            "tag_or_ref": receipt_source["tag_or_ref"],
            "commit": receipt_source["commit"],
            "tree_hash": receipt_source["tree"],
        })
        if name == "VeriPlanPT":
            source["path"] = str(framework_root.resolve())
        else:
            source["path"] = str(Path(str(source["path"])).resolve())
        envelope["recipe_path"] = _rebase_framework_path(
            str(envelope["recipe_path"]), old_framework_root, framework_root,
        )
        envelope["adapter_paths"] = {
            role: _rebase_framework_path(str(path), old_framework_root, framework_root)
            for role, path in dict(envelope["adapter_paths"]).items()
        }
        if envelope["dependency_lock"] != original_lock:
            raise ValueError(f"dependency lock changed while materializing {name}")
    receipt_metadata: dict[str, str] = {
        "schema_version": str(validated_receipt["schema_version"]),
        "receipt_hash": validated_receipt.get("receipt_hash") or canonical_hash(
            _canonical_receipt_payload(validated_receipt),
        ),
    }
    if str(validated_receipt["schema_version"]) == "2.1.0":
        receipt_metadata.update({
            field: str(validated_receipt[field])
            for field in (
                "source_snapshot_hash", "source_snapshot_manifest_hash", "source_snapshot_signature_hash",
            )
        })
    output["receipt"] = receipt_metadata
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", required=True, type=Path, help="committed r4/r5 envelope template")
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--framework-root", type=Path, default=ROOT)
    parser.add_argument("--receipt-signature", required=True, type=Path)
    parser.add_argument("--receipt-public-key", required=True, type=Path)
    args = parser.parse_args(argv)
    receipt_value = json.loads(args.receipt.read_text(encoding="utf-8"))
    validated_receipt = validate_receipt(receipt_value)
    verify_detached_signature(args.receipt, args.receipt_signature, args.receipt_public_key)
    metadata_value = json.loads(args.metadata.read_text(encoding="utf-8"))
    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"refusing to overwrite receipt-scoped metadata: {output}")
    materialized = materialize_receipt_scoped_metadata(
        metadata_value, validated_receipt, framework_root=args.framework_root.resolve(),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(materialized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "metadata_sha256": sha256_file(output), "receipt_hash": materialized["receipt"]["receipt_hash"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
