from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scripts.build_wheelhouses import sha256_file, verified_reuse
from scripts.materialize_receipt_envelopes import materialize_receipt_scoped_metadata
from scripts.rebuild_runtime_images import _build_arguments, _context_manifest

ROOT = Path(__file__).resolve().parents[1]
R4_COMMIT = "ef3cf0e75009da453c2ef6c9f4edea3ee3b8ea8a"
R4_TREE = "316533abe53d7e9538fc4046a6548afdc125fddf"
R5_COMMIT = "5" * 40
R5_TREE = "6" * 40


def _receipt(*, framework_commit: str, framework_tree: str) -> dict[str, object]:
    sources: dict[str, dict[str, str]] = {}
    for index, name in enumerate(("runner", "dataset", "PentestAgent", "PentestGPT", "VulnBot", "HackSynth"), 1):
        sources[name] = {
            "remote": f"https://example.test/{name}", "tag_or_ref": f"release-{index}",
            "commit": f"{index:x}" * 40, "tree": f"{index + 1:x}" * 40,
        }
    sources["framework"] = {
        "remote": "https://github.com/dwuyn/framework.git", "tag_or_ref": "veriplanpt-runtime-v0.4.0-r5",
        "commit": framework_commit, "tree": framework_tree,
    }
    return {
        "schema_version": "2.0.0", "sources": sources,
        "dataset_freeze_manifest_hash": "a" * 64,
        "evaluator": {
            "release_root_hash": "b" * 64, "evaluator_bundle_hash": "c" * 64,
            "oracle_bundle_hash": "d" * 64, "commit": "e" * 40,
            "evaluator_image_digest": "sha256:" + "1" * 64,
            "oracle_image_digest": "sha256:" + "2" * 64,
            "feature_schema_hash": "f" * 64,
        },
        "signing_key_id": "3AEFBE29F67BC545",
        "verification_results": {"framework": True, "evaluator": True, "dataset": True},
    }


def _metadata() -> dict[str, object]:
    return json.loads((ROOT / "build/dependency-envelopes/envelopes.json").read_text(encoding="utf-8"))


def test_external_r4_and_r5_metadata_control_source_and_build_labels(tmp_path: Path) -> None:
    metadata = _metadata()
    for commit, tree in ((R4_COMMIT, R4_TREE), (R5_COMMIT, R5_TREE)):
        materialized = materialize_receipt_scoped_metadata(
            metadata, _receipt(framework_commit=commit, framework_tree=tree), framework_root=tmp_path / "framework",
        )
        framework = next(item for item in materialized["envelopes"] if item["name"] == "VeriPlanPT")
        baseline = next(item for item in materialized["envelopes"] if item["name"] == "PentestGPT")
        assert framework["source"]["commit"] == commit
        assert framework["source"]["tree_hash"] == tree
        assert _build_arguments(
            "VeriPlanPT", framework, dependency_hash="a" * 64, recipe_hash="b" * 64, adapter_hash="c" * 64,
        )[2]["FRAMEWORK_COMMIT"] == commit
        assert _build_arguments(
            "PentestGPT", baseline, dependency_hash="a" * 64, recipe_hash="b" * 64, adapter_hash="c" * 64,
        )[2]["UPSTREAM_COMMIT"] == baseline["source"]["commit"]


def test_metadata_context_sha_mismatch_fails_closed(tmp_path: Path) -> None:
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text(json.dumps({"envelopes": []}), encoding="utf-8")
    staging = tmp_path / "staging"
    manifest_dir = staging / "baseline-build-contexts"
    manifest_dir.mkdir(parents=True)
    manifest = {
        "schema_version": "1.1.0", "metadata": {"sha256": "0" * 64},
        "metadata_sha256": "0" * 64, "contexts": {},
    }
    (manifest_dir / "context-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(RuntimeError, match="metadata/context SHA-256 mismatch"):
        _context_manifest(staging, metadata_path)


def test_dependency_lock_drift_prevents_wheelhouse_reuse(tmp_path: Path) -> None:
    wheel = tmp_path / "package.whl"
    wheel.write_bytes(b"wheelhouse\n")
    manifest = {
        "dependency_lock_sha256": "a" * 64,
        "files": [{"filename": wheel.name, "size": wheel.stat().st_size, "sha256": sha256_file(wheel)}],
    }
    assert verified_reuse(wheel.parent, manifest, "a" * 64)
    assert not verified_reuse(wheel.parent, copy.deepcopy(manifest), "b" * 64)
