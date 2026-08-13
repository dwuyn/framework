from __future__ import annotations

import subprocess
from types import SimpleNamespace

from src.pipeline import baseline_lock


def _git_repo(tmp_path):
    root = tmp_path / "detached"
    root.mkdir()
    (root / ".gitignore").write_text("cache/\n")
    (root / "Dockerfile").write_text("FROM python:3.12@sha256:abc\n")
    (root / "context.txt").write_text("tracked\n")
    (root / "common.py").write_text("common\n")
    (root / "framework.py").write_text("framework\n")
    (root / "wrapper.py").write_text("wrapper\n")
    (root / "runtime.py").write_text("runtime\n")
    (root / "client_driver.py").write_text("client driver\n")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
         "commit", "-qm", "initial"],
        cwd=root,
        check=True,
    )
    return root


def _specs(root):
    return [
        {
            "name": name,
            "path": str(root),
            "recipe_path": str(root / "Dockerfile"),
            "build_context_path": str(root),
            "image": f"veriplanpt/{name.lower()}:locked",
            "adapter_bundle": {
                "common": str(root / "common.py"),
                "framework": str(root / "framework.py"),
                "wrapper": str(root / "wrapper.py"),
                "runtime": str(root / "runtime.py"),
                "client_driver": str(root / "client_driver.py"),
                "contract_version": "adapter-3.0",
            },
        }
        for name in ("PentestAgent", "PentestGPT", "VulnBot", "HackSynth")
    ]


def test_git_tree_hash_ignores_ignored_cache_and_bundle_hash_is_complete(tmp_path, monkeypatch):
    root = _git_repo(tmp_path)
    real_run = baseline_lock.subprocess.run

    def fake_run(command, *args, **kwargs):
        if command[:2] == ["docker", "image"]:
            return SimpleNamespace(returncode=0, stdout="sha256:" + "a" * 64 + "\n", stderr="")
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr(baseline_lock.subprocess, "run", fake_run)
    first = baseline_lock.generate_baseline_lock(_specs(root))
    (root / "cache").mkdir()
    (root / "cache" / "ignored.bin").write_bytes(b"runtime cache")
    second = baseline_lock.generate_baseline_lock(_specs(root))
    assert first == second
    assert first["baselines"][0]["tree_hash_kind"] == "git_tree_object"
    assert "adapter_bundle_hash" in first["baselines"][0]
    assert "docker_recipe_hash" in first["baselines"][0]
    assert "build_context_tree_hash" in first["baselines"][0]


def test_adapter_bundle_hash_changes_with_contract_version(tmp_path):
    paths = {}
    for role in ("common", "framework", "wrapper", "runtime", "client_driver"):
        path = tmp_path / f"{role}.py"
        path.write_text(role)
        paths[role] = str(path)
    first = baseline_lock._adapter_bundle_hash(paths, "adapter-3.0")
    second = baseline_lock._adapter_bundle_hash(paths, "adapter-3.1")
    assert first != second
