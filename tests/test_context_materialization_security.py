from __future__ import annotations

import subprocess

import pytest

from scripts.prepare_docker_contexts import materialize_git_tree, scan_context


def _repo(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    subprocess.run(["git", "add", "tracked.txt"], cwd=source, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "initial"],
        cwd=source,
        check=True,
    )
    return source


def test_materialization_uses_pinned_git_tree_and_ignores_untracked_files(tmp_path) -> None:
    source = _repo(tmp_path)
    (source / ".env").write_text("SECRET=must-not-stage\n", encoding="utf-8")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=source, text=True).strip()
    destination = tmp_path / "destination"
    destination.mkdir()

    materialize_git_tree(source, destination, commit=commit, tree=tree)

    assert (destination / "tracked.txt").read_text(encoding="utf-8") == "tracked\n"
    assert not (destination / ".env").exists()


def test_materialization_rejects_identity_drift(tmp_path) -> None:
    source = _repo(tmp_path)
    destination = tmp_path / "destination"
    destination.mkdir()

    with pytest.raises(SystemExit, match="pinned source"):
        materialize_git_tree(source, destination, commit="0" * 40, tree="1" * 40)


def test_scan_context_rejects_secret_and_link_material(tmp_path) -> None:
    root = tmp_path / "context"
    root.mkdir()
    (root / ".env").write_text("SECRET=1\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="security gate failed"):
        scan_context(root)

    (root / ".env").unlink()
    (root / "tracked.txt").write_text("data\n", encoding="utf-8")
    (root / "alias.txt").symlink_to(root / "tracked.txt")
    with pytest.raises(SystemExit, match="security gate failed"):
        scan_context(root)
