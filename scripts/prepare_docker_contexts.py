#!/usr/bin/env python3
"""Stage source, adapter, lock and wheelhouse inputs outside Git."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
_FORBIDDEN_PATHS = (
    re.compile(r"(^|/)\.env(?:$|\.(?!example(?:$|/)))", re.IGNORECASE),
    re.compile(r"(^|/)(?:application_default_credentials\.json|credentials\.json|google-key\.json)$", re.IGNORECASE),
    re.compile(r"(^|/)(?:service[_-]?account.*\.json|.*-key\.json)$", re.IGNORECASE),
    re.compile(r"\.pem$", re.IGNORECASE),
    re.compile(r"(^|/)\.config/gcloud(?:/|$)", re.IGNORECASE),
    re.compile(r"(^|/)docker\.sock$", re.IGNORECASE),
    re.compile(r"(^|/)(?:hidden|truth|oracle_truth|evaluator_truth)(?:/|$)", re.IGNORECASE),
    re.compile(r"(^|/)(?:hidden|truth|oracle)[_-].*\.json$", re.IGNORECASE),
)


def _run_git(source: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(source), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise SystemExit(f"pinned source Git query failed: {result.stderr.strip()[-1000:]}")
    return result.stdout.strip()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _forbidden_path(relative: str) -> str | None:
    for pattern in _FORBIDDEN_PATHS:
        if pattern.search(relative):
            return pattern.pattern
    return None


def _scan_json_secret(path: Path, relative: str) -> str | None:
    if path.suffix.lower() != ".json":
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if isinstance(value, dict) and value.get("type") == "service_account" and "private_key" in value:
        return f"service-account credential material at {relative}"
    return None


def scan_context(root: Path) -> None:
    """Fail closed on credential, hidden-truth, socket, and link material."""
    violations: list[str] = []
    seen_inodes: set[tuple[int, int]] = set()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        reason = _forbidden_path(relative)
        if reason:
            violations.append(f"{relative}: forbidden path")
            continue
        info = path.lstat()
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            violations.append(f"{relative}: symlink or special file")
            continue
        if path.is_file():
            inode = (info.st_dev, info.st_ino)
            if inode in seen_inodes:
                violations.append(f"{relative}: hardlink alias")
            seen_inodes.add(inode)
            secret = _scan_json_secret(path, relative)
            if secret:
                violations.append(secret)
    if violations:
        raise SystemExit("derived context security gate failed: " + "; ".join(violations[:20]))


def materialize_git_tree(source: Path, destination: Path, *, commit: str, tree: str) -> None:
    """Extract only the pinned Git tree; ignored/untracked files are unreachable."""
    if not source.is_dir() or not destination.is_dir():
        raise SystemExit("Git source and destination directories are required")
    if any(destination.iterdir()):
        raise SystemExit(f"refusing to overwrite materialized source: {destination}")
    if _run_git(source, "rev-parse", "--is-inside-work-tree") != "true":
        raise SystemExit(f"source is not a Git worktree: {source}")
    resolved_commit = _run_git(source, "rev-parse", f"{commit}^{{commit}}")
    resolved_tree = _run_git(source, "rev-parse", f"{resolved_commit}^{{tree}}")
    if resolved_commit != commit or resolved_tree != tree:
        raise SystemExit(
            f"pinned source identity mismatch for {source}: "
            f"commit={resolved_commit} tree={resolved_tree}"
        )
    process = subprocess.Popen(
        ["git", "-C", str(source), "archive", "--format=tar", resolved_commit],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for member in archive:
                relative = Path(member.name).as_posix()
                if relative.startswith("/") or ".." in Path(relative).parts:
                    raise SystemExit(f"Git archive contains unsafe path: {relative}")
                if _forbidden_path(relative):
                    raise SystemExit(f"Git archive contains forbidden path: {relative}")
                target = destination / relative
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=False)
                    continue
                if not member.isfile():
                    raise SystemExit(f"Git archive contains symlink or special file: {relative}")
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                if stream is None:
                    raise SystemExit(f"Git archive member cannot be read: {relative}")
                with target.open("xb") as output:
                    shutil.copyfileobj(stream, output)
                target.chmod(member.mode & 0o777)
    finally:
        process.stdout.close()
    stderr = process.stderr.read().decode("utf-8", errors="replace") if process.stderr else ""
    return_code = process.wait()
    if return_code:
        raise SystemExit(f"Git archive failed: {stderr.strip()[-1000:]}")


def copy_from_materialized_source(source_root: Path, source_path: Path, destination: Path, *, repo: Path) -> None:
    relative = source_path.resolve().relative_to(repo.resolve())
    source = source_root / relative
    if not source.is_file() or source.is_symlink():
        raise SystemExit(f"pinned adapter file is not present in Git archive: {relative}")
    shutil.copyfile(source, destination)


def copy_from_git_object(repo: Path, source_path: Path, destination: Path, *, commit: str) -> None:
    """Materialize one shared file from a verified Git object, never worktree bytes."""
    relative = source_path.resolve().relative_to(repo.resolve()).as_posix()
    result = subprocess.run(
        ["git", "-C", str(repo), "show", f"{commit}:{relative}"],
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise SystemExit(f"pinned shared adapter file is not present in Git object: {relative}")
    destination.write_bytes(result.stdout)


def materialize_lock(lock: Path, wheelhouse: Path, destination: Path) -> None:
    text = lock.read_text(encoding="utf-8")
    for url in sorted(set(re.findall(r"https?://[^\s\\]+", text))):
        filename = url.split("#", 1)[0].rsplit("/", 1)[-1]
        if (wheelhouse / filename).is_file():
            text = text.replace(url, f"file:///opt/wheelhouse/{filename}")
    destination.write_text(text, encoding="utf-8")


def materialize_os_package_envelope(lock: Path, package_root: Path, context: Path) -> dict[str, Any]:
    """Copy only the hash-verified Debian packages selected by the lock."""
    lock_hash = _sha256_file(lock)
    lock_value = json.loads(lock.read_text(encoding="utf-8"))
    if lock_value.get("aggregate_lock_hash") is None or not isinstance(lock_value.get("packages"), list):
        raise SystemExit("OS package lock is malformed")
    destination = context / "os-packages"
    destination.mkdir(parents=True, exist_ok=False)
    for package in lock_value["packages"]:
        filename = str(package["filename"])
        source = package_root / filename
        if not source.is_file() or source.is_symlink():
            raise SystemExit(f"OS package is missing: {source}")
        if source.stat().st_size != int(package["size_bytes"]) or _sha256_file(source) != str(package["sha256"]):
            raise SystemExit(f"OS package checksum mismatch: {source}")
        shutil.copyfile(source, destination / filename)
    shutil.copyfile(lock, context / "os-packages.lock.json")
    return {
        "lock_path": str(context / "os-packages.lock.json"),
        "lock_sha256": lock_hash,
        "aggregate_lock_hash": str(lock_value["aggregate_lock_hash"]),
        "package_count": len(lock_value["packages"]),
        "package_root": str(destination),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", default=str(ROOT / "build/dependency-envelopes/envelopes.json"))
    parser.add_argument("--staging-root", required=True,
                        help="new, empty staging root; historical contexts are never reused")
    parser.add_argument("--wheelhouse-root", required=True,
                        help="read-only verified wheelhouse root containing one directory per framework")
    parser.add_argument("--os-package-root", default="",
                        help="read-only host directory containing the locked Debian packages")
    args = parser.parse_args()
    metadata_path = Path(args.metadata).resolve()
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata_sha256 = _sha256_file(metadata_path)
    artifact_root = Path(args.staging_root).resolve()
    wheelhouse_root = Path(args.wheelhouse_root).resolve()
    os_package_root = Path(args.os_package_root).resolve() if args.os_package_root else None
    if artifact_root == wheelhouse_root or artifact_root in wheelhouse_root.parents:
        raise SystemExit("staging root must not overlap the verified wheelhouse root")
    if artifact_root.exists() and any(artifact_root.iterdir()):
        raise SystemExit("staging root must be new and empty")
    artifact_root.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "schema_version": "1.1.0",
        "metadata": {"path": str(metadata_path), "sha256": metadata_sha256},
        "metadata_sha256": metadata_sha256,
        "contexts": {},
    }
    framework_envelope = next(
        item for item in metadata["envelopes"] if str(item["name"]) == "VeriPlanPT"
    )
    framework_repo = Path(str(framework_envelope["source"]["path"])).resolve()
    framework_commit = str(framework_envelope["source"]["commit"])
    _run_git(framework_repo, "rev-parse", f"{framework_commit}^{{commit}}")
    for envelope in metadata["envelopes"]:
        name = str(envelope["name"])
        context = artifact_root / "baseline-build-contexts" / name
        if context.exists():
            raise SystemExit(f"refusing to overwrite staged context: {context}")
        for directory in (context / "source", context / "envelope", context / "adapter", context / "wheelhouse"):
            directory.mkdir(parents=True, exist_ok=True)
        source_repo = Path(str(envelope["source"]["path"])).resolve()
        materialize_git_tree(
            source_repo,
            context / "source",
            commit=str(envelope["source"]["commit"]),
            tree=str(envelope["source"]["tree_hash"]),
        )
        lock = ROOT / str(envelope["dependency_lock"]["path"])
        wheelhouse = wheelhouse_root / name
        if not wheelhouse.is_dir():
            raise SystemExit(f"wheelhouse missing for {name}: {wheelhouse}")
        materialize_lock(lock, wheelhouse, context / "envelope" / lock.name)
        for wheel in wheelhouse.iterdir():
            if wheel.is_file():
                shutil.copyfile(wheel, context / "wheelhouse" / wheel.name)
        os_package_record: dict[str, Any] | None = None
        if envelope.get("os_package_envelope") is not None:
            if os_package_root is None:
                raise SystemExit("--os-package-root is required for an OS package envelope")
            os_lock = ROOT / str(envelope["os_package_envelope"]["lock_path"])
            expected_lock_hash = str(envelope["os_package_envelope"]["lock_sha256"])
            if _sha256_file(os_lock) != expected_lock_hash:
                raise SystemExit(f"OS package lock hash mismatch: {os_lock}")
            os_package_record = materialize_os_package_envelope(os_lock, os_package_root, context)
        for role, source_path in dict(envelope["adapter_paths"]).items():
            source = Path(str(source_path))
            destination = context / "adapter" / f"{role}-{source.name}"
            try:
                source.resolve().relative_to(source_repo)
            except ValueError:
                # Adapter code is first-party and must come from the pinned
                # framework Git object, even when the runtime source is an
                # external baseline tree.
                copy_from_git_object(framework_repo, source, destination, commit=framework_commit)
            else:
                copy_from_materialized_source(context / "source", source, destination, repo=source_repo)
        for adapter_name in (
            "provider_shim.py", "entrypoint.sh", "runtime_entrypoint.py", "baseline_driver.py",
            "baseline_client_driver.py", "readiness_transport_driver.py",
        ):
            copy_from_git_object(
                framework_repo, ROOT / "docker/adapter" / adapter_name,
                context / "adapter" / adapter_name, commit=framework_commit,
            )
        manifest["contexts"][name] = {
            "path": str(context),
            "source_commit": envelope["source"]["commit"],
            "source_tree_hash": envelope["source"]["tree_hash"],
            "dependency_lock_sha256": envelope["dependency_lock"]["sha256"],
            "dependency_lock": str(context / "envelope" / lock.name),
            "wheelhouse": str(context / "wheelhouse"),
        }
        if os_package_record is not None:
            manifest["contexts"][name]["os_package_envelope"] = os_package_record
    relay_context = artifact_root / "gateway-relay-context"
    if relay_context.exists():
        raise SystemExit(f"refusing to overwrite staged relay context: {relay_context}")
    (relay_context / "relay").mkdir(parents=True, exist_ok=False)
    shutil.copyfile(ROOT / "docker/relay/relay.py", relay_context / "relay/relay.py")
    shutil.copyfile(ROOT / "docker/gateway-relay.Dockerfile", relay_context / "Dockerfile")
    manifest["contexts"]["gateway-relay"] = {
        "path": str(relay_context),
        "recipe": str(relay_context / "Dockerfile"),
        "source": str(relay_context / "relay/relay.py"),
    }
    scan_context(artifact_root)
    output = artifact_root / "baseline-build-contexts" / "context-manifest.json"
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "contexts": len(manifest["contexts"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
