#!/usr/bin/env python3
"""Materialize a hash-verified wheelhouse from a read-only package cache."""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
from pathlib import Path

PACKAGE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s\\]+)")
DIRECT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)\s+@\s+(\S+)")
HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _requirements(lock: Path) -> list[tuple[str, str, set[str], str]]:
    records: list[tuple[str, str, set[str], str]] = []
    current: tuple[str, str, set[str], str] | None = None
    for line in lock.read_text(encoding="utf-8").splitlines():
        match = PACKAGE.match(line)
        if match:
            if current is not None:
                records.append(current)
            current = (match.group(1), match.group(2), set(HASH.findall(line)), "")
            continue
        direct = DIRECT.match(line)
        if direct:
            if current is not None:
                records.append(current)
            filename = direct.group(2).split("#", 1)[0].rsplit("/", 1)[-1]
            current = (direct.group(1), filename, set(HASH.findall(line)), filename)
            continue
        if current is not None:
            current[2].update(HASH.findall(line))
    if current is not None:
        records.append(current)
    if not records or any(not hashes for _, _, hashes, _filename in records):
        raise ValueError("lock contains a package without SHA-256 hashes")
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True)
    parser.add_argument("--source", action="append", required=True)
    parser.add_argument("--destination", required=True)
    args = parser.parse_args()
    lock = Path(args.lock).resolve()
    sources = [Path(value).resolve() for value in args.source]
    destination = Path(args.destination).resolve()
    for source in sources:
        if not source.is_dir():
            raise SystemExit(f"package cache is missing: {source}")
    if destination.exists() and any(destination.iterdir()):
        raise SystemExit(f"refusing to overwrite wheelhouse: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    files = [
        path for source in sources
        for path in source.iterdir()
        if path.is_file() and not path.is_symlink()
    ]
    copied: list[str] = []
    for name, version, hashes, filename_hint in _requirements(lock):
        normalized_name = re.sub(r"[-_.]+", "-", name).lower()
        normalized_version = re.sub(r"[-_.]+", "-", version.lower())
        matches = {
            (path.name, _sha256(path)): path for path in files
            if re.sub(r"[-_.]+", "-", path.name.lower()).startswith(
                f"{normalized_name}-{normalized_version}"
            )
            and _sha256(path) in hashes
        }
        if filename_hint:
            matches = {
                (path.name, _sha256(path)): path for path in files
                if path.name == filename_hint and _sha256(path) in hashes
            }
        if len(matches) != 1:
            raise SystemExit(
                f"cache does not contain exactly one hash-verified artifact for {name}=={version}: "
                f"{[name for name, _hash in matches]}"
            )
        selected = next(iter(matches.values()))
        shutil.copyfile(selected, destination / selected.name)
        copied.append(selected.name)
    print(f"materialized {len(copied)} hash-verified artifacts into {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
