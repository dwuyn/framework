#!/usr/bin/env python3
"""Generate reproducible dependency envelopes from read-only upstream trees."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
CPU_REPLACEMENTS = {
    "torch": "torch==2.3.0+cpu",
    "torchvision": "torchvision==0.18.0+cpu",
    "torchaudio": "torchaudio==2.3.0+cpu",
}
CPU_REMOVED_PREFIXES = ("nvidia-",)
CPU_REMOVED_NAMES = {"triton"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git(path: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed for {path}: {result.stderr.strip()}")
    return result.stdout.strip()


def _run(command: list[str], *, cwd: Path) -> str:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()[-4_000:]
        raise RuntimeError(f"{' '.join(command)} failed: {detail}")
    return result.stdout


def _poetry_check(source: Path) -> str:
    candidates = [shutil.which("poetry"), "/home/dwyn/.pyenv/versions/3.12.12/bin/poetry"]
    last_error = "poetry executable was not found"
    for candidate in candidates:
        if not candidate or not Path(candidate).exists():
            continue
        result = subprocess.run([candidate, "check", "--lock"], cwd=source, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            return candidate
        last_error = (result.stderr or result.stdout).strip()
    raise RuntimeError(f"Poetry lock verification failed in {source}: {last_error}")


def _input_hashes(source: Path, paths: list[str]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative in paths:
        path = source / relative
        if not path.is_file():
            raise FileNotFoundError(f"dependency input is missing: {path}")
        hashes[relative] = sha256_file(path)
    return hashes


def _cpu_input(source: Path, destination: Path) -> dict[str, Any]:
    removed: list[str] = []
    replacements: dict[str, str] = {}
    output: list[str] = ["--extra-index-url https://download.pytorch.org/whl/cpu"]
    for raw_line in (source / "requirements.txt").read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            output.append(raw_line)
            continue
        name = stripped.split("==", 1)[0].split("[", 1)[0].strip().lower()
        if name.startswith(CPU_REMOVED_PREFIXES) or name in CPU_REMOVED_NAMES:
            removed.append(name)
            continue
        if name in CPU_REPLACEMENTS:
            output.append(CPU_REPLACEMENTS[name])
            replacements[name] = CPU_REPLACEMENTS[name]
            continue
        output.append(raw_line)
    destination.write_text("\n".join(output) + "\n", encoding="utf-8")
    return {
            "input_path": str(destination),
        "input_sha256": sha256_file(destination),
        "removed_packages": sorted(set(removed)),
        "replaced_packages": replacements,
        "added_index": "https://download.pytorch.org/whl/cpu",
    }


def _compile(input_path: Path, output_path: Path, *, extra_cpu_index: bool = False) -> None:
    command = [
        "uv", "pip", "compile", str(input_path),
        "--python-version", "3.11",
        "--python-platform", "x86_64-unknown-linux-gnu",
        "--generate-hashes",
        "--no-annotate",
        "--custom-compile-command", "uv 0.11.28 pip compile <input>",
        "--output-file", str(output_path),
    ]
    if extra_cpu_index:
        command.extend(["--index-strategy", "unsafe-best-match"])
    _run(command, cwd=ROOT)


def _source_record(source: Path, config: Mapping[str, Any]) -> dict[str, Any]:
    remotes = git(source, "remote", "-v").splitlines()
    observed_remote = next((line.split()[1] for line in remotes if "(fetch)" in line), "")
    expected_remote = str(config.get("repo_url", ""))
    if expected_remote and observed_remote and expected_remote != observed_remote:
        raise RuntimeError(f"remote mismatch for {source}: {observed_remote} != {expected_remote}")
    return {
        "path": str(source),
        "remote": expected_remote or observed_remote,
        "commit": git(source, "rev-parse", "HEAD"),
        "tree_hash": git(source, "rev-parse", "HEAD^{tree}"),
    }


def _envelope(name: str, config: Mapping[str, Any], target: Mapping[str, Any]) -> dict[str, Any]:
    source = (ROOT / str(config["source_path"])).resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"source tree is missing for {name}: {source}")
    source_record = _source_record(source, config)
    source_dirty = bool(git(source, "status", "--porcelain", "--untracked-files=all"))
    if name != "VeriPlanPT" and source_dirty:
        raise RuntimeError(f"upstream source tree is dirty: {source}")
    destination = ROOT / "build" / "dependency-envelopes" / name
    destination.mkdir(parents=True, exist_ok=True)
    input_hashes = _input_hashes(source, [str(item) for item in config["input_paths"]])
    delta: dict[str, Any] = {}

    if name == "PentestAgent":
        poetry_path = source / "poetry.lock"
        _poetry_check(source)
        shutil.copyfile(poetry_path, destination / "poetry.lock")
        _compile(source / "pyproject.toml", destination / "requirements.lock")
        lock_format = "poetry-source+uv-requirements"
        source_lock_hash = sha256_file(poetry_path)
    elif name == "HackSynth":
        with tempfile.TemporaryDirectory(prefix="veriplanpt-hacksynth-") as temp:
            cpu_input = Path(temp) / "requirements.cpu.in"
            delta = _cpu_input(source, cpu_input)
            shutil.copyfile(cpu_input, destination / "requirements.cpu.in")
            delta["input_path"] = str((destination / "requirements.cpu.in").relative_to(ROOT))
            _compile(cpu_input, destination / "requirements.cpu.lock", extra_cpu_index=True)
        lock_format = "requirements-cpu"
        source_lock_hash = ""
    else:
        input_path = source / "requirements.txt"
        shutil.copyfile(input_path, destination / "requirements.in")
        _compile(input_path, destination / "requirements.lock")
        lock_format = "requirements"
        source_lock_hash = ""

    lock_name = "requirements.cpu.lock" if name == "HackSynth" else "requirements.lock"
    lock_path = destination / lock_name
    return {
        "name": name,
        "target": dict(target),
        "source": source_record,
        "input_hashes": input_hashes,
        "source_dependency_lock_sha256": source_lock_hash,
        "dependency_lock": {
            "path": str(lock_path.relative_to(ROOT)),
            "sha256": sha256_file(lock_path),
            "format": lock_format,
            "hashed": True,
        },
        "os_package_requirements": [str(item) for item in config.get("os_package_requirements", [])],
        "recipe_path": str((ROOT / str(config["recipe_path"])).resolve()),
        "adapter_paths": {
            role: str((ROOT / str(path)).resolve())
            for role, path in dict(config["adapter_paths"]).items()
        },
        "build_delta": delta,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=str(ROOT / "build" / "envelope-config.json"))
    parser.add_argument("--output", default=str(ROOT / "build" / "dependency-envelopes" / "envelopes.json"))
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    target = json.loads((ROOT / str(config["target"])).read_text(encoding="utf-8"))
    entries = [_envelope("VeriPlanPT", config["framework"], target)]
    entries.extend(_envelope(str(item["name"]), item, target) for item in config["baselines"])
    result = {"schema_version": "1.0.0", "target": target, "envelopes": entries}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"envelopes": len(entries), "output": str(output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
