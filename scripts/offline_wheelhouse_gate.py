#!/usr/bin/env python3
"""Install one wheelhouse without indexes and run pip/import gates."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT_ROOT = ROOT.parent / "veriplanpt-artifacts"
IMPORTS = {
    "VeriPlanPT": ["pydantic", "langgraph", "google.genai"],
    "PentestAgent": ["langchain", "spacy"],
    "PentestGPT": ["langchain", "google.generativeai"],
    "VulnBot": ["fastapi", "pymilvus"],
    "HackSynth": ["torch", "torchaudio", "torchvision"],
}


def run(command: list[str], cwd: Path) -> None:
    result = subprocess.run(command, cwd=cwd, check=False, text=True)
    if result.returncode:
        raise SystemExit(result.returncode)


def localize_direct_urls(lock: Path, wheelhouse: Path, output: Path) -> Path:
    """Materialize direct-URL requirements from the local wheelhouse only."""
    text = lock.read_text(encoding="utf-8")
    for url in sorted(set(re.findall(r"https?://[^\s\\]+", text))):
        filename = url.split("#", 1)[0].rsplit("/", 1)[-1]
        local_file = wheelhouse / filename
        if local_file.is_file():
            text = text.replace(url, local_file.resolve().as_uri())
    output.write_text(text, encoding="utf-8")
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("name", choices=sorted(IMPORTS))
    parser.add_argument("--metadata", default=str(ROOT / "build/dependency-envelopes/envelopes.json"))
    parser.add_argument("--artifact-root", default=str(DEFAULT_ARTIFACT_ROOT))
    args = parser.parse_args()
    metadata = json.loads(Path(args.metadata).read_text(encoding="utf-8"))
    envelope = next(item for item in metadata["envelopes"] if item["name"] == args.name)
    lock = ROOT / str(envelope["dependency_lock"]["path"])
    wheelhouse = Path(args.artifact_root).resolve() / "wheelhouses" / args.name
    if not wheelhouse.is_dir():
        raise SystemExit(f"wheelhouse missing: {wheelhouse}")
    temp_root = Path(args.artifact_root).resolve() / "tmp"
    temp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"veriplanpt-offline-{args.name}-", dir=temp_root) as temp:
        temp_path = Path(temp)
        venv = temp_path / "venv"
        run(["uv", "venv", "--seed", "--python", "3.11", str(venv)], ROOT)
        python = str(venv / "bin" / "python")
        offline_lock = localize_direct_urls(lock, wheelhouse, temp_path / "requirements.lock")
        run([
            "uv", "pip", "install", "--offline", "--no-index", "--require-hashes", "--no-build-isolation",
            "--find-links", str(wheelhouse), "-r", str(offline_lock), "--python", python,
        ], ROOT)
        run([python, "-m", "pip", "uninstall", "--yes", "wheel"], ROOT)
        run([python, "-m", "pip", "check"], ROOT)
        for module in IMPORTS[args.name]:
            run([python, "-c", f"import {module}"], ROOT)
    print(json.dumps({"name": args.name, "network": "disabled", "pip_check": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
