#!/usr/bin/env python3
"""Fail-closed verification for generated dependency envelopes."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


SHA256 = re.compile(r"^[0-9a-f]{64}$")
ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", default=str(ROOT / "build/dependency-envelopes/envelopes.json"))
    args = parser.parse_args()
    metadata = json.loads(Path(args.metadata).read_text(encoding="utf-8"))
    target = metadata.get("target", {})
    expected = {
        "platform": "x86_64-unknown-linux-gnu",
        "python": "3.11",
        "python_implementation": "CPython",
        "resolver": "uv",
        "resolver_version": "0.11.28",
    }
    for key, value in expected.items():
        if target.get(key) != value:
            raise SystemExit(f"target mismatch for {key}: {target.get(key)!r}")
    envelopes = metadata.get("envelopes")
    if not isinstance(envelopes, list) or {item.get("name") for item in envelopes} != {
        "VeriPlanPT", "PentestAgent", "PentestGPT", "VulnBot", "HackSynth"
    }:
        raise SystemExit("metadata must contain VeriPlanPT and exactly four external envelopes")
    for item in envelopes:
        lock = ROOT / str(item["dependency_lock"]["path"])
        if not lock.is_file() or digest(lock) != str(item["dependency_lock"]["sha256"]):
            raise SystemExit(f"dependency lock hash mismatch: {lock}")
        if not item["dependency_lock"].get("hashed"):
            raise SystemExit(f"dependency lock is not marked hashed: {lock}")
        for relative, expected_hash in dict(item.get("input_hashes", {})).items():
            source = Path(str(item["source"]["path"])) / relative
            if not source.is_file() or digest(source) != str(expected_hash):
                raise SystemExit(f"dependency input hash mismatch: {source}")
        contents = lock.read_text(encoding="utf-8").lower()
        if item["name"] == "HackSynth":
            if re.search(r"(^|\n)(nvidia-[^=\s]+|triton)==", contents):
                raise SystemExit("HackSynth CPU lock contains CUDA or triton packages")
            for expected_cpu in ("torch==2.3.0+cpu", "torchvision==0.18.0+cpu", "torchaudio==2.3.0+cpu"):
                if expected_cpu not in contents:
                    raise SystemExit(f"HackSynth CPU lock is missing {expected_cpu}")
    print(json.dumps({"verified": True, "envelopes": len(envelopes)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
