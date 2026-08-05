#!/usr/bin/env python3
"""Create a detached minisign signature for a canonical runtime payload."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Sequence

from src.pipeline.approval import canonical_approval_payload
from src.pipeline.protocol import load_json
from src.pipeline.runtime_contract import canonical_json


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("alias-exception", "approval"), required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--artifact-root", required=True)
    args = parser.parse_args(argv)
    root, key, output = Path(args.artifact_root).resolve(), Path(args.private_key).resolve(), Path(args.output).resolve()
    if root in key.parents or output.parent != root / "signatures":
        raise SystemExit("private key must stay outside artifacts and signatures must be in artifacts/signatures")
    if not key.is_file() or shutil.which("minisign") is None:
        raise SystemExit("minisign private key and executable are required")
    value = load_json(args.input)
    payload = canonical_json(value) if args.kind == "alias-exception" else canonical_approval_payload(value)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="veriplanpt-sign-") as temp:
        message = Path(temp) / "payload.json"
        message.write_bytes(payload)
        result = subprocess.run(["minisign", "-Sm", str(message), "-s", str(key), "-x", str(output)], capture_output=True, text=True, check=False)
    if result.returncode:
        raise SystemExit("minisign signing failed")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
