#!/usr/bin/env python3
"""Run the isolated vp-validation-0001 Docker lab smoke with a fake gateway."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(["docker", *args], cwd=ROOT, capture_output=True, text=True, check=False)
    if check and result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip()[-4_000:])
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--gateway-image", required=True)
    parser.add_argument("--run-root", default="")
    args = parser.parse_args()
    if shutil.which("docker") is None:
        raise SystemExit("docker is unavailable; Docker lab smoke is blocked")
    run_id = f"vp-validation-0001-{uuid.uuid4().hex[:12]}"
    label = f"com.veriplanpt.run={run_id}"
    network = f"veriplanpt-lab-{uuid.uuid4().hex[:12]}"
    run_root = Path(args.run_root) if args.run_root else Path(tempfile.mkdtemp(prefix="veriplanpt-lab-"))
    run_root.mkdir(parents=True, exist_ok=True)
    task = run_root / "public-task.json"
    task.write_text(json.dumps({
        "case_id": "vp-validation-0001", "track": "blind", "objective": "submit synthetic proof",
        "target": {"host": "lab.local", "exposed_ports": [80]},
    }, sort_keys=True) + "\n", encoding="utf-8")
    created = False
    try:
        run(["network", "create", "--label", label, network])
        created = True
        gateway_name = f"{network}-gateway"
        run(["run", "-d", "--rm", "--label", label, "--network", network, "--name", gateway_name, args.gateway_image])
        run([
            "run", "--rm", "--user", "10001:10001", "--label", label, "--network", network,
            "--volume", f"{run_root}:/run/veriplanpt:rw", "--env", f"VERIPLANPT_PROVIDER_URL=http://{gateway_name}:8080/v1/generate",
            "--env", "VERIPLANPT_RUN_DIR=/run/veriplanpt", args.image,
            "python", "/opt/adapter/provider_shim.py", "--contract-smoke",
        ])
    finally:
        run(["rm", "-f", f"{network}-gateway"], check=False)
        if created:
            run(["network", "rm", network], check=False)
    residual_containers = run(["ps", "-aq", "--filter", f"label={label}"], check=False).stdout.strip()
    residual_networks = run(["network", "ls", "-q", "--filter", f"label={label}"], check=False).stdout.strip()
    if residual_containers or residual_networks:
        raise SystemExit(f"lab cleanup evidence failed: {residual_containers} {residual_networks}")
    print(json.dumps({"case_id": "vp-validation-0001", "network": "isolated", "cleanup": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
