#!/usr/bin/env python3
"""Run the offline container contract smoke for all five framework images."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXTERNAL_NAMES = ("PentestAgent", "PentestGPT", "VulnBot", "HackSynth")


def docker(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(["docker", *args], cwd=ROOT, capture_output=True, text=True, check=False)
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip()[-4_000:]
        raise RuntimeError(f"docker {' '.join(args)} failed: {detail}")
    return result


def audit(run_label: str) -> None:
    containers = docker(["ps", "-aq", "--filter", f"label={run_label}"], check=False).stdout.strip()
    networks = docker(["network", "ls", "-q", "--filter", f"label={run_label}"], check=False).stdout.strip()
    if containers or networks:
        raise RuntimeError(f"run cleanup evidence failed: containers={containers!r} networks={networks!r}")


def inspect_image(image: str, expected_name: str) -> dict[str, object]:
    result = docker(["image", "inspect", "--format", "{{json .}}", image])
    record = json.loads(result.stdout)
    labels = record.get("Config", {}).get("Labels", {})
    if not isinstance(labels, dict) or labels.get("com.veriplanpt.framework") != expected_name:
        raise RuntimeError(f"{image} has incorrect framework label")
    if not str(record.get("Id", "")).startswith("sha256:"):
        raise RuntimeError(f"{image} has no immutable image ID")
    return {"image_id": record["Id"], "labels": labels}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", default=str(ROOT / "build/baselines.inventory.json"))
    parser.add_argument("--veriplanpt-image", required=True)
    parser.add_argument("--run-root", default="")
    args = parser.parse_args()
    if shutil.which("docker") is None:
        raise SystemExit("docker is unavailable; container contract gate is blocked")
    inventory = json.loads(Path(args.inventory).read_text(encoding="utf-8"))
    entries = {str(item["name"]): item for item in inventory["baselines"]}
    images = {name: str(entries[name]["image"]) for name in EXTERNAL_NAMES}
    images["VeriPlanPT"] = args.veriplanpt_image
    run_root = Path(args.run_root) if args.run_root else Path(tempfile.mkdtemp(prefix="veriplanpt-contract-"))
    run_root.mkdir(parents=True, exist_ok=True)
    task = run_root / "public-task.json"
    profile = run_root / "model-profile.json"
    task.write_text(json.dumps({
        "case_id": "vp-validation-0001", "track": "blind", "objective": "submit synthetic proof",
        "target": {"host": "lab.local", "exposed_ports": [80]},
    }, sort_keys=True) + "\n", encoding="utf-8")
    profile.write_text(json.dumps({"provider": "fake", "logical_label": "fake-model", "revision": "smoke"}) + "\n", encoding="utf-8")
    results = {}
    for name, image in images.items():
        run_label = f"com.veriplanpt.run={name.lower()}-vp-validation-0001"
        identity = inspect_image(image, name)
        docker([
            "run", "--rm", "--user", "10001:10001", "--network", "none", "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev", "--label", run_label,
            "--volume", f"{run_root}:/run/veriplanpt:rw", "--env", "VERIPLANPT_PROVIDER_MODE=fake",
            "--env", "VERIPLANPT_RUN_DIR=/run/veriplanpt", image,
            "python", "/opt/adapter/provider_shim.py", "--contract-smoke",
        ])
        audit(run_label)
        results[name] = {"identity": identity, "provider": "fake", "cleanup": True}
    print(json.dumps({"case_id": "vp-validation-0001", "frameworks": results}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
