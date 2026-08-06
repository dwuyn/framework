from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE_IMAGE = "python:3.11.15-slim-bookworm@sha256:b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba"


def test_build_target_and_envelope_metadata_are_unified() -> None:
    target = json.loads((ROOT / "build/baseline-target.json").read_text())
    assert target["platform"] == "x86_64-unknown-linux-gnu"
    assert target["python"] == "3.11"
    assert target["resolver_version"] == "0.11.28"
    metadata = json.loads((ROOT / "build/dependency-envelopes/envelopes.json").read_text())
    assert {item["name"] for item in metadata["envelopes"]} == {
        "VeriPlanPT", "PentestAgent", "PentestGPT", "VulnBot", "HackSynth"
    }


def test_all_recipes_pin_base_and_hacksynth_is_cpu_only() -> None:
    recipes = [ROOT / "docker/veriplanpt.Dockerfile", *sorted((ROOT / "docker/baselines").glob("*.Dockerfile"))]
    assert len(recipes) == 5
    for recipe in recipes:
        text = recipe.read_text()
        assert text.count(BASE_IMAGE) == 2
        assert "--network=host" not in text
        assert "GOOGLE_APPLICATION_CREDENTIALS" not in text
        assert "/runner/run" in text
    hacksynth = (ROOT / "docker/baselines/HackSynth.Dockerfile").read_text()
    assert "cpu-only" in hacksynth
    assert "picoctf_bench" not in hacksynth


def test_provider_bundle_refuses_direct_vertex_and_root() -> None:
    provider = (ROOT / "docker/adapter/provider_shim.py").read_text()
    entrypoint = (ROOT / "docker/adapter/entrypoint.sh").read_text()
    runtime = (ROOT / "docker/adapter/runtime_entrypoint.py").read_text()
    assert "googleapis.com" in provider
    assert "refuses root" in entrypoint
    assert "unset GOOGLE_APPLICATION_CREDENTIALS" in entrypoint
    assert "paid stage requires a locked framework-specific automation adapter" in runtime


def test_rebuild_writes_strict_four_baseline_lock() -> None:
    script = (ROOT / "scripts/rebuild_runtime_images.py").read_text()
    assert 'item["name"] != "VeriPlanPT"' in script
    assert "generate_baseline_lock(baseline_specs" in script


def test_hacksynth_lock_contains_hashes_and_no_gpu_packages() -> None:
    lock = (ROOT / "build/dependency-envelopes/HackSynth/requirements.cpu.lock").read_text().lower()
    assert "torch==2.3.0+cpu" in lock
    assert "torchvision==0.18.0+cpu" in lock
    assert "torchaudio==2.3.0+cpu" in lock
    assert not re.search(r"(^|\n)(nvidia-[^=\s]+|triton)==", lock)
    assert "--hash=sha256:" in lock
