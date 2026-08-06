from __future__ import annotations

import hashlib
import json

import pytest

from scripts.write_google_pricing_snapshot import EXPECTED_MODELS, main


def _manifest() -> dict[str, object]:
    models = {}
    for index, label in enumerate(sorted(EXPECTED_MODELS), 1):
        models[label] = {
            "sku_id": f"sku-{index}",
            "thinking_enabled": not label.startswith("gemma"),
            "prices": {
                "input_usd_per_token": index * 0.000001,
                "cached_input_usd_per_token": index * 0.0000001,
                "output_usd_per_token": index * 0.000002,
            },
        }
    return {"models": models}


def test_collector_hashes_raw_document_and_verifies_skus(tmp_path) -> None:
    manifest = _manifest()
    source = tmp_path / "pricing.json"
    source.write_text(json.dumps(manifest), encoding="utf-8")
    verification = tmp_path / "verified.json"
    verification.write_text(json.dumps(manifest), encoding="utf-8")
    output = tmp_path / "snapshot.json"
    assert main([
        "--output", str(output), "--source-document", str(source),
        "--source-url", "https://cloud.google.com/vertex-ai/generative-ai/pricing",
        "--verification-manifest", str(verification),
        "--effective-at", "2026-08-06T00:00:00Z",
        "--retrieved-at", "2026-08-06T01:00:00Z",
    ]) == 0
    snapshot = json.loads(output.read_text(encoding="utf-8"))
    assert snapshot["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert set(snapshot["verified_skus"]) == EXPECTED_MODELS


def test_collector_rejects_value_not_present_in_raw_document(tmp_path) -> None:
    manifest = _manifest()
    source = tmp_path / "pricing.json"
    source.write_text(json.dumps(manifest), encoding="utf-8")
    changed = _manifest()
    changed["models"]["gemini-3.5-flash"]["prices"]["output_usd_per_token"] = 99.0  # type: ignore[index]
    verification = tmp_path / "verified.json"
    verification.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(ValueError, match="does not verify"):
        main([
            "--output", str(tmp_path / "out.json"), "--source-document", str(source),
            "--source-url", "https://cloud.google.com/vertex-ai/generative-ai/pricing",
            "--verification-manifest", str(verification),
            "--effective-at", "2026-08-06T00:00:00Z",
        ])
