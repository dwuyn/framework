#!/usr/bin/env python3
"""Collect and verify a Google pricing document into a locked pricing snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from src.pipeline.vertex_runtime import PricingSnapshot

EXPECTED_MODELS = frozenset({
    "gemini-3.5-flash", "gemini-3.6-flash", "gemma-4-26b-a4b-it",
})


def _contains(value: object, expected: object) -> bool:
    if value == expected:
        return True
    if isinstance(value, dict):
        return any(_contains(item, expected) for item in value.values())
    if isinstance(value, list):
        return any(_contains(item, expected) for item in value)
    return False


def _verify(raw: object, manifest: dict[str, object]) -> tuple[dict[str, dict[str, float]], dict[str, dict[str, object]], dict[str, bool]]:
    models = manifest.get("models")
    if not isinstance(models, dict) or set(models) != EXPECTED_MODELS:
        raise ValueError("verification manifest must contain exactly the three locked models")
    prices: dict[str, dict[str, float]] = {}
    skus: dict[str, dict[str, object]] = {}
    thinking: dict[str, bool] = {}
    for label, untyped_record in models.items():
        if not isinstance(untyped_record, dict):
            raise ValueError(f"verification record for {label} must be an object")
        record = dict(untyped_record)
        sku_id = str(record.get("sku_id", ""))
        raw_prices = record.get("prices")
        if not sku_id or not isinstance(raw_prices, dict):
            raise ValueError(f"verification record for {label} requires sku_id and prices")
        normalized = {str(key): float(value) for key, value in raw_prices.items()}
        if not _contains(raw, sku_id) or any(not _contains(raw, value) for value in normalized.values()):
            raise ValueError(f"raw pricing document does not verify SKU/value record for {label}")
        prices[str(label)] = normalized
        skus[str(label)] = {"sku_id": sku_id, "prices": normalized}
        thinking[str(label)] = bool(record.get("thinking_enabled", False))
    return prices, skus, thinking


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--source-document", required=True)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--verification-manifest", required=True)
    parser.add_argument("--effective-at", required=True)
    parser.add_argument("--retrieved-at", default=datetime.now(UTC).isoformat().replace("+00:00", "Z"))
    args = parser.parse_args(argv)
    source = Path(args.source_document)
    raw = json.loads(source.read_text(encoding="utf-8"))
    manifest = json.loads(Path(args.verification_manifest).read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("verification manifest must be an object")
    model_prices, verified_skus, thinking_enabled = _verify(raw, manifest)
    snapshot = PricingSnapshot(
        source_url=args.source_url,
        retrieved_at=args.retrieved_at,
        effective_at=args.effective_at,
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        region="global",
        package="Standard",
        unit="USD/token",
        billing_semantics="reasoning_billed_once_with_output",
        thinking_enabled=thinking_enabled,
        model_prices=model_prices,
        verified_skus=verified_skus,
    )
    value = snapshot.to_dict()
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(destination), "snapshot_hash": snapshot.snapshot_hash}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
