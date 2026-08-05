#!/usr/bin/env python3
"""Write the locked Google Standard/global USD-per-token pricing snapshot."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from src.pipeline.vertex_runtime import PricingSnapshot

SOURCE_URL = "https://cloud.google.com/gemini-enterprise-agent-platform/generative-ai/pricing"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--retrieved-at", default=datetime.now(UTC).isoformat().replace("+00:00", "Z"))
    args = parser.parse_args(argv)
    snapshot = PricingSnapshot(
        source_url=SOURCE_URL,
        retrieved_at=args.retrieved_at,
        effective_at=args.retrieved_at,
        region="global",
        package="Standard",
        unit="USD/token",
        billing_semantics="reasoning_billed_once_with_output",
        thinking_enabled={
            "gemini-3.5-flash": True,
            "gemini-3.6-flash": True,
            "gemma-4-26b-a4b-it": False,
        },
        model_prices={
            "gemini-3.5-flash": {
                "input_usd_per_token": 1.50e-6,
                "cached_input_usd_per_token": 0.15e-6,
                "output_usd_per_token": 9.00e-6,
            },
            "gemini-3.6-flash": {
                "input_usd_per_token": 1.50e-6,
                "cached_input_usd_per_token": 0.15e-6,
                "output_usd_per_token": 7.50e-6,
            },
            "gemma-4-26b-a4b-it": {
                "input_usd_per_token": 0.15e-6,
                "cached_input_usd_per_token": 0.015e-6,
                "output_usd_per_token": 0.60e-6,
            },
        },
    )
    value = snapshot.to_dict()
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(destination), "snapshot_hash": snapshot.snapshot_hash}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
