#!/usr/bin/env python3
"""Collect exactly the three locked Model Garden records with impersonation.

The command is intentionally strict about the source command and writes no
fallback/placeholder identity when Google returns an unexpected shape.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.pipeline.runtime_contract import LOCKED_MODEL_LABELS
from src.pipeline.vertex_runtime import LOCKED_MODEL_INVOCATIONS


def _record_hash(value: dict[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _list_model(project: str, service_account: str, model_filter: str) -> dict[str, Any]:
    command = [
        "gcloud", "ai", "model-garden", "models", "list",
        f"--project={project}", f"--impersonate-service-account={service_account}",
        f"--model-filter={model_filter}", "--full-resource-name", "--format=json", "--limit=100",
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=120)
    if result.returncode:
        raise RuntimeError(f"Model Garden metadata lookup failed for {model_filter}")
    try:
        values = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Model Garden returned non-JSON metadata") from exc
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise RuntimeError(f"Model Garden lookup must return exactly one record for {model_filter}")
    return values[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--impersonate-service-account", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--gemma-endpoint", required=True, help="endpoint URL from the verified MaaS metadata/doc snapshot")
    args = parser.parse_args(argv)
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    retrieved_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    for label in LOCKED_MODEL_LABELS:
        expected = LOCKED_MODEL_INVOCATIONS[label]
        source = _list_model(args.project, args.impersonate_service_account, expected["model_id"])
        resource_id = str(source.get("fullResourceName") or source.get("name") or "")
        if not resource_id.startswith("projects/"):
            raise RuntimeError(f"Model Garden record for {label} has no full project resource")
        record: dict[str, Any] = {
            "logical_label": label,
            "model_id": expected["model_id"],
            "resource_id": resource_id,
            "resource_revision": "001" if label == "gemma-4-26b-a4b-it" else "default",
            "location": "global",
            "api_family": expected["api_family"],
            "resolution_mode": "immutable" if label == "gemma-4-26b-a4b-it" else "provider_alias",
            "resolution_resolved_at": retrieved_at,
            "metadata_source": "gcloud ai model-garden models list",
            "metadata_impersonated_service_account": args.impersonate_service_account,
            "metadata_retrieved_at": retrieved_at,
            "model_garden_record": source,
        }
        if label == "gemma-4-26b-a4b-it":
            record["endpoint_url"] = args.gemma_endpoint
        record["resolution_evidence_hash"] = _record_hash(source)
        record["metadata_hash"] = _record_hash(record)
        destination = output / f"{label}.json"
        destination.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"label": label, "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
