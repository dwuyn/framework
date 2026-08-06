#!/usr/bin/env python3
"""Collect the three approved Model Garden records through impersonation."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from src.pipeline.runtime_contract import LOCKED_MODEL_LABELS
from src.pipeline.vertex_runtime import LOCKED_MODEL_INVOCATIONS


def _hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _list_models(project: str, service_account: str) -> list[dict[str, Any]]:
    result = subprocess.run(
        ["gcloud", "ai", "model-garden", "models", "list", f"--project={project}",
         f"--impersonate-service-account={service_account}", "--full-resource-name", "--format=json"],
        capture_output=True, text=True, check=False, timeout=120,
    )
    if result.returncode:
        raise RuntimeError("Model Garden metadata lookup failed")
    try:
        values = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Model Garden returned non-JSON metadata") from exc
    if not isinstance(values, list) or any(not isinstance(value, dict) for value in values):
        raise RuntimeError("Model Garden response must be a JSON array of records")
    return values


def _select(records: list[dict[str, Any]], *, catalog_name: str, version: str) -> dict[str, Any]:
    matches = [record for record in records if str(record.get("name", "")) == catalog_name and str(record.get("versionId", "")) == version]
    if len(matches) != 1:
        raise RuntimeError(f"Model Garden must contain exactly one name/versionId record for {catalog_name}@{version}")
    return matches[0]


def _resource(template: Any, *, project: str, model_id: str) -> str:
    if not isinstance(template, str) or "{project}" not in template or "{location}" not in template:
        raise RuntimeError("Model Garden publisherModelTemplate must contain {project} and {location}")
    value = template.replace("{project}", project).replace("{location}", "global")
    if not value.startswith(f"projects/{project}/locations/global/publishers/") or model_id.rsplit("/", 1)[-1] not in value:
        raise RuntimeError("publisherModelTemplate does not identify the selected publisher model")
    return value


def _gemma_endpoint_snapshot(path: Path, document: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("Gemma MaaS endpoint snapshot is unreadable") from exc
    required = {"schema_version", "model_id", "endpoint_url", "source_url", "retrieved_at", "source_sha256"}
    if not isinstance(value, dict) or set(value) != required:
        raise RuntimeError("Gemma MaaS endpoint snapshot fields are invalid")
    expected_model_id = LOCKED_MODEL_INVOCATIONS["gemma-4-26b-a4b-it"]["model_id"].rsplit("/", 1)[-1]
    if value["model_id"] != expected_model_id:
        raise RuntimeError("Gemma MaaS endpoint snapshot model ID mismatch")
    if not str(value["endpoint_url"]).startswith("https://") or "googleapis.com" not in str(value["endpoint_url"]):
        raise RuntimeError("Gemma MaaS endpoint snapshot is not a verified Google endpoint")
    actual = hashlib.sha256(document.read_bytes()).hexdigest()
    if str(value["source_sha256"]) != actual:
        raise RuntimeError("Gemma MaaS endpoint snapshot does not match raw source document")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--impersonate-service-account", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--gemma-endpoint-snapshot", required=True)
    parser.add_argument("--gemma-endpoint-document", required=True)
    args = parser.parse_args(argv)
    output = Path(args.output_dir).resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit("metadata output directory must be new and empty")
    output.mkdir(parents=True, exist_ok=True)
    raw_document = Path(args.gemma_endpoint_document).resolve()
    if not raw_document.is_file():
        raise SystemExit("Gemma MaaS raw endpoint document is missing")
    endpoint = _gemma_endpoint_snapshot(Path(args.gemma_endpoint_snapshot).resolve(), raw_document)
    endpoint_path = output / "gemma-maas-endpoint.json"
    endpoint_path.write_text(json.dumps(endpoint, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    raw_output = output / "gemma-maas-endpoint.source"
    raw_output.write_bytes(raw_document.read_bytes())
    records = _list_models(args.project, args.impersonate_service_account)
    retrieved_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    for label in LOCKED_MODEL_LABELS:
        expected = LOCKED_MODEL_INVOCATIONS[label]
        version = "001" if label == "gemma-4-26b-a4b-it" else "default"
        source = _select(records, catalog_name=expected["catalog_name"], version=version)
        resource_id = _resource(source.get("publisherModelTemplate"), project=args.project, model_id=expected["model_id"])
        record: dict[str, Any] = {
            "logical_label": label, "model_id": expected["model_id"], "resource_id": resource_id,
            "resource_revision": version, "location": "global", "api_family": expected["api_family"],
            "resolution_mode": "immutable" if label == "gemma-4-26b-a4b-it" else "provider_alias",
            "resolution_resolved_at": retrieved_at, "metadata_source": "gcloud ai model-garden models list",
            "metadata_impersonated_service_account": args.impersonate_service_account,
            "metadata_retrieved_at": retrieved_at, "model_garden_record": source,
            "resolution_evidence_hash": _hash(source),
        }
        if label == "gemma-4-26b-a4b-it":
            record["endpoint_url"] = endpoint["endpoint_url"]
            record["endpoint_snapshot_sha256"] = hashlib.sha256(endpoint_path.read_bytes()).hexdigest()
            record["endpoint_source_sha256"] = hashlib.sha256(raw_output.read_bytes()).hexdigest()
        record["metadata_hash"] = _hash(record)
        destination = output / f"{label}.json"
        destination.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"label": label, "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
