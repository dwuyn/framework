from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from src.pipeline.budget import BudgetTier
from src.pipeline.framework_adapter import FrameworkAdapter, PublicTask
from src.pipeline.source_snapshot import (
    RAW_ARCHIVE,
    build_snapshot_index,
    read_indexed_records,
    validate_source_snapshot,
)


def _raw_record() -> bytes:
    return json.dumps({
        "cveMetadata": {
            "cveId": "CVE-2026-1324",
            "state": "PUBLISHED",
            "datePublished": "2026-01-22T13:02:08.642Z",
        },
        "containers": {"cna": {
            "affected": [{
                "vendor": "Sangfor",
                "product": "Operation and Maintenance Management System",
                "versions": [{"version": "3.0.0", "status": "affected"}],
            }],
            "descriptions": [{"lang": "en", "value": "command injection"}],
            "references": [{"url": "https://example.invalid/CVE-2026-1324"}],
            "metrics": [{"cvssV4_0": {
                "baseScore": 8.7,
                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N",
            }}],
        }},
    }, sort_keys=True).encode()


def _snapshot(tmp_path: Path) -> Path:
    archive = tmp_path / RAW_ARCHIVE
    archive.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive, "w") as target:
        target.writestr("cves/2026/1xxx/CVE-2026-1324.json", _raw_record())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    build_snapshot_index(
        tmp_path,
        cutoff="2026-08-01T00:00:00Z",
        upstream_release="test-release",
        upstream_asset_url="https://example.invalid/source.zip",
        upstream_asset_path=RAW_ARCHIVE,
        upstream_asset_sha256=digest,
    )
    return tmp_path


def test_build_validate_and_query_indexed_snapshot(tmp_path: Path) -> None:
    root = _snapshot(tmp_path)
    manifest = validate_source_snapshot(root)
    assert manifest["cve_count"] == 1
    records = read_indexed_records(
        root,
        source="cve_list_v5",
        product="Operation and Maintenance Management System",
        vendor="Sangfor",
    )
    assert records is not None
    assert [record["cve_id"] for record in records] == ["CVE-2026-1324"]
    assert records[0]["raw_hash"] == hashlib.sha256(_raw_record()).hexdigest()


def test_validation_rejects_index_drift(tmp_path: Path) -> None:
    root = _snapshot(tmp_path)
    with (root / "source-snapshot.sqlite3").open("ab") as handle:
        handle.write(b"drift")
    with pytest.raises(ValueError, match="index hash mismatch"):
        validate_source_snapshot(root)


def test_framework_rejects_missing_snapshot_before_graph(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    graph_started = False

    def forbidden_graph(_thread_id: str) -> None:
        nonlocal graph_started
        graph_started = True

    monkeypatch.setattr("src.graph.build_graph", forbidden_graph)
    adapter = FrameworkAdapter(results_root=str(tmp_path / "runs"), snapshot_dir=str(tmp_path / "missing"))
    task = PublicTask(
        case_id="vp-validation-0001",
        track="blind",
        objective="validate the authorized local service",
        host="127.0.0.1",
        port_range="8080",
        scope={"allowed_hosts": ["127.0.0.1"], "allowed_ports": [8080]},
    )
    with pytest.raises(ValueError, match="manifest missing"):
        adapter.run(task, object(), BudgetTier.MEDIUM)  # type: ignore[arg-type]
    assert graph_started is False
