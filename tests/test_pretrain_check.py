from __future__ import annotations

import json
from pathlib import Path

from src.pipeline import pretrain_check as pretrain_module


def test_pretrain_fails_closed_when_only_draft_lock_exists(
    tmp_path: Path,
    monkeypatch,
) -> None:
    dataset_root = tmp_path / "dataset"
    drafts = dataset_root / "drafts"
    drafts.mkdir(parents=True)
    (drafts / "dataset-lock-v1.candidate.json").write_text(
        json.dumps({"schema_version": "1.0.0"}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        pretrain_module,
        "git_state",
        lambda _root: {"commit": "framework-commit", "dirty": False},
    )
    monkeypatch.setattr(
        pretrain_module,
        "_command",
        lambda _root, args: {"command": " ".join(args)},
    )

    report = pretrain_module.pretrain_check(
        dataset_root=dataset_root,
        baseline_lock=dataset_root / "baseline.lock.json",
        training_protocol=dataset_root / "training_protocol.json",
        output=tmp_path / "pretrain-readiness.json",
        framework_root=tmp_path,
    )

    assert report["ready"] is False
    assert report["checks"]["dataset_lock"]["passed"] is False
    assert "dataset.lock.json" in report["checks"]["dataset_lock"]["detail"]
    assert report["checks"]["training_protocol"]["passed"] is False
    assert report["checks"]["smoke_evidence"]["passed"] is False
    assert report["dataset_lock_hash"] == ""
