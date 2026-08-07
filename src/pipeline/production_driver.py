"""Framework-owned production entrypoint used by the locked runtime image."""

from __future__ import annotations

import json
import os
from pathlib import Path

from src.pipeline.budget import BudgetTier
from src.pipeline.framework_adapter import ModelProfile, PublicTask


def main() -> int:
    path = Path(os.environ["VERIPLANPT_PUBLIC_INVOCATION_FILE"])
    invocation = json.loads(path.read_text(encoding="utf-8"))
    task = PublicTask.from_dict(dict(invocation["task"]))
    profile = ModelProfile.from_dict(dict(invocation["model_profile"]))
    adapter = __import__("src.pipeline.framework_adapter", fromlist=["FrameworkAdapter"]).FrameworkAdapter(
        results_root=os.environ.get("VERIPLANPT_RUN_DIR", "/run/veriplanpt"),
    )
    artifact = adapter.run(
        task, profile, BudgetTier.from_str(str(invocation.get("budget_tier", "medium"))),
        repetition=int(invocation.get("repetition", 1)),
        run_dir=os.environ.get("VERIPLANPT_RUN_DIR", "/run/veriplanpt"),
        condition=str(invocation.get("condition", "")),
        run_id=str(invocation["run_id"]),
    )
    artifact.save(str(Path(os.environ["VERIPLANPT_OUTPUT_DIR"]) / "run_artifact.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
