#!/usr/bin/env python3
"""Single-response VeriPlanPT readiness transport driver.

Readiness proves the locked client/gateway path, not the framework graph.  The
full VeriPlanPT production driver remains the path for sweep, confirmation,
and benchmark stages.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load() -> tuple[dict[str, Any], Path]:
    invocation_path = Path(os.environ["VERIPLANPT_PUBLIC_INVOCATION_FILE"])
    invocation = json.loads(invocation_path.read_text(encoding="utf-8"))
    if not isinstance(invocation, Mapping):
        raise RuntimeError("public invocation must be an object")
    output = Path(os.environ["VERIPLANPT_RUN_DIR"])
    return dict(invocation), output


def _contents(invocation: Mapping[str, Any]) -> Any:
    task = invocation["task"]
    if not isinstance(task, Mapping):
        raise RuntimeError("public task must be an object")
    prompt = json.dumps({
        "purpose": "framework-model-readiness",
        "case_id": invocation["case_id"],
        "objective": task.get("objective", "Verify the controlled model path."),
        "target": task.get("target", {}),
    }, sort_keys=True)
    if invocation["model_label"] == "gemma-4-26b-a4b-it":
        return [{"role": "user", "content": prompt}]
    return prompt


def main() -> int:
    invocation, output = _load()
    from provider_shim import request  # type: ignore[import-not-found]

    response = dict(request({"contents": _contents(invocation)}))
    text = str(response.get("text", response.get("content", "")))
    generated = output / "readiness-transport-request.json"
    generated.write_bytes(_canonical({"contents": _contents(invocation)}))
    evidence = {
        "schema_version": "1.0.0",
        "mode": "single-response-readiness-transport",
        "stage": os.environ.get("VERIPLANPT_STAGE", ""),
        "framework": "VeriPlanPT",
        "public_task_hash": hashlib.sha256(_canonical(invocation["task"])).hexdigest(),
        "generated_config_hash": hashlib.sha256(generated.read_bytes()).hexdigest(),
        "provider_response_count": 1,
        "phases": ["readiness_transport"],
        "outcome": "completed",
        "response_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }
    output.joinpath("driver-evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    output.joinpath("driver-response.json").write_text(
        json.dumps({"text": text}, sort_keys=True) + "\n", encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
