"""Public-task bridge for the external benchmark harness.

The bridge accepts only ``public_task.yml`` and writes framework artifacts;
the harness owns evaluator upload and completion.
"""

from __future__ import annotations

import argparse
import json
import os
from urllib.parse import urlparse

import yaml

from src.graph import build_graph, build_graph_v5
from src.pipeline.benchmark import variant_settings
from src.pipeline.ledger import EventLedger
from src.state import initial_state


def run_public_task(public_task_path: str, run_dir: str, *, model_profile: str = "", variant: str = "2") -> dict:
    with open(public_task_path, encoding="utf-8") as handle:
        task = yaml.safe_load(handle) or {}
    target = task.get("target") or {}
    parsed = urlparse(str(target.get("url") or ""))
    host = parsed.hostname or str(target.get("host") or "")
    port = parsed.port or int((target.get("exposed_ports") or [0])[0] or 0)
    if not host or not port:
        raise ValueError("public task requires a target URL or host and exposed port")
    os.makedirs(run_dir, exist_ok=True)
    normalized_variant = "1" if variant == "baseline" else ("2" if variant == "current" else str(variant))
    graph, config = (build_graph_v5 if normalized_variant == "1" else build_graph)(f"data-{task.get('case_id', 'case')}")
    state = initial_state(host, target_port=str(port), recon_max_steps=12, execution_max_steps=40,
                          max_runtime_seconds=1200)
    state.update({
        "public_task": task,
        "model_profile": model_profile,
        "pipeline_manifest": {},
        "source_snapshot_dir": os.environ.get("PENTEST_SOURCE_SNAPSHOT", ""),
        "retrieval_mode": "snapshot",
        "app_name": str(target.get("component") or ""),
        "pipeline_recon_observations": [{"target_ip": host, "port": port,
                                          "service_name": str(target.get("component") or parsed.scheme),
                                          "banner": str(target.get("component") or "")}],
        **variant_settings(normalized_variant),
    })
    final = graph.invoke(state, config=config)
    result = dict(final.get("pipeline_result") or {})
    source_run = str(result.get("run_dir") or "")
    transcript = os.path.join(run_dir, "transcript.jsonl")
    ledger_path = str(result.get("ledger_path") or (os.path.join(source_run, "events.jsonl") if source_run else ""))
    with open(transcript, "w", encoding="utf-8") as out:
        if ledger_path and os.path.exists(ledger_path):
            for event in EventLedger.load(ledger_path).to_list():
                out.write(json.dumps({"role": event.get("phase"), "event": event}, sort_keys=True) + "\n")
    proof_path = str(result.get("proofs_path") or (os.path.join(source_run, "proofs.json") if source_run else ""))
    summary = {"case_id": task.get("case_id"), "outcome": result.get("outcome", ""),
               "proofs_path": proof_path, "transcript": transcript, "run_dir": source_run}
    with open(os.path.join(run_dir, "framework_result.json"), "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-task", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--model-profile", default="")
    parser.add_argument("--variant", choices=["1", "2", "3", "4", "current", "baseline"], default="2")
    args = parser.parse_args()
    print(json.dumps(run_public_task(args.public_task, args.run_dir, model_profile=args.model_profile,
                                     variant=args.variant), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
