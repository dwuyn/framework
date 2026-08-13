from __future__ import annotations

import hashlib
import json
from pathlib import Path

from src.pipeline.bundle_executor import IndependentBundleExecutor
from src.pipeline.framework_adapter import BudgetTier, ModelProfile, RunArtifact
from src.pipeline.runtime_executor import RuntimeCellResult
from src.pipeline.runtime_ledger import InvocationLedger
from src.pipeline.runtime_readiness import build_canary_smoke_plan
from src.pipeline.runtime_runner import RuntimeRunner, _bundle_hash
from src.pipeline.runtime_topology import TopologyHandle


def _profile(label: str) -> ModelProfile:
    gemma = label == "gemma-4-26b-a4b-it"
    return ModelProfile.from_dict({
        "logical_label": label, "location": "global",
        "resource_id": f"projects/p/locations/global/publishers/google/models/{label}",
        "resource_revision": "001" if gemma else "default",
        "resolution_mode": "immutable" if gemma else "provider_alias",
        "resolution_evidence_hash": "a" * 64, "resolution_resolved_at": "2026-08-05T00:00:00Z",
        "endpoint_url": "https://global-aiplatform.googleapis.com/v1" if gemma else "",
        "pricing": {"input_per_million": 1.0, "cached_input_per_million": .1, "output_per_million": 2.0},
        "pricing_effective_at": "2026-08-05T00:00:00Z",
        "usage_semantics": {"input_includes_cached": "true", "total_formula": "input+output", "output_includes_reasoning": "true"},
    })


def _bundle(root: Path, kind: str) -> Path:
    bundle = root / f"{kind}-bundle"
    entrypoint = bundle / "bin/evaluate"
    entrypoint.parent.mkdir(parents=True)
    script = (
        "#!/bin/sh\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  if [ \"$1\" = \"--output\" ]; then output=\"$2\"; shift 2; "
        "elif [ \"$1\" = \"--run-dir\" ]; then run_dir=\"$2\"; shift 2; else shift; fi\n"
        "done\n"
    )
    script += "set -- \"$run_dir\"/../../runtime/*-invocation-ledger.json; test -f \"$1\"\n" if kind == "evaluator" else ""
    script += "test -f \"$run_dir/framework-cleanup.json\"\n" if kind == "evaluator" else ""
    script += "test -f \"$run_dir/evaluator.json\"\n" if kind == "oracle" else ""
    script += f"printf '{{\"schema_version\":\"2.0.0\",\"kind\":\"{kind}\",\"status\":\"passed\",\"outcome\":{{}}}}' > \"$output\"\n"
    entrypoint.write_text(script, encoding="utf-8")
    entrypoint.chmod(0o755)
    manifest = {
        "schema_version": "2.0.0", "kind": kind, "source_commit": "d" * 40,
        "entrypoint": "bin/evaluate",
    }
    manifest["image_digest"] = "sha256:" + "f" * 64
    if kind == "evaluator":
        manifest["feature_schema_hash"] = "e" * 64
    (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return bundle


class _Topology:
    def __init__(self, root: Path, lock_hash: str) -> None:
        self.root = root
        self.lock_hash = lock_hash
        self.phases: list[str] = []

    def start(self, *, phase, run_ids, gateway_factory=None, gateway_token="", **_kwargs):
        self.phases.append(phase)
        return TopologyHandle(
            phase=phase, topology_id=f"topology-{phase}", network_name=f"network-{phase}",
            socket_path=self.root / f"{phase}.sock", socket_parent=self.root,
            labels={}, relay_container=f"relay-{phase}", phase_token=gateway_token,
            allowed_run_ids=set(run_ids),
        )

    def shutdown(self, handle):
        return {
            "schema_version": "1.0.0", "phase": handle.phase,
            "topology_id": handle.topology_id, "network_name": handle.network_name,
            "gateway_relay_lock_hash": self.lock_hash,
            "resources": {"relay": handle.relay_container, "baselines": []},
            "success": True, "errors": [],
        }


def test_runtime_runner_canary_then_smoke_and_observed_usage(tmp_path: Path, monkeypatch) -> None:
    profiles = [_profile(label) for label in sorted(ModelProfile.ALLOWED_MODELS)]
    relay_hash = "9" * 64
    images = {name: "sha256:" + "2" * 64 for name in ("VeriPlanPT", "PentestGPT", "VulnBot", "HackSynth", "PentestAgent")}
    plan = build_canary_smoke_plan(
        profiles=profiles, dataset_lock_hash="a" * 64, baseline_identity_hash="b" * 64,
        native_identity_hash="c" * 64, model_resolution_lock_hash="d" * 64,
        evaluator_hash="e" * 64, oracle_hash="f" * 64, image_digests=images,
        gateway_relay_lock_hash=relay_hash, target_runtime_lock_hash="1" * 64,
        source_snapshot_hash="3" * 64, max_input_tokens=10, max_output_tokens=5,
        max_llm_calls=1, retry_policy={"max_attempts": 1}, strict=True,
    )
    lock = {
        "schema_version": "1.0.0", "uid_policy": "host_euid_nonroot",
        "relay": {
            "image": "relay:locked", "image_digest": "sha256:" + "a" * 64,
            "alias": "gateway-relay", "endpoint": "http://gateway-relay:8080/v1/generate",
            "run_as": "host_uid_gid_nonroot",
            "recipe": {"path": "Dockerfile", "sha256": "b" * 64}, "source": {"path": "relay.py", "sha256": "c" * 64},
        },
        "socket": {"path": "/run/veriplanpt-gateway/gateway.sock", "mode": "0600", "parent_mode": "0700", "mount_read_only": True},
        "network": {"mode": "internal", "alias": "gateway-relay"},
        "baseline_socket_mount": False, "baseline_credentials": False,
    }
    approval = {"cost_ceiling_usd": sum(cell["cell_worst_case_cost_usd"] for cell in plan["cells"]), "expires_at": "2099-01-01T00:00:00Z"}
    monkeypatch.setattr("src.pipeline.experiment_runner.verify_approval", lambda *args, **kwargs: approval)
    evaluator = _bundle(tmp_path, "evaluator")
    oracle = _bundle(tmp_path, "oracle")
    signature = tmp_path / "signature"
    signature.write_bytes(b"signature")

    def digest(value: object) -> str:
        return hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()

    def execute(cell, run_dir, _labels, _phase, _topology, ledger: InvocationLedger):
        observed = {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3}
        ledger.record(run_id=cell["run_id"], model_label=cell["model_label"], request={"x": 1}, response={"y": 2}, usage=observed, cost_usd=.00002, billing_status="known")
        event, proof = {"events": []}, {"proof": True}
        profile = next(item for item in profiles if item.logical_label == cell["model_label"])
        artifact = RunArtifact(
            case_id="runtime", repetition=1, track="blind", condition=cell["kind"], model_profile=profile,
            budget_tier=BudgetTier.MEDIUM, schema_version="2.1.0", run_id=cell["run_id"], run_dir=str(run_dir),
            usage={"input_tokens": 1, "output_tokens": 2, "total_tokens": 3, "total_usd": .00002},
            termination_status="completed",
            framework_identity={"name": cell.get("framework", "VeriPlanPT"), "repository_url": "https://example.test/repo", "commit": "a" * 40, "image_digest": cell["image_digest"], "adapter_version": "adapter-3.0"},
            run_context={"dataset_lock_hash": cell["dataset_lock_hash"], "framework_commit": "b" * 40, "evaluator_commit": "c" * 40, "stage": "canary_smoke", "gateway_relay_lock_hash": relay_hash, "target_runtime_lock_hash": cell["target_runtime_lock_hash"]},
            event_ledger_hash=digest(event), proof_hash=digest(proof),
        )
        cleanup = {"success": True, "resources": {"container": {"ids": []}, "network": {"ids": []}}}
        return RuntimeCellResult(artifact.to_dict(), event, proof, {**observed, "usd": .00002}, {"billing_status": "known", "cost_usd": .00002}, {"status": "passed"}, cleanup, "known", "passed")

    runner = RuntimeRunner(
        artifact_root=tmp_path, plan=plan, profiles=profiles, relay_lock=lock,
        relay_lock_hash=relay_hash, relay_image="relay:locked", approval=approval,
        signature_path=signature, public_key="test", evaluator_bundle=evaluator, oracle_bundle=oracle,
        evaluator_bundle_hash=_bundle_hash(evaluator), oracle_bundle_hash=_bundle_hash(oracle),
        cell_executor=execute, bundle_executor=IndependentBundleExecutor(
            evaluator_bundle=evaluator, oracle_bundle=oracle, hidden_case_root=tmp_path,
        ),
        topology=_Topology(tmp_path, relay_hash),
    )
    output = runner.run()
    assert output.is_file()
    assert runner.topology.phases == ["canary", "smoke"]
    assert len(list((tmp_path / "runs").rglob("evaluator.json"))) == 18
    assert len(list((tmp_path / "runs").rglob("oracle.json"))) == 18
    assert (tmp_path / "runtime" / "canary-invocation-ledger.json").is_file()
    assert (tmp_path / "runtime" / "smoke-invocation-ledger.json").is_file()
