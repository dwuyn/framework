"""
src/graph.py
─────────────
LangGraph StateGraph — the central orchestrator.

Topology (v6 — evidence-gated multi-agent pipeline)
──────────────────────────────────────────────────────────────
    START → recon → pipeline_prepare → pipeline_retrieve →
        pipeline_queue → pipeline_planner → pipeline_critic →
        pipeline_verifier → pipeline_execute → pipeline_verifier (loop)
        → pipeline_oracle → END

The verifier is the loop controller.  After each execution result it
decides: ``collect_evidence``, ``replan``, ``execute`` (next candidate),
or ``stop``.  A hard loop cap (default 5) prevents infinite cycling.

The v5 deterministic pipeline is preserved as ``build_graph_v5()`` for
backward-compatible baseline tests.

Human-in-the-loop
─────────────────
Fully autonomous mode. Safety is handled by internal quality gates
plus operator-controlled lab environment. No human approval interrupt.

Checkpointing
─────────────
Uses MemorySaver + pickle-to-disk. Resume via thread_id.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import logging
import os
import pickle
import tempfile
import threading
import time

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

from src.agents.recon import recon_node
from src.agents.planner import PlannerAgent, PlannerProposal, validate_guided_procedure
from src.agents.critic import CriticAgent, CriticVerdict
from src.agents.verifier_pipeline import PipelineVerifierAgent, VerifierDecision
from src.agents.executor import ExecutorAgent
from src.config import get_config
from src.pipeline.budget import ResourceBudget
from src.pipeline.candidates import ExploitCandidate, ProcedureStep, SUPPORTED_KINDS
from src.pipeline.collectors import (
    ExploitDbSpec,
    MetasploitSpec,
    NativeToolSpec,
    NmapNseSpec,
    NucleiSpec,
    PublicPocSpec,
    VendorRecipeSpec,
    collect_from_records,
    index_exploitdb,
    index_nse_scripts,
)
from src.pipeline.compiler import ExploitCompiler
from src.pipeline.metasploit_rpc import MetasploitRpcService
from src.pipeline.ledger import EventLedger
from src.pipeline.manifest import (
    ResourceLimits,
    RunManifest,
    Scope,
    new_manifest,
)
from src.pipeline.oracle import BenchmarkOracle, OracleResult, ProofArtifact, TargetTruth
from src.pipeline.runner import PipelineRunner, ReconObservation
from src.pipeline.queue import CandidateQueue, RankedCandidate
from src.pipeline.sources import (
    CveListV5Adapter,
    NvdAdapter,
    RawCveRecord,
    SourceRegistry,
    VulnxAdapter,
)
from src.state import PentestState

logger = logging.getLogger(__name__)

# ── Checkpoint directory ──────────────────────────────────────────────────────
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CHECKPOINT_DIR = os.path.join(_ROOT, "data", "checkpoints")


def _to_dict(d):
    """Convert nested defaultdicts to regular dicts for pickling."""
    if isinstance(d, dict):
        return {k: _to_dict(v) for k, v in d.items()}
    return d

def _from_dict(d, target_dict):
    """Restore standard dicts back into nested defaultdicts."""
    for k, v in d.items():
        if isinstance(v, dict):
            _from_dict(v, target_dict[k])
        else:
            target_dict[k] = v

class _DiskBackedSaver(MemorySaver):
    """
    Thin wrapper over MemorySaver that also persists to a pickle file.
    This gives resume-from-crash without requiring langgraph-checkpoint-sqlite.
    Thread-safe: uses a lock, deep-copies stores, and writes atomically.
    """

    def __init__(self, path: str) -> None:
        super().__init__()
        self._path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    data = pickle.load(f)
                
                if "storage" in data:
                    _from_dict(data["storage"], self.storage)
                if "writes" in data:
                    _from_dict(data["writes"], self.writes)
                if "blobs" in data and hasattr(self, "blobs"):
                    _from_dict(data["blobs"], self.blobs)
                    
                logger.info("Restored checkpoint from %s", path)
            except Exception as exc:
                logger.warning("Could not load checkpoint %s: %s", path, exc)

    def put(self, config, checkpoint, metadata, new_versions):
        with self._lock:
            result = super().put(config, checkpoint, metadata, new_versions)
            try:
                data = {
                    "storage": _to_dict(copy.deepcopy(self.storage)),
                    "writes": _to_dict(copy.deepcopy(self.writes)),
                }
                if hasattr(self, "blobs"):
                    data["blobs"] = _to_dict(copy.deepcopy(self.blobs))
            except Exception as exc:
                logger.warning("Could not snapshot checkpoint: %s", exc)
                return result
        try:
            dir_name = os.path.dirname(self._path)
            fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
            try:
                with os.fdopen(fd, "wb") as f:
                    pickle.dump(data, f)
                os.replace(tmp_path, self._path)
            except BaseException:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except Exception as exc:
            logger.warning("Could not save checkpoint: %s", exc)
        return result


# ── Route helper for recon → verifier ─────────────────────────────────────────

def _route_recon_to_verifier(state: PentestState) -> str:
    """
    After recon node: if recon is complete, go to verifier.
    Otherwise loop back to recon.
    """
    if state.get("current_phase") == "done":
        return "end"
    if state.get("recon_complete"):
        return "recon_verifier"
    if state.get("recon_step_count", 0) >= state.get("recon_max_steps", 12):
        return "recon_verifier"
    return "recon"


def _route_planning_result(state: PentestState) -> str:
    """After planning: execute a plan, or end if planning terminated early."""
    if state.get("current_phase") == "done":
        return "end"
    return "execution"


def _route_phase2_result(state: PentestState) -> str:
    route = str(state.get("phase2_route", "") or "")
    if route in {"recon", "planning", "end", "hypothesis"}:
        # Increment loop count when routing back to recon (a hypothesis→recon cycle)
        if route == "recon":
            loop_count = int(state.get("phase2_loop_count", 0) or 0) + 1
            loop_max = int(state.get("phase2_loop_max", 6) or 6)
            # Mutate state directly — LangGraph state is a mutable dict at routing time
            state["phase2_loop_count"] = loop_count  # type: ignore[index]
            if loop_count >= loop_max:
                logger.warning(
                    "Phase 2 loop cap reached (%d/%d) — forcing forward to planning",
                    loop_count, loop_max,
                )
                return "planning"
        return route
    if state.get("current_phase") == "done":
        return "end"
    return "planning"


def _route_recon_to_pipeline(state: PentestState) -> str:
    if state.get("current_phase") == "done":
        return "end"
    if state.get("recon_complete"):
        return "pipeline_prepare"
    if state.get("recon_step_count", 0) >= state.get("recon_max_steps", 12):
        return "pipeline_prepare"
    return "recon"


# ── v6 routing functions ─────────────────────────────────────────────────────


def _route_queue_to_planner(state: PentestState) -> str:
    """After queue: always go to planner (planner checks catalog exhaustion internally)."""
    if state.get("current_phase") == "done":
        return "end"
    return "pipeline_planner"


def _route_planner(state: PentestState) -> str:
    """Every active plan is challenged before the verifier can approve it."""
    if state.get("current_phase") == "done":
        return "end"
    if state.get("active_plan") or (state.get("catalog_exhausted") and state.get("planner_proposals")):
        return "pipeline_critic"
    return "pipeline_verifier"


def _route_critic(state: PentestState) -> str:
    """After critic: always go to verifier."""
    if state.get("current_phase") == "done":
        return "end"
    return "pipeline_verifier"


def _route_verifier(state: PentestState) -> str:
    """After verifier: route based on the decision."""
    action = str(state.get("current_verifier_action") or "stop")
    loop_count = int(state.get("planner_loop_count", 0) or 0)
    loop_max = int(state.get("planner_loop_max", 5) or 5)

    active_id = str(state.get("last_executed_candidate_id") or "")
    progress = (state.get("lifecycle_progress") or {}).get(active_id, {})
    if action == "execute" and active_id and progress and not progress.get("terminal"):
        return "pipeline_execute"

    if loop_count >= loop_max:
        return "pipeline_oracle"

    if action == "execute":
        state["planner_loop_count"] = loop_count + 1  # type: ignore[index]
        return "pipeline_execute"
    if action == "collect_evidence":
        state["planner_loop_count"] = loop_count + 1  # type: ignore[index]
        return "pipeline_targeted_recon"
    if action == "replan":
        state["planner_loop_count"] = loop_count + 1  # type: ignore[index]
        return "pipeline_planner"
    # "stop" or anything else → oracle
    return "pipeline_oracle"


def _route_execute_to_verifier(state: PentestState) -> str:
    """After execute: always return to verifier for evaluation."""
    if state.get("current_phase") == "done":
        return "end"
    return "pipeline_verifier"


def pipeline_targeted_recon_node(state: PentestState) -> dict:
    """Run one bounded recon step for a verifier evidence request."""
    used = int(state.get("phase2_followup_count", 0) or 0)
    limit = int(state.get("recon_followup_step_budget", 3) or 3)
    if used >= limit:
        return {"current_phase": "pipeline_targeted_recon", "pending_evidence_request": {}}
    updates = recon_node(dict(state, current_phase="recon", recon_complete=False))
    updates["current_phase"] = "pipeline_targeted_recon"
    updates["phase2_followup_count"] = used + 1
    return updates


def _scope_from_state(state: PentestState) -> Scope:
    target = str(state.get("target_ip", "") or "")
    ports: set[int] = set()
    for value in [state.get("target_port")]:
        try:
            if value:
                ports.add(int(value))
        except (TypeError, ValueError):
            pass
    for svc in state.get("target_services", []) or []:
        try:
            ports.add(int(svc.get("port", 0) or 0))
        except (TypeError, ValueError, AttributeError):
            pass
    for port in (state.get("port_services", {}) or {}).keys():
        try:
            ports.add(int(port))
        except (TypeError, ValueError):
            pass
    hostnames: list[str] = []
    networks: list[str] = []
    if target:
        try:
            networks.append(f"{ipaddress.ip_address(target)}/32")
        except ValueError:
            hostnames.append(target)
    callbacks = [str(state.get("attacker_ip") or "")] if state.get("attacker_ip") else []
    return Scope(
        allowed_hostnames=hostnames,
        allowed_networks=networks,
        allowed_ports=sorted(p for p in ports if p),
        allowed_schemes=["http", "https"],
        callback_endpoints=callbacks,
    )


def _evaluator_truth(state: PentestState, manifest: RunManifest | None = None) -> TargetTruth | None:
    """Read private benchmark truth only in the evaluator node."""
    raw = {}
    path = str(state.get("evaluator_truth_path") or "")
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
    elif manifest is not None:
        raw = (manifest.oracle_spec or {}).get("truth", {})
    if isinstance(raw, TargetTruth):
        return raw
    if isinstance(raw, dict) and raw:
        return TargetTruth.from_dict(raw)
    return None


def _manifest_from_state(state: PentestState) -> RunManifest:
    if state.get("pipeline_manifest"):
        manifest = RunManifest.from_dict(state["pipeline_manifest"])
    else:
        scope = _scope_from_state(state)
        limits = ResourceLimits(max_runtime_seconds=int(state.get("max_runtime_seconds", 1200) or 1200))
        oracle_spec = dict(state.get("oracle_spec", {}) or {})  # optional runtime override
        if state.get("approved_lab_cves"):
            oracle_spec["approved_lab_cves"] = list(state.get("approved_lab_cves") or [])
        manifest = new_manifest(
            str(state.get("target_ip") or "target"),
            variant=str(state.get("variant") or "4"),
            condition=str(state.get("condition") or "clean"),
            scope=scope,
            limits=limits,
            oracle_spec=oracle_spec,
        )
    if not manifest.run_dir:
        manifest.run_dir = os.path.join(_ROOT, "data", "runs", manifest.run_id)
    os.makedirs(manifest.run_dir, exist_ok=True)
    return manifest


def _private_truth_path(manifest: RunManifest) -> str:
    return os.path.join(manifest.run_dir, "evaluator_truth.json")


def _public_manifest(manifest: RunManifest) -> RunManifest:
    public = RunManifest.from_dict(manifest.to_dict())
    public.oracle_spec = {k: v for k, v in public.oracle_spec.items() if k != "truth"}
    return public


def _role_llm(state: PentestState, role: str):
    """Load one configured role model; model_profile selects the experiment condition."""
    try:
        return get_config().get_role_llm(role, str(state.get("model_profile") or ""))
    except Exception as exc:
        logger.warning("%s model unavailable: %s", role, exc)
        return None


def _role_usage(state: PentestState, role: str, llm) -> list[dict]:
    usage = list(state.get("role_usage") or [])
    usage.append({"role": role, "model_loaded": llm is not None})
    return usage


def _save_manifest(manifest: RunManifest) -> None:
    os.makedirs(manifest.run_dir, exist_ok=True)
    with open(os.path.join(manifest.run_dir, "manifest.json"), "w") as fh:
        fh.write(manifest.to_json())


def _ledger_path(state: PentestState, manifest: RunManifest) -> str:
    return str(state.get("pipeline_ledger_path") or os.path.join(manifest.run_dir, "events.jsonl"))


def _open_ledger(state: PentestState, manifest: RunManifest) -> EventLedger:
    path = _ledger_path(state, manifest)
    if os.path.exists(path):
        return EventLedger.resume(path, run_id=manifest.run_id)
    return EventLedger(manifest.run_id, path=path)


def _source_registry(state: PentestState, manifest: RunManifest, ledger: EventLedger) -> SourceRegistry:
    mode = str(state.get("retrieval_mode") or state.get("dataset_mode") or "snapshot")
    if mode not in {"live", "snapshot", "replay"}:
        mode = "snapshot"
    snap = str(state.get("source_snapshot_dir") or state.get("benchmark_cve_cache_path") or "")
    raw_dir = os.path.join(manifest.run_dir, "source_raw")
    return SourceRegistry([
        NvdAdapter(mode=mode, snapshot_dir=snap, ledger=ledger, raw_dir=raw_dir),
        CveListV5Adapter(mode=mode, snapshot_dir=snap, ledger=ledger, raw_dir=raw_dir),
        VulnxAdapter(mode=mode, snapshot_dir=snap, ledger=ledger, raw_dir=raw_dir,
                     base_url=str(state.get("vulnx_base_url") or "")),
    ], ledger=ledger)


def _runner(state: PentestState, manifest: RunManifest, ledger: EventLedger) -> PipelineRunner:
    limits = ResourceLimits(**manifest.limits)
    scope = Scope.from_dict(manifest.scope)
    return PipelineRunner(
        manifest=manifest,
        ledger=ledger,
        budget=ResourceBudget(limits),
        scope=scope,
        sources=_source_registry(state, manifest, ledger),
    )


def _observations_from_state(state: PentestState) -> list[ReconObservation]:
    raw = state.get("pipeline_recon_observations") or state.get("recon_observations") or []
    out: list[ReconObservation] = []
    for item in raw:
        if isinstance(item, ReconObservation):
            out.append(item)
        elif isinstance(item, dict):
            out.append(ReconObservation(
                target_ip=str(item.get("target_ip") or state.get("target_ip") or ""),
                port=int(item.get("port", 0) or 0),
                protocol=str(item.get("protocol", "tcp") or "tcp"),
                service_name=str(item.get("service_name") or item.get("name") or ""),
                banner=str(item.get("banner", "") or ""),
                version=str(item.get("version", "") or ""),
                observed_cpe=str(item.get("observed_cpe", "") or ""),
            ))
    seen = {(o.target_ip, o.port, o.service_name) for o in out}
    for svc in state.get("target_services", []) or []:
        try:
            port = int(svc.get("port", 0) or 0)
        except (TypeError, ValueError, AttributeError):
            continue
        name = str(svc.get("name") or svc.get("service_name") or "")
        key = (str(state.get("target_ip") or ""), port, name)
        if port and key not in seen:
            version = str(svc.get("version", "") or "")
            out.append(ReconObservation(
                target_ip=key[0], port=port, service_name=name,
                banner=str(svc.get("banner") or (f"{name}/{version}" if version else name)),
                version=version,
            ))
            seen.add(key)
    for port, svc in (state.get("port_services", {}) or {}).items():
        if not isinstance(svc, dict):
            continue
        try:
            p = int(port)
        except (TypeError, ValueError):
            continue
        name = str(svc.get("name") or svc.get("service_name") or "")
        key = (str(state.get("target_ip") or ""), p, name)
        if p and key not in seen:
            version = str(svc.get("version", "") or "")
            out.append(ReconObservation(
                target_ip=key[0], port=p, service_name=name,
                banner=str(svc.get("banner") or (f"{name}/{version}" if version else name)),
                version=version,
                observed_cpe=str(svc.get("cpe") or svc.get("observed_cpe") or ""),
            ))
            seen.add(key)
    if not out and state.get("target_port"):
        out.append(ReconObservation(
            target_ip=str(state.get("target_ip") or ""),
            port=int(state.get("target_port") or 0),
            service_name=str(state.get("app_name") or state.get("keyword") or ""),
            version=str(state.get("app_version") or ""),
        ))
    return [obs for obs in out if obs.target_ip and obs.port]


def _records_path(manifest: RunManifest) -> str:
    return os.path.join(manifest.run_dir, "source_records.json")


def _candidates_path(manifest: RunManifest) -> str:
    return os.path.join(manifest.run_dir, "candidates.json")


def _proofs_path(manifest: RunManifest) -> str:
    return os.path.join(manifest.run_dir, "proofs.json")


def _write_json(path: str, obj) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        json.dump(obj, fh, sort_keys=True, indent=2, default=str)
    return path


def _load_records(path: str) -> list[RawCveRecord]:
    if not path or not os.path.exists(path):
        return []
    with open(path) as fh:
        return [RawCveRecord.from_dict(item) for item in json.load(fh)]


def _candidate_objs(items) -> list[ExploitCandidate]:
    out: list[ExploitCandidate] = []
    for item in items or []:
        if isinstance(item, ExploitCandidate):
            out.append(item)
        elif isinstance(item, dict):
            out.append(ExploitCandidate.from_dict(item))
    return out


def _candidate_specs_from_state(state: PentestState) -> list:
    specs = list(state.get("exploit_candidate_specs", []) or [])
    for key in ("exploitdb_dir", "exploitdb_root"):
        root = str(state.get(key) or "")
        if root:
            specs.extend(index_exploitdb(root))
    for key in ("nse_scripts_dir", "nmap_nse_dir"):
        root = str(state.get(key) or "")
        if root:
            specs.extend(index_nse_scripts(root))
    for item in state.get("candidate_specs", []) or []:
        if not isinstance(item, dict):
            specs.append(item)
            continue
        spec = _spec_from_dict(item)
        if spec is not None:
            specs.append(spec)
    return specs


def _spec_from_dict(item: dict):
    kind = str(item.get("kind") or item.get("type") or "").lower()
    try:
        if kind == "poc":
            return PublicPocSpec(
                cve_id=item["cve_id"], repo=item["repo"], commit=item["commit"],
                entry_point=item["entry_point"],
                capability=item.get("capability", "code_execution"),
                license=item.get("license", "unknown"),
            )
        if kind == "exploitdb":
            return ExploitDbSpec(
                cve_id=item["cve_id"], edb_id=str(item["edb_id"]),
                local_path=item["local_path"],
                capability=item.get("capability", "code_execution"),
                language=item.get("language", "unknown"),
            )
        if kind == "metasploit":
            return MetasploitSpec(
                cve_id=item["cve_id"], module_name=item["module_name"],
                options=dict(item.get("options", {}) or {}),
                rank=item.get("rank", "manual"),
                check_supported=bool(item.get("check_supported", True)),
                capability=item.get("capability", "code_execution"),
            )
        if kind == "nuclei":
            return NucleiSpec(
                cve_id=item["cve_id"], template_id=item["template_id"],
                template_path=item["template_path"],
                classification=item.get("classification", "cve"),
                pinned_commit=item["pinned_commit"],
                capability=item.get("capability", "detection"),
            )
        if kind == "nmap_nse":
            return NmapNseSpec(
                cve_id=item["cve_id"], script_name=item["script_name"],
                script_path=item["script_path"],
                script_args=list(item.get("script_args", []) or []),
                capability=item.get("capability", "detection"),
            )
        if kind == "vendor_recipe":
            return VendorRecipeSpec(
                cve_id=item["cve_id"], vendor=item["vendor"], product=item["product"],
                steps=[ProcedureStep.from_dict(step) for step in item.get("steps", [])],
                references=list(item.get("references", []) or []),
                license=item.get("license", "vendor-documented"),
                capability=item.get("capability", "code_execution"),
            )
        if kind == "native_tool":
            return NativeToolSpec(
                cve_id=item["cve_id"], tool_name=item["tool_name"],
                argv=list(item.get("argv", []) or []),
                capability=item.get("capability", "detection"),
                references=list(item.get("references", []) or []),
            )
    except KeyError:
        return None
    return None


def _proof_objs(path: str) -> list[ProofArtifact]:
    if not path or not os.path.exists(path):
        return []
    with open(path) as fh:
        return [ProofArtifact(**item) for item in json.load(fh)]


def pipeline_prepare_node(state: PentestState) -> dict:
    manifest = _manifest_from_state(state)
    truth = state.get("oracle_truth") or manifest.oracle_spec.get("truth")
    truth_path = ""
    if truth:
        truth_path = _private_truth_path(manifest)
        _write_json(truth_path, truth.to_dict() if isinstance(truth, TargetTruth) else truth)
    manifest = _public_manifest(manifest)
    snapshot = str(state.get("source_snapshot_dir") or state.get("benchmark_cve_cache_path") or "")
    if snapshot and os.path.exists(snapshot):
        digest = hashlib.sha256()
        for root, _, names in os.walk(snapshot):
            for name in sorted(names):
                with open(os.path.join(root, name), "rb") as handle:
                    digest.update(handle.read())
        manifest.source_snapshot_hashes = {snapshot: digest.hexdigest()}
    _save_manifest(manifest)
    ledger = _open_ledger(state, manifest)
    observations = _observations_from_state(state)
    ledger.record(phase="recon", stage="applicability",
                  detail=f"prepared {len(observations)} observation(s)")
    result = dict(state.get("pipeline_result", {}) or {})
    result.update({"run_dir": manifest.run_dir, "observation_count": len(observations)})
    return {
        "current_phase": "pipeline_prepare",
        "pipeline_manifest": manifest.to_dict(),
        "pipeline_ledger_path": _ledger_path(state, manifest),
        "pipeline_result": result,
        "retrieval_mode": str(state.get("retrieval_mode") or "snapshot"),
        "source_snapshot_dir": str(state.get("source_snapshot_dir") or ""),
        "oracle_truth": {},
        "evaluator_truth_path": truth_path,
    }


def pipeline_retrieve_node(state: PentestState) -> dict:
    manifest = _manifest_from_state(state)
    ledger = _open_ledger(state, manifest)
    runner = _runner(state, manifest, ledger)
    observations = _observations_from_state(state)
    fingerprints = runner.evidence(observations)
    records: list[RawCveRecord] = []
    for fp in fingerprints:
        records.extend(runner.retrieve(fp))
    path = _write_json(_records_path(manifest), [r.to_dict() for r in records])
    result = dict(state.get("pipeline_result", {}) or {})
    result.update({
        "fingerprints": [fp.to_dict() for fp in fingerprints],
        "source_records_path": path,
        "source_record_count": len(records),
        "source_record_ids": sorted({r.cve_id for r in records}),
    })
    return {
        "current_phase": "pipeline_retrieve",
        "pipeline_result": result,
        "retrieval_status": "ok" if records else "empty",
    }


def pipeline_queue_node(state: PentestState) -> dict:
    manifest = _manifest_from_state(state)
    ledger = _open_ledger(state, manifest)
    runner = _runner(state, manifest, ledger)
    records = _load_records((state.get("pipeline_result", {}) or {}).get("source_records_path") or _records_path(manifest))
    limits = ResourceLimits(**manifest.limits)
    existing = _candidate_objs(state.get("exploit_candidates", []))
    if records:
        candidates = collect_from_records(
            records,
            specs=_candidate_specs_from_state(state),
            candidates=existing,
            max_cves=limits.max_cves_per_service,
        )
    else:
        candidates = existing
    # Variant 3/4 opt in here.  The default remains the preserved manual
    # catalog so old snapshots and current v6 tests do not acquire tools.
    if state.get("automatic_exploit_compilation") and records and str(state.get("retrieval_mode") or "") != "replay":
        msf_service = None
        try:
            if state.get("automatic_metasploit_discovery"):
                msf_service = MetasploitRpcService(manifest.run_dir)
                compiler = ExploitCompiler(manifest.run_dir, msf=msf_service.start())
            else:
                compiler = ExploitCompiler(manifest.run_dir)
            known = {c.candidate_id for c in candidates}
            for cve_id in sorted({record.cve_id for record in records}):
                for candidate in compiler.compile_cve(cve_id):
                    if candidate.candidate_id not in known:
                        candidates.append(candidate)
                        known.add(candidate.candidate_id)
                        ledger.record(phase="candidates", stage="applicability", cve_id=candidate.cve_id,
                                      candidate_id=candidate.candidate_id, method=candidate.kind,
                                      detail="compiled", payload={
                                          "source_kind": candidate.provenance.source_kind,
                                          "runtime_kind": candidate.runtime_kind,
                                          "artifact_hash": candidate.artifact_hash,
                                      })
            ledger.record(phase="candidates", stage="applicability", detail="automatic_compilation",
                          payload={"candidate_count": len(candidates)})
        except Exception as exc:  # compilation failure is non-fatal to other sources
            ledger.record(phase="candidates", stage="execution_failure", outcome="execution_failed",
                          failure_class="runtime_error", detail=f"automatic compilation: {exc}")
        finally:
            if msf_service is not None:
                msf_service.stop()
    selected: dict[str, ExploitCandidate] = {}
    plan: list[dict] = []
    for fp in runner.evidence(_observations_from_state(state)):
        queue = runner.build_queue(fp=fp, candidates=candidates)
        for rc in queue.ranked:
            cand = rc.candidate
            selected.setdefault(cand.candidate_id, cand)
            plan.append({
                "candidate_id": cand.candidate_id,
                "cve_id": cand.cve_id,
                "kind": cand.kind,
                "source": cand.source,
                "score": rc.score,
                "applicability": rc.applicability,
            })
    selected_candidates = list(selected.values())
    manifest.candidate_ids = [c.candidate_id for c in selected_candidates]
    manifest.artifact_hashes = {c.candidate_id: c.artifact_hash for c in selected_candidates if c.artifact_hash}
    _save_manifest(manifest)
    cand_path = _write_json(_candidates_path(manifest), [c.to_dict() for c in selected_candidates])
    result = dict(state.get("pipeline_result", {}) or {})
    result.update({
        "candidates_path": cand_path,
        "candidate_count": len(selected_candidates),
        "queue": plan,
    })
    cves = sorted({c.cve_id for c in selected_candidates})
    return {
        "current_phase": "pipeline_queue",
        "pipeline_manifest": manifest.to_dict(),
        "pipeline_result": result,
        "exploit_candidates": [c.to_dict() for c in selected_candidates],
        "cve_list": cves,
        "exploit_plan": plan,
        "selected_exploit": plan[0] if plan else None,
        "planning_complete": bool(plan),
    }


def pipeline_execute_node(state: PentestState) -> dict:
    """Execute the next candidate selected by the verifier.

    Runs ONE candidate, captures proof, returns state update for the
    verifier to evaluate.
    """
    manifest = _manifest_from_state(state)
    ledger = _open_ledger(state, manifest)
    if str(state.get("retrieval_mode") or "") == "replay":
        result = dict(state.get("pipeline_result", {}) or {})
        result.setdefault("proofs_path", _proofs_path(manifest))
        return {"current_phase": "pipeline_execute", "pipeline_result": result}

    runner = _runner(state, manifest, ledger)
    candidates = _candidate_objs(state.get("exploit_candidates", []))

    # Only the current verifier decision can authorize this execution.
    verifier_decisions = state.get("verifier_decisions") or []
    decision = VerifierDecision.from_dict(verifier_decisions[-1]) if verifier_decisions else None
    if not decision or decision.action != "execute" or not decision.approved_for_execution:
        result = dict(state.get("pipeline_result", {}) or {})
        return {"current_phase": "pipeline_execute", "pipeline_result": result}
    target = next((c for c in candidates if c.candidate_id == decision.target_candidate_id), None)
    if not target:
        return {"current_phase": "pipeline_execute"}

    fps = runner.evidence(_observations_from_state(state))
    fp = fps[0] if fps else None
    if not fp:
        result = dict(state.get("pipeline_result", {}) or {})
        return {"current_phase": "pipeline_execute", "pipeline_result": result}

    queue = runner.build_queue(fp=fp, candidates=candidates)
    rc = next((item for item in queue.ranked if item.candidate.candidate_id == target.candidate_id), None)
    if rc is None and target.kind == "guided_procedure":
        from src.pipeline.queue import rank_candidates
        ranked = rank_candidates([target], fingerprint=fp,
                                 proof_capability=manifest.oracle_spec.get("capability", "code_execution"),
                                 ledger=ledger, scope=_scope_from_state(state))
        rc = ranked[0] if ranked else None
    if rc is None or rc.rejection_reasons or not rc.capability_match or not rc.procedure_complete:
        ledger.record(phase="execution", stage="policy_decision", candidate_id=target.candidate_id,
                      cve_id=target.cve_id, outcome="blocked_by_policy", failure_class="policy_block",
                      detail="verifier selected non-executable candidate")
        return {"current_phase": "pipeline_execute"}
    progress = dict(state.get("lifecycle_progress") or {})
    candidate_progress = dict(progress.get(target.candidate_id) or {})
    completed = {int(index) for index in candidate_progress.get("completed", [])}
    llm = _role_llm(state, "executor")
    intent = ExecutorAgent(llm).select(target, completed_step_indexes=completed)
    if intent.step_index < 0:
        return {"current_phase": "pipeline_execute", "role_usage": _role_usage(state, "executor", llm)}
    session_artifacts = list(state.get("session_artifacts") or [])
    if target.runtime_kind == "metasploit_rpc":
        rpc_result = runner.execute_metasploit_lifecycle(target, fp)
        runner.last_results = [rpc_result.result]
        if rpc_result.session:
            session_artifacts.append(rpc_result.session.to_dict())
        # RPC owns its atomic lifecycle so a session cannot be orphaned across
        # graph process boundaries.
        completed.update(range(len(target.procedure)))
    else:
        runner._execute_one(rc, fp, verifier_approved_ids={target.candidate_id}, step_indexes={intent.step_index},
                            count_attempt=not completed)
        completed.add(intent.step_index)
    candidate_progress["completed"] = sorted(completed)
    candidate_progress["terminal"] = len(completed) >= len(target.procedure) or \
        target.procedure[intent.step_index].stage == "cleanup"
    progress[target.candidate_id] = candidate_progress

    # Capture proof for verifier evaluation.
    last_proof = {}
    if runner._proofs:
        last_proof = runner._proofs[-1].to_dict()

    # Proof artifacts are append-only across fresh runner instances.
    proofs = _proof_objs(_proofs_path(manifest)) + runner._proofs
    unique = {p.content_hash: p for p in proofs if p.content_hash}
    proofs = list(unique.values())
    proof_path = _write_json(_proofs_path(manifest), [p.to_dict() for p in proofs])
    result = dict(state.get("pipeline_result", {}) or {})
    result.update({"proofs_path": proof_path, "proof_count": len(proofs)})
    last_result = runner.last_results[-1].__dict__ if runner.last_results else {}
    return {
        "current_phase": "pipeline_execute",
        "pipeline_result": result,
        "last_executed_candidate_id": target.candidate_id,
        "last_execution_proof": last_proof,
        "proof_artifacts": [p.to_dict() for p in proofs],
        "last_execution_result": last_result,
        "execution_intent": intent.to_dict(),
        "lifecycle_progress": progress,
        "session_artifacts": session_artifacts,
        "role_usage": _role_usage(state, "executor", llm),
        "execution_step_count": int(state.get("execution_step_count", 0) or 0) + 1,
    }


def pipeline_planner_node(state: PentestState) -> dict:
    """Planner role selects a catalog method or a bounded guided fallback."""
    manifest = _manifest_from_state(state)
    ledger = _open_ledger(state, manifest)
    candidates = _candidate_objs(state.get("exploit_candidates", []))
    observations = _observations_from_state(state)
    runner = _runner(state, manifest, ledger)
    fps = runner.evidence(observations)
    fp = fps[0] if fps else None
    if not fp:
        return {"current_phase": "pipeline_planner"}
    attempted = {e.candidate_id for e in ledger.events if e.candidate_id and e.detail == "candidate_attempted"}
    queue = runner.build_queue(fp=fp, candidates=candidates)
    eligible = [rc.candidate for rc in queue.ranked if rc.candidate.candidate_id not in attempted]
    catalog = [c for c in eligible if c.kind != "guided_procedure"]
    catalog_exhausted = not catalog
    references: list[str] = []
    records = _load_records((state.get("pipeline_result", {}) or {}).get("source_records_path") or _records_path(manifest))
    for record in records:
        references.extend(record.references)
    for c in candidates:
        references.extend(c.provenance.references)
    references = list(dict.fromkeys(ref for ref in references if ref))
    llm = _role_llm(state, "restore_planner" if state.get("last_execution_result") else "planner")
    planner = PlannerAgent(llm=llm, scope=_scope_from_state(state), ledger=ledger)
    proposal = planner.propose_catalog(fingerprint=fp, candidates=catalog, catalog_exhausted=False) if catalog else None
    if proposal is None and catalog_exhausted and state.get("allow_llm_fallback", True):
        cve_ids = list(state.get("cve_list") or []) or [r.cve_id for r in records]
        cve_id = next((c for c in cve_ids if c), "")
        proposal = planner.propose(
            fingerprint=fp, cve_id=cve_id, observations=observations,
            executed_candidates=candidates,
            prior_failures=[e.failure_class for e in ledger.events if e.failure_class],
            references=references,
        )

    proposals = list(state.get("planner_proposals") or [])
    guided = list(state.get("guided_procedures") or [])
    all_candidates = list(candidates)
    if proposal:
        proposals.append(proposal.to_dict())
        guided.append(proposal.candidate.to_dict())
        all_candidates.append(proposal.candidate)

    return {
        "current_phase": "pipeline_planner",
        "catalog_exhausted": catalog_exhausted,
        "planner_proposals": proposals,
        "guided_procedures": guided,
        "exploit_candidates": [c.to_dict() for c in all_candidates],
        "active_plan": proposal.to_dict() if proposal else {},
        "role_usage": _role_usage(state, "restore_planner" if state.get("last_execution_result") else "planner", llm),
    }


def pipeline_critic_node(state: PentestState) -> dict:
    """LLM Critic: challenges planner proposals before verifier commits."""
    manifest = _manifest_from_state(state)
    ledger = _open_ledger(state, manifest)

    active = state.get("active_plan") or {}
    if not active:
        return {"current_phase": "pipeline_critic", "critic_verdicts": list(state.get("critic_verdicts") or [])}
    latest_proposal = PlannerProposal.from_dict(active) if isinstance(active, dict) else active

    observations = _observations_from_state(state)
    runner = _runner(state, manifest, ledger)
    fps = runner.evidence(observations)
    fp = fps[0] if fps else None

    llm = _role_llm(state, "critic")
    critic = CriticAgent(
        llm=llm,
        scope=_scope_from_state(state),
        ledger=ledger,
    )

    verdict = critic.evaluate(
        latest_proposal,
        fingerprint=fp,
        executed_candidates=_candidate_objs(state.get("exploit_candidates", [])),
        catalog_candidates=_candidate_objs(state.get("exploit_candidates", [])),
    )

    verdicts = list(state.get("critic_verdicts") or [])
    verdicts.append(verdict.to_dict())

    return {
        "current_phase": "pipeline_critic",
        "critic_verdicts": verdicts,
        "role_usage": _role_usage(state, "critic", llm),
    }


def pipeline_verifier_node(state: PentestState) -> dict:
    """Evidence-gated verifier: decides collect_evidence | replan | execute | stop.

    Called both before execution (to pick the next candidate) and after
    execution (to evaluate results and decide the next step).
    """
    manifest = _manifest_from_state(state)
    ledger = _open_ledger(state, manifest)
    runner = _runner(state, manifest, ledger)
    observations = _observations_from_state(state)
    fps = runner.evidence(observations)
    fp = fps[0] if fps else None

    candidates = _candidate_objs(state.get("exploit_candidates", []))
    queue = runner.build_queue(fp=fp, candidates=candidates) if fp else CandidateQueue(ranked=[])

    # Gather executed IDs from ledger.
    executed_ids: set[str] = set()
    for e in ledger.events:
        if e.candidate_id and (e.detail == "candidate_attempted" or e.outcome):
            executed_ids.add(e.candidate_id)

    # Gather prior failures.
    prior_failures = [e.failure_class for e in ledger.events
                      if e.failure_class and e.outcome == "execution_failed"]

    # Parse prior verifier decisions.
    prior_decisions = [VerifierDecision.from_dict(d)
                       for d in (state.get("verifier_decisions") or [])]

    # Parse planner proposals and critic verdicts.
    planner_proposals = state.get("planner_proposals") or []
    critic_verdicts = state.get("critic_verdicts") or []

    # Get last execution result/proof.
    last_proof = None
    if state.get("last_execution_proof"):
        try:
            last_proof = ProofArtifact(**state["last_execution_proof"])
        except Exception:
            pass

    last_result = None
    if state.get("last_execution_result"):
        try:
            last_result = ExecutionResult(**state["last_execution_result"])
        except (TypeError, ValueError):
            pass

    llm = _role_llm(state, "verifier")
    verifier = PipelineVerifierAgent(llm=llm, ledger=ledger)

    progress = dict(state.get("lifecycle_progress") or {})
    active_id = str(state.get("last_executed_candidate_id") or "")
    active = dict(progress.get(active_id) or {})
    if active_id and active and not active.get("terminal"):
        decision = VerifierDecision(
            action="execute", reason="continue approved lifecycle",
            cited_state_keys=["lifecycle_progress"], target_candidate_id=active_id,
            approved_for_execution=True,
        )
    else:
        decision = verifier.decide(
        fingerprint=fp,
        ranked_queue=queue,
        executed_candidates=candidates,
        executed_ids=executed_ids,
        prior_verifier_decisions=prior_decisions,
        planner_proposals=planner_proposals,
        critic_verdicts=critic_verdicts,
        last_execution_result=last_result,
        last_proof=last_proof,
        prior_failures=prior_failures,
        catalog_exhausted=bool(state.get("catalog_exhausted")),
        loop_count=int(state.get("planner_loop_count", 0) or 0),
        loop_max=int(state.get("planner_loop_max", 5) or 5),
        )
    decision = verifier.review(decision)

    ledger.record(
        phase="verifier", stage="policy_decision",
        detail=f"action={decision.action}",
        payload={"decision": decision.to_dict()},
    )

    decisions = list(state.get("verifier_decisions") or [])
    decisions.append(decision.to_dict())

    return {
        "current_phase": "pipeline_verifier",
        "verifier_decisions": decisions,
        "current_verifier_action": decision.action,
        "pending_evidence_request": decision.new_evidence_request or {},
        "role_usage": _role_usage(state, "verifier", llm),
    }


def pipeline_oracle_node(state: PentestState) -> dict:
    manifest = _manifest_from_state(state)
    ledger = _open_ledger(state, manifest)
    truth = _evaluator_truth(state, manifest)
    proofs = _proof_objs((state.get("pipeline_result", {}) or {}).get("proofs_path") or _proofs_path(manifest))
    result = OracleResult(outcome="execution_failed", reason="no truth supplied")
    if truth is not None:
        oracle = BenchmarkOracle()
        cves = [manifest.oracle_spec.get("cve_id", "")] if manifest.oracle_spec.get("cve_id") else truth.applicable_cves
        result = OracleResult(outcome="execution_failed", reason="no proof accepted")
        for cve_id in [c for c in cves if c]:
            for proof in proofs:
                candidate = oracle.evaluate_proof(cve_id, proof, truth)
                if candidate.task_proof:
                    result = candidate
                    break
                if candidate.vulnerability_confirmed and not result.vulnerability_confirmed:
                    result = candidate
            if result.task_proof:
                break
    ledger.record(
        phase="oracle", stage="task_proof",
        outcome=result.outcome,
        failure_class="" if result.task_proof or result.vulnerability_confirmed else "oracle_reject",
        detail=result.reason,
        proof_ref=result.proof_artifact.path if result.proof_artifact else "",
        payload={"evidence_used": result.evidence_used},
    )
    manifest.oracle_result = result.to_dict()
    _save_manifest(manifest)
    pipeline_result = dict(state.get("pipeline_result", {}) or {})
    pipeline_result.update({
        "outcome": result.outcome,
        "reason": result.reason,
        "ledger_path": _ledger_path(state, manifest),
        "run_dir": manifest.run_dir,
    })
    return {
        "current_phase": "done",
        "pipeline_manifest": manifest.to_dict(),
        "pipeline_result": pipeline_result,
        "execution_success": result.task_proof,
        "execution_summary": result.reason or result.outcome,
        "run_end_time": time.time(),
    }


def _build_v5_graph(thread_id: str):
    """Build the legacy v5 deterministic pipeline graph.

    Topology: recon → prepare → retrieve → queue → execute → oracle → END
    Preserved for backward-compatible baseline tests.
    """
    checkpoint_path = os.path.join(_CHECKPOINT_DIR, f"{thread_id}.pkl")
    saver = _DiskBackedSaver(checkpoint_path)

    graph = StateGraph(PentestState)

    # ── Nodes ─────────────────────────────────────────────────────────────────
    graph.add_node("recon", recon_node)
    graph.add_node("pipeline_prepare", pipeline_prepare_node)
    graph.add_node("pipeline_retrieve", pipeline_retrieve_node)
    graph.add_node("pipeline_queue", pipeline_queue_node)
    graph.add_node("pipeline_execute", pipeline_execute_node)
    graph.add_node("pipeline_oracle", pipeline_oracle_node)

    # ── Edges ─────────────────────────────────────────────────────────────────
    graph.set_entry_point("recon")

    graph.add_conditional_edges("recon", _route_recon_to_pipeline, {
        "recon": "recon",
        "pipeline_prepare": "pipeline_prepare",
        "end": END,
    })
    graph.add_edge("pipeline_prepare", "pipeline_retrieve")
    graph.add_edge("pipeline_retrieve", "pipeline_queue")
    graph.add_edge("pipeline_queue", "pipeline_execute")
    graph.add_edge("pipeline_execute", "pipeline_oracle")
    graph.add_edge("pipeline_oracle", END)

    # ── Compile with disk-backed MemorySaver ──────────────────────────────────
    compiled = graph.compile(
        checkpointer=saver,
    )

    config = {"configurable": {"thread_id": thread_id}, "recursion_limit": 100}
    logger.info("v5 graph compiled. Thread: %s  Checkpoint: %s", thread_id, checkpoint_path)
    return compiled, config


def build_graph_v5(thread_id: str = "default"):
    """Public alias for the v5 deterministic pipeline graph."""
    return _build_v5_graph(thread_id)


def _build_v6_graph(thread_id: str):
    """Build the v6 evidence-gated multi-agent graph.

    Topology:
        recon → prepare → retrieve → queue → planner → critic →
        verifier → execute → verifier (loop) → oracle → END

    The verifier is the loop controller.  After each execution result
    it decides: collect_evidence, replan, execute (next candidate),
    or stop.  A hard loop cap (default 5) prevents infinite cycling.
    """
    from src.pipeline.queue import CandidateQueue as _CQ
    from src.pipeline.candidates import SUPPORTED_KINDS as _SK

    checkpoint_path = os.path.join(_CHECKPOINT_DIR, f"{thread_id}.pkl")
    saver = _DiskBackedSaver(checkpoint_path)

    graph = StateGraph(PentestState)

    # ── Nodes ─────────────────────────────────────────────────────────────────
    graph.add_node("recon", recon_node)
    graph.add_node("pipeline_prepare", pipeline_prepare_node)
    graph.add_node("pipeline_retrieve", pipeline_retrieve_node)
    graph.add_node("pipeline_queue", pipeline_queue_node)
    graph.add_node("pipeline_planner", pipeline_planner_node)
    graph.add_node("pipeline_critic", pipeline_critic_node)
    graph.add_node("pipeline_verifier", pipeline_verifier_node)
    graph.add_node("pipeline_targeted_recon", pipeline_targeted_recon_node)
    graph.add_node("pipeline_execute", pipeline_execute_node)
    graph.add_node("pipeline_oracle", pipeline_oracle_node)

    # ── Edges ─────────────────────────────────────────────────────────────────
    graph.set_entry_point("recon")

    graph.add_conditional_edges("recon", _route_recon_to_pipeline, {
        "recon": "recon",
        "pipeline_prepare": "pipeline_prepare",
        "end": END,
    })
    graph.add_edge("pipeline_prepare", "pipeline_retrieve")
    graph.add_edge("pipeline_retrieve", "pipeline_queue")

    # Queue → Planner (planner checks catalog exhaustion internally)
    graph.add_conditional_edges("pipeline_queue", _route_queue_to_planner, {
        "pipeline_planner": "pipeline_planner",
        "end": END,
    })

    # Planner → Critic or Verifier
    graph.add_conditional_edges("pipeline_planner", _route_planner, {
        "pipeline_critic": "pipeline_critic",
        "pipeline_verifier": "pipeline_verifier",
        "end": END,
    })

    # Critic → Verifier
    graph.add_conditional_edges("pipeline_critic", _route_critic, {
        "pipeline_verifier": "pipeline_verifier",
        "end": END,
    })

    # Verifier → Execute | Planner | targeted recon | Oracle
    graph.add_conditional_edges("pipeline_verifier", _route_verifier, {
        "pipeline_execute": "pipeline_execute",
        "pipeline_planner": "pipeline_planner",
        "pipeline_targeted_recon": "pipeline_targeted_recon",
        "pipeline_oracle": "pipeline_oracle",
        "end": END,
    })
    graph.add_edge("pipeline_targeted_recon", "pipeline_retrieve")

    # Execute → Verifier (loop back)
    graph.add_conditional_edges("pipeline_execute", _route_execute_to_verifier, {
        "pipeline_verifier": "pipeline_verifier",
        "end": END,
    })

    graph.add_edge("pipeline_oracle", END)

    # ── Compile with disk-backed MemorySaver ──────────────────────────────────
    compiled = graph.compile(checkpointer=saver)

    config = {"configurable": {"thread_id": thread_id}, "recursion_limit": 200}
    logger.info("v6 graph compiled. Thread: %s  Checkpoint: %s", thread_id, checkpoint_path)
    return compiled, config


def build_graph(thread_id: str = "default"):
    """Build the v6 evidence-gated multi-agent graph.

    This is the default graph.  For the legacy v5 deterministic pipeline,
    use ``build_graph_v5()``.
    """
    return _build_v6_graph(thread_id)
