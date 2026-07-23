"""
src/graph.py
─────────────
LangGraph StateGraph — the central orchestrator.

Topology (v4 — minimal evidence-driven graph)
──────────────────────────────────────────────────────────────
    START → recon → recon_verifier → evidence → retrieval →
        candidates → queue → execution → execution_verifier → END

The legacy planner/skeptic/risk debate and the misleading
``maintain_access`` phase have been removed. The improved pipeline lives
in ``src.pipeline.runner`` and is the recommended entry point; this
graph remains for backward compatibility with the existing tests, but it
deliberately bypasses the now-deprecated debate and persistence phase.
The Phase 2 hypothesis subgraph is retained only to keep existing test
imports working — its planner/skeptic/risk debate is no longer invoked.

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
import logging
import os
import pickle
import tempfile
import threading

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

from src.agents.execution import execution_node
from src.agents.hypothesis_phase import build_hypothesis_phase_graph
from src.agents.planning import (
    finalize_planning_node,
    planner_node,
    route_risk_officer,
)
from src.agents.recon import recon_node
from src.agents.verifier import (
    execution_verifier_node,
    recon_verifier_node,
    route_execution_verifier,
    route_recon_verifier,
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


def build_graph(thread_id: str = "default"):
    """
    Build and compile the PentestAgent StateGraph.

    Parameters
    ----------
    thread_id : str
        Used as the filename for the disk checkpoint (one file per thread).
        Reuse the same thread_id to resume a previous run.

    Returns
    -------
    compiled_graph, config_dict
    """
    checkpoint_path = os.path.join(_CHECKPOINT_DIR, f"{thread_id}.pkl")
    saver = _DiskBackedSaver(checkpoint_path)

    graph = StateGraph(PentestState)

    # ── Nodes ─────────────────────────────────────────────────────────────────
    graph.add_node("recon", recon_node)
    graph.add_node("recon_verifier", recon_verifier_node)
    graph.add_node("hypothesis_phase", build_hypothesis_phase_graph())

    # ── Planning Sub-Graph (deterministic queue, no debate) ─────────────────
    # The legacy planner/skeptic/risk debate has been removed. The planning
    # node now defers to the deterministic queue in src/pipeline/queue.py.
    planning_graph = StateGraph(PentestState)
    planning_graph.add_node("planner", planner_node)
    planning_graph.add_node("finalize_planning", finalize_planning_node)
    planning_graph.add_edge("planner", "finalize_planning")
    planning_graph.set_entry_point("planner")

    graph.add_node("planning", planning_graph.compile())

    graph.add_node("execution", execution_node)
    graph.add_node("execution_verifier", execution_verifier_node)

    # ── Edges ─────────────────────────────────────────────────────────────────
    graph.set_entry_point("recon")

    # Recon loops until complete, then goes to recon_verifier
    graph.add_conditional_edges("recon", _route_recon_to_verifier, {
        "recon": "recon",
        "recon_verifier": "recon_verifier",
        "end": END,
    })

    # Recon verifier: pass → hypothesis, block → recon
    graph.add_conditional_edges("recon_verifier", route_recon_verifier, {
        "recon": "recon",
        "hypothesis": "hypothesis_phase",
        "end": END,
    })

    # Phase 2 subgraph routes back to recon, forward to planning, retries hypothesis, or terminates.
    graph.add_conditional_edges("hypothesis_phase", _route_phase2_result, {
        "recon": "recon",
        "planning": "planning",
        "hypothesis": "hypothesis_phase",
        "end": END,
    })

    # Planning → execution
    graph.add_conditional_edges("planning", _route_planning_result, {
        "execution": "execution",
        "end": END,
    })

    # Execution → execution_verifier (always)
    graph.add_edge("execution", "execution_verifier")

    # Execution verifier:
    #   continue  → loop back to execution
    #   end       → END  (the legacy maintain_access phase has been removed)
    #   exhausted → END
    #   replan    → hypothesis_phase
    graph.add_conditional_edges("execution_verifier", route_execution_verifier, {
        "execution": "execution",
        "end": END,                  # no maintain_access; oracle proof already adjudicates
        "exhausted": END,
        "replan": "hypothesis_phase",
    })

    # No maintain_access phase; the runner in src/pipeline/runner.py records
    # cleanup events into the ledger when the procedure declares cleanup steps.

    # ── Compile with disk-backed MemorySaver ──────────────────────────────────
    compiled = graph.compile(
        checkpointer=saver,
    )

    config = {"configurable": {"thread_id": thread_id}, "recursion_limit": 100}
    logger.info("Graph compiled. Thread: %s  Checkpoint: %s", thread_id, checkpoint_path)
    return compiled, config
