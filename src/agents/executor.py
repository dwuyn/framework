"""Constrained executor role: selects an approved procedure step, never argv."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.pipeline.candidates import ExploitCandidate


@dataclass
class ExecutionIntent:
    candidate_id: str
    step_index: int
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"candidate_id": self.candidate_id, "step_index": self.step_index, "rationale": self.rationale}


class ExecutorAgent:
    """Selects one pre-approved step; the runner remains the command authority."""

    def __init__(self, llm: Any | None = None) -> None:
        self.llm = llm

    def select(self, candidate: ExploitCandidate, *, completed_step_indexes: set[int] | None = None) -> ExecutionIntent:
        """Return the first unfinished lifecycle action in declared order."""
        completed = completed_step_indexes or set()
        indices = [i for i, step in enumerate(candidate.procedure)
                   if step.stage in {"setup", "prepare", "check", "execute", "verify", "cleanup"}
                   and i not in completed]
        step_index = indices[0] if indices else -1
        return ExecutionIntent(candidate_id=candidate.candidate_id, step_index=step_index,
                               rationale="next approved lifecycle action")
