"""
src/pipeline/budget.py
──────────────────────
Resource-budget enforcement.

Implements the fixed execution configuration as hard gates:
    20 minutes per target, 50 tool calls, 40 executed commands,
    5 CVEs per service, 2 methods per CVE, 3 executed candidates,
    3 bounded attempts per candidate.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from src.pipeline.manifest import ResourceLimits


class BudgetExceeded(Exception):
    """Raised when a hard resource limit would be exceeded."""

    def __init__(self, limit: str, used: int | float, maximum: int | float) -> None:
        self.limit = limit
        self.used = used
        self.maximum = maximum
        super().__init__(f"Budget '{limit}' exceeded: {used}/{maximum}")


@dataclass
class BudgetState:
    started_at: float = 0.0
    tool_calls: int = 0
    executed_commands: int = 0
    cves_per_service: dict[str, int] = field(default_factory=dict)
    methods_per_cve: dict[str, int] = field(default_factory=dict)
    executed_candidates: int = 0
    attempts_per_candidate: dict[str, int] = field(default_factory=dict)


class ResourceBudget:
    """Stateful budget tracker enforcing ``ResourceLimits`` as hard gates."""

    def __init__(self, limits: ResourceLimits | None = None) -> None:
        self.limits = limits or ResourceLimits()
        self.state = BudgetState(started_at=time.time())

    # ── Runtime ───────────────────────────────────────────────────────────────
    def remaining_seconds(self, now: float | None = None) -> float:
        if self.state.started_at <= 0:
            return float(self.limits.max_runtime_seconds)
        elapsed = (now if now is not None else time.time()) - self.state.started_at
        return max(0.0, float(self.limits.max_runtime_seconds) - elapsed)

    def check_runtime(self, now: float | None = None) -> None:
        remaining = self.remaining_seconds(now)
        if remaining <= 0:
            elapsed = (now if now is not None else time.time()) - self.state.started_at
            raise BudgetExceeded("max_runtime_seconds", round(elapsed, 1), self.limits.max_runtime_seconds)

    # ── Tool calls / commands ─────────────────────────────────────────────────
    def record_tool_call(self) -> None:
        self.state.tool_calls += 1
        if self.state.tool_calls > self.limits.max_tool_calls:
            raise BudgetExceeded("max_tool_calls", self.state.tool_calls, self.limits.max_tool_calls)

    def check_command(self) -> None:
        if self.state.executed_commands >= self.limits.max_executed_commands:
            raise BudgetExceeded("max_executed_commands", self.state.executed_commands, self.limits.max_executed_commands)

    def record_command(self) -> None:
        self.check_command()
        self.state.executed_commands += 1

    # ── CVEs per service ──────────────────────────────────────────────────────
    def check_cve_for_service(self, service_key: str) -> None:
        used = self.state.cves_per_service.get(service_key, 0)
        if used >= self.limits.max_cves_per_service:
            raise BudgetExceeded("max_cves_per_service", used, self.limits.max_cves_per_service)

    def record_cve_for_service(self, service_key: str) -> None:
        self.check_cve_for_service(service_key)
        self.state.cves_per_service[service_key] = self.state.cves_per_service.get(service_key, 0) + 1

    # ── Methods per CVE ───────────────────────────────────────────────────────
    def check_method_for_cve(self, cve_id: str) -> None:
        used = self.state.methods_per_cve.get(cve_id, 0)
        if used >= self.limits.max_methods_per_cve:
            raise BudgetExceeded("max_methods_per_cve", used, self.limits.max_methods_per_cve)

    def record_method_for_cve(self, cve_id: str) -> None:
        self.check_method_for_cve(cve_id)
        self.state.methods_per_cve[cve_id] = self.state.methods_per_cve.get(cve_id, 0) + 1

    # ── Executed candidates ────────────────────────────────────────────────────
    def check_candidate(self) -> None:
        if self.state.executed_candidates >= self.limits.max_executed_candidates:
            raise BudgetExceeded("max_executed_candidates", self.state.executed_candidates, self.limits.max_executed_candidates)

    def record_candidate(self) -> None:
        self.check_candidate()
        self.state.executed_candidates += 1

    # ── Attempts per candidate ─────────────────────────────────────────────────
    def check_attempt(self, candidate_id: str) -> None:
        used = self.state.attempts_per_candidate.get(candidate_id, 0)
        if used >= self.limits.max_attempts_per_candidate:
            raise BudgetExceeded("max_attempts_per_candidate", used, self.limits.max_attempts_per_candidate)

    def record_attempt(self, candidate_id: str) -> None:
        self.check_attempt(candidate_id)
        self.state.attempts_per_candidate[candidate_id] = self.state.attempts_per_candidate.get(candidate_id, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "limits": self.limits.to_dict(),
            "state": {
                "started_at": self.state.started_at,
                "tool_calls": self.state.tool_calls,
                "executed_commands": self.state.executed_commands,
                "cves_per_service": dict(self.state.cves_per_service),
                "methods_per_cve": dict(self.state.methods_per_cve),
                "executed_candidates": self.state.executed_candidates,
                "attempts_per_candidate": dict(self.state.attempts_per_candidate),
            },
        }
