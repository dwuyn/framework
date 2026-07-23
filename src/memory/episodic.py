"""
src/memory/episodic.py
──────────────────────
Structured episodic memory: a machine-queryable log of every action,
its outcome, and cost. Not just chat message history.

Enables:
  - Repetition detection (Metric 13: RAR)
  - Recovery tracking (Metric 15: RR)
  - Token accumulation (Metrics 8-10)
  - Context summary injection (replaces full message history)

Solves: "session context lost" (PentestGPT failure mode #1)
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Episode:
    """A single recorded action in the pentest timeline."""
    step: int                                  # global step counter
    timestamp: float = 0.0                     # time.time()
    phase: str = ""                            # "recon" | "hypothesis" | "planning" | "execution"
    action_type: str = ""                      # "tool_call" | "llm_inference" | "verifier_check"
    command: str = ""                          # actual command or tool name
    args: dict = field(default_factory=dict)   # tool arguments (for dedup)
    output_summary: str = ""                   # first 500 chars of output
    outcome: str = ""                          # "success" | "fail" | "timeout" | "blocked" | "error"
    tokens_used: int = 0                       # approximate token count
    was_repeat: bool = False                   # set by EpisodicMemory.log()
    error_message: str = ""                    # empty if no error


class EpisodicMemory:
    """
    Append-only structured action log.
    
    Every tool call, LLM inference, and verifier check is recorded here
    with outcome and cost. The memory supports fast dedup detection and
    can generate compact context summaries for LLM prompt injection.
    """

    def __init__(self) -> None:
        self._episodes: list[Episode] = []
        self._command_set: set[str] = set()  # for O(1) dedup detection

    def _dedup_key(self, ep: Episode) -> str:
        """Canonical key for dedup: command + sorted args."""
        return f"{ep.command}|{json.dumps(ep.args, sort_keys=True)}"

    def log(self, episode: Episode) -> None:
        """Append an episode. Automatically marks if it's a repeat."""
        key = self._dedup_key(episode)
        episode.was_repeat = key in self._command_set
        self._command_set.add(key)
        if not episode.timestamp:
            episode.timestamp = time.time()
        self._episodes.append(episode)

    # ── Queries ───────────────────────────────────────────────────────────

    def last_n(self, n: int) -> list[Episode]:
        return self._episodes[-n:]

    def by_phase(self, phase: str) -> list[Episode]:
        return [e for e in self._episodes if e.phase == phase]

    def count_repeats(self) -> int:
        return sum(1 for e in self._episodes if e.was_repeat)

    def count_errors(self) -> int:
        return sum(1 for e in self._episodes if e.outcome in ("fail", "error", "timeout"))

    def count_recoveries(self) -> int:
        """Count sequences where an error is followed by a non-error (successful recovery)."""
        recoveries = 0
        prev_error = False
        for ep in self._episodes:
            is_error = ep.outcome in ("fail", "error", "timeout")
            if prev_error and not is_error:
                recoveries += 1
            prev_error = is_error
        return recoveries

    def count_invalid_commands(self) -> int:
        return sum(1 for e in self._episodes if e.outcome == "blocked")

    def total_tokens(self) -> int:
        return sum(e.tokens_used for e in self._episodes)

    def total_steps(self) -> int:
        return len(self._episodes)

    # ── Context summary for LLM injection ─────────────────────────────────

    def to_context_summary(self, max_entries: int = 15) -> str:
        """
        Generate a compact text summary of recent actions for LLM context injection.
        This replaces raw message history with structured, compressed context.
        
        Format:
          [step] phase: command → outcome (tokens)
          
        Only includes the last max_entries episodes + a stats header.
        """
        total = len(self._episodes)
        repeats = self.count_repeats()
        errors = self.count_errors()
        tokens = self.total_tokens()

        lines = [
            f"=== Action History ({total} total, {repeats} repeats, {errors} errors, {tokens} tokens) ===",
        ]

        recent = self._episodes[-max_entries:]
        for ep in recent:
            repeat_tag = " [REPEAT]" if ep.was_repeat else ""
            error_tag = f" ERR: {ep.error_message[:60]}" if ep.error_message else ""
            output_preview = ep.output_summary[:80].replace("\n", " ") if ep.output_summary else ""
            lines.append(
                f"  [{ep.step}] {ep.phase}: {ep.command[:60]} → {ep.outcome}{repeat_tag}{error_tag}"
            )
            if output_preview and ep.outcome == "success":
                lines.append(f"        └─ {output_preview}")

        return "\n".join(lines)

    # ── Serialization ─────────────────────────────────────────────────────

    def to_list(self) -> list[dict]:
        return [asdict(e) for e in self._episodes]

    @classmethod
    def from_list(cls, data: list[dict]) -> EpisodicMemory:
        em = cls()
        for d in data:
            ep = Episode(**d)
            em._command_set.add(em._dedup_key(ep))
            em._episodes.append(ep)
        return em
