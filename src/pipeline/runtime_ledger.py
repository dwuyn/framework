"""Thread-safe host-side ledger for observed gateway invocations."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping


def _hash(value: Any) -> str:
    if isinstance(value, bytes):
        payload = value
    else:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(payload).hexdigest()


class InvocationLedger:
    """Capture request/response identities and observed usage/cost only."""

    def __init__(self, *, phase: str, gateway_relay_lock_hash: str) -> None:
        if phase not in {"canary", "smoke", "sweep", "confirmation", "benchmark"}:
            raise ValueError("invocation ledger phase is not a locked runtime stage")
        self.phase = phase
        self.gateway_relay_lock_hash = gateway_relay_lock_hash
        self._lock = threading.RLock()
        self._records: list[dict[str, Any]] = []

    def record(
        self, *, run_id: str, model_label: str, request: Any, response: Any,
        usage: Mapping[str, Any], cost_usd: float | None, billing_status: str,
    ) -> dict[str, Any]:
        if not run_id or not model_label:
            raise ValueError("invocation ledger requires run_id and model label")
        if billing_status != "known" or cost_usd is None:
            raise ValueError("invocation ledger refuses unknown billing")
        cost = float(cost_usd)
        if cost < 0:
            raise ValueError("invocation cost cannot be negative")
        normalized = {
            "input_tokens": int(usage.get("input_tokens", -1)),
            "output_tokens": int(usage.get("output_tokens", -1)),
            "total_tokens": int(usage.get("total_tokens", -1)),
        }
        if any(value < 0 for value in normalized.values()):
            raise ValueError("observed invocation usage is incomplete")
        record = {
            "run_id": run_id, "model_label": model_label, "phase": self.phase,
            "request_sha256": _hash(request), "response_sha256": _hash(response),
            "usage": normalized, "cost_usd": cost, "billing_status": billing_status,
            "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "gateway_relay_lock_hash": self.gateway_relay_lock_hash,
        }
        with self._lock:
            self._records.append(record)
        return dict(record)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(record) for record in self._records]

    def aggregate(self, run_id: str) -> dict[str, Any]:
        rows = [row for row in self.snapshot() if row["run_id"] == run_id]
        if not rows:
            raise ValueError(f"no observed gateway invocation for {run_id}")
        return {
            "input_tokens": sum(int(row["usage"]["input_tokens"]) for row in rows),
            "output_tokens": sum(int(row["usage"]["output_tokens"]) for row in rows),
            "total_tokens": sum(int(row["usage"]["total_tokens"]) for row in rows),
            "usd": sum(float(row["cost_usd"]) for row in rows),
        }

    def write(self, path: str | Path) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            value = {
                "schema_version": "1.0.0", "phase": self.phase,
                "gateway_relay_lock_hash": self.gateway_relay_lock_hash,
                "invocations": [dict(record) for record in self._records],
            }
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{destination.name}.", dir=destination.parent,
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    handle.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary_name, destination)
            except Exception:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass
                raise
        return destination


def invocation_ledger_hash(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
