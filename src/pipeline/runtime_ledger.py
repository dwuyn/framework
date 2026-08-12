"""Thread-safe, durable ledger for observed gateway invocations."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping


class BillingUnknownError(RuntimeError):
    """A provider response exists but billing evidence is not durable/complete."""

    billing_unknown = True
    model_response_received = True


class BillableInvocationError(RuntimeError):
    """A known-billed invocation failed after the provider response."""

    billing_unknown = False
    model_response_received = True
    billable_model_response = True

    def __init__(self, message: str, *, cost_usd: float) -> None:
        super().__init__(message)
        self.cost_usd = float(cost_usd)


class InvocationConflictError(RuntimeError):
    """A restarted call reused an invocation slot with a different request."""


def _hash(value: Any) -> str:
    if isinstance(value, bytes):
        payload = value
    else:
        payload = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class InvocationLedger:
    """Capture response state and atomically persist it before gateway return."""

    CURRENT_SCHEMA = "1.2.0"
    _PHASES = {"canary", "smoke", "sweep", "confirmation", "benchmark"}

    def __init__(
        self,
        *,
        phase: str,
        gateway_relay_lock_hash: str,
        path: str | Path | None = None,
        epoch: str = "",
    ) -> None:
        if phase not in self._PHASES:
            raise ValueError("invocation ledger phase is not a locked runtime stage")
        self.phase = phase
        self.gateway_relay_lock_hash = gateway_relay_lock_hash
        self.epoch = str(epoch)
        self.path = Path(path).resolve() if path is not None else None
        self._lock = threading.RLock()
        self._records: list[dict[str, Any]] = []

    @classmethod
    def from_file(cls, path: str | Path) -> "InvocationLedger":
        source = Path(path)
        value = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(value, Mapping):
            raise ValueError("invocation ledger must be a JSON object")
        schema = str(value.get("schema_version", ""))
        if schema not in {"1.0.0", "1.1.0", cls.CURRENT_SCHEMA}:
            raise ValueError("unsupported invocation ledger schema")
        phase = str(value.get("phase", ""))
        lock_hash = str(value.get("gateway_relay_lock_hash", ""))
        ledger = cls(
            phase=phase, gateway_relay_lock_hash=lock_hash, path=source,
            epoch=str(value.get("epoch", "")),
        )
        rows = value.get("invocations", [])
        if not isinstance(rows, list):
            raise ValueError("invocation ledger invocations must be an array")
        for raw in rows:
            if not isinstance(raw, Mapping):
                raise ValueError("invocation ledger record must be an object")
            record = dict(raw)
            # r5 records are completed, known invocations.  Normalize them at
            # read time while keeping the original file immutable.
            if schema == "1.0.0":
                record.setdefault("outcome", "completed")
                record.setdefault("model_response_received", True)
            ledger._validate_record(record)
            ledger._records.append(record)
        return ledger

    read = from_file

    @staticmethod
    def _normalized_usage(usage: Mapping[str, Any] | None) -> dict[str, int] | None:
        if usage is None:
            return None
        normalized = {
            "input_tokens": int(usage.get("input_tokens", -1)),
            "output_tokens": int(usage.get("output_tokens", -1)),
            "total_tokens": int(usage.get("total_tokens", -1)),
        }
        if any(value < 0 for value in normalized.values()):
            raise ValueError("observed invocation usage is incomplete")
        return normalized

    @staticmethod
    def _validate_record(record: Mapping[str, Any]) -> None:
        if not str(record.get("run_id", "")) or not str(record.get("model_label", "")):
            raise ValueError("invocation ledger record requires run_id and model label")
        outcome = str(record.get("outcome", ""))
        status = str(record.get("billing_status", ""))
        if outcome not in {"completed", "post_response_failure"}:
            raise ValueError("invocation ledger outcome is invalid")
        if status not in {"known", "unknown"}:
            raise ValueError("invocation ledger billing status is invalid")
        if status == "known":
            if record.get("cost_usd") is None or record.get("usage") is None:
                raise ValueError("known billing requires usage and cost")
            if float(record["cost_usd"]) < 0:
                raise ValueError("invocation cost cannot be negative")
        elif record.get("cost_usd") is not None or record.get("usage") is not None:
            raise ValueError("unknown billing cannot carry partial cost evidence")

    def _value(self) -> dict[str, Any]:
        return {
            "schema_version": self.CURRENT_SCHEMA,
            "phase": self.phase,
            "epoch": self.epoch,
            "gateway_relay_lock_hash": self.gateway_relay_lock_hash,
            "invocations": [dict(record) for record in self._records],
        }

    def _write_locked(self, destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(self._value(), indent=2, sort_keys=True) + "\n")
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

    def record(
        self,
        *,
        run_id: str,
        model_label: str,
        request: Any,
        response: Any = None,
        response_hash: str | None = None,
        usage: Mapping[str, Any] | None = None,
        cost_usd: float | None,
        billing_status: str,
        outcome: str = "completed",
        model_response_received: bool = True,
        epoch: str = "",
        call_index: int | None = None,
        model_profile_hash: str = "",
        replay_count: int = 0,
    ) -> dict[str, Any]:
        if not run_id or not model_label:
            raise ValueError("invocation ledger requires run_id and model label")
        if billing_status not in {"known", "unknown"}:
            raise ValueError("invocation ledger billing status is invalid")
        if outcome not in {"completed", "post_response_failure"}:
            raise ValueError("invocation ledger outcome is invalid")
        if not model_response_received:
            raise ValueError("invocation ledger records require a provider response")
        normalized = self._normalized_usage(usage)
        cost = None if cost_usd is None else float(cost_usd)
        if billing_status == "known":
            if normalized is None or cost is None:
                raise ValueError("known billing requires complete usage and cost")
            if cost < 0:
                raise ValueError("invocation cost cannot be negative")
        elif normalized is not None or cost is not None:
            raise ValueError("unknown billing cannot carry partial cost evidence")
        if response_hash is None and response is not None:
            response_hash = _hash(response)
        record = {
            "run_id": run_id,
            "model_label": model_label,
            "phase": self.phase,
            "request_sha256": _hash(request),
            "response_sha256": response_hash,
            "usage": normalized,
            "cost_usd": cost,
            "billing_status": billing_status,
            "outcome": outcome,
            "model_response_received": model_response_received,
            "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "gateway_relay_lock_hash": self.gateway_relay_lock_hash,
        }
        identity_epoch = str(epoch or self.epoch)
        if identity_epoch:
            record["epoch"] = identity_epoch
        if call_index is not None:
            if int(call_index) < 0:
                raise ValueError("invocation call_index cannot be negative")
            record["call_index"] = int(call_index)
        if model_profile_hash:
            record["model_profile_hash"] = str(model_profile_hash)
        if response is not None:
            record["response"] = response
        record["replay_count"] = int(replay_count)
        self._validate_record(record)
        with self._lock:
            self._records.append(record)
            try:
                if self.path is not None:
                    self._write_locked(self.path)
            except Exception:
                # Atomic write-through failed.  An in-memory tombstone is
                # sticky so a durable classification is never destroyed:
                # later lookups report "unknown", never "none".  The gateway
                # converts this into BillingUnknownError and the coordinator
                # halts with billing_unknown instead of misreading the moment
                # as a pre-response infrastructure failure.
                record["billing_status"] = "unknown"
                record["usage"] = None
                record["cost_usd"] = None
                raise
        return dict(record)

    def replay_or_conflict(
        self, *, epoch: str, run_id: str, call_index: int, request: Any,
        model_profile_hash: str,
    ) -> dict[str, Any] | None:
        """Replay one durable response, or fail closed on slot reuse.

        The identity is intentionally scoped to this ledger's epoch and never
        searches another run or another ledger file.
        """
        request_hash = _hash(request)
        with self._lock:
            matches = [
                row for row in self._records
                if row.get("epoch") == str(epoch)
                and row.get("run_id") == run_id
                and int(row.get("call_index", -1)) == int(call_index)
                and row.get("model_profile_hash") == model_profile_hash
            ]
            if not matches:
                return None
            row = matches[0]
            if row.get("request_sha256") != request_hash:
                raise InvocationConflictError(
                    "durable invocation slot reused with a different request hash"
                )
            row["replay_count"] = int(row.get("replay_count", 0)) + 1
            if self.path is not None:
                self._write_locked(self.path)
            return dict(row)

    def provider_call_count(self, run_id: str, *, epoch: str = "") -> int:
        """Count provider responses in one run/epoch, excluding replays."""
        return sum(
            1 for row in self.snapshot()
            if row.get("run_id") == run_id and (not epoch or row.get("epoch") == str(epoch))
        )

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(record) for record in self._records]

    def lookup(self, run_id: str) -> dict[str, Any]:
        rows = [row for row in self.snapshot() if row["run_id"] == run_id]
        if not rows:
            return {"found": False, "billing_status": "none", "cost_usd": 0.0}
        if any(row["billing_status"] == "unknown" for row in rows):
            return {
                "found": True, "billing_status": "unknown", "cost_usd": None,
                "records": rows,
            }
        return {
            "found": True,
            "billing_status": "known",
            "cost_usd": sum(float(row["cost_usd"]) for row in rows),
            "records": rows,
        }

    def aggregate(self, run_id: str) -> dict[str, Any]:
        state = self.lookup(run_id)
        if not state["found"]:
            raise ValueError(f"no observed gateway invocation for {run_id}")
        if state["billing_status"] != "known":
            raise BillingUnknownError(f"billing is unknown for {run_id}")
        rows = state["records"]
        return {
            "input_tokens": sum(int(row["usage"]["input_tokens"]) for row in rows),
            "output_tokens": sum(int(row["usage"]["output_tokens"]) for row in rows),
            "total_tokens": sum(int(row["usage"]["total_tokens"]) for row in rows),
            "usd": float(state["cost_usd"]),
        }

    def write(self, path: str | Path | None = None) -> Path:
        destination = Path(path).resolve() if path is not None else self.path
        if destination is None:
            raise ValueError("invocation ledger write requires a path")
        with self._lock:
            self.path = destination
            return self._write_locked(destination)


def invocation_ledger_hash(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
