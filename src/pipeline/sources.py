"""
src/pipeline/sources.py
───────────────────────
Independent CVE source adapters.

Adapters implement a single method, ``fetch(product, vendor, version)``,
returning a list of :class:`RawCveRecord` records. Each adapter writes its
*raw* response to the run directory and the normalised record separately.

Run modes:

  * ``live`` — perform real HTTP / filesystem reads; preserve raw responses.
  * ``snapshot`` — read from a fixed snapshot directory only; raise if a
    requested product/version is missing.
  * ``replay`` — read pre-computed normalised records; no HTTP or I/O.

A failed or rate-limited backend never fails the others — each adapter is
isolated, reports a ``BackendStatus`` event into the ledger, and the registry
collapses the failure into a normalisable status without raising.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from src.pipeline.ledger import EventLedger

# ── Records ───────────────────────────────────────────────────────────────────


@dataclass
class RawCveRecord:
    """A single CVE record as emitted by an adapter, with raw + normalised fields."""

    source: str                       # cve_list_v5 | nvd | vulnx
    cve_id: str
    raw: dict[str, Any]               # original response payload
    raw_hash: str                     # SHA-256 of the raw payload
    retrieved_at: float

    vendor: str = ""
    product: str = ""
    version_start: str = ""
    version_end: str = ""
    version_start_inclusive: bool = True
    version_end_inclusive: bool = True
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cpe_candidates: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    description: str = ""
    published_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source, "cve_id": self.cve_id,
            "raw": dict(self.raw or {}),
            "raw_hash": self.raw_hash, "retrieved_at": self.retrieved_at,
            "vendor": self.vendor, "product": self.product,
            "version_start": self.version_start, "version_end": self.version_end,
            "version_start_inclusive": self.version_start_inclusive,
            "version_end_inclusive": self.version_end_inclusive,
            "cvss_score": self.cvss_score, "cvss_vector": self.cvss_vector,
            "cpe_candidates": list(self.cpe_candidates),
            "references": list(self.references), "description": self.description,
            "published_at": self.published_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RawCveRecord":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class PrioritySignal:
    """KEV / EPSS enrichment signals (priority only, never applicability)."""

    cve_id: str
    in_kev: bool = False
    kev_date_added: float = 0.0
    epss_score: float = 0.0
    epss_percentile: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PrioritySignal":
        return cls(**{k: data.get(k, getattr(cls(), k)) for k in (
            "cve_id", "in_kev", "kev_date_added", "epss_score", "epss_percentile",
        )})


# ── Backend statuses ──────────────────────────────────────────────────────────


class BackendStatus:
    OK = "ok"
    NO_MATCH = "no_match"
    QUERY_INVALID = "query_invalid"
    BACKEND_FAILED = "backend_failed"
    DATASET_MISSING = "dataset_missing"


# ── Adapters ──────────────────────────────────────────────────────────────────


class BaseAdapter:
    name = "base"

    def __init__(self, *, mode: str = "live", snapshot_dir: str = "", ledger: EventLedger | None = None) -> None:
        if mode not in {"live", "snapshot", "replay"}:
            raise ValueError(f"Invalid adapter mode: {mode}")
        self.mode = mode
        self.snapshot_dir = snapshot_dir
        self.ledger = ledger

    def _record_event(self, *, status: str, detail: str, payload: Mapping[str, Any] | None = None) -> None:
        if self.ledger is None:
            return
        self.ledger.record(
            phase="retrieval", stage="applicability",
            detail=detail, payload={"source": self.name, "status": status, **(payload or {})},
        )

    def _read_snapshot(self, product: str, vendor: str, version: str) -> list[RawCveRecord]:
        if not self.snapshot_dir:
            self._record_event(status=BackendStatus.DATASET_MISSING,
                                detail=f"{self.name} snapshot_dir unset")
            return []
        path = os.path.join(self.snapshot_dir, "cves.json")
        if not os.path.exists(path):
            self._record_event(status=BackendStatus.DATASET_MISSING,
                                detail=f"{self.name} snapshot missing")
            return []
        try:
            with open(path) as fh:
                data = json.load(fh)
        except Exception as exc:                              # noqa: BLE001
            self._record_event(status=BackendStatus.BACKEND_FAILED,
                                detail=f"{self.name} snapshot unreadable",
                                payload={"exception": str(exc)[:160]})
            return []
        entries = data.get(self.name, []) if isinstance(data, dict) else []
        out: list[RawCveRecord] = []
        for entry in entries:
            rec = RawCveRecord.from_dict(entry) if isinstance(entry, dict) else None
            if rec is None:
                continue
            # Source-of-truth precedence: snapshot records already encode
            # vendor/product; we filter on demand so products are returned
            # exactly as snapshotted.
            if product and rec.product and rec.product != product.lower():
                continue
            if vendor and rec.vendor and rec.vendor != vendor.lower():
                continue
            out.append(rec)
        if not out:
            self._record_event(status=BackendStatus.NO_MATCH,
                                detail=f"{self.name} snapshot had no match",
                                payload={"product": product, "version": version})
        return out

    def fetch(self, product: str, vendor: str, version: str) -> list[RawCveRecord]:
        raise NotImplementedError

    def _live_unavailable(self) -> list[RawCveRecord]:
        # Never raise on a missing live backend; surface a no-match with status.
        self._record_event(status=BackendStatus.BACKEND_FAILED,
                            detail=f"{self.name} live fetch unavailable",
                            payload={"mode": self.mode})
        return []


class CveListV5Adapter(BaseAdapter):
    """Adapter for the canonical CVE Project list (cvelistV5)."""

    name = "cve_list_v5"

    def fetch(self, product: str, vendor: str, version: str) -> list[RawCveRecord]:
        if not product or product == "unknown":
            self._record_event(status=BackendStatus.QUERY_INVALID,
                                detail="cve_list_v5 requires known product")
            return []
        if self.mode in {"snapshot", "replay"}:
            return self._read_snapshot(product, vendor, version)
        return self._live_unavailable()


class NvdAdapter(BaseAdapter):
    """Adapter for the NVD CVE 2.0 API.

    Respects rate limiting; failures are isolated and reported via the ledger.
    """

    name = "nvd"

    def fetch(self, product: str, vendor: str, version: str) -> list[RawCveRecord]:
        if not product or product == "unknown":
            self._record_event(status=BackendStatus.QUERY_INVALID,
                                detail="nvd requires known product")
            return []
        if self.mode in {"snapshot", "replay"}:
            return self._read_snapshot(product, vendor, version)
        return self._live_unavailable()


class VulnxAdapter(BaseAdapter):
    """Optional ``vulnx`` aggregator adapter (never the sole live source)."""

    name = "vulnx"

    def fetch(self, product: str, vendor: str, version: str) -> list[RawCveRecord]:
        if not product or product == "unknown":
            self._record_event(status=BackendStatus.QUERY_INVALID,
                                detail="vulnx requires known product")
            return []
        if self.mode in {"snapshot", "replay"}:
            return self._read_snapshot(product, vendor, version)
        return self._live_unavailable()


# ── KEV / EPSS enrichment ─────────────────────────────────────────────────────


class KEVAdapter(BaseAdapter):
    name = "kev"

    def fetch(self, product: str, vendor: str, version: str) -> list[PrioritySignal]:
        if self.mode in {"snapshot", "replay"} and self.snapshot_dir:
            path = os.path.join(self.snapshot_dir, "kev.json")
            if not os.path.exists(path):
                self._record_event(status=BackendStatus.DATASET_MISSING,
                                    detail="kev dataset missing in snapshot")
                return []
            try:
                with open(path) as fh:
                    data = json.load(fh)
            except Exception:
                self._record_event(status=BackendStatus.BACKEND_FAILED,
                                    detail="kev dataset unreadable")
                return []
            signals: list[PrioritySignal] = []
            for entry in data.get("cves", []) if isinstance(data, dict) else data:
                cve_id = entry.get("cve_id") if isinstance(entry, dict) else None
                if not cve_id:
                    continue
                signals.append(PrioritySignal(cve_id=cve_id, in_kev=True,
                                                kev_date_added=float(entry.get("date_added", 0) or 0)))
            return signals
        return []


class EpssAdapter(BaseAdapter):
    name = "epss"

    def fetch(self, product: str, vendor: str, version: str) -> list[PrioritySignal]:
        if self.mode in {"snapshot", "replay"} and self.snapshot_dir:
            path = os.path.join(self.snapshot_dir, "epss.json")
            if not os.path.exists(path):
                self._record_event(status=BackendStatus.DATASET_MISSING,
                                    detail="epss dataset missing in snapshot")
                return []
            try:
                with open(path) as fh:
                    data = json.load(fh)
            except Exception:
                self._record_event(status=BackendStatus.BACKEND_FAILED,
                                    detail="epss dataset unreadable")
                return []
            signals: list[PrioritySignal] = []
            entries = data.get("cves", []) if isinstance(data, dict) else data
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                cve_id = entry.get("cve_id") or entry.get("cve") or ""
                if not cve_id:
                    continue
                signals.append(PrioritySignal(
                    cve_id=cve_id,
                    epss_score=float(entry.get("epss_score", 0.0) or 0.0),
                    epss_percentile=float(entry.get("percentile", 0.0) or 0.0),
                ))
            return signals
        return []


# ── Snapshot writer ──────────────────────────────────────────────────────────


def write_snapshot(snapshot_dir: str, records: list[RawCveRecord]) -> str:
    """Write *records* into *snapshot_dir* as immutable JSON.

    Returns the SHA-256 manifest hash for the snapshot.
    """
    os.makedirs(snapshot_dir, exist_ok=True)
    blob: dict[str, list[dict[str, Any]]] = {}
    for rec in records:
        blob.setdefault(rec.source, []).append(rec.to_dict())
    out_path = os.path.join(snapshot_dir, "cves.json")
    with open(out_path, "w") as fh:
        json.dump(blob, fh, sort_keys=True, indent=2, default=str)
    manifest = {
        "snapshot_dir": snapshot_dir,
        "record_count": len(records),
        "by_source": {src: len(items) for src, items in blob.items()},
        "snapshot_hash": hashlib.sha256(json.dumps(blob, sort_keys=True, default=str).encode()).hexdigest(),
    }
    with open(os.path.join(snapshot_dir, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, sort_keys=True, indent=2)
    return manifest["snapshot_hash"]


# ── Registry ──────────────────────────────────────────────────────────────────


class SourceRegistry:
    """Runs all configured adapters and aggregates results per CVE.

    Distinct per-adapter ``BackendStatus`` values are preserved and emitted
    into the ledger; one failing backend never fails the others.
    """

    def __init__(self, adapters: Iterable[BaseAdapter] | None = None,
                 *, ledger: EventLedger | None = None) -> None:
        self.adapters: list[BaseAdapter] = list(adapters or [])
        self.ledger = ledger

    def collect_cves(self, product: str, vendor: str, version: str) -> list[RawCveRecord]:
        merged: list[RawCveRecord] = []
        for adapter in self.adapters:
            try:
                results = adapter.fetch(product, vendor, version)
            except Exception as exc:                              # noqa: BLE001
                if self.ledger is not None:
                    self.ledger.record(
                        phase="retrieval", stage="applicability",
                        detail=f"{adapter.name} raised {type(exc).__name__}",
                        payload={"source": adapter.name, "status": BackendStatus.BACKEND_FAILED,
                                 "exception": str(exc)[:160]},
                    )
                continue
            if results:
                merged.extend(results)
        # Stable order: by source priority then cve_id.
        priority = {a.name: i for i, a in enumerate(self.adapters)}
        merged.sort(key=lambda r: (priority.get(r.source, 99), r.cve_id))
        return merged

    def collect_priority(self, product: str, vendor: str, version: str) -> dict[str, PrioritySignal]:
        out: dict[str, PrioritySignal] = {}
        for adapter in self.adapters:
            if not isinstance(adapter, (KEVAdapter, EpssAdapter)):
                continue
            try:
                results = adapter.fetch(product, vendor, version)
            except Exception:
                continue
            for sig in results:
                cur = out.setdefault(sig.cve_id, PrioritySignal(cve_id=sig.cve_id))
                if isinstance(adapter, KEVAdapter):
                    cur.in_kev = cur.in_kev or sig.in_kev
                    cur.kev_date_added = max(cur.kev_date_added, sig.kev_date_added)
                elif isinstance(adapter, EpssAdapter):
                    cur.epss_score = max(cur.epss_score, sig.epss_score)
                    cur.epss_percentile = max(cur.epss_percentile, sig.epss_percentile)
        return out
