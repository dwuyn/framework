from __future__ import annotations

import hashlib
import json

import pytest

from src.pipeline.ledger import Event, EventLedger


def _hash(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for child in value.values() for key in _keys(child)}
    if isinstance(value, list):
        return {key for child in value for key in _keys(child)}
    return set()


@pytest.mark.parametrize("cve_id", ["", "CVE-2026-12345"])
def test_public_event_projection_omits_cve_id_but_internal_ledger_keeps_it(cve_id: str) -> None:
    event = Event(
        run_id="run-1", phase="retrieval", cve_id=cve_id,
        candidate_id="candidate-1", detail="safe detail",
        payload={
            "cve_id": cve_id,
            "truth": "hidden",
            "alias": "hidden-alias",
            "decoy": {"id": "hidden-decoy"},
            "access_token": "secret",
            "service_account": "secret",
            "provider_alias": "allowed",
            "safe_metric": 1,
        },
    )

    internal = event.to_dict()
    public = event.to_public_dict()

    assert internal["cve_id"] == cve_id
    assert "cve_id" not in public
    keys = _keys(public)
    assert not keys.intersection({
        "cve_id", "truth", "alias", "decoy", "access_token", "service_account",
    })
    assert {"run_id", "phase", "candidate_id", "detail", "payload", "provider_alias", "safe_metric"}.issubset(keys)
    assert public["payload"] == {"provider_alias": "allowed", "safe_metric": 1}


def test_event_ledger_raw_projection_and_public_hash_are_distinct() -> None:
    ledger = EventLedger("run-1")
    ledger.record(
        phase="execution", cve_id="CVE-2026-98765", outcome="task_proof_obtained",
        payload={"truth": "hidden", "proof_ref": "proof-1"},
    )

    raw = ledger.events[0].to_dict()
    public = [{"role": event.phase, "event": event.to_public_dict()} for event in ledger.events]

    assert raw["cve_id"] == "CVE-2026-98765"
    assert "cve_id" not in json.dumps(public, sort_keys=True)
    assert public[0]["event"]["payload"] == {"proof_ref": "proof-1"}
    canonical = json.dumps(public, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    assert _hash(public) == hashlib.sha256(canonical).hexdigest()
