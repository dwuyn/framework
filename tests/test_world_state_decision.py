"""
tests/test_world_state_decision.py
───────────────────────────────────
Unit tests for VeriPlanPT Phase D1 (WorldStateGraph) and Phase D2 (DecisionRecord).
"""

from __future__ import annotations

import time
import pytest

from src.memory.world_state import WorldState, HostInfo, ServiceInfo, Credential, Session
from src.memory.decision import DecisionMemory, Decision


class TestWorldStateD1:
    def test_service_info_ttl_and_is_active(self):
        now = time.time()
        # Active service
        svc_active = ServiceInfo(port=80, name="http", activated_at=now, ttl_seconds=3600)
        assert svc_active.is_active(now + 100) is True

        # Expired TTL
        svc_expired = ServiceInfo(port=80, name="http", activated_at=now - 4000, ttl_seconds=3600)
        assert svc_expired.is_active(now) is False

        # Deactivated explicitly
        svc_deactivated = ServiceInfo(port=80, name="http", activated_at=now, deactivated_at=now + 10)
        assert svc_deactivated.is_active(now + 20) is False

    def test_provenance_sources(self):
        svc = ServiceInfo(port=22, name="ssh", provenance_sources=["nmap", "banner_grab"])
        assert "nmap" in svc.provenance_sources
        assert "banner_grab" in svc.provenance_sources

    def test_conflict_detection(self):
        ws = WorldState()
        # Add service with 2 conflicting evidence sources claiming different versions
        svc = ServiceInfo(
            port=80,
            name="apache",
            version="2.4.49",
            confidence=0.8,
            provenance_sources=["nmap", "http_header"],
            evidence=["nmap: Apache 2.4.49", "http_header: Server: Apache/2.4.50"],
        )
        ws.add_service("192.168.1.10", svc)

        conflicts = ws.detect_conflicts()
        assert len(conflicts) == 1
        c = conflicts[0]
        assert c["ip"] == "192.168.1.10"
        assert c["port"] == 80
        assert "2.4.49" in c["conflicting_versions"]
        assert "2.4.50" in c["conflicting_versions"]

    def test_get_active_services(self):
        now = time.time()
        ws = WorldState()
        active = ServiceInfo(port=80, name="apache", confidence=0.9, activated_at=now)
        low_conf = ServiceInfo(port=443, name="nginx", confidence=0.2, activated_at=now)
        expired = ServiceInfo(port=8080, name="tomcat", confidence=0.9, activated_at=now - 5000, ttl_seconds=3600)

        ws.add_service("10.0.0.1", active)
        ws.add_service("10.0.0.1", low_conf)
        ws.add_service("10.0.0.1", expired)

        res = ws.get_active_services(threshold=0.5, now=now)
        assert len(res) == 1
        assert res[0].port == 80

    def test_to_context_dict_filtering(self):
        ws = WorldState()
        s1 = ServiceInfo(port=80, name="apache", version="2.4.49")
        s2 = ServiceInfo(port=22, name="openssh", version="8.2p1")
        ws.add_service("10.0.0.1", s1)
        ws.add_service("10.0.0.1", s2)

        # Filter by specific service key
        key = "10.0.0.1:80:apache"
        ctx = ws.to_context_dict(service_key=key)
        assert "hosts" in ctx
        assert "10.0.0.1" in ctx["hosts"]
        svcs = ctx["hosts"]["10.0.0.1"]["services"]
        assert len(svcs) == 1
        assert svcs[0]["port"] == 80


class TestDecisionMemoryD2:
    def test_extended_decision_fields(self):
        d = Decision(
            step=1,
            phase="planning",
            question="Target selection?",
            chosen="CVE-2021-41773",
            action="run_metasploit CVE-2021-41773",
            evidence_ids=["evt_001", "evt_002"],
            difficulty_vector={"difficulty_score": 0.45},
            expected_utility=0.82,
            budget_before={"tool_calls": 5},
            budget_after={"tool_calls": 6},
            verifier_verdict="approved",
        )
        assert d.action == "run_metasploit CVE-2021-41773"
        assert d.evidence_ids == ["evt_001", "evt_002"]
        assert d.difficulty_vector["difficulty_score"] == 0.45
        assert d.expected_utility == 0.82
        assert d.verifier_verdict == "approved"

    def test_get_pending_decisions(self):
        dm = DecisionMemory()
        d1 = Decision(step=1, verifier_verdict="pending")
        d2 = Decision(step=2, verifier_verdict="approved")
        d3 = Decision(step=3, verifier_verdict="pending")
        dm.record(d1)
        dm.record(d2)
        dm.record(d3)

        pending = dm.get_pending()
        assert len(pending) == 2
        assert [p.step for p in pending] == [1, 3]
