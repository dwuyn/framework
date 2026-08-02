"""
End-to-end control flow regression: HTTP candidates exhaust, SIP retrieval
alternates ok/backend_failed, and the graph exits cleanly with a deterministic
terminal reason instead of recursion overflow.
"""

import unittest

from src.agents.hypothesis_phase.critic_agent import _apply_critic_report, _deterministic_fast_path
from src.retrieval.models import RetrievalBundle
from src.state import initial_state


class TestE2EControlFlow(unittest.TestCase):
    """Simulate a multi-service scenario that previously caused recursion overflow."""

    def test_http_exhaust_sip_alternates_exits_cleanly(self):
        """
        Scenario:
        - 2 services: HTTP (port 80) and SIP (port 5060)
        - HTTP: backend_failed, no shortlist → fast path marks exhausted, rotates to SIP
        - SIP: ok with shortlist → proceeds to planning
        - Graph exits cleanly without hitting recursion limit
        """
        state = initial_state(target_ip="10.0.0.1")
        state["phase2_followup_max"] = 2
        state["target_services"] = [
            {"service_key": "10.0.0.1:80:http", "name": "http", "port": 80, "version": "2.4.49"},
            {"service_key": "10.0.0.1:5060:sip", "name": "sip", "port": 5060, "version": "1.0"},
        ]
        state["current_service_index"] = 0
        state["phase2_exhausted_service_keys"] = []

        # --- Pass 1: HTTP — backend_failed, no shortlist → fast path returns need_more_recon
        state["retrieval_status"] = "backend_failed"
        state["phase2_followup_count"] = 1  # already used 1 followup
        bundle1 = RetrievalBundle(shortlist=[])
        report1 = _deterministic_fast_path(state, bundle1)
        self.assertEqual(report1["verdict"], "need_more_recon")

        update1 = _apply_critic_report(state, bundle1, report1, 0, 0, False)
        # followup_count reaches max (1+1=2 >= 2), so service is exhausted
        self.assertIn("10.0.0.1:80:http", update1.get("phase2_exhausted_service_keys", []))
        self.assertEqual(update1["phase2_route"], "hypothesis")
        self.assertEqual(update1["current_service_index"], 1)
        state.update(update1)

        # --- Pass 2: SIP — ok with shortlist → proceed
        state["retrieval_status"] = "ok"
        state["phase2_followup_count"] = 0
        shortlist2 = [{"cve_id": "CVE-2024-0001", "candidate_id": "sip-cand-1", "score": 0.8}]
        bundle2 = RetrievalBundle(shortlist=shortlist2)
        # Simulate LLM returning pass
        update2 = _apply_critic_report(state, bundle2, {
            "verdict": "pass",
            "approved_candidate_ids": ["sip-cand-1"],
            "rejected_candidate_ids": [],
            "issues": [],
            "recon_requests": [],
            "reason": "Good evidence",
        }, 100, 50, True)
        self.assertEqual(update2["phase2_route"], "planning")
        state.update(update2)

        # Verify we reached planning
        self.assertEqual(state["current_phase"], "planning")

    def test_all_services_backend_failed_exits_cleanly(self):
        """
        All services get backend_failed with no shortlist → graph terminates.
        """
        state = initial_state(target_ip="10.0.0.1")
        state["phase2_followup_max"] = 2
        state["target_services"] = [
            {"service_key": "10.0.0.1:80:http", "name": "http", "port": 80},
            {"service_key": "10.0.0.1:5060:sip", "name": "sip", "port": 5060},
        ]
        state["current_service_index"] = 0
        # Both services exhausted
        state["phase2_exhausted_service_keys"] = [
            "10.0.0.1:80:http",
            "10.0.0.1:5060:sip",
        ]
        state["retrieval_status"] = "backend_failed"

        bundle = RetrievalBundle(shortlist=[])
        report = _deterministic_fast_path(state, bundle)
        self.assertEqual(report["verdict"], "exhausted")
        self.assertIn("all services exhausted", report["reason"].lower())

    def test_rotation_never_returns_to_recon(self):
        """
        After service rotation (exhausted), phase2_route should be 'hypothesis'
        not 'recon'. This ensures the graph converges.
        """
        state = initial_state(target_ip="10.0.0.1")
        state["phase2_followup_count"] = 1
        state["phase2_followup_max"] = 2
        state["phase2_exhausted_service_keys"] = []
        state["target_services"] = [
            {"service_key": "10.0.0.1:80:http", "name": "http", "port": 80, "version": "2.4.49"},
            {"service_key": "10.0.0.1:5060:sip", "name": "sip", "port": 5060, "version": "1.0"},
        ]
        state["current_service_index"] = 0

        bundle = RetrievalBundle(shortlist=[])
        bundle.critic_report = {"verdict": "need_more_recon", "reason": "test"}
        report = {
            "verdict": "need_more_recon",
            "approved_candidate_ids": [],
            "rejected_candidate_ids": [],
            "issues": [],
            "recon_requests": [],
            "reason": "Need more data",
        }
        update = _apply_critic_report(state, bundle, report, 0, 0, False)
        # The key assertion: after exhaustion, route is 'hypothesis' not 'recon'
        self.assertEqual(update["phase2_route"], "hypothesis")
        self.assertIn("10.0.0.1:80:http", update["phase2_exhausted_service_keys"])


class TestPhase2RouteHypothesisAccepted(unittest.TestCase):
    """Verify that the graph routing function accepts 'hypothesis' as a valid route."""

    def test_route_accepts_hypothesis(self):
        from src.graph import _route_phase2_result
        state = {"phase2_route": "hypothesis"}
        self.assertEqual(_route_phase2_result(state), "hypothesis")

    def test_route_still_accepts_recon(self):
        from src.graph import _route_phase2_result
        state = {"phase2_route": "recon"}
        self.assertEqual(_route_phase2_result(state), "recon")

    def test_route_still_accepts_planning(self):
        from src.graph import _route_phase2_result
        state = {"phase2_route": "planning"}
        self.assertEqual(_route_phase2_result(state), "planning")

    def test_route_still_accepts_end(self):
        from src.graph import _route_phase2_result
        state = {"phase2_route": "end"}
        self.assertEqual(_route_phase2_result(state), "end")

    def test_route_defaults_to_planning_for_unknown(self):
        from src.graph import _route_phase2_result
        state = {"phase2_route": "something_else"}
        self.assertEqual(_route_phase2_result(state), "planning")

    def test_route_ends_when_phase_done(self):
        from src.graph import _route_phase2_result
        state = {"phase2_route": "", "current_phase": "done"}
        self.assertEqual(_route_phase2_result(state), "end")


class TestPhase2Convergence(unittest.TestCase):
    """Phase 2 converges through planning/hypothesis/end without empty loops."""

    def test_convergence_through_planning(self):
        """Retrieval succeeds with shortlist → critic passes → planning reached."""
        state = initial_state(target_ip="10.0.0.1")
        state["phase2_followup_max"] = 2
        state["target_services"] = [
            {"service_key": "10.0.0.1:80:http", "name": "http", "port": 80, "version": "2.4.49"},
        ]
        state["current_service_index"] = 0
        state["retrieval_status"] = "ok"
        state["phase2_followup_count"] = 0
        shortlist = [{"cve_id": "CVE-2024-0001", "candidate_id": "c1", "score": 0.8}]
        bundle = RetrievalBundle(shortlist=shortlist)

        update = _apply_critic_report(state, bundle, {
            "verdict": "pass",
            "approved_candidate_ids": ["c1"],
            "rejected_candidate_ids": [],
            "issues": [],
            "recon_requests": [],
            "reason": "Strong evidence",
        }, 100, 50, True)

        self.assertEqual(update["phase2_route"], "planning")
        self.assertEqual(update["current_phase"], "planning")

    def test_backend_failed_retry_then_success_converges(self):
        """backend_failed retry succeeds → shortlist produced → proceeds to planning."""
        state = initial_state(target_ip="10.0.0.1")
        state["retrieval_status"] = "ok"  # retry succeeded
        state["phase2_followup_count"] = 0
        state["target_services"] = [
            {"service_key": "10.0.0.1:80:http", "name": "http", "port": 80},
        ]
        shortlist = [{"cve_id": "CVE-2024-0001", "candidate_id": "c1", "score": 0.8}]
        bundle = RetrievalBundle(shortlist=shortlist)

        update = _apply_critic_report(state, bundle, {
            "verdict": "pass",
            "approved_candidate_ids": ["c1"],
            "rejected_candidate_ids": [],
            "issues": [],
            "recon_requests": [],
            "reason": "Good evidence after retry",
        }, 100, 50, True)

        self.assertEqual(update["phase2_route"], "planning")

    def test_phase2_never_loops_empty_recon(self):
        """After exhausting services, phase2 terminates — never returns to recon."""
        state = initial_state(target_ip="10.0.0.1")
        state["phase2_followup_count"] = 1
        state["phase2_followup_max"] = 2
        state["retrieval_status"] = "backend_failed"
        state["phase2_exhausted_service_keys"] = ["10.0.0.1:80:http"]
        state["target_services"] = [
            {"service_key": "10.0.0.1:80:http", "name": "http", "port": 80},
        ]
        state["current_service_index"] = 0

        bundle = RetrievalBundle(shortlist=[])
        report = _deterministic_fast_path(state, bundle)
        self.assertEqual(report["verdict"], "exhausted")

        update = _apply_critic_report(state, bundle, report, 0, 0, False)
        self.assertEqual(update["phase2_route"], "end")
        self.assertEqual(update["current_phase"], "done")
        # Must not be "recon"
        self.assertNotEqual(update.get("phase2_route"), "recon")

    def test_multi_service_convergence(self):
        """HTTP exhausts → SIP proceeds → planning reached. No loops."""
        state = initial_state(target_ip="10.0.0.1")
        state["phase2_followup_max"] = 2
        state["target_services"] = [
            {"service_key": "10.0.0.1:80:http", "name": "http", "port": 80, "version": "2.4.49"},
            {"service_key": "10.0.0.1:5060:sip", "name": "sip", "port": 5060, "version": "1.0"},
        ]
        state["current_service_index"] = 0
        state["phase2_exhausted_service_keys"] = []

        # Pass 1: HTTP — backend_failed, no shortlist → exhaust, rotate to SIP
        state["retrieval_status"] = "backend_failed"
        state["phase2_followup_count"] = 1
        bundle1 = RetrievalBundle(shortlist=[])
        report1 = _deterministic_fast_path(state, bundle1)
        self.assertEqual(report1["verdict"], "need_more_recon")
        update1 = _apply_critic_report(state, bundle1, report1, 0, 0, False)
        self.assertIn("10.0.0.1:80:http", update1.get("phase2_exhausted_service_keys", []))
        self.assertEqual(update1["phase2_route"], "hypothesis")
        state.update(update1)

        # Pass 2: SIP — ok with shortlist → planning
        state["retrieval_status"] = "ok"
        state["phase2_followup_count"] = 0
        shortlist2 = [{"cve_id": "CVE-2024-0001", "candidate_id": "sip-1", "score": 0.8}]
        bundle2 = RetrievalBundle(shortlist=shortlist2)
        update2 = _apply_critic_report(state, bundle2, {
            "verdict": "pass",
            "approved_candidate_ids": ["sip-1"],
            "rejected_candidate_ids": [],
            "issues": [],
            "recon_requests": [],
            "reason": "SIP evidence",
        }, 100, 50, True)
        self.assertEqual(update2["phase2_route"], "planning")
        self.assertEqual(update2["current_phase"], "planning")


if __name__ == "__main__":
    unittest.main()
