"""
tests/test_graph_v6.py
──────────────────────
Tests for the v6 evidence-gated multi-agent graph topology,
verifier routing, and backward compatibility with the v5 graph.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.pipeline.candidates import (
    SUPPORTED_KINDS,
    ExploitCandidate,
    ProcedureStep,
    Provenance,
    derive_candidate_id,
)

# ── Graph topology tests ─────────────────────────────────────────────────────


class TestGraphV6Topology(unittest.TestCase):
    """Test the v6 graph wiring."""

    def test_graph_has_planner_node(self):
        from src.graph import _build_v6_graph
        graph, config = _build_v6_graph("test-v6-planner")
        # The graph should compile without error.
        self.assertIsNotNone(graph)

    def test_graph_has_verifier_node(self):
        from src.graph import _build_v6_graph
        graph, config = _build_v6_graph("test-v6-verifier")
        self.assertIsNotNone(graph)

    def test_graph_recursion_limit(self):
        from src.graph import _build_v6_graph
        _, config = _build_v6_graph("test-v6-recursion")
        self.assertEqual(config["recursion_limit"], 200)

    def test_backward_compat_v5_graph(self):
        from src.graph import build_graph_v5
        graph, config = build_graph_v5("test-v5-compat")
        self.assertIsNotNone(graph)
        self.assertEqual(config["recursion_limit"], 100)

    def test_build_graph_calls_v6(self):
        from src.graph import build_graph
        # build_graph should be _build_v6_graph.
        graph1, _ = build_graph("test-default")
        self.assertIsNotNone(graph1)


# ── Routing function tests ───────────────────────────────────────────────────


class TestRoutingFunctions(unittest.TestCase):

    def test_route_queue_to_planner(self):
        from src.graph import _route_queue_to_planner
        state = {"current_phase": "pipeline_queue"}
        self.assertEqual(_route_queue_to_planner(state), "pipeline_planner")

    def test_route_queue_to_planner_respects_done(self):
        from src.graph import _route_queue_to_planner
        state = {"current_phase": "done"}
        self.assertEqual(_route_queue_to_planner(state), "end")

    def test_route_planner_to_critic_when_exhausted(self):
        from src.graph import _route_planner
        state = {
            "current_phase": "pipeline_planner",
            "catalog_exhausted": True,
            "planner_proposals": [{"cve_id": "CVE-2021-41773"}],
        }
        self.assertEqual(_route_planner(state), "pipeline_critic")

    def test_route_planner_to_critic_for_catalog_plan(self):
        from src.graph import _route_planner
        state = {
            "current_phase": "pipeline_planner",
            "catalog_exhausted": False,
        }
        state["active_plan"] = {"proposal_id": "plan-catalog"}
        self.assertEqual(_route_planner(state), "pipeline_critic")

    def test_route_planner_to_verifier_when_no_proposals(self):
        from src.graph import _route_planner
        state = {
            "current_phase": "pipeline_planner",
            "catalog_exhausted": True,
            "planner_proposals": [],
        }
        self.assertEqual(_route_planner(state), "pipeline_verifier")

    def test_route_critic_to_verifier(self):
        from src.graph import _route_critic
        state = {"current_phase": "pipeline_critic"}
        self.assertEqual(_route_critic(state), "pipeline_verifier")

    def test_route_verifier_execute(self):
        from src.graph import _route_verifier
        state = {
            "current_verifier_action": "execute",
            "planner_loop_count": 0,
            "planner_loop_max": 5,
        }
        self.assertEqual(_route_verifier(state), "pipeline_execute")
        self.assertEqual(state["planner_loop_count"], 1)

    def test_route_verifier_replan(self):
        from src.graph import _route_verifier
        state = {
            "current_verifier_action": "replan",
            "planner_loop_count": 1,
            "planner_loop_max": 5,
        }
        self.assertEqual(_route_verifier(state), "pipeline_planner")
        self.assertEqual(state["planner_loop_count"], 2)

    def test_route_verifier_collect_evidence(self):
        from src.graph import _route_verifier
        state = {
            "current_verifier_action": "collect_evidence",
            "planner_loop_count": 0,
            "planner_loop_max": 5,
        }
        self.assertEqual(_route_verifier(state), "pipeline_targeted_recon")

    def test_route_verifier_stop(self):
        from src.graph import _route_verifier
        state = {
            "current_verifier_action": "stop",
            "planner_loop_count": 0,
            "planner_loop_max": 5,
        }
        self.assertEqual(_route_verifier(state), "pipeline_oracle")

    def test_route_verifier_loop_cap_forces_oracle(self):
        from src.graph import _route_verifier
        state = {
            "current_verifier_action": "execute",
            "planner_loop_count": 5,
            "planner_loop_max": 5,
        }
        self.assertEqual(_route_verifier(state), "pipeline_oracle")

    def test_route_execute_to_verifier(self):
        from src.graph import _route_execute_to_verifier
        state = {"current_phase": "pipeline_execute"}
        self.assertEqual(_route_execute_to_verifier(state), "pipeline_verifier")

    def test_route_execute_to_verifier_respects_done(self):
        from src.graph import _route_execute_to_verifier
        state = {"current_phase": "done"}
        self.assertEqual(_route_execute_to_verifier(state), "end")


# ── Planner loop cap tests ───────────────────────────────────────────────────


class TestPlannerLoopCap(unittest.TestCase):

    def test_loop_cap_increments_on_execute(self):
        from src.graph import _route_verifier
        state = {
            "current_verifier_action": "execute",
            "planner_loop_count": 0,
            "planner_loop_max": 3,
        }
        # loop_max=3 allows 3 execute passes before forcing oracle.
        for i in range(3):
            result = _route_verifier(state)
            self.assertEqual(result, "pipeline_execute",
                              msg=f"iteration {i} should execute")
            self.assertEqual(state["planner_loop_count"], i + 1)
        # 4th call: count=3 >= max=3 → oracle.
        result = _route_verifier(state)
        self.assertEqual(result, "pipeline_oracle")

    def test_loop_cap_increments_on_replan(self):
        from src.graph import _route_verifier
        state = {
            "current_verifier_action": "replan",
            "planner_loop_count": 0,
            "planner_loop_max": 2,
        }
        # 1st: count=0, check 0>=2 → False, increment to 1, return planner.
        self.assertEqual(_route_verifier(state), "pipeline_planner")
        self.assertEqual(state["planner_loop_count"], 1)
        # 2nd: count=1, check 1>=2 → False, increment to 2, return planner.
        self.assertEqual(_route_verifier(state), "pipeline_planner")
        self.assertEqual(state["planner_loop_count"], 2)
        # 3rd: count=2, check 2>=2 → True, return oracle (no increment).
        self.assertEqual(_route_verifier(state), "pipeline_oracle")


# ── Candidate integration tests ─────────────────────────────────────────────


class TestCandidateIntegration(unittest.TestCase):

    def test_all_eight_kinds_present(self):
        expected = {"poc", "exploitdb", "metasploit", "nuclei", "nmap_nse",
                    "vendor_recipe", "native_tool", "guided_procedure"}
        self.assertEqual(set(SUPPORTED_KINDS), expected)

    def test_guided_procedure_in_candidates(self):
        prov = Provenance(trust="llm_provisional", source_kind="llm_planner")
        cand = ExploitCandidate(
            candidate_id=derive_candidate_id(kind="guided_procedure",
                                              cve_id="CVE-2021-41773",
                                              locator="llm-test", provenance=prov),
            cve_id="CVE-2021-41773",
            kind="guided_procedure",
            source="llm_planner",
            locator="llm-test",
            provenance=prov,
            procedure=[ProcedureStep(stage="execute",
                                      argv=["curl", "-s", "http://10.0.0.1/"])],
        )
        self.assertEqual(cand.kind, "guided_procedure")
        self.assertEqual(cand.provenance.trust, "llm_provisional")
        # Serializes and deserializes.
        d = cand.to_dict()
        restored = ExploitCandidate.from_dict(d)
        self.assertEqual(restored.kind, "guided_procedure")
        self.assertEqual(restored.provenance.trust, "llm_provisional")


if __name__ == "__main__":
    unittest.main()
