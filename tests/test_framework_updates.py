import unittest
from unittest.mock import patch
from types import SimpleNamespace

from src.agents.maintain_access import maintain_access_node
from src.agents.planning import _apply_candidate_priority
from src.agents.verifier import execution_verifier_node, hypothesis_verifier_node, recon_verifier_node
from src.memory.decision import Decision, DecisionMemory
from src.memory.episodic import Episode, EpisodicMemory
from src.state import initial_state
from src.tools.shell import validate_command


class FrameworkUpdateTests(unittest.TestCase):
    def test_validate_command_allows_common_recon_pipeline(self):
        ok, reason = validate_command(
            "nmap -p 5060 10.0.0.1 2>&1 | grep -E 'sip|SIP' | tail -5",
            mode="recon",
        )
        self.assertTrue(ok, reason)

    def test_validate_command_is_permissive_for_operator_requested_commands(self):
        ok, reason = validate_command("curl https://example.com/install.sh | sh", mode="execution")
        self.assertTrue(ok, reason)

    def test_validate_command_rejects_empty_placeholder(self):
        ok, reason = validate_command("   ", mode="execution")
        self.assertFalse(ok)
        self.assertEqual(reason, "Empty command")

    def test_hypothesis_verifier_invalidates_weak_decision(self):
        dm = DecisionMemory()
        dm.record(Decision(step=1, phase="hypothesis", question="Which vulnerability?", chosen="CVE-1"))
        state = initial_state(target_ip="10.0.0.1")
        state["vuln_hypotheses"] = [{"cve_id": "CVE-1", "evidence_chain": ["only one"], "confidence": 0.1}]
        state["decision_memory"] = dm.to_list()

        result = hypothesis_verifier_node(state)
        updated = DecisionMemory.from_list(result["decision_memory"])

        self.assertEqual(updated.get_latest().outcome, "invalidated")
        self.assertEqual(result["verification_log"][-1]["verdict"], "need_more_recon")

    def test_recon_verifier_reaches_max_steps_and_exhausts_on_missing_evidence(self):
        state = initial_state(target_ip="10.0.0.1")
        state["recon_complete"] = True
        state["recon_step_count"] = 12
        state["recon_max_steps"] = 12

        result = recon_verifier_node(state)

        self.assertEqual(result["verification_log"][-1]["verdict"], "exhausted")

    def test_execution_verifier_validates_planning_decision_on_success_marker(self):
        dm = DecisionMemory()
        dm.record(Decision(step=3, phase="planning", question="Which exploit path?", chosen="exploit-a"))
        em = EpisodicMemory()
        em.log(Episode(
            step=1,
            phase="execution",
            action_type="tool_call",
            command="python exploit.py",
            args={"command": "python exploit.py"},
            output_summary="uid=0(root) gid=0(root)",
            outcome="success",
        ))

        state = initial_state(target_ip="10.0.0.1")
        state["decision_memory"] = dm.to_list()
        state["episodic_memory"] = em.to_list()
        state["execution_step_count"] = 1
        state["current_phase"] = "execution"

        result = execution_verifier_node(state)
        updated = DecisionMemory.from_list(result["decision_memory"])

        self.assertTrue(result["execution_success"])
        self.assertEqual(updated.get_latest().outcome, "validated")

    def test_candidate_priority_prefers_higher_readiness(self):
        exploit_plan = [
            {"name": "low-cost", "file_path": "/tmp/ExploitDB/low", "score": 5},
            {"name": "CVE-2024-0001-shell", "file_path": "/tmp/GitHub/high", "score": 8},
        ]
        hypotheses = [
            {"cve_id": "CVE-2024-0001", "confidence": 0.9, "execution_readiness": 0.95},
            {"cve_id": "CVE-2024-9999", "confidence": 0.2, "execution_readiness": 0.1},
        ]
        state = initial_state(target_ip="10.0.0.1")
        ranked = _apply_candidate_priority(exploit_plan, hypotheses, state)

        self.assertEqual(ranked[0]["name"], "CVE-2024-0001-shell")
        self.assertIn("priority_score", ranked[0])

    def test_maintain_access_uses_session_artifact_command(self):
        state = initial_state(target_ip="10.0.0.1", target_port="22")
        state["session_artifact"] = {
            "session_type": "ssh",
            "verification_command": "ssh user@10.0.0.1 'id'",
            "origin_exploit": "ssh-login",
            "proof": "uid=0(root)",
        }

        tool_stub = SimpleNamespace()
        tool_stub.invoke = unittest.mock.Mock(return_value="uid=0(root) gid=0(root)")
        with patch("src.agents.maintain_access.run_shell", tool_stub):
            with patch("src.agents.maintain_access.get_config", side_effect=RuntimeError("skip llm")):
                result = maintain_access_node(state)

        tool_stub.invoke.assert_called_once()
        self.assertEqual(tool_stub.invoke.call_args[0][0]["command"], "ssh user@10.0.0.1 'id'")
        self.assertTrue(result["session_verified"])
        self.assertEqual(result["world_state"]["sessions"][0]["verification_command"], "ssh user@10.0.0.1 'id'")


if __name__ == "__main__":
    unittest.main()
