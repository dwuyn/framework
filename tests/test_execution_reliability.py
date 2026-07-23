import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from src.agents.execution import execution_node
from src.agents.verifier import execution_verifier_node
from src.execution.placeholders import resolve_placeholder_values
from src.execution.preflight import prepare_candidate
from src.memory.world_state import Credential, HostInfo, ServiceInfo, WorldState
from src.state import initial_state


class _FakeConfig:
    def __init__(self, workspace_root: str) -> None:
        self.planning = {
            "budget_controller": {
                "enabled": True,
                "soft_pressure_ratio": 0.70,
                "replan_ratio": 0.85,
                "hard_stop_ratio": 1.00,
            }
        }
        self.execution = {
            "model": "fake",
            "workspace_root": workspace_root,
            "max_candidates": 3,
            "per_candidate_max_attempts": 3,
            "command_timeout": 15,
            "verify_timeout": 10,
            "install_timeout": 20,
            "allow_workspace_installs": True,
            "llm_fallback_attempts": 3,
        }

    def get_llm(self, name: str):
        raise AssertionError(f"LLM should not be called in this test: {name}")


class ExecutionReliabilityTests(unittest.TestCase):
    def test_resolve_placeholder_values_prefers_verified_credentials(self):
        ws = WorldState(credentials=[
            Credential(username="alice", password="s3cr3t", target_service="ssh", verified=True),
            Credential(username="bob", password="guess", target_service="ssh", verified=False),
        ])
        exploit = {
            "service": "ssh",
            "commands": ["ssh USERNAME@RHOST -p RPORT", "curl URL"],
        }
        state = {
            "target_ip": "10.0.0.1",
            "target_port": "22",
            "attacker_ip": "10.0.0.2",
        }

        values, missing = resolve_placeholder_values(exploit, state, ws)

        self.assertEqual(values["USERNAME"], "alice")
        self.assertEqual(values["PASSWORD"], "s3cr3t")
        self.assertEqual(values["RHOST"], "10.0.0.1")
        self.assertEqual(values["RPORT"], "22")
        self.assertTrue(values["URL"].startswith("http://10.0.0.1:22"))
        self.assertEqual(missing, [])

    def test_resolve_placeholder_values_assigns_lport(self):
        ws = WorldState()
        exploit = {
            "service": "apache",
            "commands": ["python exploit.py --lhost LHOST --lport LPORT"],
        }
        state = {
            "target_ip": "10.0.0.1",
            "target_port": "80",
            "attacker_ip": "10.0.0.2",
        }

        values, missing = resolve_placeholder_values(exploit, state, ws)

        self.assertEqual(values["LHOST"], "10.0.0.2")
        self.assertTrue(values["LPORT"].isdigit())
        self.assertEqual(missing, [])

    def test_prepare_candidate_fails_on_missing_placeholder(self):
        with tempfile.TemporaryDirectory(prefix="exec-preflight-") as tmp:
            exploit_path = os.path.join(tmp, "exploit.py")
            with open(exploit_path, "w", encoding="utf-8") as handle:
                handle.write("print('hello')\n")

            result = prepare_candidate(
                {
                    "file_path": exploit_path,
                    "commands": ["python exploit.py --rhost RHOST --lport LPORT"],
                    "required_placeholders": ["RHOST", "LPORT"],
                },
                os.path.join(tmp, "workspace"),
                {"RHOST": "10.0.0.1"},
                ["LPORT"],
            )

            self.assertEqual(result.status, "preflight_failed")
            self.assertIn("LPORT", result.reason)

    def test_execution_node_runs_deterministic_command_and_verifies_success(self):
        with tempfile.TemporaryDirectory(prefix="exec-success-") as tmp:
            exploit_path = os.path.join(tmp, "exploit.py")
            with open(exploit_path, "w", encoding="utf-8") as handle:
                handle.write("print('exploit')\n")

            state = initial_state(target_ip="10.0.0.1", target_port="80", attacker_ip="10.0.0.2")
            state["planning_output_dir"] = tmp
            state["exploit_plan"] = [{
                "candidate_id": "exploitdb:CVE-1:file",
                "name": "CVE-1::file",
                "file_path": exploit_path,
                "working_directory": tmp,
                "commands": ["python exploit.py"],
                "verify_commands": ["id"],
                "success_indicators": ["uid="],
                "service": "apache",
                "target_ip": "10.0.0.1",
                "target_port": 80,
            }]
            state["world_state"] = WorldState(hosts={
                "10.0.0.1": HostInfo(
                    ip="10.0.0.1",
                    services=[ServiceInfo(port=80, name="apache", version="2.4.49", confidence=0.9)],
                )
            }).to_dict()

            tool_stub = SimpleNamespace()
            tool_stub.invoke = Mock(side_effect=[
                "uid=0(root) gid=0(root)",
                "uid=0(root) gid=0(root)",
            ])

            with patch("src.agents.execution.get_config", return_value=_FakeConfig(tmp)):
                with patch("src.agents.execution.run_shell", tool_stub):
                    result = execution_node(state)

            self.assertTrue(result["execution_success"])
            self.assertEqual(result["current_phase"], "done")
            self.assertEqual(result["session_artifact"]["candidate_id"], "exploitdb:CVE-1:file")
            self.assertEqual(result["execution_tracker"]["candidate_results"]["exploitdb:CVE-1:file"]["status"], "success")
            self.assertEqual(tool_stub.invoke.call_count, 2)

    def test_execution_node_ignores_retry_budget_limits(self):
        with tempfile.TemporaryDirectory(prefix="exec-budget-") as tmp:
            exploit_path = os.path.join(tmp, "exploit.py")
            with open(exploit_path, "w", encoding="utf-8") as handle:
                handle.write("print('exploit')\n")

            state = initial_state(target_ip="10.0.0.1", target_port="80", attacker_ip="10.0.0.2")
            state["planning_output_dir"] = tmp
            state["retry_budget"] = 1
            state["retry_spent"] = 1
            state["exploit_plan"] = [{
                "candidate_id": "exploitdb:CVE-1:file",
                "name": "CVE-1::file",
                "file_path": exploit_path,
                "working_directory": tmp,
                "commands": ["python exploit.py"],
                "verify_commands": ["id"],
                "success_indicators": ["uid="],
                "service": "apache",
                "target_ip": "10.0.0.1",
                "target_port": 80,
            }]

            tool_stub = SimpleNamespace()
            tool_stub.invoke = Mock(side_effect=[
                "uid=0(root) gid=0(root)",
                "uid=0(root) gid=0(root)",
            ])

            with patch("src.agents.execution.get_config", return_value=_FakeConfig(tmp)):
                with patch("src.agents.execution.run_shell", tool_stub):
                    result = execution_node(state)

            self.assertTrue(result["execution_success"])

    def test_execution_node_skips_missing_path_candidate_then_runs_next(self):
        with tempfile.TemporaryDirectory(prefix="exec-skip-") as tmp:
            good_path = os.path.join(tmp, "good.py")
            with open(good_path, "w", encoding="utf-8") as handle:
                handle.write("print('ok')\n")

            state = initial_state(target_ip="10.0.0.1", target_port="80", attacker_ip="10.0.0.2")
            state["planning_output_dir"] = tmp
            state["exploit_plan"] = [
                {
                    "candidate_id": "github:CVE-1:missing",
                    "name": "missing",
                    "file_path": os.path.join(tmp, "missing.py"),
                    "commands": ["python missing.py"],
                    "service": "apache",
                },
                {
                    "candidate_id": "exploitdb:CVE-1:good",
                    "name": "good",
                    "file_path": good_path,
                    "working_directory": tmp,
                    "commands": ["python good.py"],
                    "verify_commands": ["id"],
                    "success_indicators": ["uid="],
                    "service": "apache",
                },
            ]

            tool_stub = SimpleNamespace()
            tool_stub.invoke = Mock(side_effect=[
                "uid=0(root) gid=0(root)",
                "uid=0(root) gid=0(root)",
            ])

            with patch("src.agents.execution.get_config", return_value=_FakeConfig(tmp)):
                with patch("src.agents.execution.run_shell", tool_stub):
                    result = execution_node(state)

            tracker = result["execution_tracker"]["candidate_results"]
            self.assertEqual(tracker["github:CVE-1:missing"]["status"], "preflight_failed")
            self.assertEqual(tracker["exploitdb:CVE-1:good"]["status"], "success")

    def test_execution_node_uses_workspace_setup_for_python_dependencies(self):
        with tempfile.TemporaryDirectory(prefix="exec-setup-") as tmp:
            exploit_path = os.path.join(tmp, "exploit.py")
            req_path = os.path.join(tmp, "requirements.txt")
            with open(exploit_path, "w", encoding="utf-8") as handle:
                handle.write("print('exploit')\n")
            with open(req_path, "w", encoding="utf-8") as handle:
                handle.write("requests==2.32.0\n")

            state = initial_state(target_ip="10.0.0.1", target_port="80", attacker_ip="10.0.0.2")
            state["planning_output_dir"] = tmp
            state["exploit_plan"] = [{
                "candidate_id": "github:CVE-1:setup",
                "name": "setup",
                "file_path": exploit_path,
                "working_directory": tmp,
                "commands": ["python exploit.py"],
                "dependencies": ["pip install -r requirements.txt"],
                "success_indicators": ["uid="],
                "service": "apache",
            }]

            tool_stub = SimpleNamespace()
            tool_stub.invoke = Mock(side_effect=[
                "[Exit 0] No output produced.",
                "[Exit 0] No output produced.",
                "[Exit 0] No output produced.",
                "uid=0(root) gid=0(root)",
                "uid=0(root) gid=0(root)",
            ])

            with patch("src.agents.execution.get_config", return_value=_FakeConfig(tmp)):
                with patch("src.agents.execution.run_shell", tool_stub):
                    result = execution_node(state)

            commands = [call.args[0]["command"] for call in tool_stub.invoke.call_args_list[:3]]
            self.assertIn(".venv", commands[0])
            self.assertIn(".venv", commands[1])
            self.assertIn(".venv", commands[2])
            self.assertTrue(result["execution_success"])

    def test_execution_node_uses_llm_fallback_after_unknown_output(self):
        with tempfile.TemporaryDirectory(prefix="exec-fallback-") as tmp:
            exploit_path = os.path.join(tmp, "exploit.py")
            with open(exploit_path, "w", encoding="utf-8") as handle:
                handle.write("print('exploit')\n")

            state = initial_state(target_ip="10.0.0.1", target_port="80", attacker_ip="10.0.0.2")
            state["planning_output_dir"] = tmp
            state["exploit_plan"] = [{
                "candidate_id": "github:CVE-1:fallback",
                "name": "fallback",
                "file_path": exploit_path,
                "working_directory": tmp,
                "commands": ["python exploit.py"],
                "success_indicators": ["uid="],
                "service": "apache",
            }]

            tool_stub = SimpleNamespace()
            tool_stub.invoke = Mock(side_effect=[
                "unexpected banner",
                "still inconclusive",
                "uid=0(root) gid=0(root)",
                "uid=0(root) gid=0(root)",
            ])

            with patch("src.agents.execution.get_config", return_value=_FakeConfig(tmp)):
                with patch("src.agents.execution.run_shell", tool_stub):
                    first = execution_node(state)
                    self.assertFalse(first.get("execution_success", False))
                    with patch("src.agents.execution._llm_fallback_command", return_value=("python exploit.py --mode fallback", "fallback", 0, 0, 1)):
                        second = execution_node({**state, **first})

            self.assertTrue(second["execution_success"])
            self.assertTrue(second["execution_tracker"]["candidate_results"]["github:CVE-1:fallback"]["llm_fallback_used"])

    def test_execution_verifier_uses_tracker_for_continue_replan_and_exhausted(self):
        state = initial_state(target_ip="10.0.0.1")
        state["execution_tracker"] = {
            "candidate_order": ["cand-1"],
            "current_candidate_index": 0,
            "candidate_results": {
                "cand-1": {
                    "status": "ready",
                    "failure_class": "network",
                }
            },
        }
        cont = execution_verifier_node(state)
        self.assertEqual(cont["verification_log"][-1]["verdict"], "continue")

        state["execution_tracker"] = {
            "candidate_order": ["cand-1"],
            "current_candidate_index": 1,
            "candidate_results": {
                "cand-1": {
                    "status": "failed",
                    "failure_class": "not_vulnerable",
                }
            },
        }
        replan = execution_verifier_node(state)
        self.assertEqual(replan["verification_log"][-1]["verdict"], "replan")
        self.assertEqual(replan["replan_count"], 1)

        state["replan_count"] = 3
        exhausted = execution_verifier_node(state)
        self.assertEqual(exhausted["verification_log"][-1]["verdict"], "exhausted")


if __name__ == "__main__":
    unittest.main()
