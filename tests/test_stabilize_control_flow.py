"""
Tests for stabilized recon-to-hypothesis control flow.
"""

import tempfile
import unittest
from unittest.mock import MagicMock, patch

from langchain_core.messages import HumanMessage

from src.agents.hypothesis_phase.critic_agent import (
    _apply_critic_report,
    _deterministic_fast_path,
    _next_non_exhausted_service,
)
from src.agents.hypothesis_phase.retrieval_agent import retrieval_agent_node
from src.agents.recon import (
    _LOW_SIGNAL_SERVICES,
    _dedup_recent_commands,
    _parse_nmap_services,
    _targeted_recon_messages,
)
from src.agents.verifier import MAX_VERIFIER_BLOCKS, hypothesis_verifier_node, recon_verifier_node
from src.memory.episodic import Episode, EpisodicMemory
from src.memory.world_state import HostInfo, ServiceInfo, WorldState
from src.retrieval.authoritative import _load_curated_benchmark_cve_cache
from src.retrieval.models import (
    ProductFingerprint,
    RetrievalBundle,
)
from src.state import initial_state


class TestInitialStateNewFields(unittest.TestCase):
    """Verify that initial_state() includes all new Phase 2 control fields."""

    def test_new_fields_present(self):
        state = initial_state(target_ip="10.0.0.1")
        self.assertEqual(state["recon_verifier_blocks"], 0)
        self.assertEqual(state["hypothesis_verifier_blocks"], 0)
        self.assertEqual(state["phase2_followup_count"], 0)
        self.assertEqual(state["phase2_followup_max"], 2)
        self.assertEqual(state["phase2_target_service_key"], "")
        self.assertEqual(state["phase2_target_port"], 0)
        self.assertEqual(state["phase2_target_product"], "")
        self.assertEqual(state["retrieval_status"], "")
        self.assertEqual(state["retrieval_errors"], [])
        self.assertFalse(state["service_exhausted"])
        self.assertEqual(state["recon_followup_step_budget"], 3)
        self.assertEqual(state["recon_command_dedupe_window"], 10)
        self.assertEqual(state["live_retrieval_retry_max"], 1)


class TestReconVerifierBlocks(unittest.TestCase):
    """recon_verifier_node uses recon_verifier_blocks (not shared verifier_blocks)."""

    @patch("src.agents.verifier.get_config")
    def test_recon_block_increments_own_counter(self, mock_cfg):
        state = initial_state(target_ip="10.0.0.1")
        state["recon_step_count"] = 1
        state["recon_complete"] = True
        ws = WorldState()
        host = HostInfo(ip="10.0.0.1")
        host.upsert_service(ServiceInfo(
            port=80, protocol="tcp", name="http", confidence=0.4,
            evidence=["nmap -p80"],
        ))
        ws.hosts["10.0.0.1"] = host
        state["world_state"] = ws.to_dict()

        result = recon_verifier_node(state)
        self.assertEqual(result.get("recon_verifier_blocks"), 1)
        self.assertFalse(result.get("recon_complete", True))
        self.assertIn("verification_log", result)

    @patch("src.agents.verifier.get_config")
    def test_max_blocks_forces_proceed(self, mock_cfg):
        state = initial_state(target_ip="10.0.0.1")
        state["recon_step_count"] = 1
        state["recon_complete"] = True
        state["recon_verifier_blocks"] = MAX_VERIFIER_BLOCKS
        ws = WorldState()
        host = HostInfo(ip="10.0.0.1")
        host.upsert_service(ServiceInfo(
            port=80, protocol="tcp", name="http", confidence=0.4,
            evidence=["nmap -p80"],
        ))
        ws.hosts["10.0.0.1"] = host
        state["world_state"] = ws.to_dict()

        result = recon_verifier_node(state)
        self.assertNotIn("recon_verifier_blocks", result)


class TestHypothesisVerifierBlocks(unittest.TestCase):
    """hypothesis_verifier_node uses hypothesis_verifier_blocks."""

    def test_need_more_recon_increments_hypothesis_counter(self):
        state = initial_state(target_ip="10.0.0.1")
        bundle = RetrievalBundle(shortlist=[])
        bundle.critic_report = {
            "verdict": "need_more_recon",
            "reason": "test",
            "approved_candidate_ids": [],
            "rejected_candidate_ids": [],
            "issues": [],
            "recon_requests": ["test"],
        }
        state["retrieval_bundle"] = bundle.to_dict()
        state["vuln_hypotheses"] = []

        result = hypothesis_verifier_node(state)
        self.assertEqual(result.get("hypothesis_verifier_blocks"), 1)

    def test_no_hypotheses_increments_hypothesis_counter(self):
        state = initial_state(target_ip="10.0.0.1")
        bundle = RetrievalBundle()
        state["retrieval_bundle"] = bundle.to_dict()

        result = hypothesis_verifier_node(state)
        self.assertEqual(result.get("hypothesis_verifier_blocks"), 1)


class TestCriticFastPath(unittest.TestCase):
    """_deterministic_fast_path handles Phase 2 control fields."""

    def _bundle(self, shortlist=None, fingerprints=None):
        return RetrievalBundle(
            shortlist=shortlist or [],
            fingerprints=fingerprints or [],
        )

    def test_retrieval_backend_failed_with_shortlist(self):
        state = initial_state(target_ip="10.0.0.1")
        state["retrieval_status"] = "backend_failed"
        shortlist = [{"cve_id": "CVE-2024-0001", "candidate_id": "abc"}]
        bundle = self._bundle(shortlist=shortlist)
        report = _deterministic_fast_path(state, bundle)
        self.assertIsNotNone(report)
        self.assertEqual(report["verdict"], "best_effort_pass")
        self.assertIn("abc", report["approved_candidate_ids"])

    def test_retrieval_backend_failed_no_shortlist(self):
        state = initial_state(target_ip="10.0.0.1")
        state["retrieval_status"] = "backend_failed"
        state["target_services"] = [
            {"service_key": "10.0.0.1:80:http", "name": "http"},
        ]
        bundle = self._bundle()
        report = _deterministic_fast_path(state, bundle)
        self.assertIsNotNone(report)
        self.assertEqual(report["verdict"], "need_more_recon")

    def test_retrieval_backend_failed_no_shortlist_no_services(self):
        """backend_failed with no shortlist and no target_services → exhausted."""
        state = initial_state(target_ip="10.0.0.1")
        state["retrieval_status"] = "backend_failed"
        bundle = self._bundle()
        report = _deterministic_fast_path(state, bundle)
        self.assertIsNotNone(report)
        self.assertEqual(report["verdict"], "exhausted")

    def test_service_exhausted_with_shortlist(self):
        state = initial_state(target_ip="10.0.0.1")
        state["service_exhausted"] = True
        shortlist = [{"cve_id": "CVE-2024-0001", "candidate_id": "abc"}]
        bundle = self._bundle(shortlist=shortlist)
        report = _deterministic_fast_path(state, bundle)
        self.assertIsNotNone(report)
        self.assertEqual(report["verdict"], "best_effort_pass")

    def test_service_exhausted_no_shortlist(self):
        state = initial_state(target_ip="10.0.0.1")
        state["service_exhausted"] = True
        bundle = self._bundle()
        report = _deterministic_fast_path(state, bundle)
        self.assertIsNotNone(report)
        self.assertEqual(report["verdict"], "exhausted")

    def test_followup_count_exceeded_with_shortlist(self):
        state = initial_state(target_ip="10.0.0.1")
        state["phase2_followup_count"] = 2
        state["phase2_followup_max"] = 2
        shortlist = [{"cve_id": "CVE-2024-0001", "candidate_id": "abc"}]
        bundle = self._bundle(shortlist=shortlist)
        report = _deterministic_fast_path(state, bundle)
        self.assertIsNotNone(report)
        self.assertEqual(report["verdict"], "best_effort_pass")

    def test_followup_count_exceeded_no_shortlist(self):
        state = initial_state(target_ip="10.0.0.1")
        state["phase2_followup_count"] = 2
        state["phase2_followup_max"] = 2
        bundle = self._bundle()
        report = _deterministic_fast_path(state, bundle)
        self.assertIsNotNone(report)
        self.assertEqual(report["verdict"], "need_more_recon")


class TestCriticApplyReport(unittest.TestCase):
    """_apply_critic_report increments followup count and rotates services."""

    def _bundle(self, shortlist=None):
        bundle = RetrievalBundle(shortlist=shortlist or [])
        bundle.critic_report = {"verdict": "need_more_recon", "reason": "test"}
        return bundle

    def test_need_more_recon_increments_followup_count(self):
        state = initial_state(target_ip="10.0.0.1")
        state["phase2_followup_count"] = 0
        state["target_services"] = [
            {"service_key": "10.0.0.1:80:apache", "name": "apache", "port": 80},
        ]
        state["current_service_index"] = 0
        bundle = self._bundle()
        report = {"verdict": "need_more_recon", "approved_candidate_ids": [],
                  "rejected_candidate_ids": [], "issues": [],
                  "recon_requests": ["check version"], "reason": "test"}
        update = _apply_critic_report(state, bundle, report, 0, 0, False)
        self.assertEqual(update["phase2_followup_count"], 1)
        self.assertEqual(update["phase2_route"], "recon")
        self.assertEqual(update["phase2_target_service_key"], "10.0.0.1:80:apache")

    def test_need_more_recon_exhausts_service_at_max(self):
        """When followup reaches max with single service, terminates with 'end'."""
        state = initial_state(target_ip="10.0.0.1")
        state["phase2_followup_count"] = 1
        state["phase2_followup_max"] = 2
        target_svc = {
            "target_ip": "10.0.0.1", "port": 80, "name": "apache",
            "version": "2.4.57", "service_key": "10.0.0.1:80:apache",
        }
        state["target_services"] = [target_svc]
        state["current_service_index"] = 0
        bundle = self._bundle()
        report = {"verdict": "need_more_recon", "approved_candidate_ids": [],
                  "rejected_candidate_ids": [], "issues": [],
                  "recon_requests": ["check version"], "reason": "test"}
        update = _apply_critic_report(state, bundle, report, 0, 0, False)
        # Single service exhausted → terminate
        self.assertIn("10.0.0.1:80:apache", update["phase2_exhausted_service_keys"])
        self.assertEqual(update["phase2_followup_count"], 0)
        self.assertEqual(update["phase2_route"], "end")
        self.assertEqual(update["current_phase"], "done")
        self.assertIn("all target services exhausted", update["execution_summary"])
        self.assertIn("Last critic reason: test", update["execution_summary"])

    def test_pass_does_not_increment_followup(self):
        state = initial_state(target_ip="10.0.0.1")
        state["phase2_followup_count"] = 0
        shortlist = [{"cve_id": "CVE-2024-0001", "candidate_id": "abc"}]
        bundle = RetrievalBundle(shortlist=shortlist)
        report = {"verdict": "pass", "approved_candidate_ids": ["abc"],
                  "rejected_candidate_ids": [], "issues": [],
                  "recon_requests": [], "reason": "ok"}
        update = _apply_critic_report(state, bundle, report, 0, 0, False)
        self.assertNotIn("phase2_followup_count", update)


class TestCuratedBenchmarkCache(unittest.TestCase):
    """_load_curated_benchmark_cve_cache loads and filters records."""

    def test_loads_valid_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('''[
                {"cve_id": "CVE-2024-0001", "vendor": "apache", "product": "httpd", "title": "Test", "description": "desc"}
            ]''')
            path = f.name
        fp = ProductFingerprint(target_ip="10.0.0.1", port=80, vendor="apache", product="httpd")
        records = _load_curated_benchmark_cve_cache(path, [fp])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].cve_id, "CVE-2024-0001")
        self.assertEqual(records[0].source, "benchmark")

    def test_filters_by_vendor_product(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('''[
                {"cve_id": "CVE-2024-0001", "vendor": "apache", "product": "httpd"},
                {"cve_id": "CVE-2024-0002", "vendor": "microsoft", "product": "iis"}
            ]''')
            path = f.name
        fp = ProductFingerprint(target_ip="10.0.0.1", port=80, vendor="microsoft", product="iis")
        records = _load_curated_benchmark_cve_cache(path, [fp])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].cve_id, "CVE-2024-0002")

    def test_empty_on_missing_path(self):
        records = _load_curated_benchmark_cve_cache("/nonexistent/path.json", [])
        self.assertEqual(records, [])


class TestNmapParsingLowSignal(unittest.TestCase):
    """_parse_nmap_services skips low-signal rows and Nmap trailer lines."""

    def test_trailer_lines_filtered(self):
        output = """PORT   STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http
Nmap done: 1 IP address (1 host up) scanned in 0.91 seconds
"""
        services = _parse_nmap_services(output)
        self.assertEqual(len(services), 2)
        self.assertEqual(services[0]["port"], 22)
        self.assertEqual(services[0]["name"], "ssh")

    def test_script_output_lines_skipped(self):
        output = """PORT   STATE SERVICE VERSION
80/tcp  open  http
| http-title: Test
|_http-server-header: Apache/2.4.57
"""
        services = _parse_nmap_services(output)
        self.assertEqual(len(services), 1)

    def test_low_signal_services_still_listed_no_version(self):
        output = """PORT     STATE SERVICE    VERSION
1000/tcp open  tcpwrapped
2000/tcp open  unknown
"""
        services = _parse_nmap_services(output)
        service_ports = {s["port"] for s in services}
        self.assertIn(1000, service_ports)
        self.assertIn(2000, service_ports)
        # Low-signal services have empty version
        for s in services:
            if s["name"].lower() in _LOW_SIGNAL_SERVICES:
                self.assertEqual(s["version"], "")

    def test_low_signal_set_contents(self):
        self.assertIn("tcpwrapped", _LOW_SIGNAL_SERVICES)
        self.assertIn("http", _LOW_SIGNAL_SERVICES)
        self.assertIn("https", _LOW_SIGNAL_SERVICES)
        self.assertIn("https-alt", _LOW_SIGNAL_SERVICES)
        self.assertIn("unknown", _LOW_SIGNAL_SERVICES)


class TestWorldStateUpsert(unittest.TestCase):
    """WorldState.upsert_service never downgrades name from specific to generic."""

    def test_generic_does_not_overwrite_specific_name(self):
        service = ServiceInfo(port=80, protocol="tcp", name="apache", version="2.4.57",
                              confidence=0.55, evidence=["nmap"])
        generic = ServiceInfo(port=80, protocol="tcp", name="http", version="",
                              confidence=0.6, evidence=["nmap -sV"])
        host = HostInfo(ip="10.0.0.1")
        host.upsert_service(service)
        host.upsert_service(generic)
        self.assertEqual(host.services[0].name, "apache")
        self.assertEqual(host.services[0].confidence, 0.6)

    def test_specific_upgrades_generic_even_at_lower_confidence(self):
        generic = ServiceInfo(port=80, protocol="tcp", name="http", version="",
                              confidence=0.55, evidence=["nmap"])
        specific = ServiceInfo(port=80, protocol="tcp", name="apache", version="2.4.57",
                               confidence=0.45, evidence=["banner"])
        host = HostInfo(ip="10.0.0.1")
        host.upsert_service(generic)
        host.upsert_service(specific)
        self.assertEqual(host.services[0].name, "apache")

    def test_empty_banner_never_replaces_nonempty(self):
        svc_a = ServiceInfo(port=22, protocol="tcp", name="ssh", banner="SSH-2.0-OpenSSH_8.9",
                            confidence=0.55, evidence=["nmap"])
        svc_b = ServiceInfo(port=22, protocol="tcp", name="ssh", banner="",
                            confidence=0.7, evidence=["nmap -sV"])
        host = HostInfo(ip="10.0.0.1")
        host.upsert_service(svc_a)
        host.upsert_service(svc_b)
        self.assertEqual(host.services[0].banner, "SSH-2.0-OpenSSH_8.9")


class TestReconCommandDedup(unittest.TestCase):
    """_dedup_recent_commands detects recent command repeats."""

    def test_exact_match_detected(self):
        state = initial_state(target_ip="10.0.0.1")
        state["recon_command_dedupe_window"] = 10
        em = EpisodicMemory()
        em.log(Episode(
            step=1, timestamp=0.0, phase="recon", action_type="tool_call",
            command="nmap -sV -p 80 10.0.0.1",
        ))
        state["episodic_memory"] = em.to_list()
        self.assertTrue(_dedup_recent_commands(state, "nmap -sV -p 80 10.0.0.1"))

    def test_different_command_not_deduped(self):
        state = initial_state(target_ip="10.0.0.1")
        state["recon_command_dedupe_window"] = 10
        em = EpisodicMemory()
        em.log(Episode(
            step=1, timestamp=0.0, phase="recon", action_type="tool_call",
            command="nmap -sV -p 80 10.0.0.1",
        ))
        state["episodic_memory"] = em.to_list()
        self.assertFalse(_dedup_recent_commands(state, "nmap -sC -p 80 10.0.0.1"))

    def test_empty_memory_no_dedup(self):
        state = initial_state(target_ip="10.0.0.1")
        state["recon_command_dedupe_window"] = 10
        state["episodic_memory"] = []
        self.assertFalse(_dedup_recent_commands(state, "nmap -sV 10.0.0.1"))


class TestBackendFailedRotation(unittest.TestCase):
    """backend_failed without shortlist rotates off current service, never returns to recon."""

    def _bundle(self, shortlist=None):
        return RetrievalBundle(shortlist=shortlist or [])

    def test_backend_failed_no_shortlist_rotates_when_services_remain(self):
        state = initial_state(target_ip="10.0.0.1")
        state["retrieval_status"] = "backend_failed"
        state["phase2_exhausted_service_keys"] = []
        state["target_services"] = [
            {"service_key": "10.0.0.1:80:http", "name": "http"},
            {"service_key": "10.0.0.1:5060:sip", "name": "sip"},
        ]
        bundle = self._bundle()
        report = _deterministic_fast_path(state, bundle)
        self.assertIsNotNone(report)
        self.assertEqual(report["verdict"], "need_more_recon")
        self.assertNotIn("recon", report.get("issues", []))

    def test_backend_failed_no_shortlist_exhausted_when_all_services_done(self):
        state = initial_state(target_ip="10.0.0.1")
        state["retrieval_status"] = "backend_failed"
        state["phase2_exhausted_service_keys"] = [
            "10.0.0.1:80:http",
            "10.0.0.1:5060:sip",
        ]
        state["target_services"] = [
            {"service_key": "10.0.0.1:80:http", "name": "http"},
            {"service_key": "10.0.0.1:5060:sip", "name": "sip"},
        ]
        bundle = self._bundle()
        report = _deterministic_fast_path(state, bundle)
        self.assertIsNotNone(report)
        self.assertEqual(report["verdict"], "exhausted")


class TestServiceExhaustionLedger(unittest.TestCase):
    """Service hits followup_max, is added to exhausted-service ledger, and rotation targets different service."""

    def _bundle(self, shortlist=None):
        bundle = RetrievalBundle(shortlist=shortlist or [])
        bundle.critic_report = {"verdict": "need_more_recon", "reason": "test"}
        return bundle

    def test_exhaustion_adds_to_ledger_and_rotates_to_hypothesis(self):
        state = initial_state(target_ip="10.0.0.1")
        state["phase2_followup_count"] = 1
        state["phase2_followup_max"] = 2
        state["phase2_exhausted_service_keys"] = []
        state["target_services"] = [
            {"service_key": "10.0.0.1:80:http", "name": "http", "port": 80, "version": "2.4.49"},
            {"service_key": "10.0.0.1:5060:sip", "name": "sip", "port": 5060, "version": "1.0"},
        ]
        state["current_service_index"] = 0
        bundle = self._bundle()
        report = {"verdict": "need_more_recon", "approved_candidate_ids": [],
                  "rejected_candidate_ids": [], "issues": [],
                  "recon_requests": ["check version"], "reason": "test"}
        update = _apply_critic_report(state, bundle, report, 0, 0, False)
        self.assertIn("10.0.0.1:80:http", update["phase2_exhausted_service_keys"])
        self.assertEqual(update["current_service_index"], 1)
        self.assertEqual(update["phase2_followup_count"], 0)
        self.assertEqual(update["phase2_route"], "hypothesis")
        self.assertEqual(update["keyword"], "sip")

    def test_all_exhausted_terminates(self):
        state = initial_state(target_ip="10.0.0.1")
        state["phase2_followup_count"] = 1
        state["phase2_followup_max"] = 2
        state["phase2_exhausted_service_keys"] = ["10.0.0.1:5060:sip"]
        state["target_services"] = [
            {"service_key": "10.0.0.1:80:http", "name": "http", "port": 80},
            {"service_key": "10.0.0.1:5060:sip", "name": "sip", "port": 5060},
        ]
        state["current_service_index"] = 0
        bundle = self._bundle()
        report = {"verdict": "need_more_recon", "approved_candidate_ids": [],
                  "rejected_candidate_ids": [], "issues": [],
                  "recon_requests": [], "reason": "test"}
        update = _apply_critic_report(state, bundle, report, 0, 0, False)
        self.assertIn("10.0.0.1:80:http", update["phase2_exhausted_service_keys"])
        self.assertEqual(update["phase2_route"], "end")
        self.assertEqual(update["current_phase"], "done")
        self.assertIn("all target services exhausted", update["execution_summary"])
        self.assertIn("Last critic reason: test", update["execution_summary"])


class TestNoStaleKeywordOnRotation(unittest.TestCase):
    """Repeated Phase 2 passes do not preserve stale keyword/app_name from previous service."""

    def _bundle(self, shortlist=None):
        bundle = RetrievalBundle(shortlist=shortlist or [])
        bundle.critic_report = {"verdict": "need_more_recon", "reason": "test"}
        return bundle

    def test_rotation_updates_keyword_from_new_service(self):
        state = initial_state(target_ip="10.0.0.1")
        state["phase2_followup_count"] = 1
        state["phase2_followup_max"] = 2
        state["phase2_exhausted_service_keys"] = []
        state["keyword"] = "apache"
        state["app_name"] = "apache"
        state["app_version"] = "2.4.49"
        state["target_services"] = [
            {"service_key": "10.0.0.1:80:apache", "name": "apache", "port": 80, "version": "2.4.49"},
            {"service_key": "10.0.0.1:5060:sip", "name": "sip", "port": 5060, "version": "3.1"},
        ]
        state["current_service_index"] = 0
        bundle = self._bundle()
        report = {"verdict": "need_more_recon", "approved_candidate_ids": [],
                  "rejected_candidate_ids": [], "issues": [],
                  "recon_requests": [], "reason": "test"}
        update = _apply_critic_report(state, bundle, report, 0, 0, False)
        self.assertEqual(update["keyword"], "sip")
        self.assertEqual(update["app_name"], "sip")
        self.assertEqual(update["app_version"], "3.1")


class TestNextNonExhaustedService(unittest.TestCase):
    """_next_non_exhausted_service helper finds the correct index."""

    def test_finds_next_non_exhausted(self):
        services = [
            {"service_key": "a:80:http"},
            {"service_key": "a:5060:sip"},
            {"service_key": "a:22:ssh"},
        ]
        result = _next_non_exhausted_service(services, 0, ["a:80:http"])
        self.assertEqual(result, 1)

    def test_skips_multiple_exhausted(self):
        services = [
            {"service_key": "a:80:http"},
            {"service_key": "a:5060:sip"},
            {"service_key": "a:22:ssh"},
        ]
        result = _next_non_exhausted_service(services, 0, ["a:80:http", "a:5060:sip"])
        self.assertEqual(result, 2)

    def test_returns_none_when_all_exhausted(self):
        services = [
            {"service_key": "a:80:http"},
            {"service_key": "a:5060:sip"},
        ]
        result = _next_non_exhausted_service(services, 0, ["a:80:http", "a:5060:sip"])
        self.assertIsNone(result)


class TestRetrievalAgentStatus(unittest.TestCase):
    """retrieval_agent_node sets retrieval_status."""

    def test_sets_retrieval_status_on_empty_results(self):
        state = initial_state(target_ip="10.0.0.1")
        ws = WorldState()
        host = HostInfo(ip="10.0.0.1")
        host.upsert_service(ServiceInfo(
            port=80, protocol="tcp", name="http", confidence=0.55,
            evidence=["nmap"],
        ))
        ws.hosts["10.0.0.1"] = host
        state["world_state"] = ws.to_dict()
        state["target_services"] = [{
            "target_ip": "10.0.0.1", "port": 80, "name": "http",
            "service_key": "10.0.0.1:80:http",
        }]

        with patch("src.agents.hypothesis_phase.retrieval_agent.collect_authoritative_records", return_value=([], "no_match")):
            with patch("src.agents.hypothesis_phase.retrieval_agent.collect_poc_candidates", return_value=[]):
                with patch("src.agents.hypothesis_phase.retrieval_agent.extract_procedure_snippets", return_value=[]):
                    result = retrieval_agent_node(state)
        self.assertIn("retrieval_status", result)


class TestAlreadyRunInjection(unittest.TestCase):
    """_targeted_recon_messages injects already_run command list."""

    def test_already_run_included_in_prompt(self):
        state = initial_state(target_ip="10.0.0.1")
        already_run = [
            "nmap -sV -p 80 10.0.0.1",
            "curl -I http://10.0.0.1",
        ]
        messages = _targeted_recon_messages(state, already_run=already_run)
        human = [m for m in messages if isinstance(m, HumanMessage)]
        self.assertTrue(len(human) > 0)
        text = human[0].content
        self.assertIn("already run", text.lower())
        self.assertIn("nmap -sV -p 80 10.0.0.1", text)
        self.assertIn("curl -I http://10.0.0.1", text)
        self.assertIn("forbidden", text.lower())

    def test_empty_already_run_omits_block(self):
        state = initial_state(target_ip="10.0.0.1")
        messages = _targeted_recon_messages(state, already_run=[])
        human = [m for m in messages if isinstance(m, HumanMessage)]
        self.assertTrue(len(human) > 0)
        self.assertNotIn("forbidden", human[0].content.lower())

    def test_already_run_none_omits_block(self):
        state = initial_state(target_ip="10.0.0.1")
        messages = _targeted_recon_messages(state, already_run=None)
        human = [m for m in messages if isinstance(m, HumanMessage)]
        self.assertTrue(len(human) > 0)
        self.assertNotIn("forbidden", human[0].content.lower())

    def test_already_run_requests_different_probes(self):
        state = initial_state(target_ip="10.0.0.1")
        messages = _targeted_recon_messages(state, already_run=["nmap -sV 10.0.0.1"])
        human = [m for m in messages if isinstance(m, HumanMessage)]
        text = human[0].content
        self.assertIn("materially different", text.lower())


class TestPhase2RouteClearing(unittest.TestCase):
    """phase2_route is cleared on dedup-rejection and successful phase2 recon completion."""

    @patch("src.agents.recon.get_config")
    def test_dedup_rejection_clears_phase2_route(self, mock_cfg):
        """When all follow-up commands are dedup-rejected, phase2_route='' in result."""
        from src.agents.recon import recon_node
        mock_llm = MagicMock()
        mock_llm.bind_tools.return_value = mock_llm
        # LLM proposes a tool call with a command already in episodic memory
        response = MagicMock()
        response.content = ""
        response.tool_calls = [{"name": "run_shell", "args": {"command": "nmap -sV -p 80 10.0.0.1"}, "id": "tc1"}]
        mock_llm.invoke.return_value = response
        mock_cfg.return_value = MagicMock()
        mock_cfg.return_value.recon = {"model": "test"}
        mock_cfg.return_value.get_llm.return_value = mock_llm

        state = initial_state(target_ip="10.0.0.1")
        state["phase2_route"] = "recon"
        # Add a recon tool_call episode that matches the command the LLM will propose
        em = EpisodicMemory()
        em.log(Episode(
            step=1, timestamp=0.0, phase="recon", action_type="tool_call",
            command="nmap -sV -p 80 10.0.0.1",
        ))
        state["episodic_memory"] = em.to_list()
        state["recon_complete"] = False

        result = recon_node(state)
        # The command is dedup-rejected → phase2_route should be cleared
        self.assertEqual(result.get("phase2_route"), "")
        self.assertTrue(result.get("recon_complete"))


class TestBackendFailedRetry(unittest.TestCase):
    """retrieval_agent_node retries backend_failed using live_retrieval_retry_max."""

    def _make_state(self, retry_max=1):
        state = initial_state(target_ip="10.0.0.1")
        state["live_retrieval_retry_max"] = retry_max
        ws = WorldState()
        host = HostInfo(ip="10.0.0.1")
        host.upsert_service(ServiceInfo(
            port=80, protocol="tcp", name="http", confidence=0.55,
            evidence=["nmap"],
        ))
        ws.hosts["10.0.0.1"] = host
        state["world_state"] = ws.to_dict()
        state["target_services"] = [{
            "target_ip": "10.0.0.1", "port": 80, "name": "http",
            "service_key": "10.0.0.1:80:http",
        }]
        return state

    def test_retries_on_backend_failed_then_succeeds(self):
        state = self._make_state(retry_max=2)
        call_count = [0]
        def mock_collect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] < 3:
                return [], "backend_failed"
            return [], "no_match"
        with patch("src.agents.hypothesis_phase.retrieval_agent.collect_authoritative_records", side_effect=mock_collect):
            with patch("src.agents.hypothesis_phase.retrieval_agent.collect_poc_candidates", return_value=[]):
                with patch("src.agents.hypothesis_phase.retrieval_agent.extract_procedure_snippets", return_value=[]):
                    result = retrieval_agent_node(state)
        self.assertEqual(call_count[0], 3)  # 1 initial + 2 retries
        self.assertEqual(result["retrieval_status"], "no_match")

    def test_backend_failed_stops_after_max_retries(self):
        state = self._make_state(retry_max=1)
        call_count = [0]
        def mock_collect(*args, **kwargs):
            call_count[0] += 1
            return [], "backend_failed"
        with patch("src.agents.hypothesis_phase.retrieval_agent.collect_authoritative_records", side_effect=mock_collect):
            with patch("src.agents.hypothesis_phase.retrieval_agent.collect_poc_candidates", return_value=[]):
                with patch("src.agents.hypothesis_phase.retrieval_agent.extract_procedure_snippets", return_value=[]):
                    result = retrieval_agent_node(state)
        self.assertEqual(call_count[0], 2)  # 1 initial + 1 retry
        self.assertEqual(result["retrieval_status"], "backend_failed")

    def test_no_retry_on_query_invalid(self):
        state = self._make_state(retry_max=2)
        call_count = [0]
        def mock_collect(*args, **kwargs):
            call_count[0] += 1
            return [], "query_invalid"
        with patch("src.agents.hypothesis_phase.retrieval_agent.collect_authoritative_records", side_effect=mock_collect):
            with patch("src.agents.hypothesis_phase.retrieval_agent.collect_poc_candidates", return_value=[]):
                with patch("src.agents.hypothesis_phase.retrieval_agent.extract_procedure_snippets", return_value=[]):
                    result = retrieval_agent_node(state)
        self.assertEqual(call_count[0], 1)  # No retry for query_invalid
        self.assertEqual(result["retrieval_status"], "query_invalid")

    def test_no_retry_on_dataset_missing(self):
        state = self._make_state(retry_max=2)
        call_count = [0]
        def mock_collect(*args, **kwargs):
            call_count[0] += 1
            return [], "dataset_missing"
        with patch("src.agents.hypothesis_phase.retrieval_agent.collect_authoritative_records", side_effect=mock_collect):
            with patch("src.agents.hypothesis_phase.retrieval_agent.collect_poc_candidates", return_value=[]):
                with patch("src.agents.hypothesis_phase.retrieval_agent.extract_procedure_snippets", return_value=[]):
                    result = retrieval_agent_node(state)
        self.assertEqual(call_count[0], 1)
        self.assertEqual(result["retrieval_status"], "dataset_missing")


class TestBestEffortPassAfterRetryExhaustion(unittest.TestCase):
    """After retry exhaustion, critic fast path uses best_effort_pass with prior shortlist."""

    def test_backend_failed_with_prior_shortlist_uses_best_effort(self):
        state = initial_state(target_ip="10.0.0.1")
        state["retrieval_status"] = "backend_failed"
        shortlist = [{"cve_id": "CVE-2024-0001", "candidate_id": "abc"}]
        bundle = RetrievalBundle(shortlist=shortlist)
        report = _deterministic_fast_path(state, bundle)
        self.assertEqual(report["verdict"], "best_effort_pass")
        self.assertIn("abc", report["approved_candidate_ids"])

    def test_backend_failed_no_shortlist_rotates_to_next_service(self):
        state = initial_state(target_ip="10.0.0.1")
        state["retrieval_status"] = "backend_failed"
        state["target_services"] = [
            {"service_key": "10.0.0.1:80:http", "name": "http"},
            {"service_key": "10.0.0.1:5060:sip", "name": "sip"},
        ]
        bundle = RetrievalBundle(shortlist=[])
        report = _deterministic_fast_path(state, bundle)
        self.assertEqual(report["verdict"], "need_more_recon")

    def test_backend_failed_no_shortlist_all_exhausted_ends(self):
        state = initial_state(target_ip="10.0.0.1")
        state["retrieval_status"] = "backend_failed"
        state["phase2_exhausted_service_keys"] = [
            "10.0.0.1:80:http", "10.0.0.1:5060:sip",
        ]
        state["target_services"] = [
            {"service_key": "10.0.0.1:80:http", "name": "http"},
            {"service_key": "10.0.0.1:5060:sip", "name": "sip"},
        ]
        bundle = RetrievalBundle(shortlist=[])
        report = _deterministic_fast_path(state, bundle)
        self.assertEqual(report["verdict"], "exhausted")


class TestUnifiedGenericLabels(unittest.TestCase):
    """LOW_SIGNAL_LABELS is consistent across modules and includes http-proxy."""

    def test_shared_set_includes_http_proxy(self):
        from src.agents.hypothesis_phase.shared import LOW_SIGNAL_LABELS
        self.assertIn("http-proxy", LOW_SIGNAL_LABELS)
        self.assertIn("http proxy", LOW_SIGNAL_LABELS)

    def test_recon_uses_shared_set(self):
        from src.agents.hypothesis_phase.shared import LOW_SIGNAL_LABELS
        from src.agents.recon import _GENERIC_LABELS
        self.assertEqual(_GENERIC_LABELS, LOW_SIGNAL_LABELS)

    def test_http_proxy_resolves_to_httpd_keyword(self):
        from src.agents.hypothesis_phase.shared import keyword_from_fingerprints
        state = initial_state(target_ip="10.0.0.1")
        fp = ProductFingerprint(
            target_ip="10.0.0.1", port=80,
            raw_service="http-proxy", vendor="apache", product="httpd",
            version="2.4.57",
        )
        keyword, app_name, version = keyword_from_fingerprints([fp], state)
        self.assertEqual(keyword, "httpd")
        self.assertEqual(app_name, "httpd")
        self.assertEqual(version, "2.4.57")

    def test_http_proxy_raw_service_filtered_in_scoring(self):
        from src.agents.hypothesis_phase.shared import keyword_from_fingerprints
        state = initial_state(target_ip="10.0.0.1")
        # http-proxy raw service with generic product should prefer the product fallback
        fp = ProductFingerprint(
            target_ip="10.0.0.1", port=80,
            raw_service="http-proxy", vendor="apache", product="httpd",
            version="2.4.57",
        )
        keyword, app_name, _ = keyword_from_fingerprints([fp], state)
        # Should resolve to httpd, not "http-proxy"
        self.assertNotEqual(keyword, "http-proxy")
        self.assertEqual(app_name, "httpd")


class TestLegacyKeywordConsistency(unittest.TestCase):
    """Legacy hypothesis.py produces same keyword as modular pipeline."""

    def test_legacy_and_modular_agree(self):
        from src.agents.hypothesis import _keyword_from_fingerprints as legacy_kw
        from src.agents.hypothesis_phase.shared import keyword_from_fingerprints as shared_kw
        state = initial_state(target_ip="10.0.0.1")
        fp = ProductFingerprint(
            target_ip="10.0.0.1", port=80,
            raw_service="http", vendor="apache", product="httpd",
            version="2.4.57",
        )
        legacy_result = legacy_kw([fp], state)
        shared_result = shared_kw([fp], state)
        self.assertEqual(legacy_result, shared_result)

    def test_legacy_with_http_proxy_matches_shared(self):
        from src.agents.hypothesis import _keyword_from_fingerprints as legacy_kw
        from src.agents.hypothesis_phase.shared import keyword_from_fingerprints as shared_kw
        state = initial_state(target_ip="10.0.0.1")
        fp = ProductFingerprint(
            target_ip="10.0.0.1", port=3128,
            raw_service="http-proxy", vendor="apache", product="httpd",
            version="2.4.57",
        )
        legacy_result = legacy_kw([fp], state)
        shared_result = shared_kw([fp], state)
        self.assertEqual(legacy_result[0], shared_result[0])  # keyword
        self.assertEqual(legacy_result[1], shared_result[1])  # app_name
        self.assertEqual(legacy_result[2], shared_result[2])  # version

    def test_legacy_with_generic_state_keyword_falls_back(self):
        from src.agents.hypothesis import _keyword_from_fingerprints as legacy_kw
        from src.agents.hypothesis_phase.shared import keyword_from_fingerprints as shared_kw
        state = initial_state(target_ip="10.0.0.1")
        state["keyword"] = "http-proxy"  # stale generic label in state
        fp = ProductFingerprint(
            target_ip="10.0.0.1", port=80,
            raw_service="http-proxy", vendor="apache", product="httpd",
            version="2.4.57",
        )
        legacy_result = legacy_kw([fp], state)
        shared_result = shared_kw([fp], state)
        # Both should reject the generic state keyword and fall back to fingerprint
        self.assertEqual(legacy_result[0], shared_result[0])


class TestBackendFailedNeverSendsEmptyToCriticLlm(unittest.TestCase):
    """backend_failed with no shortlist never reaches the LLM critic path."""

    def test_fast_path_intercepts_before_llm(self):
        state = initial_state(target_ip="10.0.0.1")
        state["retrieval_status"] = "backend_failed"
        state["target_services"] = [
            {"service_key": "10.0.0.1:80:http", "name": "http"},
        ]
        bundle = RetrievalBundle(shortlist=[])
        report = _deterministic_fast_path(state, bundle)
        # Must be intercepted by fast path, not None (which would trigger LLM)
        self.assertIsNotNone(report)
        self.assertIn(report["verdict"], {"need_more_recon", "exhausted", "best_effort_pass"})


if __name__ == "__main__":
    unittest.main()
