import tempfile
import unittest
from unittest.mock import patch

from src.agents.hypothesis_phase import build_hypothesis_phase_graph
from src.agents.verifier import hypothesis_verifier_node
from src.memory.world_state import HostInfo, ServiceInfo, WorldState
from src.retrieval.models import (
    ApplicabilityAssessment,
    AuthoritativeRecord,
    PocCandidate,
    ProcedureSnippet,
    ProductFingerprint,
)
from src.state import initial_state


class Phase2SubgraphTests(unittest.TestCase):
    def _base_state(self):
        state = initial_state(target_ip="10.0.0.1")
        state["planning_output_dir"] = tempfile.mkdtemp(prefix="phase2-")
        state["world_state"] = WorldState(hosts={
            "10.0.0.1": HostInfo(
                ip="10.0.0.1",
                services=[ServiceInfo(port=80, name="Apache", version="2.4.49", confidence=0.9)],
            )
        }).to_dict()
        return state

    def _sample_objects(self):
        fp = ProductFingerprint(
            target_ip="10.0.0.1",
            port=80,
            raw_service="Apache",
            vendor="apache",
            product="httpd",
            version="2.4.49",
            cpe_candidates=["cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*"],
            platform_hints=["linux"],
            confidence=0.9,
            evidence=["fp"],
        )
        record = AuthoritativeRecord(
            cve_id="CVE-2021-41773",
            source="vendor",
            title="Apache httpd traversal",
            description="Vendor advisory",
            cvss_score=7.5,
            references=["https://httpd.apache.org/security/vulnerabilities_24.html"],
            evidence=["record"],
        )
        candidate = PocCandidate(
            candidate_id="exploitdb:CVE-2021-41773:apache",
            cve_id="CVE-2021-41773",
            source="exploitdb",
            path="/tmp/apache.py",
            evidence=["candidate"],
        )
        snippet = ProcedureSnippet(
            candidate_id=candidate.candidate_id,
            commands=["python apache.py --target 10.0.0.1"],
            target_assumptions=["linux"],
            confidence=0.8,
        )
        return fp, record, candidate, snippet

    def test_phase2_subgraph_routes_to_planning_for_strong_shortlist(self):
        state = self._base_state()
        fp, record, candidate, snippet = self._sample_objects()
        assessment = ApplicabilityAssessment(
            cve_id=record.cve_id,
            candidate_id=candidate.candidate_id,
            version_match="yes",
            cpe_match="yes",
            platform_match="yes",
            auth_match="yes",
            network_match="yes",
            procedure_ready=True,
            trust_score=1.0,
            estimated_cost=1.1,
            score=0.84,
            verdict="strong",
            reasons=["version=yes", "cpe=yes"],
        )
        shortlist = [{
            "cve_id": record.cve_id,
            "candidate_id": candidate.candidate_id,
            "source": candidate.source,
            "title": record.title,
            "score": 0.84,
            "verdict": "strong",
            "trust_score": 1.0,
            "estimated_cost": 1.1,
            "service": "Apache",
            "vendor": "apache",
            "product": "httpd",
            "version": "2.4.49",
            "port": 80,
            "target_ip": "10.0.0.1",
            "path": candidate.path,
            "locator": "local",
            "references": record.references,
            "commands": snippet.commands,
            "dependencies": [],
            "placeholders": [],
            "required_placeholders": [],
            "working_directory": "/tmp",
            "setup_commands": [],
            "verify_commands": [],
            "success_indicators": [],
            "failure_indicators": [],
            "reasons": assessment.reasons,
        }]

        with patch("src.agents.hypothesis_phase.retrieval_agent.build_fingerprints", return_value=[fp]):
            with patch("src.agents.hypothesis_phase.retrieval_agent.collect_authoritative_records", return_value=([record], "ok")):
                with patch("src.agents.hypothesis_phase.retrieval_agent.collect_poc_candidates", return_value=[candidate]):
                    with patch("src.agents.hypothesis_phase.retrieval_agent.extract_procedure_snippets", return_value=[snippet]):
                        with patch("src.agents.hypothesis_phase.evidence_normalizer.assess_candidates", return_value=[assessment]):
                            with patch("src.agents.hypothesis_phase.evidence_normalizer.build_shortlist", return_value=shortlist):
                                result = build_hypothesis_phase_graph().invoke(state)

        self.assertEqual(result["phase2_route"], "planning")
        self.assertTrue(result["hypothesis_complete"])
        self.assertEqual(result["retrieval_bundle"]["critic_report"]["verdict"], "pass")
        self.assertEqual(result["retrieval_bundle"]["shortlist"][0]["candidate_id"], candidate.candidate_id)

    def test_phase2_subgraph_routes_to_recon_when_version_unconfirmed(self):
        state = self._base_state()
        fp, record, candidate, snippet = self._sample_objects()
        assessment = ApplicabilityAssessment(
            cve_id=record.cve_id,
            candidate_id=candidate.candidate_id,
            version_match="unknown",
            cpe_match="yes",
            platform_match="yes",
            auth_match="yes",
            network_match="yes",
            procedure_ready=True,
            trust_score=1.0,
            estimated_cost=1.1,
            score=0.84,
            verdict="strong",
            reasons=["version=unknown", "version_confirmation_required"],
        )
        shortlist = [{
            "cve_id": record.cve_id,
            "candidate_id": candidate.candidate_id,
            "source": candidate.source,
            "title": record.title,
            "score": 0.84,
            "verdict": "strong",
            "trust_score": 1.0,
            "estimated_cost": 1.1,
            "service": "Apache",
            "vendor": "apache",
            "product": "httpd",
            "version": "2.4.49",
            "port": 80,
            "target_ip": "10.0.0.1",
            "path": candidate.path,
            "locator": "local",
            "references": record.references,
            "commands": snippet.commands,
            "dependencies": [],
            "placeholders": [],
            "required_placeholders": [],
            "working_directory": "/tmp",
            "setup_commands": [],
            "verify_commands": [],
            "success_indicators": [],
            "failure_indicators": [],
            "reasons": assessment.reasons,
        }]

        with patch("src.agents.hypothesis_phase.retrieval_agent.build_fingerprints", return_value=[fp]):
            with patch("src.agents.hypothesis_phase.retrieval_agent.collect_authoritative_records", return_value=([record], "ok")):
                with patch("src.agents.hypothesis_phase.retrieval_agent.collect_poc_candidates", return_value=[candidate]):
                    with patch("src.agents.hypothesis_phase.retrieval_agent.extract_procedure_snippets", return_value=[snippet]):
                        with patch("src.agents.hypothesis_phase.evidence_normalizer.assess_candidates", return_value=[assessment]):
                            with patch("src.agents.hypothesis_phase.evidence_normalizer.build_shortlist", return_value=shortlist):
                                result = build_hypothesis_phase_graph().invoke(state)

        self.assertEqual(result["phase2_route"], "recon")
        self.assertFalse(result["hypothesis_complete"])
        self.assertEqual(result["retrieval_bundle"]["critic_report"]["verdict"], "need_more_recon")

    def test_phase2_subgraph_loops_hypothesis_once_on_rework(self):
        state = self._base_state()
        fp, record, candidate, snippet = self._sample_objects()
        candidate_2 = PocCandidate(
            candidate_id="github:CVE-2021-41773:apache",
            cve_id=record.cve_id,
            source="github",
            path="/tmp/apache-repo",
            evidence=["candidate-2"],
        )
        snippet_2 = ProcedureSnippet(
            candidate_id=candidate_2.candidate_id,
            commands=["python github.py --target 10.0.0.1"],
            target_assumptions=["linux"],
            confidence=0.75,
        )
        assessment_1 = ApplicabilityAssessment(
            cve_id=record.cve_id,
            candidate_id=candidate.candidate_id,
            version_match="yes",
            cpe_match="yes",
            platform_match="yes",
            auth_match="yes",
            network_match="yes",
            procedure_ready=True,
            trust_score=1.0,
            estimated_cost=1.1,
            score=0.84,
            verdict="strong",
            reasons=["version=yes"],
        )
        assessment_2 = ApplicabilityAssessment(
            cve_id=record.cve_id,
            candidate_id=candidate_2.candidate_id,
            version_match="yes",
            cpe_match="yes",
            platform_match="yes",
            auth_match="yes",
            network_match="yes",
            procedure_ready=True,
            trust_score=0.8,
            estimated_cost=1.2,
            score=0.79,
            verdict="strong",
            reasons=["version=yes"],
        )
        shortlist = [
            {
                "cve_id": record.cve_id,
                "candidate_id": candidate.candidate_id,
                "source": candidate.source,
                "title": record.title,
                "score": 0.84,
                "verdict": "strong",
                "trust_score": 1.0,
                "estimated_cost": 1.1,
                "service": "Apache",
                "vendor": "apache",
                "product": "httpd",
                "version": "2.4.49",
                "port": 80,
                "target_ip": "10.0.0.1",
                "path": candidate.path,
                "locator": "local",
                "references": record.references,
                "commands": snippet.commands,
                "dependencies": [],
                "placeholders": [],
                "required_placeholders": [],
                "working_directory": "/tmp",
                "setup_commands": [],
                "verify_commands": [],
                "success_indicators": [],
                "failure_indicators": [],
                "reasons": assessment_1.reasons,
            },
            {
                "cve_id": record.cve_id,
                "candidate_id": candidate_2.candidate_id,
                "source": candidate_2.source,
                "title": record.title,
                "score": 0.79,
                "verdict": "strong",
                "trust_score": 0.8,
                "estimated_cost": 1.2,
                "service": "Apache",
                "vendor": "apache",
                "product": "httpd",
                "version": "2.4.49",
                "port": 80,
                "target_ip": "10.0.0.1",
                "path": candidate_2.path,
                "locator": "repo",
                "references": record.references,
                "commands": snippet_2.commands,
                "dependencies": [],
                "placeholders": [],
                "required_placeholders": [],
                "working_directory": "/tmp",
                "setup_commands": [],
                "verify_commands": [],
                "success_indicators": [],
                "failure_indicators": [],
                "reasons": assessment_2.reasons,
            },
        ]

        llm_reports = [
            ({
                "verdict": "rework_hypothesis",
                "approved_candidate_ids": [candidate.candidate_id, candidate_2.candidate_id],
                "rejected_candidate_ids": [],
                "issues": ["normalize hypothesis ordering"],
                "recon_requests": [],
                "reason": "Hypotheses should be regenerated once with cleaner filtering.",
            }, 0, 0),
            ({
                "verdict": "rework_hypothesis",
                "approved_candidate_ids": [candidate.candidate_id, candidate_2.candidate_id],
                "rejected_candidate_ids": [],
                "issues": ["normalize hypothesis ordering"],
                "recon_requests": [],
                "reason": "Still prefers one more rewrite, but budgeted loop should stop here.",
            }, 0, 0),
        ]

        with patch("src.agents.hypothesis_phase.retrieval_agent.build_fingerprints", return_value=[fp]):
            with patch("src.agents.hypothesis_phase.retrieval_agent.collect_authoritative_records", return_value=([record], "ok")):
                with patch("src.agents.hypothesis_phase.retrieval_agent.collect_poc_candidates", return_value=[candidate, candidate_2]):
                    with patch("src.agents.hypothesis_phase.retrieval_agent.extract_procedure_snippets", return_value=[snippet, snippet_2]):
                        with patch("src.agents.hypothesis_phase.evidence_normalizer.assess_candidates", return_value=[assessment_1, assessment_2]):
                            with patch("src.agents.hypothesis_phase.evidence_normalizer.build_shortlist", return_value=shortlist):
                                with patch("src.agents.hypothesis_phase.critic_agent._llm_critic_report", side_effect=llm_reports):
                                    result = build_hypothesis_phase_graph().invoke(state)

        self.assertEqual(result["phase2_route"], "planning")
        self.assertEqual(result["hypothesis_rework_count"], 1)
        self.assertEqual(result["retrieval_bundle"]["critic_report"]["verdict"], "best_effort_pass")

    def test_legacy_hypothesis_verifier_understands_critic_report(self):
        state = self._base_state()
        state["retrieval_bundle"] = {
            "critic_report": {
                "verdict": "pass",
                "reason": "Critic approved the shortlist.",
                "approved_candidate_ids": ["cand-1"],
            },
            "shortlist": [{"candidate_id": "cand-1", "cve_id": "CVE-1"}],
        }
        state["vuln_hypotheses"] = [{"candidate_id": "cand-1", "cve_id": "CVE-1", "confidence": 0.9, "evidence_chain": ["a", "b"]}]

        result = hypothesis_verifier_node(state)
        self.assertEqual(result["verification_log"][-1]["verdict"], "proceed")


if __name__ == "__main__":
    unittest.main()
