import tempfile
import unittest
from unittest.mock import patch

from src.agents.hypothesis import hypothesis_node
from src.agents.planning import finalize_planning_node
from src.agents.verifier import hypothesis_verifier_node
from src.memory.world_state import HostInfo, ServiceInfo, WorldState
from src.retrieval.applicability import assess_candidates
from src.retrieval.fingerprint import apply_cpe_updates, build_fingerprints
from src.retrieval.models import (
    ApplicabilityAssessment,
    AuthoritativeRecord,
    PocCandidate,
    ProcedureSnippet,
    ProductFingerprint,
)
from src.state import initial_state


class RetrievalRefactorTests(unittest.TestCase):
    def test_build_fingerprints_normalizes_service_and_cpe(self):
        ws = WorldState(hosts={
            "10.0.0.1": HostInfo(
                ip="10.0.0.1",
                services=[
                    ServiceInfo(
                        port=80,
                        name="Apache",
                        version="2.4.49",
                        banner="Apache httpd 2.4.49",
                        confidence=0.9,
                    )
                ],
            )
        })

        fps = build_fingerprints(ws, top_services=5)
        self.assertEqual(len(fps), 1)
        self.assertEqual(fps[0].vendor, "apache")
        self.assertEqual(fps[0].product, "httpd")
        self.assertTrue(fps[0].cpe_candidates)

        updated = apply_cpe_updates(ws, fps)
        self.assertTrue(updated.hosts["10.0.0.1"].services[0].cpe.startswith("cpe:2.3:a:apache:httpd"))

    def test_build_fingerprints_prefers_current_service_and_skips_attempted(self):
        ws = WorldState(hosts={
            "10.0.0.1": HostInfo(
                ip="10.0.0.1",
                services=[
                    ServiceInfo(port=80, name="Apache", version="2.4.49", confidence=0.8),
                    ServiceInfo(port=3306, name="MySQL", version="8.0.35", confidence=0.95),
                ],
            )
        })

        fps = build_fingerprints(
            ws,
            top_services=5,
            state={
                "target_services": [
                    {"target_ip": "10.0.0.1", "port": 80, "name": "Apache", "service_key": "10.0.0.1:80:apache"},
                    {"target_ip": "10.0.0.1", "port": 3306, "name": "MySQL", "service_key": "10.0.0.1:3306:mysql"},
                ],
                "current_service_index": 1,
                "attempted_services": ["10.0.0.1:80:apache"],
            },
        )

        self.assertEqual(len(fps), 1)
        self.assertEqual(fps[0].port, 3306)

    def test_assess_candidates_rejects_version_mismatch(self):
        ws = WorldState(hosts={
            "10.0.0.1": HostInfo(
                ip="10.0.0.1",
                services=[ServiceInfo(port=80, name="Apache", version="2.4.41", accessibility="open", confidence=0.9)],
            )
        })
        fp = ProductFingerprint(
            target_ip="10.0.0.1",
            port=80,
            raw_service="Apache",
            vendor="apache",
            product="httpd",
            version="2.4.41",
            cpe_candidates=["cpe:2.3:a:apache:httpd:2.4.41:*:*:*:*:*:*:*"],
            platform_hints=["linux"],
            confidence=0.9,
            evidence=["fingerprint"],
        )
        record = AuthoritativeRecord(
            cve_id="CVE-2021-41773",
            source="cvemap",
            title="Apache httpd path traversal",
            description="Apache httpd on Linux",
            affected_ranges=[{"min_version": "2.4.49", "max_version": "2.4.50"}],
            platform_hints=["linux"],
        )
        candidate = PocCandidate(
            candidate_id="exploitdb:CVE-2021-41773:apache",
            cve_id="CVE-2021-41773",
            source="exploitdb",
            path="/tmp/apache.py",
        )
        snippet = ProcedureSnippet(candidate_id=candidate.candidate_id, commands=["python apache.py"], confidence=0.8)

        assessments = assess_candidates(ws, [fp], [record], [candidate], [snippet])
        self.assertEqual(len(assessments), 1)
        self.assertEqual(assessments[0].version_match, "no")
        self.assertEqual(assessments[0].verdict, "reject")

    def test_assess_candidates_caps_unknown_version_to_weak(self):
        ws = WorldState(hosts={
            "10.0.0.1": HostInfo(
                ip="10.0.0.1",
                services=[ServiceInfo(port=80, name="Apache", version="", accessibility="open", confidence=0.9)],
            )
        })
        fp = ProductFingerprint(
            target_ip="10.0.0.1",
            port=80,
            raw_service="Apache",
            vendor="apache",
            product="httpd",
            version="",
            cpe_candidates=["cpe:2.3:a:apache:httpd:*:*:*:*:*:*:*:*"],
            platform_hints=["linux"],
            confidence=0.9,
            evidence=["fingerprint"],
        )
        record = AuthoritativeRecord(
            cve_id="CVE-2021-41773",
            source="vendor",
            title="Apache httpd path traversal",
            description="Apache httpd on Linux",
            affected_ranges=[{"min_version": "2.4.49", "max_version": "2.4.50"}],
            platform_hints=["linux"],
        )
        candidate = PocCandidate(
            candidate_id="exploitdb:CVE-2021-41773:apache",
            cve_id="CVE-2021-41773",
            source="exploitdb",
            path="/tmp/apache.py",
        )
        snippet = ProcedureSnippet(candidate_id=candidate.candidate_id, commands=["python apache.py"], confidence=0.8)

        assessments = assess_candidates(ws, [fp], [record], [candidate], [snippet])
        self.assertEqual(len(assessments), 1)
        self.assertEqual(assessments[0].version_match, "unknown")
        self.assertEqual(assessments[0].verdict, "weak")
        self.assertIn("version_confirmation_required", assessments[0].reasons)

    def test_hypothesis_node_emits_retrieval_bundle_and_derived_hypotheses(self):
        state = initial_state(target_ip="10.0.0.1")
        state["planning_output_dir"] = tempfile.mkdtemp(prefix="retrieval-hypo-")
        state["world_state"] = WorldState(hosts={
            "10.0.0.1": HostInfo(ip="10.0.0.1", services=[ServiceInfo(port=80, name="Apache", version="2.4.49", confidence=0.9)])
        }).to_dict()

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
        assessment = ApplicabilityAssessment(
            cve_id="CVE-2021-41773",
            candidate_id=candidate.candidate_id,
            version_match="yes",
            cpe_match="yes",
            platform_match="yes",
            auth_match="yes",
            network_match="yes",
            procedure_ready=True,
            trust_score=1.0,
            estimated_cost=1.2,
            score=0.84,
            verdict="strong",
            reasons=["version=yes", "cpe=yes"],
        )
        shortlist = [{
            "cve_id": "CVE-2021-41773",
            "candidate_id": candidate.candidate_id,
            "source": "exploitdb",
            "title": record.title,
            "score": 0.84,
            "verdict": "strong",
            "trust_score": 1.0,
            "estimated_cost": 1.2,
            "service": "Apache",
            "vendor": "apache",
            "product": "httpd",
            "version": "2.4.49",
            "port": 80,
            "target_ip": "10.0.0.1",
            "path": "/tmp/apache.py",
            "locator": "local",
            "references": record.references,
            "commands": snippet.commands,
            "dependencies": [],
            "placeholders": [],
            "reasons": assessment.reasons,
        }]

        with patch("src.agents.hypothesis.build_fingerprints", return_value=[fp]):
            with patch("src.agents.hypothesis.collect_authoritative_records", return_value=([record], "ok")):
                with patch("src.agents.hypothesis.collect_poc_candidates", return_value=[candidate]):
                    with patch("src.agents.hypothesis.extract_procedure_snippets", return_value=[snippet]):
                        with patch("src.agents.hypothesis.assess_candidates", return_value=[assessment]):
                            with patch("src.agents.hypothesis.build_shortlist", return_value=shortlist):
                                result = hypothesis_node(state)

        self.assertIn("retrieval_bundle", result)
        self.assertEqual(result["retrieval_bundle"]["shortlist"][0]["cve_id"], "CVE-2021-41773")
        self.assertEqual(result["vuln_hypotheses"][0]["candidate_id"], candidate.candidate_id)

    def test_hypothesis_verifier_blocks_when_only_google_candidate_survives(self):
        state = initial_state(target_ip="10.0.0.1")
        state["retrieval_bundle"] = {
            "authoritative_records": [{"cve_id": "CVE-1", "source": "vendor"}],
            "poc_candidates": [
                {"candidate_id": "google:CVE-1:doc", "cve_id": "CVE-1", "source": "google"},
                {"candidate_id": "github:CVE-1:repo", "cve_id": "CVE-1", "source": "github"},
            ],
            "assessments": [
                {
                    "candidate_id": "google:CVE-1:doc",
                    "cve_id": "CVE-1",
                    "version_match": "yes",
                    "cpe_match": "yes",
                    "platform_match": "yes",
                    "network_match": "yes",
                    "verdict": "strong",
                }
            ],
            "shortlist": [{"candidate_id": "google:CVE-1:doc", "cve_id": "CVE-1", "source": "google"}],
        }
        state["vuln_hypotheses"] = [{"candidate_id": "google:CVE-1:doc", "cve_id": "CVE-1", "confidence": 0.9, "evidence_chain": ["x", "y"]}]

        result = hypothesis_verifier_node(state)
        self.assertEqual(result["verification_log"][-1]["verdict"], "need_more_recon")

    def test_hypothesis_verifier_blocks_when_version_not_confirmed(self):
        state = initial_state(target_ip="10.0.0.1")
        state["retrieval_bundle"] = {
            "authoritative_records": [{"cve_id": "CVE-1", "source": "vendor"}],
            "poc_candidates": [
                {"candidate_id": "exploitdb:CVE-1:file", "cve_id": "CVE-1", "source": "exploitdb"},
            ],
            "assessments": [
                {
                    "candidate_id": "exploitdb:CVE-1:file",
                    "cve_id": "CVE-1",
                    "version_match": "unknown",
                    "cpe_match": "yes",
                    "platform_match": "yes",
                    "network_match": "yes",
                    "verdict": "strong",
                }
            ],
            "shortlist": [{"candidate_id": "exploitdb:CVE-1:file", "cve_id": "CVE-1", "source": "exploitdb"}],
        }
        state["vuln_hypotheses"] = [{"candidate_id": "exploitdb:CVE-1:file", "cve_id": "CVE-1", "confidence": 0.9, "evidence_chain": ["x", "y"]}]

        result = hypothesis_verifier_node(state)
        self.assertEqual(result["verification_log"][-1]["verdict"], "need_more_recon")
        self.assertIn("confirmed version", result["verification_log"][-1]["reason"])

    def test_finalize_planning_uses_retrieval_bundle_shortlist(self):
        state = initial_state(target_ip="10.0.0.1")
        state["planning_output_dir"] = tempfile.mkdtemp(prefix="retrieval-plan-")
        state["app_name"] = "httpd"
        state["app_version"] = "2.4.49"
        state["keyword"] = "httpd"
        state["current_proposal"] = {
            "keyword": "httpd",
            "app_name": "httpd",
            "app_version": "2.4.49",
            "selected_candidates": ["github:CVE-1:repo", "exploitdb:CVE-1:file"],
            "cve_list": ["CVE-1"],
            "done": True,
        }
        state["retrieval_bundle"] = {
            "shortlist": [
                {
                    "candidate_id": "exploitdb:CVE-1:file",
                    "cve_id": "CVE-1",
                    "source": "exploitdb",
                    "score": 0.78,
                    "verdict": "strong",
                    "trust_score": 1.0,
                    "estimated_cost": 1.0,
                    "service": "Apache",
                    "version": "2.4.49",
                    "target_ip": "10.0.0.1",
                    "port": 80,
                    "commands": ["python exploitdb.py"],
                    "dependencies": [],
                    "placeholders": [],
                    "reasons": ["good"],
                },
                {
                    "candidate_id": "github:CVE-1:repo",
                    "cve_id": "CVE-1",
                    "source": "github",
                    "score": 0.82,
                    "verdict": "strong",
                    "trust_score": 0.8,
                    "estimated_cost": 1.3,
                    "service": "Apache",
                    "version": "2.4.49",
                    "target_ip": "10.0.0.1",
                    "port": 80,
                    "commands": ["python github.py"],
                    "dependencies": [],
                    "placeholders": [],
                    "reasons": ["better"],
                },
            ],
            "poc_candidates": [
                {"candidate_id": "exploitdb:CVE-1:file", "source": "exploitdb", "path": "/tmp/exploitdb.py", "repo_name": "file"},
                {"candidate_id": "github:CVE-1:repo", "source": "github", "path": "/tmp/repo", "repo_name": "repo"},
            ],
            "assessments": [
                {"candidate_id": "exploitdb:CVE-1:file", "score": 0.78, "trust_score": 1.0, "estimated_cost": 1.0, "procedure_ready": True, "verdict": "strong"},
                {"candidate_id": "github:CVE-1:repo", "score": 0.82, "trust_score": 0.8, "estimated_cost": 1.3, "procedure_ready": True, "verdict": "strong"},
            ],
        }

        result = finalize_planning_node(state)
        self.assertTrue(result["planning_complete"])
        self.assertEqual(result["exploit_plan"][0]["candidate_id"], "github:CVE-1:repo")
        self.assertEqual(result["cve_list"][0], "CVE-1")


if __name__ == "__main__":
    unittest.main()
