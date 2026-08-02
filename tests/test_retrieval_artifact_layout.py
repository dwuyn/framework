"""
Tests for stable, non-nesting retrieval artifact paths.
"""

import os
import tempfile
import unittest

from src.agents.hypothesis_phase.shared import hypothesis_runtime_cfg, output_dir
from src.state import initial_state


class TestOutputDirLayout(unittest.TestCase):
    """output_dir writes to data/retrieval_candidates/<ip>/<service-key>, not nested."""

    def test_basic_path_structure(self):
        with tempfile.TemporaryDirectory(prefix="retrieval-") as tmp:
            cfg = {"candidate_cache_dir": tmp}
            path = output_dir("10.0.0.1", "10.0.0.1:80:httpd", cfg)
            # Dots in IP are preserved; colons in service key become hyphens
            self.assertIn("10.0.0.1", path)
            self.assertIn("10.0.0.1-80-httpd", path)
            self.assertTrue(os.path.isdir(path))

    def test_repeated_rotations_write_to_sibling_directories(self):
        with tempfile.TemporaryDirectory(prefix="retrieval-") as tmp:
            cfg = {"candidate_cache_dir": tmp}
            path1 = output_dir("10.0.0.1", "10.0.0.1:80:httpd", cfg)
            path2 = output_dir("10.0.0.1", "10.0.0.1:5060:sip", cfg)
            # Both should be siblings under the same IP directory
            ip_dir = os.path.join(tmp, "10.0.0.1")
            self.assertTrue(path1.startswith(ip_dir))
            self.assertTrue(path2.startswith(ip_dir))
            self.assertNotEqual(path1, path2)
            # Neither should be nested (no .../sip/sip/...)
            self.assertNotIn(os.sep + "sip" + os.sep + "sip", path2)

    def test_no_nesting_from_same_keyword(self):
        """Repeated calls with the same service key should not nest paths."""
        with tempfile.TemporaryDirectory(prefix="retrieval-") as tmp:
            cfg = {"candidate_cache_dir": tmp}
            path1 = output_dir("10.0.0.1", "10.0.0.1:5060:sip", cfg)
            path2 = output_dir("10.0.0.1", "10.0.0.1:5060:sip", cfg)
            self.assertEqual(path1, path2)
            # Verify no nested sip/sip
            self.assertNotIn(os.sep + "sip" + os.sep + "sip", path1)

    def test_empty_service_key_uses_default(self):
        with tempfile.TemporaryDirectory(prefix="retrieval-") as tmp:
            cfg = {"candidate_cache_dir": tmp}
            path = output_dir("10.0.0.1", "", cfg)
            self.assertIn("default", path)

    def test_special_characters_in_ip_are_sanitized(self):
        with tempfile.TemporaryDirectory(prefix="retrieval-") as tmp:
            cfg = {"candidate_cache_dir": tmp}
            path = output_dir("10.0.0.1/../../escape", "svc", cfg)
            # Slashes are replaced with hyphens
            self.assertNotIn("../../", path)
            self.assertTrue(path.startswith(tmp))


class TestNoPlanningOutputDirFeedback(unittest.TestCase):
    """hypothesis_runtime_cfg does not feed planning_output_dir back into candidate_cache_dir."""

    def test_planning_output_dir_not_used_as_cache_dir(self):
        state = initial_state(target_ip="10.0.0.1")
        state["planning_output_dir"] = "/some/nested/dir/sip/sip/sip"
        cfg = hypothesis_runtime_cfg(state)
        retrieval_cfg = cfg["retrieval"]
        self.assertNotEqual(retrieval_cfg.get("candidate_cache_dir"), "/some/nested/dir/sip/sip/sip")

    def test_default_cache_dir_preserved(self):
        state = initial_state(target_ip="10.0.0.1")
        cfg = hypothesis_runtime_cfg(state)
        retrieval_cfg = cfg["retrieval"]
        self.assertEqual(retrieval_cfg.get("candidate_cache_dir"), "data/retrieval_candidates")


if __name__ == "__main__":
    unittest.main()
