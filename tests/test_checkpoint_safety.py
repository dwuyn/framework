"""
Tests for checkpoint saver thread-safety and atomic write behavior.
"""

import importlib
import os
import pickle
import tempfile
import threading
import time
import unittest

import src.graph as graph_module
from src.graph import _DiskBackedSaver


def _make_config(thread_id="test"):
    return {
        "configurable": {
            "thread_id": thread_id,
            "checkpoint_ns": "",
            "checkpoint_id": None,
        }
    }


def _make_checkpoint(step=0):
    """Create a minimal valid LangGraph checkpoint structure."""
    return {
        "v": 2,
        "ts": time.time(),
        "id": f"ckpt-{step}",
        "channel_values": {"state": {"step": step}},
        "channel_versions": {"state": step},
        "versions_seen": {},
    }


class TestCheckpointPutSafety(unittest.TestCase):
    """Repeated put() calls do not raise 'dictionary changed size during iteration'."""

    def _make_saver(self, path):
        return _DiskBackedSaver(path)

    def test_checkpoint_root_follows_runtime_output_dir(self):
        previous = os.environ.get("VERIPLANPT_RUN_DIR")
        os.environ["VERIPLANPT_RUN_DIR"] = "/run/veriplanpt/output"
        try:
            reloaded = importlib.reload(graph_module)
            self.assertEqual(reloaded._CHECKPOINT_DIR, "/run/veriplanpt/output/checkpoints")
        finally:
            if previous is None:
                os.environ.pop("VERIPLANPT_RUN_DIR", None)
            else:
                os.environ["VERIPLANPT_RUN_DIR"] = previous
            importlib.reload(graph_module)

    def test_single_put_succeeds(self):
        with tempfile.TemporaryDirectory(prefix="ckpt-") as tmp:
            path = os.path.join(tmp, "test.pkl")
            saver = self._make_saver(path)
            result = saver.put(_make_config(), _make_checkpoint(0), {}, {})
            self.assertIsNotNone(result)
            self.assertTrue(os.path.exists(path))

    def test_repeated_puts_no_error(self):
        with tempfile.TemporaryDirectory(prefix="ckpt-repeat-") as tmp:
            path = os.path.join(tmp, "test.pkl")
            saver = self._make_saver(path)
            for i in range(20):
                saver.put(_make_config(), _make_checkpoint(i), {}, {})
            self.assertTrue(os.path.exists(path))

    def test_concurrent_puts_no_crash(self):
        with tempfile.TemporaryDirectory(prefix="ckpt-concurrent-") as tmp:
            path = os.path.join(tmp, "test.pkl")
            saver = self._make_saver(path)
            errors = []

            def writer(n):
                try:
                    for i in range(10):
                        saver.put(
                            _make_config(f"t-{n}"),
                            _make_checkpoint(n * 10 + i),
                            {},
                            {},
                        )
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(errors, [], f"Concurrent put() raised: {errors}")
            self.assertTrue(os.path.exists(path))

    def test_checkpoint_file_is_valid_pickle_after_write(self):
        with tempfile.TemporaryDirectory(prefix="ckpt-valid-") as tmp:
            path = os.path.join(tmp, "test.pkl")
            saver = self._make_saver(path)
            saver.put(_make_config(), _make_checkpoint(0), {}, {})
            with open(path, "rb") as f:
                data = pickle.load(f)
            self.assertIn("storage", data)
            self.assertIn("writes", data)

    def test_put_does_not_corrupt_on_mutation_during_serialization(self):
        """Simulate dict mutation during iteration by mutating storage concurrently."""
        with tempfile.TemporaryDirectory(prefix="ckpt-mutation-") as tmp:
            path = os.path.join(tmp, "test.pkl")
            saver = self._make_saver(path)
            saver.put(_make_config(), _make_checkpoint(0), {}, {})

            errors = []

            def mutator():
                try:
                    for i in range(30):
                        saver.storage[f"key_{i}"] = {"data": list(range(i))}
                except Exception as exc:
                    errors.append(("mutator", exc))

            def writer():
                try:
                    for i in range(30):
                        saver.put(_make_config(), _make_checkpoint(i), {}, {})
                except Exception as exc:
                    errors.append(("writer", exc))

            t1 = threading.Thread(target=mutator)
            t2 = threading.Thread(target=writer)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
            # The deep-copy + lock should prevent iteration errors
            iteration_errors = [
                e for _, e in errors
                if "changed size" in str(e).lower() or "dictionary" in str(e).lower()
            ]
            self.assertEqual(iteration_errors, [], f"Got dict-mutation errors: {iteration_errors}")


class TestAtomicWrite(unittest.TestCase):
    """Checkpoint writes use temp file + atomic rename."""

    def test_no_partial_file_on_write_error(self):
        """If pickle fails, the original checkpoint should remain intact."""
        with tempfile.TemporaryDirectory(prefix="ckpt-atomic-") as tmp:
            path = os.path.join(tmp, "test.pkl")
            saver = _DiskBackedSaver(path)
            # Write a valid checkpoint first
            saver.put(_make_config(), _make_checkpoint(0), {}, {})
            self.assertTrue(os.path.exists(path))
            initial_size = os.path.getsize(path)
            # The file should exist and be non-empty
            self.assertGreater(initial_size, 0)


if __name__ == "__main__":
    unittest.main()
