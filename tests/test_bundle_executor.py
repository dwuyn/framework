from __future__ import annotations

import json
import stat
import textwrap
import zipfile
from pathlib import Path

import pytest

from src.pipeline.bundle_executor import BundleExecutionError, IndependentBundleExecutor


def _write_bundle(root: Path, kind: str, script: str, *, entrypoint: str = "bin/evaluate") -> Path:
    bundle = root / f"{kind}-bundle"
    entrypoint_path = bundle / entrypoint
    entrypoint_path.parent.mkdir(parents=True)
    entrypoint_path.write_text(textwrap.dedent(script).lstrip(), encoding="utf-8")
    entrypoint_path.chmod(entrypoint_path.stat().st_mode | stat.S_IXUSR)
    manifest = {
        "schema_version": "2.0.0",
        "kind": kind,
        "source_commit": "a" * 40,
        "entrypoint": entrypoint,
    }
    manifest["image_digest"] = "sha256:" + "c" * 64
    if kind == "evaluator":
        manifest["feature_schema_hash"] = "b" * 64
    (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return bundle


_PASS = """
    #!/usr/bin/env python3
    import argparse, json, os
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-dir', required=True)
    parser.add_argument('--run-artifact', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    assert not any(name.startswith('GOOGLE_') for name in os.environ)
    assert 'GOOGLE_APPLICATION_CREDENTIALS' not in os.environ
    json.load(open(args.run_artifact, encoding='utf-8'))
    json.dump({'schema_version': '2.0.0', 'kind': 'KIND', 'status': 'passed', 'outcome': {}}, open(args.output, 'w', encoding='utf-8'))
"""


def test_independent_bundle_executor_passes_and_strips_cloud_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/should/not/be/inherited")
    monkeypatch.setenv("CLOUDSDK_AUTH_ACCESS_TOKEN", "should-not-be-inherited")
    evaluator_script = _PASS.replace("KIND", "evaluator")
    oracle_script = _PASS.replace("KIND", "oracle")
    evaluator = _write_bundle(tmp_path, "evaluator", evaluator_script)
    oracle = _write_bundle(tmp_path, "oracle", oracle_script)
    executor = IndependentBundleExecutor(evaluator_bundle=evaluator, oracle_bundle=oracle)

    verdict = executor(evaluator, tmp_path, {"status": "public"})

    assert verdict == {"schema_version": "2.0.0", "kind": "evaluator", "status": "passed", "outcome": {}}


def test_independent_bundle_executor_passes_hidden_root_to_oracle(tmp_path: Path) -> None:
    hidden_root = tmp_path / "hidden"
    hidden_root.mkdir()
    oracle_script = """
        #!/usr/bin/env python3
        import argparse, json
        parser = argparse.ArgumentParser()
        parser.add_argument('--run-dir', required=True)
        parser.add_argument('--run-artifact', required=True)
        parser.add_argument('--output', required=True)
        parser.add_argument('--hidden-case-root', required=True)
        args = parser.parse_args()
        assert args.hidden_case_root == __import__('pathlib').Path("HIDDEN").resolve().as_posix()
        json.dump({'schema_version': '2.0.0', 'kind': 'oracle', 'status': 'passed', 'outcome': {}}, open(args.output, 'w', encoding='utf-8'))
    """.replace("HIDDEN", str(hidden_root).replace("\\", "\\\\"))
    evaluator = _write_bundle(tmp_path, "evaluator", _PASS.replace("KIND", "evaluator"))
    oracle = _write_bundle(tmp_path, "oracle", oracle_script)
    executor = IndependentBundleExecutor(
        evaluator_bundle=evaluator, oracle_bundle=oracle, hidden_case_root=hidden_root,
    )

    verdict = executor(oracle, tmp_path, {"case_id": "vp-test-0001"})

    assert verdict == {"schema_version": "2.0.0", "kind": "oracle", "status": "passed", "outcome": {}}


def test_independent_bundle_executor_rejects_wrong_bundle_kind(tmp_path: Path) -> None:
    evaluator = _write_bundle(tmp_path, "evaluator", _PASS.replace("KIND", "evaluator"))
    oracle = _write_bundle(tmp_path, "oracle", _PASS.replace("KIND", "oracle"))
    (oracle / "manifest.json").write_text(
        json.dumps({
            "schema_version": "2.0.0", "kind": "evaluator", "source_commit": "a" * 40,
            "entrypoint": "bin/evaluate", "feature_schema_hash": "b" * 64,
            "image_digest": "sha256:" + "c" * 64,
        }),
        encoding="utf-8",
    )
    executor = IndependentBundleExecutor(evaluator_bundle=evaluator, oracle_bundle=oracle)

    with pytest.raises(BundleExecutionError, match="kind"):
        executor(oracle, tmp_path, {})


@pytest.mark.parametrize(
    ("script", "message"),
    [
        (_PASS.replace("KIND", "evaluator").replace("'status': 'passed'", "'status': 'failed'"), "verdict"),
        (
            """
            #!/usr/bin/env python3
            import argparse
            parser = argparse.ArgumentParser()
            parser.add_argument('--run-dir', required=True)
            parser.add_argument('--run-artifact', required=True)
            parser.add_argument('--output', required=True)
            args = parser.parse_args()
            open(args.output, 'w', encoding='utf-8').write('not-json')
            """,
            "verdict",
        ),
    ],
)
def test_independent_bundle_executor_rejects_failed_or_invalid_verdict(
    tmp_path: Path, script: str, message: str,
) -> None:
    evaluator = _write_bundle(tmp_path, "evaluator", script)
    oracle = _write_bundle(tmp_path, "oracle", _PASS.replace("KIND", "oracle"))
    executor = IndependentBundleExecutor(evaluator_bundle=evaluator, oracle_bundle=oracle)

    with pytest.raises(BundleExecutionError, match=message):
        executor(evaluator, tmp_path, {})


def test_independent_bundle_executor_rejects_missing_entrypoint(tmp_path: Path) -> None:
    evaluator = _write_bundle(tmp_path, "evaluator", _PASS.replace("KIND", "evaluator"))
    manifest = json.loads((evaluator / "manifest.json").read_text(encoding="utf-8"))
    manifest["entrypoint"] = "bin/missing"
    (evaluator / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    oracle = _write_bundle(tmp_path, "oracle", _PASS.replace("KIND", "oracle"))
    executor = IndependentBundleExecutor(evaluator_bundle=evaluator, oracle_bundle=oracle)

    with pytest.raises(BundleExecutionError, match="entrypoint"):
        executor(evaluator, tmp_path, {})


def test_independent_bundle_executor_rejects_timeout(tmp_path: Path) -> None:
    evaluator = _write_bundle(
        tmp_path,
        "evaluator",
        """
        #!/usr/bin/env python3
        import time
        time.sleep(2)
        """,
    )
    oracle = _write_bundle(tmp_path, "oracle", _PASS.replace("KIND", "oracle"))
    executor = IndependentBundleExecutor(evaluator_bundle=evaluator, oracle_bundle=oracle, timeout_seconds=0.05)

    with pytest.raises(BundleExecutionError, match="timed out"):
        executor(evaluator, tmp_path, {})


def test_independent_bundle_executor_supports_archive_bundle(tmp_path: Path) -> None:
    evaluator = _write_bundle(tmp_path, "evaluator", _PASS.replace("KIND", "evaluator"))
    archive = tmp_path / "evaluator.zip"

    with zipfile.ZipFile(archive, "w") as output:
        for path in evaluator.rglob("*"):
            if path.is_file():
                relative = str(path.relative_to(evaluator))
                info = zipfile.ZipInfo(relative)
                info.create_system = 3
                info.external_attr = (0o755 if path.name == "evaluate" else 0o644) << 16
                output.writestr(info, path.read_bytes())
    oracle = _write_bundle(tmp_path, "oracle", _PASS.replace("KIND", "oracle"))
    executor = IndependentBundleExecutor(evaluator_bundle=archive, oracle_bundle=oracle)

    verdict = executor(archive, tmp_path, {"status": "public"})

    assert verdict == {"schema_version": "2.0.0", "kind": "evaluator", "status": "passed", "outcome": {}}
