from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "docker/adapter/baseline_driver.py"


def _module():
    spec = importlib.util.spec_from_file_location("baseline_driver_test", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_hacksynth_dispatches_with_writable_run_directory(tmp_path, monkeypatch) -> None:
    module = _module()
    source = tmp_path / "source"
    source.mkdir()
    run_dir = tmp_path / "output"
    invocation = run_dir / "public-invocation.json"
    run_dir.mkdir()
    invocation.write_text(
        json.dumps({
            "case_id": "case-1", "model_label": "model-1",
            "task": {
                "objective": "probe", "target": {"host": "127.0.0.1", "exposed_ports": [9090],
                "url": "http://127.0.0.1:9090"},
                "scope": {"allowed_ports": [9090]},
            },
        }),
        encoding="utf-8",
    )
    calls: list[tuple[tuple[str, ...], Path, dict[str, str]]] = []

    def fake_run(command, *, cwd, env, check):
        calls.append((command, cwd, env))
        return SimpleNamespace(returncode=0)

    monkeypatch.setenv("VERIPLANPT_FRAMEWORK_NAME", "HackSynth")
    monkeypatch.setenv("VERIPLANPT_RUN_DIR", str(run_dir))
    monkeypatch.setenv("VERIPLANPT_SOURCE_DIR", str(source))
    monkeypatch.setenv("VERIPLANPT_PUBLIC_INVOCATION_FILE", str(invocation))
    monkeypatch.setattr(module.subprocess, "run", fake_run)

    assert module.main() == 0
    assert len(calls) == 1
    command, cwd, env = calls[0]
    assert command[1] == "/opt/adapter/baseline_client_driver.py"
    assert cwd == run_dir
    assert env["PYTHONPATH"].split(":", 1)[0] == str(source)
    assert (run_dir / "hacksynth-benchmark.json").is_file()
    assert (run_dir / "hacksynth-config.json").is_file()


def test_pentestagent_commands_are_source_absolute() -> None:
    module = _module()
    assert module._framework.__name__ == "_framework"
