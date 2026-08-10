from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from src.pipeline.runtime_contract import validate_gateway_relay_lock
from src.pipeline.runtime_topology import TopologyLifecycle, validate_runtime_topology_evidence


def _lock() -> dict:
    return {
        "schema_version": "1.0.0", "uid_policy": "host_euid_nonroot",
        "relay": {
            "image": "relay:locked", "image_digest": "sha256:" + "a" * 64,
            "alias": "gateway-relay", "endpoint": "http://gateway-relay:8080/v1/generate",
            "run_as": "host_uid_gid_nonroot",
            "recipe": {"path": "Dockerfile", "sha256": "b" * 64},
            "source": {"path": "relay.py", "sha256": "c" * 64},
        },
        "socket": {"path": "/run/veriplanpt-gateway/gateway.sock", "mode": "0600", "parent_mode": "0700", "mount_read_only": True},
        "network": {"mode": "internal", "alias": "gateway-relay"},
        "baseline_socket_mount": False, "baseline_credentials": False,
    }


class _Docker:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.inputs: list[bytes | None] = []

    def run(self, args, input_bytes=None):
        self.commands.append(list(args))
        self.inputs.append(input_bytes)
        if args[0] in {"container", "network"} and args[1] == "ls":
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 0, "relay-id\n", "")


def test_topology_is_internal_readonly_and_label_owned(tmp_path: Path) -> None:
    lock = _lock()
    validate_gateway_relay_lock(lock)
    docker = _Docker()
    lifecycle = TopologyLifecycle(
        artifact_root=tmp_path, relay_lock={**lock, "lock_hash": "d" * 64},
        relay_image="relay:locked", docker=docker, host_uid=1000, host_gid=1000,
    )
    handle = lifecycle.start(phase="canary", run_ids={"canary-a"})
    evidence = lifecycle.shutdown(handle)
    assert evidence["success"] is True
    network = docker.commands[0]
    relay = docker.commands[1]
    assert "--internal" in network
    assert "--read-only" in relay
    assert "--network-alias" in relay and "gateway-relay" in relay
    assert "readonly" in " ".join(relay)
    assert not list((tmp_path / "runtime-sockets").glob("*/gateway.sock"))


def test_topology_evidence_rejects_failed_phase() -> None:
    try:
        validate_runtime_topology_evidence({"schema_version": "1.0.0", "success": False, "phases": []})
    except ValueError as exc:
        assert "success" in str(exc)
    else:
        raise AssertionError("failed topology evidence was accepted")


def test_baseline_receives_only_public_stdin_and_output_mount(tmp_path: Path) -> None:
    docker = _Docker()
    lifecycle = TopologyLifecycle(
        artifact_root=tmp_path, relay_lock={**_lock(), "lock_hash": "d" * 64},
        relay_image="relay:locked", docker=docker, host_uid=1000, host_gid=1000,
    )
    handle = lifecycle.start(phase="smoke", run_ids={"smoke-a"}, gateway_token="token", token_expires_at="2999-01-01T00:00:00Z")
    output = tmp_path / "output"
    output.mkdir()
    environment = lifecycle.runtime_environment(
        handle, run_id="smoke-a", model_label="gemini-3.5-flash", profile_hash="e" * 64,
    )
    lifecycle.run_baseline(
        handle, run_id="smoke-a", image="sha256:" + "f" * 64,
        command=("/runner/run",), environment=environment,
        public_payload=b"{}", output_dir=output,
    )
    command = docker.commands[-1]
    assert "--rm" in command and "--read-only" in command
    assert "--interactive" in command
    assert "--tty" not in command
    assert command[command.index("--user") + 1] == "1000:1000"
    mount = command[command.index("--mount") + 1]
    assert mount == f"type=bind,src={output.resolve()},dst=/run/veriplanpt/output"
    assert docker.inputs[-1] == b"{}"
    lifecycle.shutdown(handle)


def test_baseline_backend_without_stdin_fails_closed(tmp_path: Path) -> None:
    class NoStdinDocker(_Docker):
        def run(self, args):  # type: ignore[no-untyped-def]
            return super().run(args)

    docker = NoStdinDocker()
    lifecycle = TopologyLifecycle(
        artifact_root=tmp_path, relay_lock={**_lock(), "lock_hash": "d" * 64},
        relay_image="relay:locked", docker=docker, host_uid=1000, host_gid=1000,
    )
    handle = lifecycle.start(phase="smoke", run_ids={"smoke-a"}, gateway_token="token", token_expires_at="2999-01-01T00:00:00Z")
    output = tmp_path / "output"
    output.mkdir()
    environment = lifecycle.runtime_environment(
        handle, run_id="smoke-a", model_label="gemini-3.5-flash", profile_hash="e" * 64,
    )
    with pytest.raises(TypeError):
        lifecycle.run_baseline(
            handle, run_id="smoke-a", image="sha256:" + "f" * 64,
            command=("/runner/run",), environment=environment,
            public_payload=b"{}", output_dir=output,
        )
    lifecycle.shutdown(handle)


def test_output_mount_is_accepted_by_docker(tmp_path: Path) -> None:
    image = "veriplanpt/veriplanpt:locked"
    available = subprocess.run(
        ["docker", "image", "inspect", image], capture_output=True, text=True, check=False,
    )
    if available.returncode != 0:
        pytest.skip(f"locked runtime image is unavailable: {available.stderr.strip()}")
    output = tmp_path / "output"
    output.mkdir()
    result = subprocess.run(
        [
            "docker", "run", "--rm", "--interactive", "--network", "none",
            "--mount", f"type=bind,src={output.resolve()},dst=/run/veriplanpt/output",
            "--entrypoint", "/bin/true", image,
        ],
        input=b"{}", capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
