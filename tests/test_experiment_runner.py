from __future__ import annotations

import threading

from src.pipeline.experiment_runner import BillingUnknownError, CellResult, ExperimentRunner


def _plan() -> dict:
    return {
        "cell_count": 2,
        "cells": [
            {"run_id": "run-a", "estimated_cost_usd": 0.01},
            {"run_id": "run-b", "estimated_cost_usd": 0.01},
        ],
    }


def test_runner_retries_only_unbilled_infrastructure_failure(tmp_path) -> None:
    runner = ExperimentRunner(artifact_root=tmp_path)
    runner.register_plan(_plan())
    claimed = runner._claim("worker", 1.0)
    assert claimed is not None
    runner._finish("run-a", CellResult("infrastructure_failure", billable_model_response=False, retryable=True), "hash-a")
    assert runner.status()["states"] == {"pending": 2}

    claimed = runner._claim("worker", 1.0)
    assert claimed is not None
    runner._finish("run-a", CellResult("infrastructure_failure", billable_model_response=True), "hash-b")
    assert runner.status()["states"]["infrastructure_failure"] == 1
    runner.close()


def test_runner_rejects_duplicate_run_ids(tmp_path) -> None:
    runner = ExperimentRunner(artifact_root=tmp_path)
    bad = {"cell_count": 2, "cells": [{"run_id": "same"}, {"run_id": "same"}]}
    try:
        runner.register_plan(bad)
    except ValueError as exc:
        assert "unique run_id" in str(exc)
    else:
        raise AssertionError("duplicate plan was accepted")
    finally:
        runner.close()


def test_two_connections_claim_distinct_cells_atomically(tmp_path) -> None:
    runner = ExperimentRunner(artifact_root=tmp_path, workers=2)
    runner.register_plan({
        "cells": [
            {"run_id": f"run-{index}", "cell_worst_case_cost_usd": 0.1}
            for index in range(2)
        ]
    })
    connections = [runner._connect(), runner._connect()]
    barrier = threading.Barrier(2)
    claimed: list[str] = []

    def claim(index: int) -> None:
        barrier.wait()
        row = runner._claim(
            f"worker-{index}", 1.0, connection=connections[index]
        )
        assert row is not None
        claimed.append(str(row["run_id"]))

    threads = [threading.Thread(target=claim, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert set(claimed) == {"run-0", "run-1"}
    assert runner.status()["states"] == {"running": 2}
    for connection in connections:
        connection.close()
    runner.close()


def test_expired_lease_is_reclaimed_and_gets_new_attempt(tmp_path) -> None:
    runner = ExperimentRunner(artifact_root=tmp_path)
    runner.register_plan({"cells": [{"run_id": "run-a", "cell_worst_case_cost_usd": 0.1}]})
    first = runner._claim("worker-1", 1.0, lease_seconds=-1)
    assert first is not None
    second = runner._claim("worker-2", 1.0)
    assert second is not None
    assert second["attempts"] == 2
    runner.close()


def test_ceiling_reservation_blocks_second_worker_until_release(tmp_path) -> None:
    runner = ExperimentRunner(artifact_root=tmp_path)
    runner.register_plan({
        "cells": [
            {"run_id": "run-a", "cell_worst_case_cost_usd": 0.6},
            {"run_id": "run-b", "cell_worst_case_cost_usd": 0.6},
        ]
    })
    first = runner._claim("worker-1", 1.0)
    assert first is not None
    assert runner._claim("worker-2", 1.0) is None
    runner._finish("run-a", CellResult("completed", cost_usd=0.2), "hash-a")
    second = runner._claim("worker-2", 1.0)
    assert second is not None
    runner.close()


def test_retry_preserves_attempt_artifacts_and_cleanup_evidence(tmp_path, monkeypatch) -> None:
    runner = ExperimentRunner(artifact_root=tmp_path)
    runner.register_plan({"cells": [{"run_id": "run-a", "cell_worst_case_cost_usd": 0.1}]})
    cleanup_calls: list[tuple[str, str]] = []

    def cleanup(run_id: str, *, stage: str = "") -> dict:
        cleanup_calls.append((run_id, stage))
        return {"run_id": run_id, "stage": stage, "success": True}

    monkeypatch.setattr(runner, "cleanup_labeled_docker_resources", cleanup)
    first = runner._claim("worker-1", 1.0)
    assert first is not None
    runner._execute_claim(
        claimed=first,
        executor=lambda _cell, _path, _labels: CellResult("infrastructure_failure", retryable=True),
        labels={"veriplanpt.run_id": "run-a"},
        stage="smoke",
        connection=runner.db,
    )
    second = runner._claim("worker-2", 1.0)
    assert second is not None
    runner._execute_claim(
        claimed=second,
        executor=lambda _cell, _path, _labels: CellResult("completed"),
        labels={"veriplanpt.run_id": "run-a"},
        stage="smoke",
        connection=runner.db,
    )
    assert (tmp_path / "runs/smoke/run-a/attempt-01/cleanup.json").is_file()
    assert (tmp_path / "runs/smoke/run-a/attempt-02/cleanup.json").is_file()
    assert cleanup_calls == [("run-a", "smoke"), ("run-a", "smoke")]
    runner.close()


def test_unknown_billing_halts_without_retry(tmp_path, monkeypatch) -> None:
    runner = ExperimentRunner(artifact_root=tmp_path)
    runner.register_plan({"cells": [{"run_id": "run-a", "cell_worst_case_cost_usd": 0.1}]})
    monkeypatch.setattr(
        runner,
        "cleanup_labeled_docker_resources",
        lambda run_id, *, stage="": {"run_id": run_id, "stage": stage, "success": True},
    )
    claimed = runner._claim("worker", 1.0)
    assert claimed is not None

    def executor(_cell, _path, _labels):
        raise BillingUnknownError("response returned before billing metadata")

    runner._execute_claim(
        claimed=claimed,
        executor=executor,
        labels={},
        stage="sweep",
        connection=runner.db,
    )
    status = runner.status()
    assert status["states"] == {"billing_unknown": 1}
    assert status["halt_reason"] == "billing_unknown"
    assert (tmp_path / "runs/sweep/run-a/attempt-01/coordinator-error.json").is_file()
    runner.close()


def test_stage_health_halts_expired_approval_and_invalid_credentials(tmp_path) -> None:
    runner = ExperimentRunner(artifact_root=tmp_path)
    runner.register_plan({"cells": [{"run_id": "run-a", "cell_worst_case_cost_usd": 0.1}]})
    connection = runner._connect()
    assert not runner._stage_health(
        expires_at="2000-01-01T00:00:00Z",
        credential_validator=lambda: True,
        connection=connection,
    )
    assert runner.status()["halt_reason"] == "approval_expired"
    connection.close()
    runner.close()


def test_execute_two_subsets_share_full_plan_reservation(tmp_path, monkeypatch) -> None:
    import src.pipeline.experiment_runner as coordinator

    plan = {"cell_count": 18, "cells": [
        {"run_id": f"canary-{index}", "cell_worst_case_cost_usd": 0.01}
        for index in range(3)
    ] + [
        {"run_id": f"smoke-{index}", "cell_worst_case_cost_usd": 0.01}
        for index in range(15)
    ]}
    monkeypatch.setattr(coordinator, "verify_approval", lambda *_args, **_kwargs: {
        "cost_ceiling_usd": 1.0, "expires_at": "2099-01-01T00:00:00Z",
    })
    runner = ExperimentRunner(artifact_root=tmp_path, workers=2)
    monkeypatch.setattr(runner, "cleanup_labeled_docker_resources", lambda run_id, *, stage="": {
        "run_id": run_id, "stage": stage, "success": True, "resources": {},
    })
    calls: list[str] = []

    def execute(cell, _path, _labels):
        calls.append(cell["run_id"])
        return CellResult("completed", cost_usd=0.005)

    approval = {"cost_ceiling_usd": 1.0}
    canary_ids = {f"canary-{index}" for index in range(3)}
    first = runner.execute(plan=plan, approval=approval, signature_path=tmp_path / "sig", stage="canary_smoke", public_key="key", executor=execute, eligible_run_ids=canary_ids)
    assert not first["halted"] and first["completed"] == 3 and first["selected"] == 3
    assert set(calls) == canary_ids
    smoke_ids = {f"smoke-{index}" for index in range(15)}
    second = runner.execute(plan=plan, approval=approval, signature_path=tmp_path / "sig", stage="canary_smoke", public_key="key", executor=execute, eligible_run_ids=smoke_ids)
    assert not second["halted"] and second["completed"] == 15 and second["selected"] == 15
    assert runner.status()["states"] == {"completed": 18}
    assert runner.status()["accumulated_cost_usd"] == 0.09
    runner.close()
