"""
tests/test_veriplanpt_core.py
──────────────────────────────
Unit tests for VeriPlanPT core additions:
  - BudgetTier enum and ResourceBudget singleton restore
  - DifficultyEstimator
  - BudgetPolicy
  - LedgerMetrics (offline computation)
  - FrameworkAdapter schema types
"""

from __future__ import annotations

import pytest

# ── BudgetTier & ResourceBudget ────────────────────────────────────────────────

class TestBudgetTier:
    def test_all_tiers_produce_valid_limits(self):
        from src.pipeline.budget import BudgetTier
        for tier in BudgetTier:
            lim = tier.to_limits()
            assert lim.max_runtime_seconds > 0
            assert lim.max_tool_calls > 0
            assert lim.max_total_tokens > 0
            assert lim.max_llm_calls > 0

    def test_tier_ordering(self):
        from src.pipeline.budget import BudgetTier
        low = BudgetTier.LOW.to_limits()
        med = BudgetTier.MEDIUM.to_limits()
        high = BudgetTier.HIGH.to_limits()
        assert low.max_total_tokens < med.max_total_tokens < high.max_total_tokens
        assert low.max_tool_calls < med.max_tool_calls < high.max_tool_calls

    def test_from_str_valid(self):
        from src.pipeline.budget import BudgetTier
        assert BudgetTier.from_str("low") == BudgetTier.LOW
        assert BudgetTier.from_str("HIGH") == BudgetTier.HIGH
        assert BudgetTier.from_str("Medium") == BudgetTier.MEDIUM

    def test_from_str_invalid_raises(self):
        from src.pipeline.budget import BudgetTier
        with pytest.raises(ValueError, match="unknown budget tier"):
            BudgetTier.from_str("nonexistent")

    def test_budget_exceeded_on_token_cap(self):
        from src.pipeline.budget import BudgetExceeded, BudgetTier, ResourceBudget
        tier = BudgetTier.LOW
        lim = tier.to_limits()
        budget = ResourceBudget(lim)
        # Exhaust token budget
        with pytest.raises(BudgetExceeded) as exc_info:
            budget.record_llm_usage(input_tokens=lim.max_total_tokens + 1)
        assert "max_total_tokens" in str(exc_info.value)

    def test_budget_exceeded_on_llm_call_cap(self):
        from src.pipeline.budget import BudgetExceeded, BudgetTier, ResourceBudget
        tier = BudgetTier.LOW
        lim = tier.to_limits()
        budget = ResourceBudget(lim)
        # Use up LLM call limit
        for _ in range(lim.max_llm_calls):
            budget.record_llm_usage(input_tokens=1)
        with pytest.raises(BudgetExceeded) as exc_info:
            budget.record_llm_usage(input_tokens=1)
        assert "max_llm_calls" in str(exc_info.value)

    def test_budget_singleton_restore(self):
        """B1: BudgetState restored from dict must accumulate correctly."""
        from src.pipeline.budget import BudgetTier, ResourceBudget
        tier = BudgetTier.MEDIUM
        lim = tier.to_limits()
        b1 = ResourceBudget(lim)
        b1.record_llm_usage(input_tokens=500, output_tokens=100, usd=0.01)
        b1.record_tool_call()
        b1.record_command()

        # Serialize and restore
        state_dict = b1.state_to_dict()
        b2 = ResourceBudget.restore(lim, state_dict)

        # b2 should have the same state as b1
        assert b2.state.total_input_tokens == 500
        assert b2.state.total_output_tokens == 100
        assert b2.state.total_usd == pytest.approx(0.01)
        assert b2.state.tool_calls == 1
        assert b2.state.executed_commands == 1
        assert b2.state.llm_calls == 1

        # Further accumulation in b2 stacks on top
        b2.record_llm_usage(input_tokens=200)
        assert b2.state.total_input_tokens == 700
        assert b2.state.llm_calls == 2

    def test_total_tokens_property(self):
        from src.pipeline.budget import BudgetTier, ResourceBudget
        b = ResourceBudget(BudgetTier.MEDIUM.to_limits())
        b.record_llm_usage(input_tokens=100, cached_input_tokens=50,
                           output_tokens=200, thinking_tokens=30)
        assert b.state.total_tokens == 330


# ── DifficultyEstimator ───────────────────────────────────────────────────────

class TestDifficultyEstimator:
    def test_score_bounds(self):
        from src.planning.difficulty import DifficultyEstimator
        e = DifficultyEstimator()
        v = e.estimate(remaining_steps=30, max_steps=60,
                       mean_evidence_confidence=0.6,
                       token_fraction_used=0.3,
                       historical_success_rate=0.5)
        assert 0.0 <= v.difficulty_score <= 1.0

    def test_easy_scenario(self):
        """Many steps left, high confidence, low token use → low difficulty."""
        from src.planning.difficulty import DifficultyEstimator
        e = DifficultyEstimator()
        v = e.estimate(remaining_steps=59, max_steps=60,
                       mean_evidence_confidence=0.95,
                       token_fraction_used=0.05,
                       historical_success_rate=0.9)
        assert v.difficulty_score < 0.25

    def test_hard_scenario(self):
        """No steps left, no confidence, full token load → high difficulty."""
        from src.planning.difficulty import DifficultyEstimator
        e = DifficultyEstimator()
        v = e.estimate(remaining_steps=0, max_steps=60,
                       mean_evidence_confidence=0.0,
                       token_fraction_used=1.0,
                       historical_success_rate=0.0)
        assert v.difficulty_score >= 0.9

    def test_from_budget_state(self):
        from src.planning.difficulty import DifficultyEstimator
        state = {
            "tool_calls": 10, "executed_commands": 5,
            "total_input_tokens": 10000, "total_cached_input_tokens": 0,
            "total_output_tokens": 2000, "total_thinking_tokens": 500,
        }
        est, vec = DifficultyEstimator.from_budget_state(
            state, max_tool_calls=25, max_commands=20, max_tokens=100_000,
            mean_confidence=0.7, historical_success=0.5,
        )
        assert 0 <= vec.difficulty_score <= 1
        assert vec.context_load == pytest.approx(0.125)  # 12500/100000

    def test_custom_weights_sum_to_one(self):
        from src.planning.difficulty import DifficultyEstimator
        e = DifficultyEstimator(weights={"horizon_pressure": 1.0, "evidence_gap": 1.0,
                                         "context_load": 0.0, "historical_failure": 0.0})
        v = e.estimate(remaining_steps=60, max_steps=60,  # horizon_pressure=0
                       mean_evidence_confidence=0.0,       # evidence_gap=1
                       token_fraction_used=0.5,
                       historical_success_rate=0.5)
        # weights normalized: each 0.5; horizon_pressure=0*0.5 + evidence_gap=1*0.5 = 0.5
        assert v.difficulty_score == pytest.approx(0.5)

    def test_to_dict_keys(self):
        from src.planning.difficulty import DifficultyEstimator
        e = DifficultyEstimator()
        v = e.estimate(remaining_steps=10, max_steps=20,
                       mean_evidence_confidence=0.5,
                       token_fraction_used=0.5,
                       historical_success_rate=0.5)
        d = v.to_dict()
        assert set(d.keys()) == {
            "horizon_pressure", "evidence_gap", "context_load",
            "historical_failure", "difficulty_score"
        }


# ── BudgetPolicy ──────────────────────────────────────────────────────────────

class TestBudgetPolicy:
    def test_score_action(self):
        from src.planning.difficulty import DifficultyVector
        from src.planning.policy import BudgetPolicy
        p = BudgetPolicy()
        v = DifficultyVector(difficulty_score=0.3)
        a = p.score_action("c1", "host:80:apache", "CVE-2021-X", "metasploit",
                            p_success=0.8, expected_evidence_gain=0.6,
                            normalized_cost=0.2, risk=0.1, difficulty=v)
        assert a.candidate_id == "c1"
        assert isinstance(a.policy_score, float)

    def test_rank_actions_sorted(self):
        from src.planning.policy import BudgetPolicy, ScoredAction
        p = BudgetPolicy()
        actions = [
            ScoredAction("c1", "s", "CVE-A", "m", policy_score=0.1),
            ScoredAction("c2", "s", "CVE-B", "m", policy_score=0.9),
            ScoredAction("c3", "s", "CVE-C", "m", policy_score=0.5),
        ]
        ranked = p.rank_actions(actions)
        assert ranked[0].candidate_id == "c2"
        assert ranked[1].candidate_id == "c3"
        assert ranked[2].candidate_id == "c1"
        assert [a.rank for a in ranked] == [0, 1, 2]

    def test_service_rotation_threshold(self):
        from src.planning.policy import BudgetPolicy
        p = BudgetPolicy()
        # Two consecutive failures → rotate
        assert not p.should_rotate_service("svc1", produced_evidence=False)
        assert p.should_rotate_service("svc1", produced_evidence=False)

    def test_service_rotation_resets_on_evidence(self):
        from src.planning.policy import BudgetPolicy
        p = BudgetPolicy()
        p.should_rotate_service("svc1", produced_evidence=False)
        p.should_rotate_service("svc1", produced_evidence=True)  # reset
        assert not p.should_rotate_service("svc1", produced_evidence=False)

    def test_service_budget_cap_blocks_low_confidence(self):
        from src.planning.policy import BudgetPolicy
        p = BudgetPolicy()
        # 80% budget already used, confidence < 0.8 → block
        allowed = p.is_service_budget_allowed(
            "svc1",
            remaining_budget_tokens=20_000,
            max_budget_tokens=100_000,
            service_confidence=0.5,
            other_services_exhausted=False,
        )
        assert not allowed  # 1 - 20000/100000 = 0.8 > SERVICE_BUDGET_CAP(0.5)

    def test_service_budget_allowed_when_confident(self):
        from src.planning.policy import BudgetPolicy
        p = BudgetPolicy()
        allowed = p.is_service_budget_allowed(
            "svc1",
            remaining_budget_tokens=20_000,
            max_budget_tokens=100_000,
            service_confidence=0.85,  # >= CONFIDENCE_THRESHOLD
            other_services_exhausted=False,
        )
        assert allowed

    def test_service_budget_allowed_when_exhausted(self):
        from src.planning.policy import BudgetPolicy
        p = BudgetPolicy()
        allowed = p.is_service_budget_allowed(
            "svc1",
            remaining_budget_tokens=1_000,
            max_budget_tokens=100_000,
            service_confidence=0.1,
            other_services_exhausted=True,  # last resort
        )
        assert allowed


# ── LedgerMetrics ─────────────────────────────────────────────────────────────

class TestLedgerMetrics:
    def _make_ledger(self, run_id: str = "test-run"):
        """Build a simple EventLedger with some test events."""
        from src.pipeline.ledger import EventLedger
        ledger = EventLedger(run_id=run_id)
        return ledger

    def test_osr_zero_on_empty_ledger(self):
        from src.scoring.ledger_metrics import compute_metrics
        ledger = self._make_ledger()
        m = compute_metrics(ledger)
        assert m.osr == 0.0
        assert not m.task_proof_obtained

    def test_osr_one_on_task_proof_obtained(self):
        from src.scoring.ledger_metrics import compute_metrics
        ledger = self._make_ledger()
        ledger.record(phase="execution", stage="exploit", outcome="task_proof_obtained",
                      cve_id="CVE-2021-X", candidate_id="c1")
        m = compute_metrics(ledger)
        assert m.osr == 1.0
        assert m.task_proof_obtained is True

    def test_false_positive_on_control(self):
        from src.scoring.ledger_metrics import compute_metrics
        ledger = self._make_ledger()
        ledger.record(phase="execution", stage="exploit", outcome="task_proof_obtained",
                      cve_id="CVE-X", candidate_id="c1")
        m = compute_metrics(ledger, is_patched_control=True)
        assert m.false_positive_on_control is True
        assert m.osr == 0.0  # FP does not count

    def test_correct_cve_at_k(self):
        from src.scoring.ledger_metrics import compute_metrics
        ledger = self._make_ledger()
        ledger.record(phase="retrieve", stage="applicability", outcome="not_applicable",
                      cve_id="CVE-wrong-1", candidate_id="c0")
        ledger.record(phase="retrieve", stage="applicability", outcome="not_applicable",
                      cve_id="CVE-wrong-2", candidate_id="c0b")
        ledger.record(phase="execution", stage="exploit", outcome="vulnerability_confirmed",
                      cve_id="CVE-correct", candidate_id="c1")
        m = compute_metrics(ledger, applicable_cves=["CVE-correct"])
        assert m.correct_cve_at_1 is False   # first proposed was CVE-wrong-1
        assert m.correct_cve_at_3 is True    # correct appears at position 3

    def test_to_dict_has_all_keys(self):
        from src.scoring.ledger_metrics import compute_metrics
        ledger = self._make_ledger()
        m = compute_metrics(ledger)
        d = m.to_dict()
        required_keys = [
            "osr", "task_proof_obtained", "SSR_recon", "SSR_vuln",
            "SSR_exploit", "SSR_maintain", "total_tokens", "total_usd",
            "invalid_command_rate", "repeated_action_rate", "recovery_rate",
            "hallucination_total", "false_positive_on_control",
        ]
        for k in required_keys:
            assert k in d, f"Missing key: {k}"

    def test_hallucination_counting(self):
        from src.scoring.ledger_metrics import compute_metrics
        ledger = self._make_ledger()
        ledger.record(phase="execution", stage="run", outcome="execution_failed",
                      failure_class="command_invalid", detail="nonexistent option --foo")
        ledger.record(phase="execution", stage="run", outcome="execution_failed",
                      failure_class="fabricated_cve", detail="CVE not in snapshot")
        m = compute_metrics(ledger)
        assert m.hallucination.nonexistent_command >= 1
        assert m.hallucination.fabricated_cve >= 1
        assert m.hallucination.total >= 2


# ── FrameworkAdapter types ─────────────────────────────────────────────────────

class TestFrameworkAdapterTypes:
    @staticmethod
    def _model_profile(label="gemini-3.5-flash"):
        from src.pipeline.framework_adapter import ModelProfile
        return ModelProfile(
            model_name=label,
            project="vertex-project",
            location="us-central1",
            resource_id=f"publishers/google/models/{label}-endpoint",
            resource_revision=f"endpoints/{label}/deployedModels/20260801",
            pricing={
                "input_per_million": 1.0,
                "cached_input_per_million": 0.25,
                "output_per_million": 2.0,
                "thinking_per_million": 3.0,
            },
            generation_parameters={"temperature": 0.0},
            usage_semantics={"input_includes_cached": "true", "total_formula": "input+output+thinking"},
            pricing_effective_at="2026-08-02T00:00:00Z",
        )

    def test_model_profile_validates(self):
        mp = self._model_profile()
        assert mp.model_name == "gemini-3.5-flash"
        assert mp.resource_id != mp.model_name

    def test_model_profile_rejects_unknown(self):
        from src.pipeline.framework_adapter import ModelProfile
        with pytest.raises(ValueError, match="not in the preregistered set"):
            ModelProfile(
                model_name="gpt-4",
                project="vertex-project",
                location="us-central1",
                resource_id="publishers/openai/models/gpt-4",
                resource_revision="endpoints/gpt-4/deployedModels/20260801",
                pricing={
                    "input_per_million": 1.0,
                    "cached_input_per_million": 0.25,
                    "output_per_million": 2.0,
                    "thinking_per_million": 3.0,
                },
                generation_parameters={"temperature": 0.0},
                usage_semantics={"input_includes_cached": "true", "total_formula": "input+output+thinking"},
                pricing_effective_at="2026-08-02T00:00:00Z",
            )

    def test_public_task_roundtrip(self):
        from src.pipeline.framework_adapter import PublicTask
        t = PublicTask(case_id="vp-test-0001", track="blind",
                       objective="gain rce", host="10.0.0.1", port_range="80,443")
        d = t.to_dict()
        t2 = PublicTask.from_dict(d)
        assert t2.case_id == "vp-test-0001"
        assert t2.track == "blind"
        assert t2.host == "10.0.0.1"

    def test_public_task_guided_fields(self):
        from src.pipeline.framework_adapter import PublicTask
        t = PublicTask(case_id="vp-test-0002", track="guided",
                       objective="bypass auth", host="10.0.0.1", port_range="8080",
                       hints={"component": "MyApp", "endpoint": "/login", "method": "POST injection"})
        assert t.hints["component"] == "MyApp"
        assert t.hints["method"] == "POST injection"

    def test_budget_tier_in_adapter(self):
        from src.pipeline.framework_adapter import BudgetTier
        assert BudgetTier.MEDIUM.value == "medium"

    def test_run_artifact_to_dict(self):
        from src.pipeline.framework_adapter import BudgetTier, RunArtifact
        mp = self._model_profile("gemini-3.6-flash")
        ra = RunArtifact(case_id="CVE-X", repetition=1, track="blind",
                         model_profile=mp, budget_tier=BudgetTier.MEDIUM,
                         run_id="test-run", internal_outcome="no_truth")
        d = ra.to_dict()
        assert d["schema_version"] == "2.0.0"
        assert d["internal_outcome"] == "no_truth"
        assert d["termination_status"] == "no_truth"
        assert d["budget_tier"] == "medium"
        assert d["model_profile"]["model_name"] == "gemini-3.6-flash"
        assert d["model_revision"] == mp.resource_revision


# ── Fingerprint.service_key ────────────────────────────────────────────────────

class TestFingerprintServiceKey:
    def test_service_key_format(self):
        from src.pipeline.evidence import ServiceObservation, fingerprint_service
        obs = ServiceObservation(target_ip="192.168.1.10", port=443,
                                 service_name="nginx", banner="nginx/1.24.0")
        fp = fingerprint_service(obs)
        key = fp.service_key
        assert key.startswith("192.168.1.10:443:")
        assert ":" in key

    def test_service_key_stable(self):
        """Same observation produces same service_key."""
        from src.pipeline.evidence import ServiceObservation, fingerprint_service
        obs = ServiceObservation(target_ip="10.0.0.1", port=80,
                                 service_name="apache", banner="Apache/2.4.54")
        fp1 = fingerprint_service(obs)
        fp2 = fingerprint_service(obs)
        assert fp1.service_key == fp2.service_key


# ── no_truth ledger outcome ───────────────────────────────────────────────────

class TestNoTruthOutcome:
    def test_no_truth_is_allowed_outcome(self):
        from src.pipeline.ledger import ALLOWED_OUTCOMES
        assert "no_truth" in ALLOWED_OUTCOMES

    def test_no_truth_can_be_recorded(self):
        from src.pipeline.ledger import EventLedger
        ledger = EventLedger(run_id="t")
        ledger.record(phase="oracle", stage="eval", outcome="no_truth",
                      detail="no evaluator truth supplied")
        assert ledger.events[-1].outcome == "no_truth"
