"""
Project Sentinel — Trust Scoring Evaluation Suite
===================================================
Metrics evaluated:
  TRUST-01  Weighted score calculation accuracy
  TRUST-02  Component clamping (0-1 boundary enforcement)
  TRUST-03  Default weight distribution sums to 1.0
  TRUST-04  Custom weight injection
  TRUST-05  Grade thresholds (A/B/C/D/E mapping)
  TRUST-06  Risk level classification
  TRUST-07  Trust decay model logistic curve
  TRUST-08  Penalty application reduces trust ceiling
  TRUST-09  Decay rate escalation after breach
  TRUST-10  Trust history accumulation
  TRUST-11  Perfect-score scenario produces A grade
  TRUST-12  Zero-score scenario produces E grade
  TRUST-13  Adversarial resistance inversion (threat_level → resistance)
  TRUST-14  Behavioral stability inversion (drift severity → stability)
"""

import time
import math
import pytest

from aintegrity.modules.trust_grader import TrustDecayModel, TrustGradingEngineV4


# ── TRUST-01: Weighted score calculation ──────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.trust
class TestWeightedScoreCalculation:
    """Verify that weighted trust scores are mathematically correct."""

    def test_perfect_inputs_yield_score_one(self, trust_engine):
        """All components at 1.0 should produce overall_score ≈ 1.0."""
        results = {
            "logical_analysis": {"consistency_score": 1.0},
            "citation_analysis": {"verifiability_score": 1.0},
            "visual_consistency": {"consistency_score": 1.0},
            "session_drift": {"max_severity": 0.0},
            "adversarial_threat": {"threat_level": 0.0},
        }
        score = trust_engine.calculate_trust_score(results)
        assert score["overall_score_instantaneous"] == pytest.approx(1.0, abs=1e-6)

    def test_zero_inputs_yield_score_zero(self, trust_engine):
        """All components at worst should produce overall_score ≈ 0.0."""
        results = {
            "logical_analysis": {"consistency_score": 0.0},
            "citation_analysis": {"verifiability_score": 0.0},
            "visual_consistency": {"consistency_score": 0.0},
            "session_drift": {"max_severity": 1.0},
            "adversarial_threat": {"threat_level": 1.0},
        }
        score = trust_engine.calculate_trust_score(results)
        assert score["overall_score_instantaneous"] == pytest.approx(0.0, abs=1e-6)

    def test_half_inputs_yield_half_score(self, trust_engine):
        """All components at 0.5 should produce overall_score ≈ 0.5."""
        results = {
            "logical_analysis": {"consistency_score": 0.5},
            "citation_analysis": {"verifiability_score": 0.5},
            "visual_consistency": {"consistency_score": 0.5},
            "session_drift": {"max_severity": 0.5},
            "adversarial_threat": {"threat_level": 0.5},
        }
        score = trust_engine.calculate_trust_score(results)
        assert score["overall_score_instantaneous"] == pytest.approx(0.5, abs=1e-6)

    def test_manual_weighted_calculation(self, trust_engine):
        """Manually verify the weighted sum against known component values."""
        results = {
            "logical_analysis": {"consistency_score": 0.8},
            "citation_analysis": {"verifiability_score": 0.6},
            "visual_consistency": {"consistency_score": 0.9},
            "session_drift": {"max_severity": 0.2},    # stability = 0.8
            "adversarial_threat": {"threat_level": 0.1},  # resistance = 0.9
        }
        score = trust_engine.calculate_trust_score(results)

        expected = (
            0.25 * 0.8 +   # logical_consistency
            0.20 * 0.6 +   # factual_accuracy
            0.15 * 0.9 +   # visual_consistency
            0.20 * 0.8 +   # behavioral_stability (1 - 0.2)
            0.20 * 0.9     # adversarial_resistance (1 - 0.1)
        )
        assert score["overall_score_instantaneous"] == pytest.approx(expected, abs=1e-6)


# ── TRUST-02: Component clamping ──────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.trust
class TestComponentClamping:
    """Components must be clamped to [0, 1]."""

    def test_negative_scores_clamped_to_zero(self, trust_engine):
        results = {
            "logical_analysis": {"consistency_score": -0.5},
            "session_drift": {"max_severity": 2.0},  # stability = -1.0 → clamped
        }
        score = trust_engine.calculate_trust_score(results)
        components = score["components"]
        assert all(0.0 <= v <= 1.0 for v in components.values())

    def test_excessive_scores_clamped_to_one(self, trust_engine):
        results = {
            "logical_analysis": {"consistency_score": 5.0},
        }
        score = trust_engine.calculate_trust_score(results)
        assert score["components"]["logical_consistency"] == 1.0


# ── TRUST-03 / TRUST-04: Weight distribution ─────────────────────────────

@pytest.mark.sentinel
@pytest.mark.trust
class TestWeightDistribution:

    def test_default_weights_sum_to_one(self):
        assert sum(TrustGradingEngineV4.DEFAULT_WEIGHTS.values()) == pytest.approx(1.0)

    def test_custom_weights_applied(self):
        custom = {
            "logical_consistency": 0.5,
            "factual_accuracy": 0.1,
            "visual_consistency": 0.1,
            "behavioral_stability": 0.1,
            "adversarial_resistance": 0.2,
        }
        engine = TrustGradingEngineV4(agent_id="custom", initial_weights=custom)
        assert engine.weights == custom


# ── TRUST-05: Grade thresholds ────────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.trust
class TestGradeThresholds:

    @pytest.mark.parametrize("score,expected_grade", [
        (95, "A"), (80, "A"),
        (79, "B"), (60, "B"),
        (59, "C"), (40, "C"),
        (39, "D"), (20, "D"),
        (19, "E"), (0, "E"),
    ])
    def test_grade_boundaries(self, trust_engine, score, expected_grade):
        assert trust_engine.get_grade(score) == expected_grade


# ── TRUST-06: Risk level classification ───────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.trust
class TestRiskLevel:

    def test_critical_on_disproven_source(self, trust_engine):
        assert trust_engine.get_risk_level(score=90, disproven_count=1) == "critical"

    def test_critical_on_multiple_deceptions(self, trust_engine):
        assert trust_engine.get_risk_level(score=90, deception_count=2) == "critical"

    def test_critical_on_many_critical_findings(self, trust_engine):
        assert trust_engine.get_risk_level(score=90, critical_count=3) == "critical"

    def test_high_on_single_deception(self, trust_engine):
        assert trust_engine.get_risk_level(score=90, deception_count=1) == "high"

    def test_medium_on_low_score(self, trust_engine):
        assert trust_engine.get_risk_level(score=40) == "medium"

    def test_low_on_moderate_score(self, trust_engine):
        assert trust_engine.get_risk_level(score=65) == "low"

    def test_minimal_on_high_score_no_findings(self, trust_engine):
        assert trust_engine.get_risk_level(score=85) == "minimal"


# ── TRUST-07: Trust decay model logistic curve ────────────────────────────

@pytest.mark.sentinel
@pytest.mark.trust
class TestTrustDecayModel:

    def test_initial_score_near_max(self, decay_model):
        """Immediately after creation, score should be near t_max."""
        score = decay_model.get_current_score()
        # With default k=0.01, t_mid=30d, at t≈0 the exponent is very negative
        # so denominator ≈ 0+, score ≈ t_min + (t_max - t_min)/1 ≈ t_max
        assert score >= 0.95

    def test_score_bounded_by_min(self, decay_model):
        """Score must never drop below t_min."""
        decay_model.t_max = 0.0  # Force worst case
        assert decay_model.get_current_score() >= decay_model.t_min

    def test_update_score_clamps_to_unit(self, decay_model):
        decay_model.update_score(2.0)
        assert decay_model.t_max == 1.0
        decay_model.update_score(-1.0)
        assert decay_model.t_max == 0.0

    def test_state_dict_keys(self, decay_model):
        state = decay_model.get_state()
        expected_keys = {"t_max", "t_min", "decay_rate", "midpoint_seconds", "last_update", "current_score"}
        assert set(state.keys()) == expected_keys


# ── TRUST-08: Penalty application ─────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.trust
class TestPenaltyApplication:

    def test_penalty_reduces_t_max(self, decay_model):
        original = decay_model.t_max
        decay_model.apply_penalty(0.3)
        assert decay_model.t_max == pytest.approx(original - 0.3)

    def test_penalty_cannot_go_below_t_min(self, decay_model):
        decay_model.apply_penalty(5.0)
        assert decay_model.t_max >= decay_model.t_min


# ── TRUST-09: Decay rate escalation ──────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.trust
class TestDecayRateEscalation:

    def test_increase_decay_rate(self, decay_model):
        original_k = decay_model.k
        decay_model.increase_decay_rate(2.0)
        assert decay_model.k == pytest.approx(original_k * 2.0)

    def test_event_penalty_escalates_on_deception(self, trust_engine):
        original_k = trust_engine.decay_model.k
        trust_engine.apply_event_penalty("deception_proven", severity=0.1)
        assert trust_engine.decay_model.k > original_k


# ── TRUST-10: History accumulation ────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.trust
class TestHistoryAccumulation:

    def test_history_grows_with_calculations(self, trust_engine):
        results = {"logical_analysis": {"consistency_score": 0.8}}
        trust_engine.calculate_trust_score(results)
        trust_engine.calculate_trust_score(results)
        assert len(trust_engine.history) == 2

    def test_history_records_contain_timestamps(self, trust_engine):
        results = {"logical_analysis": {"consistency_score": 0.8}}
        trust_engine.calculate_trust_score(results)
        assert "calculation_timestamp_utc" in trust_engine.history[0]


# ── TRUST-11/12: Extreme scenarios ────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.trust
class TestExtremeScenarios:

    def test_perfect_scenario_grade_a(self, trust_engine):
        results = {
            "logical_analysis": {"consistency_score": 1.0},
            "citation_analysis": {"verifiability_score": 1.0},
            "visual_consistency": {"consistency_score": 1.0},
            "session_drift": {"max_severity": 0.0},
            "adversarial_threat": {"threat_level": 0.0},
        }
        score = trust_engine.calculate_trust_score(results)
        grade = trust_engine.get_grade(score["overall_score_instantaneous"] * 100)
        assert grade == "A"

    def test_worst_scenario_grade_e(self, trust_engine):
        results = {
            "logical_analysis": {"consistency_score": 0.0},
            "citation_analysis": {"verifiability_score": 0.0},
            "visual_consistency": {"consistency_score": 0.0},
            "session_drift": {"max_severity": 1.0},
            "adversarial_threat": {"threat_level": 1.0},
        }
        score = trust_engine.calculate_trust_score(results)
        grade = trust_engine.get_grade(score["overall_score_instantaneous"] * 100)
        assert grade == "E"


# ── TRUST-13/14: Inversion metrics ───────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.trust
class TestInversionMetrics:

    def test_adversarial_resistance_inverts_threat(self, trust_engine):
        """adversarial_resistance = 1.0 - threat_level."""
        results = {"adversarial_threat": {"threat_level": 0.7}}
        score = trust_engine.calculate_trust_score(results)
        assert score["components"]["adversarial_resistance"] == pytest.approx(0.3, abs=1e-6)

    def test_behavioral_stability_inverts_drift(self, trust_engine):
        """behavioral_stability = 1.0 - max_severity."""
        results = {"session_drift": {"max_severity": 0.4}}
        score = trust_engine.calculate_trust_score(results)
        assert score["components"]["behavioral_stability"] == pytest.approx(0.6, abs=1e-6)

    def test_missing_components_default_to_best(self, trust_engine):
        """Missing analysis keys should default to best-case (1.0)."""
        results = {}
        score = trust_engine.calculate_trust_score(results)
        assert score["components"]["logical_consistency"] == 1.0
        assert score["components"]["factual_accuracy"] == 1.0
        assert score["components"]["visual_consistency"] == 1.0
        assert score["components"]["behavioral_stability"] == 1.0
        assert score["components"]["adversarial_resistance"] == 1.0
