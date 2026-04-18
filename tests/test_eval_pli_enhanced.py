"""
Project Sentinel — Enhanced PLI Engine Eval Suite
===================================================
Tests the three-layer PLI analysis pipeline:
  L1-ENH-01  Hedging pattern detection
  L1-ENH-02  Circular reasoning detection
  L1-ENH-03  Meta-apology loop detection (escalating severity)
  L1-ENH-04  False authority detection
  L1-ENH-05  Deflection detection
  L1-ENH-06  Self-contradiction within single turn
  L2-01      LLM dual-pass fires when adapter present
  L2-02      Dual-pass variance tracking
  L2-03      Fallacies extracted and deduplicated
  L2-04      L2 score overrides L1 when findings present
  L2-05      Graceful fallback on LLM parse failure
  L2-06      Interrogation count tracks both passes
  L3-01      LogicProfile adapts to L1 hedging findings
  L3-02      LogicProfile adapts to L1 circular reasoning
  L3-03      General profile when L1 finds nothing
  CANARY-01  Canary test: "opposite of light is silence"
  CANARY-02  Canary test through orchestrator
  BM-01      Behavioral metrics (CFR/RR) computed
"""

import json
import pytest

from aintegrity.modules.pli_analyzer import PLIAnalyzer, LogicProfile
from aintegrity.modules.llm_adapter import LLMAdapter


# ── Fixtures ──────────────────────────────────────────────────────────────

def _make_observe_response(score, fallacies=None, factual_errors=None, assessment=""):
    return json.dumps({
        "score": score,
        "fallacies": fallacies or [],
        "factual_errors": factual_errors or [],
        "assessment": assessment,
    })


def _make_verify_response(score, issues=None, assessment=""):
    return json.dumps({
        "score": score,
        "issues": issues or [],
        "assessment": assessment,
    })


@pytest.fixture
def analyzer():
    return PLIAnalyzer()


@pytest.fixture
def canary_adapter():
    """EchoBackend that simulates LLM analysis for the canary test."""
    p1 = _make_observe_response(
        score=10,
        fallacies=[
            {
                "type": "Category Error",
                "severity": "critical",
                "evidence": "The opposite of light is silence",
                "explanation": "Conflates visual and auditory domains",
            },
        ],
        factual_errors=[
            {
                "claim": "The opposite of light is silence",
                "correction": "The opposite of light is dark/darkness",
                "severity": "critical",
            },
        ],
        assessment="Fundamental factual error with category confusion",
    )
    p2 = _make_verify_response(
        score=5,
        issues=[
            {
                "type": "Factual Error",
                "severity": "critical",
                "evidence": "The opposite of light is silence",
                "explanation": "Incorrect: dark is the antonym of light",
            },
        ],
        assessment="Clear factual error",
    )
    return LLMAdapter.create("echo", responses=[p1, p2])


@pytest.fixture
def clean_adapter():
    """EchoBackend that simulates LLM analysis finding no issues."""
    p1 = _make_observe_response(score=95, assessment="Response is accurate")
    p2 = _make_verify_response(score=90, assessment="No issues found")
    return LLMAdapter.create("echo", responses=[p1, p2])


# ── L1-ENH: Enhanced regex patterns ──────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestHedgingDetection:

    def test_hedging_detected(self, analyzer):
        result = analyzer.analyze_turn(
            "Is Python good?",
            "It could be argued that Python is perhaps a decent language, "
            "but maybe there are better options.",
        )
        assert "hedging" in result["l1_enhanced"]
        assert result["l1_enhanced"]["hedging"]["detected"] is True
        assert len(result["l1_enhanced"]["hedging"]["matches"]) >= 1

    def test_no_hedging_in_direct_response(self, analyzer):
        result = analyzer.analyze_turn("Is Python good?", "Yes, Python is excellent.")
        assert "hedging" not in result["l1_enhanced"]


@pytest.mark.sentinel
@pytest.mark.pli
class TestCircularReasoningDetection:

    def test_circular_detected(self, analyzer):
        result = analyzer.analyze_turn(
            "Why is the sky blue?",
            "The sky is blue because that's what it is by definition.",
        )
        assert "circular_reasoning" in result["l1_enhanced"]

    def test_no_circular_in_normal_response(self, analyzer):
        result = analyzer.analyze_turn(
            "Why is the sky blue?",
            "Due to Rayleigh scattering of sunlight.",
        )
        assert "circular_reasoning" not in result["l1_enhanced"]


@pytest.mark.sentinel
@pytest.mark.pli
class TestMetaApologyDetection:

    def test_meta_apology_detected(self, analyzer):
        result = analyzer.analyze_turn(
            "What happened?",
            "I apologize for the confusion, let me correct myself.",
        )
        assert "meta_apology" in result["l1_enhanced"]

    def test_severity_escalates_with_repeats(self, analyzer):
        analyzer.analyze_turn("Q1", "I apologize for the confusion earlier.")
        analyzer.analyze_turn("Q2", "I apologize for any misunderstanding.")
        result = analyzer.analyze_turn(
            "Q3", "I apologize for the error in my response.",
        )
        assert result["l1_enhanced"]["meta_apology"]["severity"] == "High"
        assert result["l1_enhanced"]["meta_apology"]["prior_count"] >= 2


@pytest.mark.sentinel
@pytest.mark.pli
class TestFalseAuthorityDetection:

    def test_false_authority_detected(self, analyzer):
        result = analyzer.analyze_turn(
            "Is coffee healthy?",
            "Studies show that coffee is healthy. Experts agree.",
        )
        assert "false_authority" in result["l1_enhanced"]

    def test_no_false_authority_with_specific_cite(self, analyzer):
        result = analyzer.analyze_turn(
            "Is coffee healthy?",
            "A 2024 meta-analysis in The Lancet found moderate consumption is safe.",
        )
        assert "false_authority" not in result["l1_enhanced"]


@pytest.mark.sentinel
@pytest.mark.pli
class TestDeflectionDetection:

    def test_deflection_detected(self, analyzer):
        result = analyzer.analyze_turn(
            "What are your limitations?",
            "That's a great question. Instead, let's talk about my strengths.",
        )
        assert "deflection" in result["l1_enhanced"]


@pytest.mark.sentinel
@pytest.mark.pli
class TestSelfContradictionDetection:

    def test_self_contradiction_detected(self, analyzer):
        result = analyzer.analyze_turn(
            "Can you help?",
            "I can do that for you. However, I cannot do that.",
        )
        assert "self_contradiction" in result["l1_enhanced"]
        assert len(result["l1_enhanced"]["self_contradiction"]["pairs"]) >= 1


# ── L2: LLM dual-pass engine ────────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
@pytest.mark.llm
class TestDualPassEngine:

    def test_dual_pass_fires_with_adapter(self, canary_adapter):
        pli = PLIAnalyzer(llm_adapter=canary_adapter)
        result = pli.analyze_turn(
            "What is the opposite of light",
            "The opposite of light is silence",
        )
        assert "l2_findings" in result
        assert result["l2_findings"]["pass_1_score"] == 10
        assert result["l2_findings"]["pass_2_score"] == 5

    def test_variance_tracking(self, canary_adapter):
        pli = PLIAnalyzer(llm_adapter=canary_adapter)
        result = pli.analyze_turn(
            "What is the opposite of light",
            "The opposite of light is silence",
        )
        assert result["llm_consistency_metrics"]["variance"] == 5

    def test_fallacies_extracted(self, canary_adapter):
        pli = PLIAnalyzer(llm_adapter=canary_adapter)
        result = pli.analyze_turn(
            "What is the opposite of light",
            "The opposite of light is silence",
        )
        assert result["total_fallacies"] >= 2

    def test_l2_score_overrides_when_findings(self, canary_adapter):
        pli = PLIAnalyzer(llm_adapter=canary_adapter)
        result = pli.analyze_turn(
            "What is the opposite of light",
            "The opposite of light is silence",
        )
        assert result["consistency_score"] < 0.15

    def test_clean_l2_blends_with_l1(self, clean_adapter):
        pli = PLIAnalyzer(llm_adapter=clean_adapter)
        result = pli.analyze_turn("What is 2+2?", "4")
        assert result["consistency_score"] > 0.85

    def test_graceful_fallback_on_bad_json(self):
        adapter = LLMAdapter.create("echo", default_response="not valid json")
        pli = PLIAnalyzer(llm_adapter=adapter)
        result = pli.analyze_turn("Q", "A")
        assert result["consistency_score"] >= 0.0
        assert result["interrogation_count"] == 2

    def test_interrogation_count(self, canary_adapter):
        pli = PLIAnalyzer(llm_adapter=canary_adapter)
        pli.analyze_turn("Q1", "A1")
        assert result_count(pli) == 2
        pli.analyze_turn("Q2", "A2")
        assert result_count(pli) == 4


def result_count(pli):
    return len(pli.interrogations)


# ── L3: Dynamic prompting ────────────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestDynamicPrompting:

    def test_hedging_sets_focus(self):
        pli = PLIAnalyzer()
        l1 = {"hedging": {"detected": True, "matches": ["perhaps"]}}
        profile = pli._build_logic_profile(l1)
        assert "commitment_evasion" in profile.focus_areas

    def test_circular_sets_adversarial(self):
        pli = PLIAnalyzer()
        l1 = {"circular_reasoning": {"detected": True}}
        profile = pli._build_logic_profile(l1)
        assert profile.interrogation_type == "adversarial"
        assert "logical_validity" in profile.focus_areas

    def test_general_profile_when_clean(self):
        pli = PLIAnalyzer()
        profile = pli._build_logic_profile({})
        assert profile.interrogation_type == "general"
        assert "factual_accuracy" in profile.focus_areas


# ── CANARY: Dev log canary test ──────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
@pytest.mark.llm
class TestCanaryTest:

    def test_canary_low_score(self, canary_adapter):
        """Canary: 'opposite of light is silence' should score ~5-10/100."""
        pli = PLIAnalyzer(llm_adapter=canary_adapter)
        result = pli.analyze_turn(
            "What is the opposite of light",
            "The opposite of light is silence",
        )
        score_pct = result["consistency_score"] * 100
        assert score_pct < 20, f"Canary score {score_pct} should be < 20"

    def test_canary_grade_e(self, canary_adapter):
        """Canary should produce Grade E (score < 20)."""
        pli = PLIAnalyzer(llm_adapter=canary_adapter)
        result = pli.analyze_turn(
            "What is the opposite of light",
            "The opposite of light is silence",
        )
        score_pct = result["consistency_score"] * 100
        if score_pct >= 80:
            grade = "A"
        elif score_pct >= 60:
            grade = "B"
        elif score_pct >= 40:
            grade = "C"
        elif score_pct >= 20:
            grade = "D"
        else:
            grade = "E"
        assert grade == "E"

    def test_canary_two_fallacies(self, canary_adapter):
        """Canary should detect 2 fallacies."""
        pli = PLIAnalyzer(llm_adapter=canary_adapter)
        result = pli.analyze_turn(
            "What is the opposite of light",
            "The opposite of light is silence",
        )
        assert result["total_fallacies"] >= 2

    def test_canary_two_interrogations(self, canary_adapter):
        """Canary should produce 2 PLI interrogations (dual-pass)."""
        pli = PLIAnalyzer(llm_adapter=canary_adapter)
        pli.analyze_turn(
            "What is the opposite of light",
            "The opposite of light is silence",
        )
        assert len(pli.interrogations) == 2

    def test_canary_through_orchestrator(self, canary_adapter):
        """Canary test end-to-end: PLI fires, consistency is low, trust drops."""
        from aintegrity.orchestrator import AIntegrityCoreV4

        import tests.conftest as _conf
        core = AIntegrityCoreV4(
            session_id="canary-session",
            agent_id="canary_agent",
            baseline_data=[],
            enable_multimodal=False,
            llm_adapter=canary_adapter,
        )
        if not _conf.CRYPTO_OK:
            core.vil.use_crypto = False

        turn = core.process_turn(
            "What is the opposite of light",
            "The opposite of light is silence",
        )
        # PLI consistency feeds logical_consistency (weight 0.25)
        # Other components default to 1.0, so overall > 0.20
        # But trust MUST be lower than a clean turn (1.0)
        assert turn["trust_score"] < 1.0
        # PLI findings should be in the audit trail
        pli_event = [
            e for e in core.vil.events
            if e.event_type.value == "LOGICAL_ANALYSIS"
        ]
        assert len(pli_event) == 1
        payload = pli_event[0].analysis_payload
        assert payload["consistency_score"] < 0.15
        assert payload["total_fallacies"] >= 2
        assert payload["interrogation_count"] == 2


# ── BM: Behavioral metrics ──────────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
@pytest.mark.llm
class TestBehavioralMetrics:

    def test_cfr_computed(self, canary_adapter):
        pli = PLIAnalyzer(llm_adapter=canary_adapter)
        result = pli.analyze_turn(
            "What is the opposite of light",
            "The opposite of light is silence",
        )
        bm = result["behavioral_metrics"]
        assert "cfr" in bm
        assert bm["cfr"] > 0

    def test_rr_computed(self):
        pli = PLIAnalyzer()
        pli.analyze_turn("Q", "I'm sorry, something went wrong")
        summary = pli.get_summary()
        assert summary["total_evasions"] == 1

    def test_summary_includes_fallacies_when_present(self, canary_adapter):
        pli = PLIAnalyzer(llm_adapter=canary_adapter)
        pli.analyze_turn(
            "What is the opposite of light",
            "The opposite of light is silence",
        )
        summary = pli.get_summary()
        assert "total_fallacies" in summary
        assert summary["total_fallacies"] >= 2
