"""
Project Sentinel — PLI Analyzer Integration Eval Suite
=======================================================
Metrics evaluated:
  PLIA-01  Clean conversation yields consistency_score = 1.0
  PLIA-02  Contradiction detected across turns
  PLIA-03  Evasion detected in model response
  PLIA-04  Consistency score degrades with contradictions
  PLIA-05  Consistency score degrades with evasions
  PLIA-06  Multiple findings compound penalty
  PLIA-07  Consistency score never drops below 0.0
  PLIA-08  Summary aggregates all findings
  PLIA-09  Turn numbering is sequential
  PLIA-10  Findings contain correct metadata
"""

import pytest

from aintegrity.modules.pli_analyzer import PLIAnalyzer


@pytest.fixture
def analyzer():
    return PLIAnalyzer()


# ── PLIA-01: Clean conversation ───────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestCleanConversation:

    def test_clean_turns_score_one(self, analyzer):
        r1 = analyzer.analyze_turn("What is 2+2?", "4")
        assert r1["consistency_score"] == 1.0
        r2 = analyzer.analyze_turn("What is 3+3?", "6")
        assert r2["consistency_score"] == 1.0

    def test_no_findings_in_clean_turn(self, analyzer):
        result = analyzer.analyze_turn("Hello", "Hi there!")
        assert result["contradiction_detected"] is False
        assert result["evasion_detected"] is False


# ── PLIA-02: Contradiction detection ─────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestContradictionDetection:

    def test_access_contradiction(self, analyzer):
        analyzer.analyze_turn(
            "Can you access my files?",
            "Yes, I can access your files and data."
        )
        result = analyzer.analyze_turn(
            "Are you sure?",
            "I do not have access to your files."
        )
        assert result["contradiction_detected"] is True
        assert result["total_contradictions"] == 1

    def test_ability_contradiction(self, analyzer):
        analyzer.analyze_turn(
            "Can you access the internet?",
            "I have access to web resources."
        )
        result = analyzer.analyze_turn(
            "Really?",
            "I'm unable to access external resources."
        )
        assert result["contradiction_detected"] is True


# ── PLIA-03: Evasion detection ────────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestEvasionDetection:

    @pytest.mark.parametrize("evasive_text", [
        "I'm sorry, something went wrong",
        "I cannot answer that question",
        "As a large language model, I have limits",
        "I am not programmed to do that",
        "Let's talk about something else",
    ])
    def test_evasion_detected(self, analyzer, evasive_text):
        result = analyzer.analyze_turn("Any question?", evasive_text)
        assert result["evasion_detected"] is True
        assert result["total_evasions"] == 1


# ── PLIA-04: Score degradation from contradictions ───────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestContradictionScoreDegradation:

    def test_contradiction_reduces_score(self, analyzer):
        analyzer.analyze_turn("Can you access my data?", "Yes I can access your data.")
        result = analyzer.analyze_turn("Sure?", "I do not have access to anything.")
        assert result["consistency_score"] < 1.0
        assert result["consistency_score"] == pytest.approx(0.85, abs=0.01)


# ── PLIA-05: Score degradation from evasions ─────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestEvasionScoreDegradation:

    def test_evasion_reduces_score(self, analyzer):
        result = analyzer.analyze_turn("Question", "I'm sorry, something went wrong")
        assert result["consistency_score"] < 1.0
        assert result["consistency_score"] == pytest.approx(0.92, abs=0.01)


# ── PLIA-06: Compound penalties ───────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestCompoundPenalties:

    def test_multiple_findings_stack(self, analyzer):
        # Evasion
        analyzer.analyze_turn("Q1", "I'm sorry, something went wrong")
        # Set up contradiction
        analyzer.analyze_turn("Can you access my files?", "I can access your files")
        # Trigger contradiction + evasion in same session
        result = analyzer.analyze_turn("Really?", "I do not have access. Let's talk about something else")
        # 1 prior evasion + 1 contradiction + 1 new evasion
        assert result["total_evasions"] >= 2
        assert result["total_contradictions"] >= 1
        assert result["consistency_score"] < 0.7


# ── PLIA-07: Floor at zero ───────────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestScoreFloor:

    def test_score_never_negative(self, analyzer):
        # Generate many evasions to force heavy penalty
        for i in range(20):
            analyzer.analyze_turn(f"Q{i}", "I'm sorry, something went wrong")
        result = analyzer.analyze_turn("Final", "I'm sorry, something went wrong")
        assert result["consistency_score"] >= 0.0


# ── PLIA-08: Summary aggregation ─────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestSummary:

    def test_summary_structure(self, analyzer):
        analyzer.analyze_turn("Q", "A")
        summary = analyzer.get_summary()
        assert "total_turns" in summary
        assert "total_contradictions" in summary
        assert "total_evasions" in summary
        assert "contradictions" in summary
        assert "evasions" in summary
        assert "final_consistency_score" in summary

    def test_summary_counts_match(self, analyzer):
        analyzer.analyze_turn("Q1", "I'm sorry, something went wrong")
        analyzer.analyze_turn("Q2", "Normal answer")
        summary = analyzer.get_summary()
        assert summary["total_turns"] == 2
        assert summary["total_evasions"] == 1
        assert summary["total_contradictions"] == 0


# ── PLIA-09: Turn numbering ──────────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestTurnNumbering:

    def test_sequential_turn_numbers(self, analyzer):
        for i in range(5):
            result = analyzer.analyze_turn(f"Q{i}", f"A{i}")
            assert result["turn_number"] == i + 1


# ── PLIA-10: Finding metadata ────────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestFindingMetadata:

    def test_contradiction_finding_details(self, analyzer):
        analyzer.analyze_turn("Can you access data?", "I can access your data")
        result = analyzer.analyze_turn("Really?", "I do not have access to data")
        finding = result["findings"]["contradiction"]
        assert finding is not None
        assert finding["type"] == "Logical Contradiction"
        assert finding["severity"] == "High"
        assert "current_turn" in finding
        assert "past_turn" in finding

    def test_evasion_finding_details(self, analyzer):
        result = analyzer.analyze_turn("Q", "As a large language model, I can't")
        finding = result["findings"]["evasion"]
        assert finding is not None
        assert finding["type"] == "Behavioral Evasion"
        assert finding["severity"] == "Moderate"
        assert "turn" in finding
