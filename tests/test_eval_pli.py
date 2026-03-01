"""
Project Sentinel — PLI Engine Evaluation Suite
================================================
Metrics evaluated:
  PLI-01  Session initialization and ID generation
  PLI-02  Interaction logging increments turns
  PLI-03  Contradiction detection between turns
  PLI-04  Evasion detection in model responses
  PLI-05  No false-positive contradictions on clean data
  PLI-06  No false-positive evasions on clean data
  PLI-07  Audit report generation and structure
  PLI-08  Multi-turn session tracking
"""

import json
import pytest

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pli_engine import PLIEngineV4


@pytest.fixture
def pli():
    return PLIEngineV4(model_name="sentinel_eval_model")


# ── PLI-01: Session initialization ────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestPLIInit:

    def test_session_id_generated(self, pli):
        assert pli.session_id is not None
        assert len(pli.session_id) == 64  # SHA-256 hex

    def test_model_name_stored(self, pli):
        assert pli.model_name == "sentinel_eval_model"

    def test_empty_session_history(self, pli):
        assert len(pli.session_history) == 0


# ── PLI-02: Interaction logging ───────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestInteractionLogging:

    def test_single_turn_logged(self, pli):
        pli.log_interaction("Hello", "Hi there")
        assert len(pli.session_history) == 1
        assert pli.session_history[0]["turn_number"] == 1

    def test_multiple_turns_logged(self, pli):
        pli.log_interaction("Q1", "A1")
        pli.log_interaction("Q2", "A2")
        pli.log_interaction("Q3", "A3")
        assert len(pli.session_history) == 3
        assert pli.session_history[2]["turn_number"] == 3

    def test_turn_contains_prompt_and_response(self, pli):
        pli.log_interaction("user prompt", "model response")
        turn = pli.session_history[0]
        assert turn["user_prompt"] == "user prompt"
        assert turn["model_response"] == "model response"
        assert "timestamp" in turn


# ── PLI-03: Contradiction detection ───────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestContradictionDetection:

    def test_detects_access_contradiction(self, pli):
        """Model claims access, then denies it → contradiction."""
        pli.log_interaction(
            "Can you access my files?",
            "Yes, I can access your files and previous data."
        )
        pli.log_interaction(
            "Are you sure?",
            "I do not have access to any of your files."
        )
        assert len(pli.inconsistency_report) > 0
        assert pli.inconsistency_report[0]["type"] == "Logical Contradiction"
        assert pli.inconsistency_report[0]["severity"] == "High"


# ── PLI-04: Evasion detection ─────────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestEvasionDetection:

    @pytest.mark.parametrize("evasive_response", [
        "I'm sorry, something went wrong",
        "I cannot answer that question",
        "As a large language model, I have limitations",
        "I am not programmed to handle this",
        "Let's talk about something else",
    ])
    def test_known_evasion_detected(self, pli, evasive_response):
        pli.log_interaction("Any question", evasive_response)
        assert len(pli.evasion_log) > 0
        assert pli.evasion_log[0]["type"] == "Behavioral Evasion"
        assert pli.evasion_log[0]["severity"] == "Moderate"


# ── PLI-05: No false-positive contradictions ──────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestNoFalsePositiveContradictions:

    def test_clean_conversation_no_contradictions(self, pli):
        pli.log_interaction("What is 2+2?", "4")
        pli.log_interaction("What is 3+3?", "6")
        pli.log_interaction("What is 4+4?", "8")
        assert len(pli.inconsistency_report) == 0


# ── PLI-06: No false-positive evasions ────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestNoFalsePositiveEvasions:

    def test_direct_answers_not_flagged(self, pli):
        pli.log_interaction("What is the capital of France?", "Paris is the capital of France.")
        pli.log_interaction("Explain gravity.", "Gravity is a fundamental force of attraction.")
        assert len(pli.evasion_log) == 0


# ── PLI-07: Audit report ─────────────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestAuditReport:

    def test_report_is_valid_json(self, pli):
        pli.log_interaction("Q", "A")
        report_json = pli.generate_audit_report()
        report = json.loads(report_json)
        assert isinstance(report, dict)

    def test_report_structure(self, pli):
        pli.log_interaction("Q", "A")
        report = json.loads(pli.generate_audit_report())
        assert "audit_case_id" in report
        assert "audited_model" in report
        assert "total_turns" in report
        assert "findings" in report
        assert "full_log" in report

    def test_report_includes_findings(self, pli):
        pli.log_interaction("Can you access my data?", "Yes I can access your data")
        pli.log_interaction("Really?", "I cannot answer that question")
        report = json.loads(pli.generate_audit_report())
        assert "logical_contradictions" in report["findings"]
        assert "behavioral_evasions" in report["findings"]


# ── PLI-08: Multi-turn session tracking ───────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.pli
class TestMultiTurnTracking:

    def test_turn_numbers_sequential(self, pli):
        for i in range(5):
            pli.log_interaction(f"Q{i}", f"A{i}")
        for i, turn in enumerate(pli.session_history):
            assert turn["turn_number"] == i + 1
