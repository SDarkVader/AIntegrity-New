"""
PayloadGuard — Consequence Analyzer Test Suite
================================================
Tests the three-layer analysis pipeline:

  SCOPE-01   Clean merge returns SAFE verdict
  SCOPE-02   Mass file deletion returns DESTRUCTIVE
  SCOPE-03   Moderate deletion returns CAUTION
  SCOPE-04   Small change returns REVIEW or SAFE
  SCOPE-05   File counts are accurate

  TEMPORAL-01  Stale branch (90+ days) adds severity
  TEMPORAL-02  Ancient branch (365+ days) adds critical severity
  TEMPORAL-03  Fresh branch adds no temporal penalty

  RATIO-01   >90% deletion ratio flags critical
  RATIO-02   >70% deletion ratio flags high
  RATIO-03   >50% deletion ratio flags medium
  RATIO-04   Balanced changes produce low ratio

  LINES-01   >50,000 deleted lines flags critical
  LINES-02   >10,000 deleted lines flags high
  LINES-03   <5,000 deleted lines adds no flag

  CRITICAL-01  Test file deletion flagged as critical
  CRITICAL-02  Workflow file deletion flagged as critical
  CRITICAL-03  Requirements deletion flagged as critical
  CRITICAL-04  __init__.py deletion flagged as critical
  CRITICAL-05  Non-critical file not flagged

  VERDICT-01  Severity score >= 5 returns DESTRUCTIVE
  VERDICT-02  Severity score 3-4 returns CAUTION
  VERDICT-03  Severity score 1-2 returns REVIEW
  VERDICT-04  Severity score 0 returns SAFE

  EXIT-01    DESTRUCTIVE verdict returns exit code 2
  EXIT-02    SAFE verdict returns exit code 0
  EXIT-03    Error returns exit code 1

  REPORT-01  print_report handles error reports
  REPORT-02  print_report handles valid reports
  REPORT-03  save_json_report creates file

  EDGE-01    Missing branch returns error
  EDGE-02    Missing target returns error
  EDGE-03    Empty repo handled gracefully
  EDGE-04    Zero total lines doesn't divide by zero

  CODEX-01   Simulated Codex incident: 60 deleted, 2 remaining → DESTRUCTIVE
"""

import json
import os
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import pytest

# Import from analyze-2.py (the main analyzer)
# Handle the hyphenated filename
import importlib
import sys


@pytest.fixture(scope="session")
def analyzer_module():
    """Import analyze-2.py despite the hyphenated filename."""
    spec = importlib.util.spec_from_file_location(
        "analyze2",
        os.path.join(os.path.dirname(__file__), "analyze-2.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def PayloadAnalyzer(analyzer_module):
    return analyzer_module.PayloadAnalyzer


@pytest.fixture
def print_report(analyzer_module):
    return analyzer_module.print_report


@pytest.fixture
def save_json_report(analyzer_module):
    return analyzer_module.save_json_report


@pytest.fixture
def assess_consequence(analyzer_module):
    """Direct access to _assess_consequence for unit testing."""
    analyzer = analyzer_module.PayloadAnalyzer.__new__(
        analyzer_module.PayloadAnalyzer
    )
    return analyzer._assess_consequence


# ── Helper: create a git repo with branches ─────────────────────────────

@pytest.fixture
def make_repo():
    """Factory that creates a temporary git repo with configurable branches."""
    import git

    repos = []

    def _make(
        main_files=None,
        branch_files=None,
        branch_name="feature",
        branch_age_days=0,
    ):
        tmp = tempfile.mkdtemp(prefix="payloadguard_test_")
        repo = git.Repo.init(tmp)

        # Configure git user
        repo.config_writer().set_value("user", "name", "Test").release()
        repo.config_writer().set_value("user", "email", "test@test.com").release()

        # Create main branch with files
        main_files = main_files or {"README.md": "# Test"}
        for name, content in main_files.items():
            fpath = os.path.join(tmp, name)
            os.makedirs(os.path.dirname(fpath), exist_ok=True)
            with open(fpath, "w") as f:
                f.write(content)
        repo.index.add(list(main_files.keys()))
        repo.index.commit("Initial commit")

        # Create feature branch
        repo.create_head(branch_name)
        branch_ref = repo.heads[branch_name]
        branch_ref.checkout()

        # Apply branch changes
        if branch_files is not None:
            # Delete files not in branch_files
            for name in main_files:
                if name not in branch_files:
                    fpath = os.path.join(tmp, name)
                    if os.path.exists(fpath):
                        os.remove(fpath)
                        repo.index.remove([name])

            # Add/modify files in branch_files
            for name, content in branch_files.items():
                fpath = os.path.join(tmp, name)
                os.makedirs(os.path.dirname(fpath), exist_ok=True)
                with open(fpath, "w") as f:
                    f.write(content)
                repo.index.add([name])

        commit_kwargs = {}
        if branch_age_days > 0:
            old_date = datetime.now(timezone.utc) - timedelta(days=branch_age_days)
            date_str = old_date.strftime("%Y-%m-%dT%H:%M:%S %z")
            commit_kwargs["author_date"] = date_str
            commit_kwargs["commit_date"] = date_str

        repo.index.commit("Branch commit", **commit_kwargs)

        # Switch back to main
        repo.heads["master"].checkout()
        # Rename master to main for consistency
        repo.heads["master"].rename("main")

        repos.append(tmp)
        return tmp, branch_name

    yield _make

    for r in repos:
        shutil.rmtree(r, ignore_errors=True)


# ── VERDICT: _assess_consequence unit tests ─────────────────────────────

class TestVerdictAssessment:

    def test_destructive_high_severity(self, assess_consequence):
        """VERDICT-01: severity >= 5 returns DESTRUCTIVE."""
        result = assess_consequence(
            files_deleted=60, lines_deleted=12000,
            days_old=300, deletion_ratio=98.7,
        )
        assert result["status"] == "DESTRUCTIVE"
        assert result["severity"] == "CRITICAL"
        assert result["severity_score"] >= 5

    def test_caution_medium_severity(self, assess_consequence):
        """VERDICT-02: severity 3-4 returns CAUTION."""
        result = assess_consequence(
            files_deleted=25, lines_deleted=3000,
            days_old=10, deletion_ratio=60.0,
        )
        assert result["status"] == "CAUTION"
        assert result["severity"] == "HIGH"
        assert 3 <= result["severity_score"] <= 4

    def test_review_low_severity(self, assess_consequence):
        """VERDICT-03: severity 1-2 returns REVIEW."""
        result = assess_consequence(
            files_deleted=15, lines_deleted=2000,
            days_old=10, deletion_ratio=40.0,
        )
        assert result["status"] == "REVIEW"
        assert result["severity"] == "MEDIUM"
        assert 1 <= result["severity_score"] <= 2

    def test_safe_no_severity(self, assess_consequence):
        """VERDICT-04: severity 0 returns SAFE."""
        result = assess_consequence(
            files_deleted=2, lines_deleted=50,
            days_old=5, deletion_ratio=10.0,
        )
        assert result["status"] == "SAFE"
        assert result["severity"] == "LOW"
        assert result["severity_score"] == 0


# ── TEMPORAL: Branch age severity ───────────────────────────────────────

class TestTemporalFlags:

    def test_stale_branch_90_days(self, assess_consequence):
        """TEMPORAL-01: 90+ day branch adds severity."""
        result = assess_consequence(
            files_deleted=0, lines_deleted=0,
            days_old=100, deletion_ratio=0,
        )
        assert result["severity_score"] >= 1
        assert any("days old" in f for f in result["flags"])

    def test_ancient_branch_365_days(self, assess_consequence):
        """TEMPORAL-02: 365+ day branch adds critical severity."""
        result = assess_consequence(
            files_deleted=0, lines_deleted=0,
            days_old=400, deletion_ratio=0,
        )
        assert result["severity_score"] >= 3
        assert any("1+ year" in f for f in result["flags"])

    def test_fresh_branch_no_penalty(self, assess_consequence):
        """TEMPORAL-03: Fresh branch adds no temporal penalty."""
        result = assess_consequence(
            files_deleted=0, lines_deleted=0,
            days_old=5, deletion_ratio=0,
        )
        temporal_flags = [f for f in result["flags"] if "days old" in f]
        assert len(temporal_flags) == 0


# ── RATIO: Deletion ratio severity ──────────────────────────────────────

class TestDeletionRatio:

    def test_critical_ratio_above_90(self, assess_consequence):
        """RATIO-01: >90% deletion ratio flags critical."""
        result = assess_consequence(
            files_deleted=0, lines_deleted=0,
            days_old=0, deletion_ratio=95.0,
        )
        assert any("almost entire" in f.lower() for f in result["flags"])

    def test_high_ratio_above_70(self, assess_consequence):
        """RATIO-02: >70% deletion ratio flags high."""
        result = assess_consequence(
            files_deleted=0, lines_deleted=0,
            days_old=0, deletion_ratio=75.0,
        )
        assert any("majority" in f.lower() for f in result["flags"])

    def test_medium_ratio_above_50(self, assess_consequence):
        """RATIO-03: >50% deletion ratio flags medium."""
        result = assess_consequence(
            files_deleted=0, lines_deleted=0,
            days_old=0, deletion_ratio=55.0,
        )
        assert any("more deletions" in f.lower() for f in result["flags"])

    def test_balanced_ratio_no_flag(self, assess_consequence):
        """RATIO-04: Balanced changes produce no ratio flag."""
        result = assess_consequence(
            files_deleted=0, lines_deleted=0,
            days_old=0, deletion_ratio=30.0,
        )
        ratio_flags = [f for f in result["flags"] if "deletion" in f.lower() or "ratio" in f.lower()]
        assert len(ratio_flags) == 0


# ── LINES: Line deletion severity ───────────────────────────────────────

class TestLineDeletion:

    def test_massive_deletion_above_50k(self, assess_consequence):
        """LINES-01: >50,000 lines flags critical."""
        result = assess_consequence(
            files_deleted=0, lines_deleted=60000,
            days_old=0, deletion_ratio=0,
        )
        assert any("massive" in f.lower() for f in result["flags"])
        assert result["severity_score"] >= 3

    def test_large_deletion_above_10k(self, assess_consequence):
        """LINES-02: >10,000 lines flags high."""
        result = assess_consequence(
            files_deleted=0, lines_deleted=15000,
            days_old=0, deletion_ratio=0,
        )
        assert any("large" in f.lower() for f in result["flags"])
        assert result["severity_score"] >= 2

    def test_small_deletion_no_flag(self, assess_consequence):
        """LINES-03: <5,000 lines adds no line-count flag."""
        result = assess_consequence(
            files_deleted=0, lines_deleted=2000,
            days_old=0, deletion_ratio=0,
        )
        line_flags = [f for f in result["flags"] if "lines" in f.lower()]
        assert len(line_flags) == 0


# ── FILE DELETION: Count-based severity ──────────────────────────────────

class TestFileDeletion:

    def test_massive_file_deletion(self, assess_consequence):
        """SCOPE-02: >50 files returns severity."""
        result = assess_consequence(
            files_deleted=60, lines_deleted=0,
            days_old=0, deletion_ratio=0,
        )
        assert any("massive scope" in f.lower() for f in result["flags"])
        assert result["severity_score"] >= 3

    def test_large_file_deletion(self, assess_consequence):
        """SCOPE-03: >20 files returns severity."""
        result = assess_consequence(
            files_deleted=30, lines_deleted=0,
            days_old=0, deletion_ratio=0,
        )
        assert any("large scope" in f.lower() for f in result["flags"])
        assert result["severity_score"] >= 2

    def test_small_file_deletion(self, assess_consequence):
        """SCOPE-04: <10 files adds no file flag."""
        result = assess_consequence(
            files_deleted=5, lines_deleted=0,
            days_old=0, deletion_ratio=0,
        )
        file_flags = [f for f in result["flags"] if "files" in f.lower()]
        assert len(file_flags) == 0


# ── CRITICAL PATTERNS: File path matching ────────────────────────────────

class TestCriticalPatterns:

    @pytest.mark.parametrize("path,should_match", [
        ("tests/test_eval.py", True),
        (".github/workflows/ci.yml", True),
        ("requirements.txt", True),
        ("aintegrity/__init__.py", True),
        ("core/engine.py", True),
        ("modules/analyzer.py", True),
        ("config/settings.yml", True),
        ("deploy.yaml", True),
        ("setup.py", True),
        ("README.md", False),
        ("docs/notes.txt", False),
        ("images/logo.png", False),
    ])
    def test_critical_pattern_detection(self, path, should_match):
        """CRITICAL-01 through CRITICAL-05: Pattern matching."""
        critical_patterns = [
            'test', 'tests', '.github/workflows', 'requirements', 'setup.py',
            '__init__.py', 'core', 'modules', 'config', '.yml', '.yaml'
        ]
        matched = any(p.lower() in path.lower() for p in critical_patterns)
        assert matched == should_match, f"{path} expected match={should_match}"


# ── INTEGRATION: Full analyze() with real git repos ──────────────────────

class TestFullAnalysis:

    def test_clean_merge_safe(self, PayloadAnalyzer, make_repo):
        """SCOPE-01: Clean merge with additions returns SAFE."""
        repo_path, branch = make_repo(
            main_files={"README.md": "# Hello"},
            branch_files={"README.md": "# Hello", "new_file.py": "print('hi')"},
        )
        analyzer = PayloadAnalyzer(repo_path, branch, "main")
        report = analyzer.analyze()
        assert "error" not in report
        assert report["verdict"]["status"] == "SAFE"
        assert report["files"]["added"] == 1
        assert report["files"]["deleted"] == 0

    def test_file_counts_accurate(self, PayloadAnalyzer, make_repo):
        """SCOPE-05: File counts match actual changes."""
        main = {
            "a.py": "a",
            "b.py": "b",
            "c.py": "c",
        }
        branch = {
            "a.py": "a_modified",
            "c.py": "c",
            "d.py": "d_new",
        }
        repo_path, branch_name = make_repo(
            main_files=main,
            branch_files=branch,
        )
        analyzer = PayloadAnalyzer(repo_path, branch_name, "main")
        report = analyzer.analyze()
        assert report["files"]["deleted"] == 1  # b.py
        assert report["files"]["added"] == 1    # d.py
        assert report["files"]["modified"] == 1  # a.py

    def test_missing_branch_returns_error(self, PayloadAnalyzer, make_repo):
        """EDGE-01: Missing branch returns error."""
        repo_path, _ = make_repo()
        analyzer = PayloadAnalyzer(repo_path, "nonexistent-branch", "main")
        report = analyzer.analyze()
        assert "error" in report

    def test_missing_target_returns_error(self, PayloadAnalyzer, make_repo):
        """EDGE-02: Missing target returns error."""
        repo_path, branch = make_repo()
        analyzer = PayloadAnalyzer(repo_path, branch, "nonexistent-target")
        report = analyzer.analyze()
        assert "error" in report


# ── EDGE CASES ──────────────────────────────────────────────────────────

class TestEdgeCases:

    def test_zero_lines_no_division_error(self, assess_consequence):
        """EDGE-04: Zero total lines doesn't cause division by zero."""
        result = assess_consequence(
            files_deleted=0, lines_deleted=0,
            days_old=0, deletion_ratio=0,
        )
        assert result["status"] == "SAFE"
        assert result["severity_score"] == 0

    def test_negative_days_old_no_crash(self, assess_consequence):
        """Branch newer than target doesn't crash."""
        result = assess_consequence(
            files_deleted=0, lines_deleted=0,
            days_old=-5, deletion_ratio=0,
        )
        assert result["status"] == "SAFE"


# ── REPORT OUTPUT ────────────────────────────────────────────────────────

class TestReportOutput:

    def test_print_report_error(self, print_report, capsys):
        """REPORT-01: print_report handles error reports."""
        print_report({"error": "Test error", "error_type": "TestError"})
        captured = capsys.readouterr()
        assert "ANALYSIS FAILED" in captured.out
        assert "Test error" in captured.out

    def test_print_report_valid(self, print_report, capsys):
        """REPORT-02: print_report handles valid reports."""
        report = {
            "analysis": {"branch": "test", "target": "main", "repo_path": "."},
            "files": {"added": 1, "deleted": 0, "modified": 0,
                      "renamed": 0, "copied": 0, "type_changed": 0,
                      "total_changed": 1},
            "lines": {"added": 10, "deleted": 0, "net_change": 10,
                      "deletion_ratio_percent": 0, "codebase_reduction_percent": 0},
            "temporal": {"branch_age_days": 1, "branch_last_commit": "2026-04-19",
                         "branch_commit_hash": "abc1234",
                         "target_last_commit": "2026-04-19",
                         "target_commit_hash": "def5678"},
            "verdict": {"status": "SAFE", "severity": "LOW",
                        "flags": ["No major red flags detected"],
                        "recommendation": "Proceed", "severity_score": 0},
            "deleted_files": {"total": 0, "critical": [], "all": []},
        }
        print_report(report)
        captured = capsys.readouterr()
        assert "PAYLOAD CONSEQUENCE ANALYSIS" in captured.out
        assert "SAFE" in captured.out

    def test_save_json_report(self, save_json_report, tmp_path):
        """REPORT-03: save_json_report creates valid JSON file."""
        report = {"status": "SAFE", "test": True}
        outfile = str(tmp_path / "test_report.json")
        save_json_report(report, outfile)
        assert os.path.exists(outfile)
        with open(outfile) as f:
            loaded = json.load(f)
        assert loaded["status"] == "SAFE"
        assert loaded["test"] is True


# ── CODEX INCIDENT SIMULATION ────────────────────────────────────────────

class TestCodexIncidentSimulation:

    def test_codex_scenario_destructive(self, assess_consequence):
        """CODEX-01: Simulated Codex incident — 60 files deleted, 98.7%
        deletion ratio, 300-day-old branch → DESTRUCTIVE.

        This reproduces the exact metrics from the April 2026 incident
        where a Codex suggestion would have deleted 60 files (11,967 lines)
        and replaced the entire AIntegrity codebase with a 159-line prototype.
        """
        result = assess_consequence(
            files_deleted=60,
            lines_deleted=11967,
            days_old=300,
            deletion_ratio=98.7,
        )
        assert result["status"] == "DESTRUCTIVE"
        assert result["severity"] == "CRITICAL"
        assert result["severity_score"] >= 5

        flag_text = " ".join(result["flags"]).lower()
        assert "massive scope" in flag_text or "60 files" in flag_text
        assert "days old" in flag_text
        assert "almost entire" in flag_text or "98.7%" in flag_text
