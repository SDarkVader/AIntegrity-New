# PayloadGuard: Destructive Merge Detection for AI-Assisted Development Pipelines

**Version 0.1 | April 2026**
**Author:** Steven Dark | AIntegrity Behavioural Auditing Framework

---

## Abstract

PayloadGuard is a pre-merge analysis tool that detects destructive code changes hidden within AI-generated suggestions, automated dependency updates, and stale branch merges. It addresses a gap in current CI/CD pipelines where automated systems can propose changes that delete critical infrastructure — tests, workflows, configuration — without surfacing the scope of destruction to the reviewer.

The tool was developed in direct response to an incident on 19 April 2026 in which a GitHub Codex suggestion, presented as a minor syntax fix, would have deleted 60 files (11,967 lines of code) from the AIntegrity repository and replaced the entire codebase with a 159-line prototype. The full forensic analysis of this incident is documented in `CODEX_FORENSIC_REPORT.md`.

---

## 1. Problem Statement

41% of shipped code is now AI-generated (GitHub, 2025). Automated dependency systems merge pull requests without human oversight. AI code review tools surface suggestions with limited transparency about the full scope of proposed changes.

The attack surface is not adversarial prompt injection — it is **presentation/payload mismatch**: the surface-level description of a change does not reflect its actual consequences. A reviewer sees "fix syntax error" while the underlying branch deletes the test suite, CI pipeline, and core modules.

Current CI pipelines check whether code *works* (tests pass, builds succeed). They do not check whether a merge *destroys* — whether the changeset removes more than it adds, deletes critical infrastructure, or originates from a stale branch with no relationship to the current codebase.

---

## 2. Architecture

PayloadGuard implements a three-layer analysis pipeline:

```
┌─────────────────────────────────────────────────┐
│              PayloadGuard Analyzer               │
├────────────┬────────────────┬───────────────────┤
│  Layer 1   │    Layer 2     │     Layer 3       │
│  Surface   │    Deep        │    Consequence    │
│  Scan      │    Forensic    │    Modeling       │
├────────────┼────────────────┼───────────────────┤
│ File count │ Line-level     │ Verdict:          │
│ Change     │ delta          │ DESTRUCTIVE /     │
│ types      │ analysis       │ CAUTION /         │
│ (A/D/M/R)  │                │ REVIEW /          │
│            │ Temporal       │ SAFE              │
│            │ validation     │                   │
│            │ (branch age)   │ Severity score    │
│            │                │ (0-12+)           │
│            │ Deletion       │                   │
│            │ ratio          │ Recommendations   │
│            │ calculation    │                   │
│            │                │ Critical file     │
│            │ Critical path  │ inventory         │
│            │ matching       │                   │
└────────────┴────────────────┴───────────────────┘
```

### 2.1 Layer 1: Surface Scan

Enumerates file-level changes between the source branch and the merge target:

| Change Type | Code | Description |
|---|---|---|
| Added | A | New files introduced |
| Deleted | D | Files removed |
| Modified | M | Existing files changed |
| Renamed | R | Files moved/renamed |
| Copied | C | Files duplicated |
| Type changed | T | File type altered |

### 2.2 Layer 2: Deep Forensic Analysis

**Line-level delta:** Counts total lines added and deleted across all changed files. Calculates:
- `deletion_ratio = lines_deleted / (lines_added + lines_deleted) * 100`
- `codebase_reduction = lines_deleted / total_lines_changed * 100`

**Temporal validation:** Compares the most recent commit on the source branch against the target branch. Flags branches that are significantly older than the target, indicating stale or abandoned work being merged into active development.

**Critical path matching:** Identifies deletions of files matching high-value patterns:

| Pattern | Why It's Critical |
|---|---|
| `test`, `tests` | Test suite deletion removes safety net |
| `.github/workflows` | CI pipeline deletion removes automated checks |
| `requirements`, `setup.py` | Dependency config deletion breaks installation |
| `__init__.py` | Package init deletion breaks imports |
| `core`, `modules` | Core module deletion removes functionality |
| `config` | Configuration deletion breaks deployment |
| `.yml`, `.yaml` | Config file deletion affects infrastructure |

### 2.3 Layer 3: Consequence Modeling

Aggregates findings into a severity score and verdict:

**Severity scoring:**

| Category | Threshold | Points |
|---|---|---|
| Branch age | >365 days | +3 |
| Branch age | >180 days | +2 |
| Branch age | >90 days | +1 |
| Files deleted | >50 | +3 |
| Files deleted | >20 | +2 |
| Files deleted | >10 | +1 |
| Deletion ratio | >90% | +3 |
| Deletion ratio | >70% | +2 |
| Deletion ratio | >50% | +1 |
| Lines deleted | >50,000 | +3 |
| Lines deleted | >10,000 | +2 |
| Lines deleted | >5,000 | +1 |

**Verdict thresholds:**

| Score | Verdict | Severity | Action |
|---|---|---|---|
| >= 5 | DESTRUCTIVE | CRITICAL | Block merge |
| 3 - 4 | CAUTION | HIGH | Manual review required |
| 1 - 2 | REVIEW | MEDIUM | Proceed with awareness |
| 0 | SAFE | LOW | Normal merge process |

**Exit codes:**
- `0` — Safe to merge
- `1` — Analysis error
- `2` — Destructive merge detected (CI gate)

---

## 3. The Codex Incident (19 April 2026)

### 3.1 What happened

GitHub Codex surfaced a suggestion on the AIntegrity repository (`SDarkVader/AIntegrity-New`), presented to the user as a minor syntax fix. The user approved the suggestion for analysis.

### 3.2 What the suggestion actually contained

The branch `SDarkVader-patch-1` — created in June 2025, 10 months prior — contained exactly 2 files (159 lines total). Merging it into `main` would have:

| Metric | Value |
|---|---|
| Files deleted | 60 |
| Lines deleted | 11,967 |
| Tests destroyed | 217 (all passing) |
| Files remaining | 2 |
| Lines remaining | 159 |
| Codebase reduction | 98.7% |
| Research papers deleted | 1 (Epistemic Decay) |
| Dev logs deleted | 2 |
| Architecture docs deleted | 22 |
| Binary data deleted | ~35 MB |

### 3.3 PayloadGuard analysis

If PayloadGuard had been active at the time, the branch would have scored:

| Category | Finding | Points |
|---|---|---|
| Branch age | 300 days (10 months) | +2 |
| Files deleted | 60 (massive scope) | +3 |
| Deletion ratio | 98.7% | +3 |
| Lines deleted | 11,967 | +2 |
| **Total** | | **10** |

**Verdict: DESTRUCTIVE (CRITICAL)**

The merge would have been blocked automatically.

### 3.4 Presentation/payload mismatch

The incident demonstrates a class of risk not covered by existing CI/CD security:

- **Presentation layer:** "Minor syntax fix" — small, helpful, non-threatening
- **Payload layer:** Complete codebase replacement — 60 file deletions, 98.7% reduction
- **User visibility:** Limited to the presentation layer
- **System transparency:** No mechanism to surface the payload scope before approval

This maps to the confidence-epistemology decoupling described in *Epistemic Decay in Agentic AI Systems* (Dark, 2026): the surface confidence of the suggestion was uncorrelated with the epistemic grounding of the actual change.

---

## 4. Usage

### Command line

```bash
python analyze-2.py /path/to/repo branch-name [target-branch]
python analyze-2.py . feature-branch main
python analyze-2.py . feature-branch main --save-json
```

### GitHub Actions (CI gate)

```yaml
name: PayloadGuard

on:
  pull_request:
    branches: [ "main" ]

permissions:
  contents: read

jobs:
  analyze:
    name: "Payload Consequence Analysis"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install GitPython==3.1.40
      - run: python analyze-2.py . HEAD main
```

Exit code 2 (DESTRUCTIVE) fails the CI check, preventing merge.

### Programmatic

```python
from analyze2 import PayloadAnalyzer

analyzer = PayloadAnalyzer("/path/to/repo", "feature-branch", "main")
report = analyzer.analyze()

if report["verdict"]["status"] == "DESTRUCTIVE":
    print("BLOCKED:", report["verdict"]["flags"])
```

---

## 5. Test Suite

35 tests covering all layers:

| Category | Tests | Coverage |
|---|---|---|
| Verdict thresholds | 4 | DESTRUCTIVE/CAUTION/REVIEW/SAFE |
| Temporal flags | 3 | 90/180/365 day thresholds |
| Deletion ratio | 4 | 50/70/90% thresholds |
| Line deletion | 3 | 5k/10k/50k thresholds |
| File deletion | 3 | 10/20/50 file thresholds |
| Critical patterns | 12 | Path matching (parametrized) |
| Full integration | 4 | Real git repos in temp dirs |
| Edge cases | 2 | Zero division, negative days |
| Report output | 3 | Terminal + JSON output |
| Codex simulation | 1 | Exact incident reproduction |

```bash
python -m pytest payloadguard_test_suite.py -v
```

---

## 6. Dependencies

- Python 3.9+
- GitPython 3.1.40

---

## 7. Limitations and Future Work

- **Current scope:** File/line-level analysis only. Does not perform semantic analysis of code changes (e.g., a single-line change in a security module could be more destructive than deleting 100 test files).
- **No content analysis:** Does not inspect what was changed within modified files, only that they were modified.
- **Binary files:** Binary file deletions are counted but line-level analysis is skipped.
- **Future:** Integration with AIntegrity PLI engine for semantic analysis of code changes. Cross-repository analysis for supply chain detection. PR description vs. actual diff comparison (transparency layer).

---

## 8. Origin

PayloadGuard was built in a single afternoon on 19 April 2026, in direct response to a live incident. The tool that was supposed to help was the threat. The tool built to detect that threat now guards the repository it nearly destroyed.

Its first live test was blocked by its own design — the initial CI configuration triggered on pushes to main as well as PRs, so the first legitimate merge was flagged as DESTRUCTIVE (exit code 2) because the commit adding PayloadGuard itself was a large changeset. The tool caught its own deployment as a destructive payload. The workflow was subsequently scoped to PR-only triggers, which is the correct gate position.

---

## License

MIT

---

*PayloadGuard is part of the AIntegrity Behavioural Auditing Framework.*
*Steven Dark | Independent AI Safety Researcher | Aberdeen, Scotland*
