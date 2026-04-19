# AIntegrity Development Log

> **Purpose:** Chronological record of development progress. Updated with every commit session.
> **Last updated:** 2026-04-19

---

## 2026-04-19 — Three-Layer PLI Engine + Epistemic Decay Paper

**Session:** Claude Code (Opus)
**Branch:** `claude/create-test-eval-suite-gwgTG`
**Commits:** 6

### What was done

1. **Read April 5 dev log** — Documented Base44 v4.1.0 breakage, root cause (Python SentenceTransformer code fed into JS Builder), 24-module architecture, 5-step action plan.

2. **Upgraded PLI engine to three-layer architecture**
   - **L1 (Regex):** Added 6 enhanced pattern detectors — hedging, circular reasoning, meta-apology (with escalating severity), false authority, deflection, within-turn self-contradiction. Preserved all original contradiction + evasion detection.
   - **L2 (LLM dual-pass):** OBSERVE pass detects fallacies and factual errors. VERIFY pass independently confirms. Variance between passes tracked as a signal. Structured JSON output with severity classification.
   - **L3 (Dynamic prompting):** `LogicProfile` dataclass adapts interrogation strategy based on L1 findings. Maps patterns to focus areas and interrogation depth.
   - **Scoring:** L2 overrides L1 when findings present. Blends 0.3*L1 + 0.7*L2 when clean.
   - **Backward compatible:** All 189 original tests pass unchanged.
   - **File:** `aintegrity/modules/pli_analyzer.py` (157 → ~400 lines)

3. **Wired LLM adapter through orchestrator**
   - `AIntegrityCoreV4.__init__` now passes `llm_adapter` to `PLIAnalyzer`
   - **File:** `aintegrity/orchestrator.py` (single-line change)

4. **Created enhanced test suite** (28 new tests)
   - L1-ENH-01 through L1-ENH-06: All enhanced regex patterns
   - L2-01 through L2-07: Dual-pass engine behavior
   - L3-01 through L3-03: Dynamic prompting / LogicProfile
   - CANARY-01 through CANARY-05: Canary test at multiple levels
   - BM-01 through BM-03: Behavioral metrics (CFR, RR)
   - **File:** `tests/test_eval_pli_enhanced.py`

5. **Built CLI audit runner**
   - `--canary` / `--user Q --ai A` / `--interactive` / `--provider openai|anthropic|echo`
   - Grades: A (80+), B (60+), C (40+), D (20+), E (<20)
   - **File:** `aintegrity/audit.py` (266 lines)

6. **Added Epistemic Decay paper to repo**
   - `Epistemic_Decay_v2.pdf` — first draft, targeting Alignment Forum
   - Central thesis: alignment presupposes epistemology
   - Four-stage cascade: Lossy Compression → Ambiguous Retrieval → Corrupted Storage → Confident Compounding
   - Three worked examples from PLI audits of Claude Sonnet 4.6, Gemini 2.5 (NotebookLM), Gemini 3.1

### Test results
- **217 passed, 2 skipped** (full suite)
- Canary fires correctly: score <20, Grade E, 2+ fallacies, 2 interrogations

### Key decisions
- PLI L2 only activates when `llm_adapter` is provided — zero breaking changes for existing usage
- Echo backend enables full L2 testing with no API credits
- Canary orchestrator test checks PLI payload directly from VIL events (not overall trust score, since trust grading blends PLI at 0.25 weight with other components)

7. **Added README.md** — Full system architecture documentation for the main repo. Covers all modules, scoring formulas, CLI usage, programmatic API, research context.

### What's next
- Finalize Epistemic Decay paper for Alignment Forum submission
- Integrate FailureModeRegistry (5 failure modes + regulatory mappings) from Base44 handoff
- FastAPI backend assembly
- Base44 3-file fix when Builder plan available
- Organize audit archive for paper evidence

---

## Pre-2026-04-19 — Foundation (Summary)

**Commits on main and earlier branches:**

- **Initial repo setup** — Core AIntegrity modules extracted from architecture documents
- **Project Sentinel test eval suite** — 189 tests covering VIL, trust grading, threat monitoring, PLI, orchestrator, LLM adapter
- **Visual dashboard** — Flask-based dashboard with live metrics (not currently deployed externally)
- **CI pipeline** — pytest + packaging configuration
- **Documentation** — Architecture PDFs, whitepapers moved to `docs/`

---

*This log is maintained across Claude sessions. Each session appends a new dated entry above the previous ones.*
