# AIntegrity — Cross-Session Handover Document

> **Purpose:** This file exists so any Claude session can load full project context in one read.
> **Rule:** Every session that makes commits MUST update this file before pushing.
> **Last updated:** 2026-04-19

---

## 1. What Is AIntegrity

AIntegrity is a behavioural auditing framework for AI systems. It detects logical inconsistency, evasion, hallucination, and epistemic decay in LLM outputs through automated multi-layer analysis.

**Author:** Steven Dark, Independent AI Safety Researcher, Aberdeen, Scotland.

**Academic foundation:** Epistemic Decay in Agentic AI Systems (Dark, 2026) — see `Epistemic_Decay_v2.pdf` in repo root. Central thesis: *alignment presupposes epistemology*. A perfectly aligned system operating on corrupted context will faithfully pursue a corrupted goal.

---

## 2. Repository Structure

```
AIntegrity-New/
├── aintegrity/
│   ├── __init__.py
│   ├── audit.py                    # CLI audit runner (--canary, --user/--ai, --interactive)
│   ├── orchestrator.py             # AIntegrityCoreV4 — main orchestrator
│   ├── core/
│   │   ├── data_structures.py      # AuditEvent, EventType, ContentBlock, SessionSummary
│   │   └── vil.py                  # Verifiable Interaction Ledger (hash chain + Merkle tree)
│   ├── modules/
│   │   ├── pli_analyzer.py         # Three-layer PLI engine (L1 regex + L2 LLM + L3 dynamic)
│   │   ├── llm_adapter.py          # LLM abstraction (OpenAI, Anthropic, Echo backends)
│   │   ├── trust_grader.py         # TrustGradingEngineV4 — weighted trust scoring
│   │   ├── threat_monitor.py       # AdversarialThreatMonitor — injection/evasion detection
│   │   └── multimodal_verifier.py  # Visual consistency + media integrity (optional)
│   └── dashboard/
│       └── app.py                  # Flask dashboard (not currently deployed)
├── tests/
│   ├── conftest.py                 # Shared fixtures, CRYPTO_OK flag
│   ├── test_eval_pli.py            # Original PLI tests
│   ├── test_eval_pli_analyzer.py   # PLI integration eval (PLIA-01 to PLIA-10)
│   ├── test_eval_pli_enhanced.py   # Enhanced PLI eval (L1-ENH, L2, L3, CANARY, BM)
│   ├── test_eval_orchestrator.py   # Orchestrator integration tests
│   ├── test_eval_vil.py            # VIL chain integrity tests
│   ├── test_eval_trust.py          # Trust grading tests
│   ├── test_eval_threat.py         # Threat monitor tests
│   ├── test_eval_llm_adapter.py    # LLM adapter tests
│   └── sentinel_runner.py          # Custom test runner
├── docs/                           # Architecture PDFs and whitepapers
├── Epistemic_Decay_v2.pdf          # Academic paper (draft, targeting Alignment Forum)
├── AIntegrity_DevLog_April5_2026.pdf  # Dev log documenting Base44 v4.1.0 breakage
├── pyproject.toml                  # Package config
└── requirements.txt                # Dependencies
```

---

## 3. Architecture — Current State

### PLI Engine (Three-Layer Pipeline)
**File:** `aintegrity/modules/pli_analyzer.py`

| Layer | Method | What It Does |
|-------|--------|--------------|
| L1 (Regex) | `_detect_enhanced_patterns()` | Fast pattern matching: hedging, circular reasoning, meta-apology, false authority, deflection, self-contradiction. Also original cross-turn contradiction + evasion detection. |
| L2 (LLM) | `_run_dual_pass()` | Dual-pass semantic analysis. Pass 1 (OBSERVE): structured fallacy/factual-error detection. Pass 2 (VERIFY): independent verification. Variance between passes is itself a signal. Only fires when `llm_adapter` is provided. |
| L3 (Dynamic) | `_build_logic_profile()` | Builds a `LogicProfile` from L1 findings to steer L2 prompts. Maps hedging→commitment_evasion focus, circular→adversarial interrogation, etc. |

**Scoring:** L2 overrides L1 when findings present. Blends 0.3*L1 + 0.7*L2 when L2 is clean. L1-only when no LLM adapter.

**Severity penalties:** critical=0.30, high=0.20, moderate=0.10, low=0.05

**Behavioral metrics:** CFR (Confabulation Rate), RR (Refusal Rate), AD (Admission Detection)

### Orchestrator
**File:** `aintegrity/orchestrator.py`

`AIntegrityCoreV4` coordinates: VIL (audit trail) → PLI (logical analysis) → Trust Grading → Threat Monitor → optional Multimodal Verifiers. `process_turn(user_text, model_text)` is the main entry point.

### Trust Grading
**File:** `aintegrity/modules/trust_grader.py`

Weighted scoring: logical_consistency (0.25) + other components defaulting to 1.0. PLI consistency_score feeds logical_consistency weight.

### VIL (Verifiable Interaction Ledger)
**File:** `aintegrity/core/vil.py`

SHA-256 hash chain with Merkle tree anchoring. Each event gets a cryptographic hash linked to the previous event. Session sealing produces a Merkle root.

### CLI Audit Runner
**File:** `aintegrity/audit.py`

```bash
python -m aintegrity.audit --canary                    # Built-in canary test
python -m aintegrity.audit --canary --provider echo    # With simulated LLM
python -m aintegrity.audit --user "Q" --ai "A"         # Single turn
python -m aintegrity.audit --interactive               # Multi-turn session
python -m aintegrity.audit --canary --provider openai  # Real LLM (needs OPENAI_API_KEY)
```

### LLM Adapter
**File:** `aintegrity/modules/llm_adapter.py`

Supports: `openai`, `anthropic`, `echo` (test backend). `LLMAdapter.create(provider, **kwargs)` factory method.

---

## 4. Test Suite Status

**217 passed, 2 skipped** (as of 2026-04-19)

Run: `python -m pytest tests/ -q`

Canary test: user="What is the opposite of light", ai="The opposite of light is silence" → expected score <20/100, Grade E, 2+ fallacies, 2 interrogations.

---

## 5. Key Design Decisions

- **Backward compatible:** All original test expectations preserved after PLI rewrite. New fields added alongside, never replacing.
- **No LLM required for basic operation:** L1 regex layer works standalone. L2/L3 activate only when adapter provided.
- **Echo backend for testing:** Deterministic LLM simulation via pre-configured JSON responses. Zero API credit cost.
- **VIL crypto optional:** `conftest.py` has `CRYPTO_OK` flag; tests skip crypto verification when dependencies unavailable.

---

## 6. What's Been Built (Completed)

- [x] Core orchestrator with VIL, trust grading, threat monitoring
- [x] Three-layer PLI engine (L1 regex + L2 LLM dual-pass + L3 dynamic prompting)
- [x] LLM adapter layer (OpenAI, Anthropic, Echo backends)
- [x] CLI audit runner with canary test
- [x] 217-test evaluation suite (all passing)
- [x] Epistemic Decay paper (v2 draft)
- [x] README.md with full system architecture documentation

---

## 7. What's Pending

- [ ] **Epistemic Decay paper finalization** — fill citation gap (Section 2.1, 80-90% figure), lead with quantitative data (Example 3), tighten within-session vs cross-session distinction, publish to Alignment Forum
- [ ] **FailureModeRegistry integration** — 5 failure modes with regulatory mappings (EU AI Act, NIST RMF, ISO 42001, OWASP) from Base44 handoff. Entities: PLISessionMetrics, RegulatoryFinding, PLIAggregateMetrics
- [ ] **FastAPI backend** — Step 4 from April 5 dev log. Sovereign Python backend for the 24-module architecture
- [ ] **Base44 PLI fix** — v4.1.0-refactored has Python module (SentenceTransformer/cos_sim) incorrectly fed into JS. Needs Builder plan to fix 3 files: NewAudit.jsx, pli-engine.js, orchestrator.js
- [ ] **Audit archive organization** — Months of daily audit transcripts, screenshots, videos need organizing by model/date/session-type for paper evidence
- [ ] **PLI methodology paper** (Dark 2026c) — Formalize the five-state interrogation cycle (CONFRONT, DETECT, COUNTER, ESCALATE, FORCE) as a companion publication

---

## 8. Base44 Context (Frontend)

Base44 is a JS/React frontend (InvokeLLM-based). The Python repo is the sovereign backend.

**Architecture boundary:** Base44 handles UI and entity management. Python handles all analysis, PLI, trust scoring, VIL.

**Current Base44 state:** v4.1.0-refactored is broken — Python SentenceTransformer code was fed into JS Builder. Needs 3-file fix when Steven gets Builder plan.

**Entity schemas designed (on Base44 side):**
- PLISessionMetrics, RegulatoryFinding, PLIAggregateMetrics
- FailureModeRegistry with 5 failure modes
- Regulatory mappings: EU AI Act Art. 15/50, NIST RMF GV-1.2/MG-3.1, ISO 42001 A.6.2.6, OWASP LLM06

---

## 9. Running Locally (Steven's PC)

**Hardware:** AMD 7800X3D, RTX 4070Ti Super, 64GB RAM, 2x4TB NVMe

```bash
git clone <repo-url>
cd AIntegrity-New
pip install -e .
python -m pytest tests/ -q                              # Run all tests (no API key needed)
python -m aintegrity.audit --canary --provider echo     # Canary with simulated LLM
OPENAI_API_KEY=sk-... python -m aintegrity.audit --canary --provider openai  # Real LLM
```

---

## 10. Session Update Protocol

**Every Claude session that makes commits must:**
1. Update Section 4 (test counts) if tests changed
2. Update Section 6 (completed) if features were finished
3. Update Section 7 (pending) if tasks changed
4. Update the DEVLOG.md with what was done
5. Update "Last updated" date at the top
6. Commit this file alongside code changes
