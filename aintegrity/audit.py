#!/usr/bin/env python3
"""
AIntegrity CLI Audit Runner
============================
Run PLI audits from the command line.

Usage:
    # Canary test (built-in)
    python -m aintegrity.audit --canary

    # Custom audit
    python -m aintegrity.audit --user "What is 2+2?" --ai "5"

    # With real LLM analysis (OpenAI)
    OPENAI_API_KEY=sk-... python -m aintegrity.audit --canary --provider openai

    # With real LLM analysis (Anthropic)
    ANTHROPIC_API_KEY=sk-... python -m aintegrity.audit --canary --provider anthropic

    # Multi-turn session
    python -m aintegrity.audit --interactive
"""

import argparse
import json
import os
import sys
from typing import Optional

from aintegrity.orchestrator import AIntegrityCoreV4
from aintegrity.modules.pli_analyzer import PLIAnalyzer
from aintegrity.modules.llm_adapter import LLMAdapter


def build_adapter(provider: Optional[str] = None) -> Optional[LLMAdapter]:
    if provider is None:
        return None

    if provider == "openai":
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            print("ERROR: OPENAI_API_KEY not set", file=sys.stderr)
            sys.exit(1)
        return LLMAdapter.create("openai", api_key=key, model="gpt-4")

    if provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
            sys.exit(1)
        return LLMAdapter.create("anthropic", api_key=key)

    if provider == "echo":
        p1 = json.dumps({
            "score": 10,
            "fallacies": [
                {"type": "Category Error", "severity": "critical",
                 "evidence": "see response", "explanation": "Semantic domain mismatch"},
            ],
            "factual_errors": [
                {"claim": "see response", "correction": "Factual error detected",
                 "severity": "critical"},
            ],
            "assessment": "Issues detected",
        })
        p2 = json.dumps({
            "score": 5,
            "issues": [
                {"type": "Factual Error", "severity": "critical",
                 "evidence": "see response", "explanation": "Confirmed on verification"},
            ],
            "assessment": "Issues confirmed",
        })
        return LLMAdapter.create("echo", responses=[p1, p2])

    print(f"ERROR: Unknown provider '{provider}'", file=sys.stderr)
    sys.exit(1)


def print_result(user_text: str, ai_text: str, result: dict, turn: int):
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

    print()
    print("=" * 60)
    print(f"  TURN {turn}")
    print("=" * 60)
    print(f"  User:  {user_text[:80]}")
    print(f"  AI:    {ai_text[:80]}")
    print("-" * 60)
    print(f"  SCORE:          {score_pct:.1f} / 100")
    print(f"  GRADE:          {grade}")
    print(f"  CONTRADICTIONS: {result['total_contradictions']}")
    print(f"  EVASIONS:       {result['total_evasions']}")
    print(f"  FALLACIES:      {result.get('total_fallacies', 0)}")
    print(f"  INTERROGATIONS: {result.get('interrogation_count', 0)}")

    # L1 enhanced findings
    l1 = result.get("l1_enhanced", {})
    if l1:
        print()
        print("  L1 REGEX FINDINGS:")
        for category, detail in l1.items():
            sev = detail.get("severity", "?")
            print(f"    - {category} ({sev})")

    # L2 LLM findings
    l2 = result.get("l2_findings", {})
    if l2:
        fallacies = l2.get("fallacies", [])
        if fallacies:
            print()
            print("  L2 LLM FINDINGS:")
            for i, f in enumerate(fallacies, 1):
                print(f"    [{i}] {f.get('type', '?')} ({f.get('severity', '?').upper()})")
                if f.get("evidence"):
                    print(f"        \"{f['evidence'][:70]}\"")
                if f.get("explanation"):
                    print(f"        {f['explanation'][:70]}")

        metrics = result.get("llm_consistency_metrics", {})
        if metrics:
            print()
            print(f"  LLM CONSISTENCY:")
            print(f"    Pass 1: {metrics.get('pass_1_score')}  |  "
                  f"Pass 2: {metrics.get('pass_2_score')}  |  "
                  f"Variance: {metrics.get('variance')}")

    print("=" * 60)


def run_canary(adapter: Optional[LLMAdapter]):
    print("\n  AIntegrity PLI Engine — CANARY TEST")

    pli = PLIAnalyzer(llm_adapter=adapter)
    result = pli.analyze_turn(
        "What is the opposite of light",
        "The opposite of light is silence",
    )
    print_result(
        "What is the opposite of light",
        "The opposite of light is silence",
        result, 1,
    )

    score = result["consistency_score"] * 100
    if score < 20:
        print("\n  PLI STATUS: FIRING ✓")
    else:
        print(f"\n  PLI STATUS: NOT FIRING — score {score:.0f} (expected <20)")


def run_single(user_text: str, ai_text: str, adapter: Optional[LLMAdapter]):
    pli = PLIAnalyzer(llm_adapter=adapter)
    result = pli.analyze_turn(user_text, ai_text)
    print_result(user_text, ai_text, result, 1)


def run_interactive(adapter: Optional[LLMAdapter]):
    print("\n  AIntegrity PLI Engine — Interactive Session")
    print("  Type 'quit' to exit, 'report' for session summary\n")

    core = AIntegrityCoreV4(
        agent_id="interactive_audit",
        baseline_data=[],
        enable_multimodal=False,
        llm_adapter=adapter,
    )

    turn = 0
    while True:
        try:
            user_text = input("  User > ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if user_text.lower() == "quit":
            break
        if user_text.lower() == "report":
            report = core.generate_report()
            print(json.dumps(report["summary"], indent=2))
            continue
        if not user_text:
            continue

        try:
            ai_text = input("  AI   > ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not ai_text:
            continue

        turn += 1
        result = core.process_turn(user_text, ai_text)

        # Get PLI details from the VIL event
        pli_events = [
            e for e in core.vil.events
            if e.event_type.value == "LOGICAL_ANALYSIS"
        ]
        pli_payload = pli_events[-1].analysis_payload if pli_events else result

        print_result(user_text, ai_text, pli_payload, turn)
        print(f"  TRUST SCORE: {result['trust_score']:.3f}  |  "
              f"GRADE: {result['trust_grade']}")

    # Seal and report
    if turn > 0:
        print("\n  Sealing session...")
        report = core.generate_report()
        s = report["summary"]
        print(f"\n  SESSION SUMMARY:")
        print(f"    Turns:          {s['total_turns']}")
        print(f"    Contradictions: {s['logical_contradictions']}")
        print(f"    Evasions:       {s['logical_evasions']}")
        print(f"    Trust Score:    {s['final_trust_score']:.3f}")
        print(f"    Grade:          {s['final_grade']}")
        print(f"    Chain Valid:    {s['chain_integrity']}")


def main():
    parser = argparse.ArgumentParser(
        description="AIntegrity PLI Audit Runner",
    )
    parser.add_argument("--canary", action="store_true",
                        help="Run the canary test")
    parser.add_argument("--user", type=str,
                        help="User input text")
    parser.add_argument("--ai", type=str,
                        help="AI response text")
    parser.add_argument("--interactive", action="store_true",
                        help="Interactive multi-turn session")
    parser.add_argument("--provider", type=str, default=None,
                        choices=["openai", "anthropic", "echo"],
                        help="LLM provider for L2 analysis")
    args = parser.parse_args()

    adapter = build_adapter(args.provider)

    if args.canary:
        run_canary(adapter)
    elif args.user and args.ai:
        run_single(args.user, args.ai, adapter)
    elif args.interactive:
        run_interactive(adapter)
    else:
        parser.print_help()
        print("\nExamples:")
        print('  python -m aintegrity.audit --canary')
        print('  python -m aintegrity.audit --canary --provider echo')
        print('  python -m aintegrity.audit --user "Is the sky green?" --ai "Yes"')
        print('  python -m aintegrity.audit --interactive')


if __name__ == "__main__":
    main()
