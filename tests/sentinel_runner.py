#!/usr/bin/env python3
"""
Project Sentinel — Evaluation Metrics Runner
==============================================

Standalone runner that executes the full AIntegrity v4.0 evaluation suite
and produces a structured metrics report aligned with the Sentinel thesis.

Usage:
    python tests/sentinel_runner.py            # Run all metrics
    python tests/sentinel_runner.py --json     # Output JSON report
    python tests/sentinel_runner.py --domain trust   # Run one domain

Eval Thesis — Project Sentinel
-------------------------------
Project Sentinel is the evaluation thesis for AIntegrity v4.0.  Its purpose
is to *verify the verifier*: systematically measuring whether the auditing
framework itself produces correct, consistent, and tamper-evident results
across every measurable surface.

The evaluation is organized into five metric domains:

  Domain                 ID Prefix   Focus
  ─────────────────────  ──────────  ─────────────────────────────────
  Trust Scoring          TRUST-xx    Weighted scoring, decay, grades
  Threat Detection       THREAT-xx   Injection, evasion, drift (PSI)
  Ledger Integrity       VIL-xx      Hash chains, Merkle, signatures
  Orchestrator E2E       ORCH-xx     Session lifecycle, reports
  PLI Engine             PLI-xx      Contradiction & evasion analysis

Each test maps 1-to-1 to a Sentinel metric.  The runner aggregates
pass / fail / skip counts per domain and computes a Sentinel Confidence
Score (SCS):

    SCS = passed / (passed + failed)   [0.0 – 1.0]

An SCS of 1.0 means every metric passed — the auditing framework is
operating within specification.
"""

import argparse
import json
import subprocess
import sys
import os
import re
from datetime import datetime, timezone


DOMAINS = {
    "trust":        {"marker": "trust",        "prefix": "TRUST",  "label": "Trust Scoring"},
    "threat":       {"marker": "threat",       "prefix": "THREAT", "label": "Threat Detection"},
    "vil":          {"marker": "vil",          "prefix": "VIL",    "label": "Ledger Integrity"},
    "orchestrator": {"marker": "orchestrator", "prefix": "ORCH",   "label": "Orchestrator E2E"},
    "pli":          {"marker": "pli",          "prefix": "PLI",    "label": "PLI Engine"},
    "llm":          {"marker": "llm",          "prefix": "LLM",    "label": "LLM Adapter"},
}


def run_pytest_for_marker(marker: str) -> dict:
    """Run pytest with a given marker and return structured results."""
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    cmd = [
        sys.executable, "-m", "pytest",
        "-m", marker,
        "--tb=no",
        "-q",
        "--no-header",
        os.path.join(project_root, "tests"),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=project_root)

    # Parse the summary line, e.g. "42 passed, 1 failed, 2 skipped"
    output = result.stdout + result.stderr
    passed = _extract_count(output, "passed")
    failed = _extract_count(output, "failed")
    skipped = _extract_count(output, "skipped")

    return {
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "total": passed + failed + skipped,
        "exit_code": result.returncode,
        "raw_output": output.strip(),
    }


def _extract_count(text: str, keyword: str) -> int:
    match = re.search(rf"(\d+)\s+{keyword}", text)
    return int(match.group(1)) if match else 0


def compute_sentinel_confidence(domains_results: dict) -> float:
    total_passed = sum(d["passed"] for d in domains_results.values())
    total_failed = sum(d["failed"] for d in domains_results.values())
    denominator = total_passed + total_failed
    return total_passed / denominator if denominator > 0 else 0.0


def grade_scs(scs: float) -> str:
    if scs >= 0.95:
        return "SENTINEL-A"
    elif scs >= 0.85:
        return "SENTINEL-B"
    elif scs >= 0.70:
        return "SENTINEL-C"
    elif scs >= 0.50:
        return "SENTINEL-D"
    else:
        return "SENTINEL-F"


def build_report(domains_results: dict) -> dict:
    scs = compute_sentinel_confidence(domains_results)
    total_passed = sum(d["passed"] for d in domains_results.values())
    total_failed = sum(d["failed"] for d in domains_results.values())
    total_skipped = sum(d["skipped"] for d in domains_results.values())

    return {
        "project": "Project Sentinel",
        "framework": "AIntegrity v4.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "sentinel_confidence_score": round(scs, 4),
        "sentinel_grade": grade_scs(scs),
        "totals": {
            "passed": total_passed,
            "failed": total_failed,
            "skipped": total_skipped,
            "total_metrics": total_passed + total_failed + total_skipped,
        },
        "domains": {
            info["label"]: {
                "id_prefix": info["prefix"],
                "passed": domains_results[name]["passed"],
                "failed": domains_results[name]["failed"],
                "skipped": domains_results[name]["skipped"],
                "domain_score": (
                    round(
                        domains_results[name]["passed"]
                        / max(domains_results[name]["passed"] + domains_results[name]["failed"], 1),
                        4,
                    )
                ),
            }
            for name, info in DOMAINS.items()
        },
    }


def print_report(report: dict):
    print()
    print("=" * 64)
    print("  PROJECT SENTINEL — AIntegrity v4.0 Evaluation Report")
    print("=" * 64)
    print(f"  Timestamp : {report['timestamp_utc']}")
    print(f"  SCS       : {report['sentinel_confidence_score']:.2%}")
    print(f"  Grade     : {report['sentinel_grade']}")
    print("-" * 64)

    totals = report["totals"]
    print(f"  Total Metrics : {totals['total_metrics']}")
    print(f"  Passed        : {totals['passed']}")
    print(f"  Failed        : {totals['failed']}")
    print(f"  Skipped       : {totals['skipped']}")
    print("-" * 64)

    print("  Domain Breakdown:")
    for label, data in report["domains"].items():
        bar = "+" * data["passed"] + "x" * data["failed"] + "." * data["skipped"]
        score_pct = f"{data['domain_score']:.0%}"
        print(f"    [{data['id_prefix']:<7}] {label:<22} {score_pct:>5}  {bar}")

    print("=" * 64)

    if report["sentinel_confidence_score"] >= 0.95:
        print("  VERDICT: All systems nominal. Auditing framework verified.")
    elif report["sentinel_confidence_score"] >= 0.70:
        print("  VERDICT: Partial confidence. Review failing metrics.")
    else:
        print("  VERDICT: Low confidence. Significant regressions detected.")

    print("=" * 64)
    print()


def main():
    parser = argparse.ArgumentParser(description="Project Sentinel — AIntegrity Eval Runner")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    parser.add_argument("--domain", choices=list(DOMAINS.keys()), help="Run single domain")
    args = parser.parse_args()

    targets = {args.domain: DOMAINS[args.domain]} if args.domain else DOMAINS
    domains_results = {}

    for name, info in targets.items():
        if not args.json:
            print(f"  Running {info['label']} ({info['prefix']}-xx)...", flush=True)
        domains_results[name] = run_pytest_for_marker(info["marker"])

    # Fill missing domains with zeros if single-domain run
    for name in DOMAINS:
        if name not in domains_results:
            domains_results[name] = {"passed": 0, "failed": 0, "skipped": 0, "total": 0, "exit_code": -1, "raw_output": ""}

    report = build_report(domains_results)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)

    # Exit with non-zero if any failures
    sys.exit(0 if report["totals"]["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
