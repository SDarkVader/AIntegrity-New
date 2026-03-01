"""
Project Sentinel Dashboard — Flask Application
================================================
Serves the AIntegrity v4.0 visual dashboard with:
  - Live audit session management
  - Trust score visualization
  - Threat detection feed
  - PLI consistency tracking
  - VIL chain status
  - Sentinel eval suite runner

Usage:
    python -m aintegrity.dashboard.app                # default port 5000
    python -m aintegrity.dashboard.app --port 8080    # custom port
"""

import argparse
import json
import subprocess
import sys
import os
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from flask import Flask, render_template, jsonify, request

# Ensure project root is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from aintegrity.orchestrator import AIntegrityCoreV4
from aintegrity.modules.llm_adapter import LLMAdapter

app = Flask(__name__, template_folder="templates", static_folder="static")

# ---------------------------------------------------------------------------
# Global session state (single-user dashboard)
# ---------------------------------------------------------------------------
_session: Optional[AIntegrityCoreV4] = None
_turn_log: list = []


def _get_or_create_session() -> AIntegrityCoreV4:
    global _session, _turn_log
    if _session is None or not _session.session_active:
        _session = AIntegrityCoreV4(
            agent_id="dashboard_agent",
            enable_multimodal=False,
        )
        _turn_log = []
    return _session


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("dashboard.html")


# ---------------------------------------------------------------------------
# API: Session
# ---------------------------------------------------------------------------

@app.route("/api/session", methods=["GET"])
def api_session_status():
    core = _get_or_create_session()
    status = core.get_session_status()
    status["pli_summary"] = core.pli_analyzer.get_summary()
    return jsonify(status)


@app.route("/api/session/new", methods=["POST"])
def api_new_session():
    global _session, _turn_log
    _session = None
    _turn_log = []
    core = _get_or_create_session()
    return jsonify({"status": "ok", "session_id": core.session_id})


@app.route("/api/session/seal", methods=["POST"])
def api_seal_session():
    core = _get_or_create_session()
    if not core.session_active:
        return jsonify({"error": "Session already sealed"}), 400
    from dataclasses import asdict
    summary = core.seal_session()
    return jsonify({"status": "sealed", "summary": asdict(summary)})


# ---------------------------------------------------------------------------
# API: Audit turns
# ---------------------------------------------------------------------------

@app.route("/api/turn", methods=["POST"])
def api_process_turn():
    core = _get_or_create_session()
    data = request.get_json(force=True)
    user_text = data.get("user_text", "")
    model_text = data.get("model_text", "")

    if not user_text or not model_text:
        return jsonify({"error": "user_text and model_text required"}), 400

    result = core.process_turn(user_text, model_text)
    _turn_log.append({
        "turn": result["turn_number"],
        "user_text": user_text[:200],
        "model_text": model_text[:200],
        "trust_score": result["trust_score"],
        "trust_grade": result["trust_grade"],
        "alerts": result["alerts"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return jsonify(result)


@app.route("/api/turns", methods=["GET"])
def api_turn_history():
    return jsonify(_turn_log)


# ---------------------------------------------------------------------------
# API: Report
# ---------------------------------------------------------------------------

@app.route("/api/report", methods=["GET"])
def api_report():
    core = _get_or_create_session()
    if core.turn_count == 0:
        return jsonify({"error": "No turns processed yet"}), 400
    report = core.generate_report()
    return jsonify(report)


# ---------------------------------------------------------------------------
# API: Integrity
# ---------------------------------------------------------------------------

@app.route("/api/integrity", methods=["GET"])
def api_integrity():
    core = _get_or_create_session()
    return jsonify(core.verify_integrity())


# ---------------------------------------------------------------------------
# API: Sentinel runner
# ---------------------------------------------------------------------------

@app.route("/api/sentinel", methods=["POST"])
def api_run_sentinel():
    """Run the full Sentinel eval suite and return JSON results."""
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    runner_path = os.path.join(project_root, "tests", "sentinel_runner.py")

    try:
        result = subprocess.run(
            [sys.executable, runner_path, "--json"],
            capture_output=True, text=True, cwd=project_root, timeout=120,
        )
        report = json.loads(result.stdout)
        return jsonify(report)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Sentinel run timed out"}), 504
    except (json.JSONDecodeError, Exception) as e:
        return jsonify({"error": str(e), "raw": result.stdout[:500] if 'result' in dir() else ""}), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="AIntegrity Sentinel Dashboard")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    print(f"\n  Project Sentinel Dashboard")
    print(f"  http://{args.host}:{args.port}")
    print()

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
