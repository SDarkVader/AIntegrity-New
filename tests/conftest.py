"""
Project Sentinel — Shared Fixtures & Test Infrastructure
=========================================================
Provides reusable fixtures for the AIntegrity v4.0 evaluation suite.
"""

import sys
import os
import pytest

# Ensure project root is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from aintegrity.core.data_structures import (
    AuditEvent,
    EventType,
    ContentBlock,
    ModalityType,
)
from aintegrity.core.vil import VerifiableInteractionLedger
from aintegrity.modules.trust_grader import TrustDecayModel, TrustGradingEngineV4
from aintegrity.modules.threat_monitor import AdversarialThreatMonitor
from aintegrity.orchestrator import AIntegrityCoreV4


# ---------------------------------------------------------------------------
# Trust fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def decay_model():
    """Fresh TrustDecayModel with default parameters."""
    return TrustDecayModel()


@pytest.fixture
def trust_engine():
    """Fresh TrustGradingEngineV4 for agent 'test_agent'."""
    return TrustGradingEngineV4(agent_id="test_agent")


# ---------------------------------------------------------------------------
# Threat monitor fixtures
# ---------------------------------------------------------------------------

BASELINE_TEXTS = [
    "The capital of France is Paris.",
    "Water boils at 100 degrees Celsius at sea level.",
    "The Earth revolves around the Sun in approximately 365.25 days.",
    "Python is a high-level programming language.",
    "Machine learning models learn patterns from data.",
    "HTTP stands for Hypertext Transfer Protocol.",
    "The speed of light is approximately 3e8 meters per second.",
    "Neural networks are inspired by biological neurons.",
    "Blockchain is a distributed ledger technology.",
    "Quantum computing uses qubits instead of classical bits.",
]


@pytest.fixture
def threat_monitor():
    """AdversarialThreatMonitor with a stable text baseline."""
    return AdversarialThreatMonitor(baseline_data=BASELINE_TEXTS)


@pytest.fixture
def threat_monitor_no_baseline():
    """AdversarialThreatMonitor without baseline data."""
    return AdversarialThreatMonitor()


# ---------------------------------------------------------------------------
# VIL fixtures
# ---------------------------------------------------------------------------

def _crypto_available():
    """Check if the cryptography library works without panicking."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        key = ed25519.Ed25519PrivateKey.generate()
        key.public_key()
        return True
    except BaseException:
        return False


CRYPTO_OK = _crypto_available()


@pytest.fixture
def vil():
    """Fresh VerifiableInteractionLedger for session 'test-session'."""
    return VerifiableInteractionLedger(session_id="test-session-001", use_crypto=CRYPTO_OK)


@pytest.fixture
def vil_no_crypto():
    """VIL with cryptographic signing disabled."""
    return VerifiableInteractionLedger(session_id="test-session-no-crypto", use_crypto=False)


# ---------------------------------------------------------------------------
# Orchestrator fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def core(capsys, monkeypatch):
    """AIntegrityCoreV4 with multimodal disabled (no heavy deps)."""
    if not CRYPTO_OK:
        # Prevent the VIL inside AIntegrityCoreV4 from attempting crypto
        monkeypatch.setattr(VerifiableInteractionLedger, "_init_crypto", lambda self: None)
    c = AIntegrityCoreV4(
        session_id="sentinel-eval-session",
        agent_id="eval_agent",
        baseline_data=BASELINE_TEXTS,
        enable_multimodal=False,
    )
    if not CRYPTO_OK:
        c.vil.use_crypto = False
    return c


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_event(
    event_type=EventType.USER_INPUT,
    text="test text",
    actor_id="tester",
):
    """Create a minimal AuditEvent for testing."""
    return AuditEvent(
        event_type=event_type,
        actor_id=actor_id,
        content_blocks=[
            ContentBlock(modality=ModalityType.TEXT, data=text, metadata={"length": len(text)})
        ],
        analysis_payload={"test": True},
    )
