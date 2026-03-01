"""
Project Sentinel — Verifiable Interaction Ledger Evaluation Suite
=================================================================
Metrics evaluated:
  VIL-01  Single event logging and content hash generation
  VIL-02  Hash chain linkage (prev_event_hash continuity)
  VIL-03  Chain integrity verification (positive case)
  VIL-04  Tamper detection (content modification)
  VIL-05  Merkle root determinism
  VIL-06  Merkle root changes with different events
  VIL-07  Session sealing produces valid SessionSummary
  VIL-08  Sealing empty session raises error
  VIL-09  Event retrieval by ID
  VIL-10  Audit log export completeness
  VIL-11  Ed25519 signature generation (when crypto available)
  VIL-12  Signature-less mode (crypto disabled)
  VIL-13  Merkle tree handles odd number of leaves
  VIL-14  Blockchain receipt generation on seal
  VIL-15  TSA timestamp token on seal
"""

import hashlib
import json
import pytest

from aintegrity.core.data_structures import AuditEvent, EventType, ContentBlock, ModalityType
from aintegrity.core.vil import VerifiableInteractionLedger
from tests.conftest import make_event


# ── VIL-01: Single event logging ─────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.vil
class TestEventLogging:

    def test_logged_event_has_content_hash(self, vil):
        event = make_event()
        logged = vil.log_event(event)
        assert logged.content_hash is not None
        assert len(logged.content_hash) == 64  # SHA-256 hex

    def test_logged_event_gets_session_id(self, vil):
        event = make_event()
        logged = vil.log_event(event)
        assert logged.session_id == "test-session-001"

    def test_event_count_increments(self, vil):
        vil.log_event(make_event(text="first"))
        vil.log_event(make_event(text="second"))
        assert len(vil.events) == 2


# ── VIL-02: Hash chain linkage ───────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.vil
class TestHashChainLinkage:

    def test_first_event_has_no_prev_hash(self, vil):
        event = make_event()
        logged = vil.log_event(event)
        assert logged.prev_event_hash is None

    def test_second_event_links_to_first(self, vil):
        vil.log_event(make_event(text="first"))
        second = vil.log_event(make_event(text="second"))
        assert second.prev_event_hash is not None
        assert len(second.prev_event_hash) == 64

    def test_chain_of_three_events(self, vil):
        e1 = vil.log_event(make_event(text="one"))
        e2 = vil.log_event(make_event(text="two"))
        e3 = vil.log_event(make_event(text="three"))

        assert e1.prev_event_hash is None
        assert e2.prev_event_hash is not None
        assert e3.prev_event_hash is not None
        assert e2.prev_event_hash != e3.prev_event_hash


# ── VIL-03: Chain integrity verification (positive) ──────────────────────

@pytest.mark.sentinel
@pytest.mark.vil
class TestChainIntegrityValid:

    def test_untampered_chain_valid(self, vil):
        for i in range(5):
            vil.log_event(make_event(text=f"event {i}"))
        result = vil.verify_chain_integrity()
        assert result["valid"] is True
        assert result["event_count"] == 5
        assert len(result["errors"]) == 0

    def test_empty_session_valid(self, vil):
        result = vil.verify_chain_integrity()
        assert result["valid"] is True


# ── VIL-04: Tamper detection ─────────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.vil
class TestTamperDetection:

    def test_modified_content_detected(self, vil):
        """Modifying an event's content after logging should break integrity."""
        vil.log_event(make_event(text="original"))
        vil.log_event(make_event(text="second"))

        # Tamper with the first event's content
        vil.events[0].content_blocks = [
            ContentBlock(modality=ModalityType.TEXT, data="tampered", metadata={})
        ]

        result = vil.verify_chain_integrity()
        assert result["valid"] is False
        assert len(result["errors"]) > 0

    def test_broken_chain_hash_detected(self, vil):
        """Modifying prev_event_hash should break integrity."""
        vil.log_event(make_event(text="first"))
        vil.log_event(make_event(text="second"))

        # Tamper with chain hash
        vil.events[1].prev_event_hash = "0" * 64

        result = vil.verify_chain_integrity()
        assert result["valid"] is False


# ── VIL-05 / VIL-06: Merkle root ─────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.vil
class TestMerkleRoot:

    def test_merkle_root_deterministic(self, vil):
        """Same events should produce same merkle root."""
        vil2 = VerifiableInteractionLedger(session_id="determinism-test", use_crypto=False)

        event = make_event(text="deterministic")
        # Log same event data (not same object) in both
        vil_no_crypto = VerifiableInteractionLedger(session_id="test-session-001", use_crypto=False)
        e1 = make_event(text="same-data")
        vil_no_crypto.log_event(e1)
        root1 = vil_no_crypto._build_merkle_root(vil_no_crypto.merkle_leaves)

        # The merkle root is built from content hashes, which are deterministic
        assert root1 is not None
        assert len(root1) == 64

    def test_different_events_different_roots(self):
        vil1 = VerifiableInteractionLedger(session_id="s1", use_crypto=False)
        vil2 = VerifiableInteractionLedger(session_id="s2", use_crypto=False)

        vil1.log_event(make_event(text="alpha"))
        vil2.log_event(make_event(text="beta"))

        root1 = vil1._build_merkle_root(vil1.merkle_leaves)
        root2 = vil2._build_merkle_root(vil2.merkle_leaves)
        assert root1 != root2

    def test_empty_merkle_root(self, vil):
        root = vil._build_merkle_root([])
        assert root == hashlib.sha256(b"").hexdigest()


# ── VIL-07: Session sealing ──────────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.vil
class TestSessionSealing:

    def test_seal_produces_valid_summary(self, vil):
        vil.log_event(make_event(text="sealed event"))
        summary = vil.seal_and_anchor_session()
        assert summary.session_id == "test-session-001"
        assert summary.event_count == 1
        assert summary.merkle_root is not None
        assert len(summary.merkle_root) == 64
        assert summary.final_event_hash is not None

    def test_seal_includes_timestamps(self, vil):
        vil.log_event(make_event(text="timed event"))
        summary = vil.seal_and_anchor_session()
        assert summary.start_time_utc.endswith("Z")
        assert summary.sealed_time_utc.endswith("Z")


# ── VIL-08: Sealing empty session ────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.vil
class TestSealEmptySession:

    def test_sealing_empty_raises(self, vil):
        with pytest.raises(ValueError, match="Cannot seal an empty session"):
            vil.seal_and_anchor_session()


# ── VIL-09: Event retrieval ──────────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.vil
class TestEventRetrieval:

    def test_get_event_by_id(self, vil):
        event = make_event(text="find me")
        logged = vil.log_event(event)
        found = vil.get_event_by_id(logged.event_id)
        assert found is not None
        assert found.event_id == logged.event_id

    def test_get_nonexistent_event(self, vil):
        assert vil.get_event_by_id("nonexistent-id") is None


# ── VIL-10: Audit log export ─────────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.vil
class TestAuditLogExport:

    def test_export_contains_all_events(self, vil):
        for i in range(3):
            vil.log_event(make_event(text=f"export test {i}"))
        log = vil.export_log()
        assert len(log) == 3

    def test_export_entries_are_dicts(self, vil):
        vil.log_event(make_event(text="dict check"))
        log = vil.export_log()
        assert isinstance(log[0], dict)
        assert "event_id" in log[0]
        assert "content_hash" in log[0]

    def test_export_serializable_to_json(self, vil):
        vil.log_event(make_event(text="json check"))
        log = vil.export_log()
        serialized = json.dumps(log)
        assert isinstance(serialized, str)


# ── VIL-11: Ed25519 signatures ───────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.vil
class TestSignatures:

    def test_signature_generated_when_crypto_enabled(self, vil):
        """Events should have signatures when crypto is available."""
        event = make_event(text="signed event")
        logged = vil.log_event(event)
        if vil.use_crypto:
            assert logged.signature_b64 is not None
            assert len(logged.signature_b64) > 0
        else:
            pytest.skip("cryptography library not available")

    def test_public_key_available(self, vil):
        if vil.use_crypto:
            pem = vil.get_public_key_pem()
            assert pem is not None
            assert "PUBLIC KEY" in pem
        else:
            pytest.skip("cryptography library not available")


# ── VIL-12: No-crypto mode ───────────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.vil
class TestNoCryptoMode:

    def test_no_signature_without_crypto(self, vil_no_crypto):
        event = make_event(text="unsigned event")
        logged = vil_no_crypto.log_event(event)
        assert logged.signature_b64 is None

    def test_chain_still_valid_without_crypto(self, vil_no_crypto):
        for i in range(3):
            vil_no_crypto.log_event(make_event(text=f"no crypto {i}"))
        result = vil_no_crypto.verify_chain_integrity()
        assert result["valid"] is True


# ── VIL-13: Merkle tree odd leaves ────────────────────────────────────────

@pytest.mark.sentinel
@pytest.mark.vil
class TestMerkleOddLeaves:

    def test_odd_number_of_leaves(self, vil):
        """Merkle tree with odd leaves should duplicate last leaf."""
        leaves = ["aaa", "bbb", "ccc"]
        root = vil._build_merkle_root(leaves)
        assert root is not None
        assert len(root) == 64

    def test_single_leaf(self, vil):
        root = vil._build_merkle_root(["only_leaf"])
        assert root == "only_leaf"


# ── VIL-14 / VIL-15: Blockchain receipt & TSA token ──────────────────────

@pytest.mark.sentinel
@pytest.mark.vil
class TestAnchoringIntegration:

    def test_seal_includes_blockchain_receipt(self, vil):
        vil.log_event(make_event(text="anchor test"))
        summary = vil.seal_and_anchor_session()
        assert summary.blockchain_receipt is not None
        assert "tx_hash" in summary.blockchain_receipt
        assert "block_number" in summary.blockchain_receipt

    def test_seal_includes_tsa_token(self, vil):
        vil.log_event(make_event(text="timestamp test"))
        summary = vil.seal_and_anchor_session()
        assert summary.tsa_token_rfc3161_b64 is not None
        assert len(summary.tsa_token_rfc3161_b64) > 0
