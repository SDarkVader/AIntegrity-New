"""
Verifiable Interaction Ledger (VIL) v4.0

Manages the creation, cryptographic sealing, and decentralized anchoring of audit events.
Extracted from AIntegrity v4.0 Technical Specification.

Note: Blockchain and TSA integrations use mock implementations by default.
Production deployments should inject real implementations.
"""

import base64
import hashlib
import json
import datetime
from dataclasses import asdict
from typing import List, Dict, Any, Optional

from .data_structures import AuditEvent, SessionSummary


class MockBlockchainClient:
    """Mock blockchain client for development/testing."""

    def anchor_hash(self, data_hash: str) -> Dict[str, Any]:
        """Simulates anchoring a hash to a blockchain."""
        return {
            "tx_hash": hashlib.sha256(data_hash.encode()).hexdigest()[:16],
            "block_number": 12345,
            "network": "mock_network",
            "anchored_at": datetime.datetime.utcnow().isoformat() + "Z"
        }


class MockTSAClient:
    """Mock Timestamp Authority client for development/testing."""

    def get_timestamp_token(self, data: bytes) -> str:
        """Simulates getting a trusted timestamp token."""
        timestamp = datetime.datetime.utcnow().isoformat()
        combined = data + timestamp.encode()
        return base64.b64encode(hashlib.sha256(combined).digest()).decode('utf-8')


class VerifiableInteractionLedger:
    """
    Manages the creation, cryptographic sealing, and decentralized anchoring of audit events.

    Version: 4.0

    This implementation provides:
    - Cryptographic hash chaining of events
    - Digital signatures using Ed25519 (when cryptography library available)
    - Merkle tree construction for session summaries
    - Mock blockchain/TSA integration (inject real clients for production)
    """

    def __init__(
        self,
        session_id: str,
        blockchain_client: Optional[Any] = None,
        tsa_client: Optional[Any] = None,
        use_crypto: bool = True
    ):
        self.session_id = session_id
        self.events: List[AuditEvent] = []
        self.merkle_leaves: List[str] = []
        self.last_event_hash: Optional[str] = None
        self.start_time_utc = datetime.datetime.utcnow().isoformat() + "Z"

        # External service clients (use mocks by default)
        self.blockchain_client = blockchain_client or MockBlockchainClient()
        self.tsa_client = tsa_client or MockTSAClient()

        # Cryptographic key management
        self.use_crypto = use_crypto
        self.private_key = None
        self.public_key = None
        self.key_id = f"session:{session_id[:8]}"

        if use_crypto:
            self._init_crypto()

    def _init_crypto(self):
        """Initialize cryptographic keys if the library is available."""
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives import serialization

            self.private_key = ed25519.Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()

            # Generate key ID from public key
            raw_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            self.key_id = f"did:key:{base64.b85encode(raw_bytes).decode('ascii')[:32]}"
        except BaseException:
            self.use_crypto = False
            print("Warning: cryptography library not available, signatures disabled")

    def get_public_key_pem(self) -> Optional[str]:
        """Returns the public key in PEM format."""
        if not self.public_key:
            return None
        try:
            from cryptography.hazmat.primitives import serialization
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        except Exception:
            return None

    def _sign_hash(self, data_hash: str) -> Optional[str]:
        """Signs a hex digest string with the session's private key."""
        if not self.private_key:
            return None
        try:
            signature = self.private_key.sign(bytes.fromhex(data_hash))
            return base64.b64encode(signature).decode('utf-8')
        except Exception:
            return None

    def _build_merkle_root(self, leaves: List[str]) -> str:
        """Builds a Merkle tree and returns the root hash."""
        if not leaves:
            return hashlib.sha256(b"").hexdigest()

        current_level = leaves[:]
        while len(current_level) > 1:
            if len(current_level) % 2 != 0:
                current_level.append(current_level[-1])  # Duplicate last if odd

            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1]
                combined = (left + right).encode('utf-8')
                next_level.append(hashlib.sha256(combined).hexdigest())
            current_level = next_level

        return current_level[0]

    def log_event(self, event: AuditEvent) -> AuditEvent:
        """Processes, seals, and logs a single audit event."""
        event.session_id = self.session_id

        # 1. Chain hash (link to previous event)
        event.prev_event_hash = self.last_event_hash

        # 2. Content hash
        event.content_hash = event.compute_content_hash()

        # 3. Signature (if crypto available)
        if self.use_crypto and self.private_key:
            header_plus_payload_dict = {
                "header": {
                    "alg": "EdDSA",
                    "kid": self.key_id
                },
                "payload": event.to_canonical_dict(include_crypto=False)
            }
            canonical_str = json.dumps(header_plus_payload_dict, sort_keys=True, separators=(",", ":"))
            message_hash = hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()
            event.signature_b64 = self._sign_hash(message_hash)

        # 4. Update ledger state
        self.events.append(event)
        self.merkle_leaves.append(event.content_hash)

        # Hash of full signed event for chain
        full_event_dict = event.to_canonical_dict(include_crypto=True)
        canonical_full = json.dumps(full_event_dict, sort_keys=True, separators=(",", ":"))
        self.last_event_hash = hashlib.sha256(canonical_full.encode('utf-8')).hexdigest()

        return event

    def seal_and_anchor_session(self) -> SessionSummary:
        """Finalizes the session, generates the summary, and anchors it."""
        if not self.events:
            raise ValueError("Cannot seal an empty session.")

        sealed_time_utc = datetime.datetime.utcnow().isoformat() + "Z"
        merkle_root = self._build_merkle_root(self.merkle_leaves)

        summary = SessionSummary(
            session_id=self.session_id,
            event_count=len(self.events),
            start_time_utc=self.start_time_utc,
            sealed_time_utc=sealed_time_utc,
            final_event_hash=self.last_event_hash or "",
            merkle_root=merkle_root,
            signing_key_id=self.key_id
        )

        # Anchor the summary hash
        summary_dict = asdict(summary)
        summary_str = json.dumps(summary_dict, sort_keys=True, separators=(",", ":"))
        summary_hash = hashlib.sha256(summary_str.encode('utf-8')).hexdigest()

        # 1. Get Trusted Timestamp
        summary.tsa_token_rfc3161_b64 = self.tsa_client.get_timestamp_token(summary_hash.encode('utf-8'))

        # 2. Anchor to Blockchain
        summary.blockchain_receipt = self.blockchain_client.anchor_hash(summary_hash)

        return summary

    def verify_chain_integrity(self) -> Dict[str, Any]:
        """Verifies the integrity of the event chain."""
        if not self.events:
            return {"valid": True, "message": "Empty session", "errors": []}

        errors = []
        prev_hash = None

        for i, event in enumerate(self.events):
            # Verify prev_event_hash chain
            if event.prev_event_hash != prev_hash:
                errors.append(f"Event {i} ({event.event_id}): chain hash mismatch")

            # Verify content hash
            computed_hash = event.compute_content_hash()
            if event.content_hash != computed_hash:
                errors.append(f"Event {i} ({event.event_id}): content hash mismatch")

            # Compute hash for next event's prev reference
            full_dict = event.to_canonical_dict(include_crypto=True)
            canonical = json.dumps(full_dict, sort_keys=True, separators=(",", ":"))
            prev_hash = hashlib.sha256(canonical.encode('utf-8')).hexdigest()

        return {
            "valid": len(errors) == 0,
            "event_count": len(self.events),
            "errors": errors
        }

    def get_event_by_id(self, event_id: str) -> Optional[AuditEvent]:
        """Retrieves an event by its ID."""
        for event in self.events:
            if event.event_id == event_id:
                return event
        return None

    def export_log(self) -> List[Dict[str, Any]]:
        """Exports the full event log as a list of dictionaries."""
        return [event.to_canonical_dict(include_crypto=True) for event in self.events]
