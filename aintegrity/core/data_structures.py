"""
Core data structures for AIntegrity v4.0

Extracted from AIntegrity v4.0 Technical Specification.
"""

import json
import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional, Union
import datetime
import uuid


class EventType(Enum):
    """Enumeration of all possible event types in the AIntegrity log."""
    # Core Interaction
    USER_INPUT = "USER_INPUT"
    MODEL_OUTPUT = "MODEL_OUTPUT"

    # Analysis Events
    LOGICAL_ANALYSIS = "LOGICAL_ANALYSIS"
    VISUAL_CONSISTENCY_ANALYSIS = "VISUAL_CONSISTENCY_ANALYSIS"
    MEDIA_INTEGRITY_ANALYSIS = "MEDIA_INTEGRITY_ANALYSIS"
    COMPLIANCE_ANALYSIS = "COMPLIANCE_ANALYSIS"
    CITATION_ANALYSIS = "CITATION_ANALYSIS"
    SESSION_DRIFT_ANALYSIS = "SESSION_DRIFT_ANALYSIS"
    ADVERSARIAL_THREAT_ANALYSIS = "ADVERSARIAL_THREAT_ANALYSIS"

    # Scoring and Remediation
    TRUST_GRADING = "TRUST_GRADING"
    RECONSTRUCTION = "RECONSTRUCTION"

    # System and Governance
    ENFORCEMENT_ACTION = "ENFORCEMENT_ACTION"
    SYSTEM_STATE = "SYSTEM_STATE"


class ModalityType(Enum):
    """Enumeration for content modalities."""
    TEXT = "text"
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"
    CODE = "code"


@dataclass
class ContentBlock:
    """Represents a piece of content with a specific modality."""
    modality: ModalityType
    data: Union[str, bytes]  # Text as string, binary data for others
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data_repr = self.data if isinstance(self.data, str) else self.data.hex()
        return {
            "modality": self.modality.value,
            "data": data_repr,
            "metadata": self.metadata
        }


@dataclass
class ProofPayload:
    """Container for verifiable computation proofs."""
    proof_type: str  # e.g., "ZKP_SNARK_GROTH16", "TEE_INTEL_SGX_QUOTE"
    proof_data: Dict[str, Any]
    verification_key_id: Optional[str] = None


@dataclass
class AuditEvent:
    """Represents a single, verifiable event in an interaction session."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    timestamp_utc: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat() + "Z")
    event_type: EventType = EventType.SYSTEM_STATE
    actor_id: str = "system"  # Can be user DID, agent DID, or module name
    content_blocks: List[ContentBlock] = field(default_factory=list)
    analysis_payload: Dict[str, Any] = field(default_factory=dict)
    parent_event_id: Optional[str] = None

    # Cryptographic elements added by the VIL
    content_hash: Optional[str] = None
    prev_event_hash: Optional[str] = None
    signature_b64: Optional[str] = None
    proof: Optional[ProofPayload] = None

    def to_canonical_dict(self, include_crypto: bool = False) -> Dict[str, Any]:
        """Creates a dictionary representation for hashing and signing."""
        d = {
            "event_id": self.event_id,
            "session_id": self.session_id,
            "timestamp_utc": self.timestamp_utc,
            "event_type": self.event_type.value,
            "actor_id": self.actor_id,
            "content_blocks": [block.to_dict() for block in self.content_blocks],
            "analysis_payload": self.analysis_payload,
            "parent_event_id": self.parent_event_id,
        }
        if include_crypto:
            d["content_hash"] = self.content_hash
            d["prev_event_hash"] = self.prev_event_hash
            d["signature_b64"] = self.signature_b64
            if self.proof:
                d["proof"] = asdict(self.proof)
        return d

    def compute_content_hash(self) -> str:
        """Computes the SHA-256 hash of the canonical event content."""
        payload_to_hash = self.to_canonical_dict(include_crypto=False)
        canonical_str = json.dumps(payload_to_hash, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()


@dataclass
class SessionSummary:
    """Cryptographic summary of a completed and sealed session."""
    schema_version: str = "4.0"
    session_id: str = ""
    event_count: int = 0
    start_time_utc: str = ""
    sealed_time_utc: str = ""
    final_event_hash: str = ""
    merkle_root: str = ""
    signing_key_id: str = ""  # e.g., a DID or public key identifier
    tsa_token_rfc3161_b64: Optional[str] = None  # Trusted Timestamp
    blockchain_receipt: Optional[Dict[str, Any]] = None  # e.g., {"tx_hash": "...", "block_number":...}
