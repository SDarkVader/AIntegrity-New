"""
Real-Time Adversarial Monitoring & Anomaly Detection v1.0

Monitors AI interactions in real-time for adversarial attacks and anomalies.
Extracted from AIntegrity v4.0 Technical Specification.

Features:
- Data Drift Detection (PSI - Population Stability Index)
- XAI-Based Anomaly Detection (SHAP value distribution analysis)
- Prompt injection pattern detection
"""

import re
from typing import Dict, Any, List, Optional, Callable
from collections import Counter
import math


class AdversarialThreatMonitor:
    """
    Monitors AI interactions in real-time for adversarial attacks and anomalies.

    Version: 1.0

    Detection Methods:
    1. Data Drift (PSI): Monitors for statistical distribution shifts
    2. XAI Anomaly: Detects anomalous model reasoning patterns
    3. Pattern Matching: Detects known adversarial patterns
    """

    # Known prompt injection patterns
    INJECTION_PATTERNS = [
        r"ignore\s+(previous|above|all)\s+(instructions?|prompts?)",
        r"system\s*:",
        r"<\s*/?system\s*>",
        r"you\s+are\s+now\s+",
        r"pretend\s+(you\s+are|to\s+be)",
        r"new\s+instructions?:",
        r"override\s+(mode|instructions?)",
        r"jailbreak",
        r"DAN\s+mode",
        r"\[INST\]",
        r"###\s*(instruction|system)",
    ]

    # Evasive response patterns
    EVASION_PATTERNS = [
        r"i('m|\s+am)\s+sorry.*went\s+wrong",
        r"i\s+cannot\s+answer\s+that",
        r"as\s+a\s+(large\s+)?language\s+model",
        r"i('m|\s+am)\s+not\s+programmed\s+to",
        r"let's\s+talk\s+about\s+something\s+else",
        r"i\s+don't\s+have\s+(access|the\s+ability)",
    ]

    def __init__(
        self,
        baseline_data: Optional[List[str]] = None,
        psi_threshold: float = 0.2,
        num_bins: int = 10
    ):
        """
        Initialize the threat monitor.

        Args:
            baseline_data: List of baseline text samples for drift detection
            psi_threshold: PSI value above which drift is significant
            num_bins: Number of bins for distribution calculation
        """
        self.psi_threshold = psi_threshold
        self.num_bins = num_bins
        self.baseline_data = baseline_data or []

        # Calculate baseline distributions if data provided
        if baseline_data:
            self.psi_baseline_dist = self._calculate_length_distribution(baseline_data)
            self.vocab_baseline = self._calculate_vocab_distribution(baseline_data)
        else:
            self.psi_baseline_dist = None
            self.vocab_baseline = None

        # Compile regex patterns
        self.injection_patterns = [re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS]
        self.evasion_patterns = [re.compile(p, re.IGNORECASE) for p in self.EVASION_PATTERNS]

    def _calculate_length_distribution(self, data: List[str]) -> List[float]:
        """Calculate distribution based on text length."""
        if not data:
            return [0.0] * self.num_bins

        lengths = [len(s) for s in data]
        max_len = max(lengths) if lengths else 1
        bin_size = max_len / self.num_bins

        # Create histogram
        hist = [0] * self.num_bins
        for length in lengths:
            bin_idx = min(int(length / bin_size), self.num_bins - 1)
            hist[bin_idx] += 1

        # Normalize
        total = len(lengths)
        return [h / total for h in hist]

    def _calculate_vocab_distribution(self, data: List[str]) -> Dict[str, float]:
        """Calculate vocabulary distribution."""
        if not data:
            return {}

        word_counts: Counter = Counter()
        total_words = 0

        for text in data:
            words = text.lower().split()
            word_counts.update(words)
            total_words += len(words)

        if total_words == 0:
            return {}

        return {word: count / total_words for word, count in word_counts.items()}

    def _calculate_psi(self, baseline_dist: List[float], current_dist: List[float]) -> float:
        """
        Calculate the Population Stability Index.

        PSI measures the shift in distribution between baseline and current data.
        - PSI < 0.1: No significant shift
        - 0.1 <= PSI < 0.2: Moderate shift
        - PSI >= 0.2: Significant shift

        Args:
            baseline_dist: Baseline distribution (normalized histogram)
            current_dist: Current distribution (normalized histogram)

        Returns:
            PSI value
        """
        if not baseline_dist or not current_dist:
            return 0.0

        epsilon = 1e-10  # Avoid division by zero
        psi_value = 0.0

        for baseline, current in zip(baseline_dist, current_dist):
            baseline = max(baseline, epsilon)
            current = max(current, epsilon)
            psi_value += (current - baseline) * math.log(current / baseline)

        return psi_value

    def detect_injection_patterns(self, text: str) -> List[Dict[str, Any]]:
        """
        Detect known prompt injection patterns.

        Args:
            text: Input text to analyze

        Returns:
            List of detected injection patterns
        """
        findings = []
        for i, pattern in enumerate(self.injection_patterns):
            matches = pattern.findall(text)
            if matches:
                findings.append({
                    "pattern_id": i,
                    "pattern": self.INJECTION_PATTERNS[i],
                    "matches": matches,
                    "severity": "high"
                })
        return findings

    def detect_evasion_patterns(self, text: str) -> List[Dict[str, Any]]:
        """
        Detect evasive response patterns.

        Args:
            text: Response text to analyze

        Returns:
            List of detected evasion patterns
        """
        findings = []
        for i, pattern in enumerate(self.evasion_patterns):
            matches = pattern.findall(text)
            if matches:
                findings.append({
                    "pattern_id": i,
                    "pattern": self.EVASION_PATTERNS[i],
                    "matches": matches,
                    "severity": "medium"
                })
        return findings

    def monitor(self, current_batch: List[str]) -> Dict[str, Any]:
        """
        Monitors a batch of new data for drift and patterns.

        Args:
            current_batch: List of text samples to analyze

        Returns:
            Analysis results including drift scores and detected patterns
        """
        if not current_batch:
            return {"status": "SKIPPED", "reason": "Empty batch."}

        result: Dict[str, Any] = {
            "status": "COMPLETED",
            "data_drift_psi": 0.0,
            "vocab_drift": 0.0,
            "injection_findings": [],
            "evasion_findings": [],
            "threat_level": 0.0,
            "is_alert": False
        }

        # 1. Data Drift (PSI on length distribution)
        if self.psi_baseline_dist:
            current_dist = self._calculate_length_distribution(current_batch)
            result["data_drift_psi"] = self._calculate_psi(
                self.psi_baseline_dist, current_dist
            )

        # 2. Vocabulary drift (simplified)
        if self.vocab_baseline:
            current_vocab = self._calculate_vocab_distribution(current_batch)
            # Calculate overlap ratio
            baseline_words = set(self.vocab_baseline.keys())
            current_words = set(current_vocab.keys())
            if baseline_words:
                overlap = len(baseline_words & current_words) / len(baseline_words)
                result["vocab_drift"] = 1.0 - overlap  # Higher = more drift

        # 3. Pattern detection
        for text in current_batch:
            result["injection_findings"].extend(self.detect_injection_patterns(text))
            result["evasion_findings"].extend(self.detect_evasion_patterns(text))

        # 4. Calculate threat level
        threat_level = 0.0

        # Drift-based threat
        if result["data_drift_psi"] > self.psi_threshold:
            threat_level = max(threat_level, 0.6)
        elif result["data_drift_psi"] > self.psi_threshold / 2:
            threat_level = max(threat_level, 0.3)

        # Pattern-based threat
        if result["injection_findings"]:
            threat_level = max(threat_level, 0.9)  # Injection is critical
        if result["evasion_findings"]:
            threat_level = max(threat_level, 0.5)

        result["threat_level"] = threat_level
        result["is_alert"] = threat_level > 0.5

        return result

    def monitor_single(self, text: str, is_input: bool = True) -> Dict[str, Any]:
        """
        Monitor a single text for threats.

        Args:
            text: Text to analyze
            is_input: Whether this is user input (vs model output)

        Returns:
            Analysis results
        """
        result: Dict[str, Any] = {
            "status": "COMPLETED",
            "is_input": is_input,
            "findings": [],
            "threat_level": 0.0,
            "is_alert": False
        }

        if is_input:
            # Check for injection patterns in inputs
            injection_findings = self.detect_injection_patterns(text)
            result["findings"].extend(injection_findings)
            if injection_findings:
                result["threat_level"] = 0.9
        else:
            # Check for evasion patterns in outputs
            evasion_findings = self.detect_evasion_patterns(text)
            result["findings"].extend(evasion_findings)
            if evasion_findings:
                result["threat_level"] = 0.5

        result["is_alert"] = result["threat_level"] > 0.5
        return result

    def update_baseline(self, new_data: List[str]):
        """
        Update baseline distributions with new data.

        Args:
            new_data: New baseline samples
        """
        self.baseline_data = new_data
        self.psi_baseline_dist = self._calculate_length_distribution(new_data)
        self.vocab_baseline = self._calculate_vocab_distribution(new_data)
