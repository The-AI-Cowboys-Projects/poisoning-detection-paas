"""
RAG Document Poisoning Detector
================================

Multi-signal analysis engine for detecting adversarial documents injected
into RAG (Retrieval-Augmented Generation) knowledge bases.

Detection signals:

1. **Cosine deviation** -- how far the document embedding is from the
   baseline centroid of known-clean documents.
2. **Statistical perplexity** -- character and bigram frequency analysis
   that flags machine-generated or adversarially crafted text without
   requiring an LLM.
3. **Semantic coherence** -- sliding-window intra-document consistency
   measured via character-level entropy variance.
4. **N-gram frequency** -- detects anomalous n-gram distributions that
   are hallmarks of adversarial text construction.
5. **Unicode homoglyph detection** -- catches visual-spoofing attacks
   using look-alike characters from non-Latin scripts.
6. **Hidden instruction detection** -- regex-based scan for prompt
   injection patterns, invisible Unicode, base64 payloads, and common
   instruction-override prefixes.
7. **Entropy analysis** -- sliding-window Shannon entropy to locate
   injected segments with abnormal information density.
"""

from __future__ import annotations

import base64
import logging
import math
import re
import time
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import numpy as np
from numpy.typing import NDArray
from scipy.spatial.distance import cosine as cosine_distance

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InstructionType(str, Enum):
    """Category of hidden instruction detected."""
    PROMPT_INJECTION = "prompt_injection"
    INVISIBLE_UNICODE = "invisible_unicode"
    BASE64_PAYLOAD = "base64_payload"
    RTL_OVERRIDE = "rtl_override"
    SPECIAL_TOKEN = "special_token"
    INSTRUCTION_TAG = "instruction_tag"
    ZERO_WIDTH = "zero_width"


@dataclass(frozen=True, slots=True)
class RAGAnalyzerConfig:
    """Configuration for the RAG poisoning detector.

    Attributes:
        cosine_deviation_threshold: Deviation (1 - sim) above which a document
            is flagged.  Default 0.25 corresponds to cosine similarity < 0.75.
        perplexity_z_threshold: Z-score threshold for the statistical
            perplexity metric relative to a reference English distribution.
        coherence_min: Minimum acceptable semantic coherence score (0-1).
        entropy_window_size: Character window for sliding entropy analysis.
        entropy_z_threshold: Z-score threshold for entropy anomalies.
        homoglyph_max_ratio: Maximum fraction of non-ASCII characters before
            flagging (in a predominantly ASCII document).
        ngram_range: Tuple of (min_n, max_n) for n-gram frequency analysis.
    """
    cosine_deviation_threshold: float = 0.25
    perplexity_z_threshold: float = 2.5
    coherence_min: float = 0.60
    entropy_window_size: int = 256
    entropy_z_threshold: float = 2.5
    homoglyph_max_ratio: float = 0.02
    ngram_range: tuple[int, int] = (2, 4)


@dataclass(slots=True)
class HiddenInstruction:
    """A hidden instruction found inside a document.

    Attributes:
        instruction_type: Category of the hidden instruction.
        matched_text: The raw text that matched the detection pattern.
        position: Character offset in the original document.
        decoded_content: For encoded payloads (e.g. base64), the decoded text.
        severity: Assessed severity.
    """
    instruction_type: InstructionType
    matched_text: str
    position: int
    decoded_content: str | None = None
    severity: Severity = Severity.HIGH


@dataclass(slots=True)
class EntropyAnomaly:
    """An entropy anomaly found via sliding-window analysis.

    Attributes:
        start: Character offset of the window start.
        end: Character offset of the window end.
        entropy: Shannon entropy of the window.
        z_score: Z-score relative to the document-wide distribution.
        severity: Assessed severity.
    """
    start: int
    end: int
    entropy: float
    z_score: float
    severity: Severity


@dataclass(slots=True)
class HomoglyphFinding:
    """A homoglyph detection finding.

    Attributes:
        position: Character offset in the document.
        character: The suspicious character.
        unicode_name: Official Unicode name.
        codepoint: Unicode codepoint as hex string.
        lookalike: The ASCII character it visually resembles, if known.
    """
    position: int
    character: str
    unicode_name: str
    codepoint: str
    lookalike: str | None = None


@dataclass(slots=True)
class NGramAnomaly:
    """An anomalous n-gram pattern.

    Attributes:
        ngram: The n-gram string.
        observed_freq: Observed frequency in the document.
        expected_range: Expected frequency range for natural text.
        z_score: Z-score relative to reference distribution.
    """
    ngram: str
    observed_freq: float
    expected_range: tuple[float, float]
    z_score: float


@dataclass(slots=True)
class RAGScanResult:
    """Complete result of a single-document RAG poisoning scan.

    Attributes:
        is_suspicious: Overall verdict -- True if any signal exceeds its
            threshold.
        risk_score: Composite risk score in [0.0, 1.0].
        cosine_deviation: Embedding deviation from baseline centroid.
        statistical_perplexity: Character/bigram perplexity score.
        semantic_coherence: Intra-document consistency score (0-1).
        hidden_instructions: Detected prompt injections / invisible content.
        entropy_anomalies: Segments with abnormal information density.
        homoglyph_findings: Suspicious look-alike characters.
        ngram_anomalies: Anomalous n-gram patterns.
        signals_triggered: List of signal names that exceeded thresholds.
        elapsed_ms: Wall-clock analysis time in milliseconds.
        metadata: Arbitrary caller-supplied metadata echoed back.
    """
    is_suspicious: bool
    risk_score: float
    cosine_deviation: float
    statistical_perplexity: float
    semantic_coherence: float
    hidden_instructions: list[HiddenInstruction]
    entropy_anomalies: list[EntropyAnomaly]
    homoglyph_findings: list[HomoglyphFinding]
    ngram_anomalies: list[NGramAnomaly]
    signals_triggered: list[str]
    elapsed_ms: float
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Compiled patterns (module-level for performance)
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[tuple[re.Pattern[str], InstructionType, Severity]] = [
    (re.compile(r"ignore\s+(previous|all|above|prior)\s+instructions", re.IGNORECASE),
     InstructionType.PROMPT_INJECTION, Severity.CRITICAL),
    (re.compile(r"disregard\s+(all|any|the|your)\s+(previous|prior|above)", re.IGNORECASE),
     InstructionType.PROMPT_INJECTION, Severity.CRITICAL),
    (re.compile(r"you\s+are\s+now\s+(a|an|the)\b", re.IGNORECASE),
     InstructionType.PROMPT_INJECTION, Severity.HIGH),
    (re.compile(r"(system|admin|root)\s*:\s*", re.IGNORECASE),
     InstructionType.PROMPT_INJECTION, Severity.HIGH),
    (re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
     InstructionType.PROMPT_INJECTION, Severity.HIGH),
    (re.compile(r"<\|.*?\|>"),
     InstructionType.SPECIAL_TOKEN, Severity.HIGH),
    (re.compile(r"\[INST\]|\[/INST\]|\[SYS\]|\[/SYS\]", re.IGNORECASE),
     InstructionType.INSTRUCTION_TAG, Severity.HIGH),
    (re.compile(r"###\s*(human|assistant|system|user)\s*:", re.IGNORECASE),
     InstructionType.INSTRUCTION_TAG, Severity.MEDIUM),
    (re.compile(r"<\|im_start\|>|<\|im_end\|>"),
     InstructionType.SPECIAL_TOKEN, Severity.HIGH),
    (re.compile(r"BEGIN\s+(SYSTEM|HIDDEN|SECRET)\s+PROMPT", re.IGNORECASE),
     InstructionType.PROMPT_INJECTION, Severity.CRITICAL),
]

# Zero-width and invisible Unicode characters
_INVISIBLE_CHARS: set[int] = {
    0x200B,  # ZERO WIDTH SPACE
    0x200C,  # ZERO WIDTH NON-JOINER
    0x200D,  # ZERO WIDTH JOINER
    0x200E,  # LEFT-TO-RIGHT MARK
    0x200F,  # RIGHT-TO-LEFT MARK
    0x202A,  # LEFT-TO-RIGHT EMBEDDING
    0x202B,  # RIGHT-TO-LEFT EMBEDDING
    0x202C,  # POP DIRECTIONAL FORMATTING
    0x202D,  # LEFT-TO-RIGHT OVERRIDE
    0x202E,  # RIGHT-TO-LEFT OVERRIDE
    0x2060,  # WORD JOINER
    0x2061,  # FUNCTION APPLICATION
    0x2062,  # INVISIBLE TIMES
    0x2063,  # INVISIBLE SEPARATOR
    0x2064,  # INVISIBLE PLUS
    0xFEFF,  # ZERO WIDTH NO-BREAK SPACE (BOM)
    0x00AD,  # SOFT HYPHEN
}

# RTL override codepoints
_RTL_OVERRIDES: set[int] = {0x202E, 0x202B, 0x200F, 0x2067}

# Base64 detection pattern (min 20 chars to reduce false positives)
_BASE64_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/=])"
    r"([A-Za-z0-9+/]{20,}={0,3})"
    r"(?![A-Za-z0-9+/=])"
)

# Common Latin homoglyphs (Cyrillic/Greek -> ASCII mapping)
_HOMOGLYPH_MAP: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u0458": "j",  # Cyrillic ј
    "\u04bb": "h",  # Cyrillic һ
    "\u03B1": "a",  # Greek alpha
    "\u03BF": "o",  # Greek omicron
    "\u03C1": "p",  # Greek rho
    "\u03B5": "e",  # Greek epsilon
    "\u0391": "A",  # Greek Alpha
    "\u0392": "B",  # Greek Beta
    "\u0395": "E",  # Greek Epsilon
    "\u0397": "H",  # Greek Eta
    "\u0399": "I",  # Greek Iota
    "\u039A": "K",  # Greek Kappa
    "\u039C": "M",  # Greek Mu
    "\u039D": "N",  # Greek Nu
    "\u039F": "O",  # Greek Omicron
    "\u03A1": "P",  # Greek Rho
    "\u03A4": "T",  # Greek Tau
    "\u03A5": "Y",  # Greek Upsilon
    "\u03A7": "X",  # Greek Chi
    "\u0417": "3",  # Cyrillic З
}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class RAGPoisoningDetector:
    """Detects adversarial documents injected into RAG knowledge bases.

    Combines seven independent detection signals into a composite risk score.
    Each signal can be run independently, but :meth:`analyze_document` runs
    the full pipeline and returns a unified :class:`RAGScanResult`.

    Example::

        detector = RAGPoisoningDetector()
        result = await detector.analyze_document(
            content="Some document text ...",
            embedding=np.array([...]),
            baseline_embeddings=np.array([...]),
        )
        if result.is_suspicious:
            print(result.signals_triggered)
    """

    def __init__(self, config: RAGAnalyzerConfig | None = None) -> None:
        self._config = config or RAGAnalyzerConfig()
        logger.info(
            "RAGPoisoningDetector initialised  cos_thresh=%.3f  entropy_window=%d",
            self._config.cosine_deviation_threshold,
            self._config.entropy_window_size,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze_document(
        self,
        content: str,
        embedding: NDArray[np.floating[Any]],
        baseline_embeddings: NDArray[np.floating[Any]],
        metadata: dict[str, Any] | None = None,
    ) -> RAGScanResult:
        """Full analysis pipeline for a single RAG document.

        Args:
            content: Raw document text to analyse.
            embedding: Pre-computed embedding vector for the document, shape ``(dim,)``.
            baseline_embeddings: 2-D array of shape ``(n, dim)`` containing
                embeddings of known-clean documents in the same index.
            metadata: Arbitrary caller-supplied metadata echoed in the result.

        Returns:
            A :class:`RAGScanResult` with per-signal findings and a composite
            risk score.

        Raises:
            ValueError: If inputs are malformed.
        """
        if not content:
            raise ValueError("Document content must be a non-empty string.")
        if embedding.ndim != 1:
            raise ValueError(f"Embedding must be 1-D, got shape {embedding.shape}")
        if baseline_embeddings.ndim != 2:
            raise ValueError(
                f"Baseline embeddings must be 2-D, got shape {baseline_embeddings.shape}"
            )

        t0 = time.perf_counter()
        metadata = metadata or {}
        signals_triggered: list[str] = []

        embedding = embedding.astype(np.float64, copy=False)
        baseline_embeddings = baseline_embeddings.astype(np.float64, copy=False)

        # Signal 1 -- cosine deviation from baseline centroid
        cos_dev = self._calculate_cosine_deviation(embedding, baseline_embeddings)
        if cos_dev > self._config.cosine_deviation_threshold:
            signals_triggered.append("cosine_deviation")

        # Signal 2 -- statistical perplexity
        perplexity = self._statistical_perplexity(content)
        # High perplexity = unusual text.  We use a simple absolute threshold
        # since we don't have a pre-computed reference corpus in this engine.
        # A perplexity > 80 is unusual for coherent English text.
        if perplexity > 80.0:
            signals_triggered.append("high_perplexity")

        # Signal 3 -- semantic coherence
        coherence = self._semantic_coherence(content)
        if coherence < self._config.coherence_min:
            signals_triggered.append("low_coherence")

        # Signal 4 -- n-gram frequency analysis
        ngram_anomalies = self._ngram_frequency_analysis(content)
        if ngram_anomalies:
            signals_triggered.append("ngram_anomalies")

        # Signal 5 -- unicode homoglyph detection
        homoglyphs = self._detect_homoglyphs(content)
        if homoglyphs:
            signals_triggered.append("homoglyphs")

        # Signal 6 -- hidden instruction detection
        hidden = self._detect_hidden_instructions(content)
        if hidden:
            signals_triggered.append("hidden_instructions")

        # Signal 7 -- entropy analysis
        entropy_anomalies = self._entropy_analysis(
            content, window_size=self._config.entropy_window_size,
        )
        if entropy_anomalies:
            signals_triggered.append("entropy_anomalies")

        # Composite risk score (weighted)
        risk_components: list[float] = [
            0.25 * min(cos_dev / 0.5, 1.0),
            0.10 * min(perplexity / 200.0, 1.0),
            0.10 * (1.0 - coherence),
            0.15 * min(len(hidden) / 3.0, 1.0),
            0.15 * min(len(entropy_anomalies) / 5.0, 1.0),
            0.10 * min(len(homoglyphs) / 10.0, 1.0),
            0.15 * min(len(ngram_anomalies) / 5.0, 1.0),
        ]
        risk_score = float(np.clip(sum(risk_components), 0.0, 1.0))

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return RAGScanResult(
            is_suspicious=len(signals_triggered) > 0,
            risk_score=risk_score,
            cosine_deviation=cos_dev,
            statistical_perplexity=perplexity,
            semantic_coherence=coherence,
            hidden_instructions=hidden,
            entropy_anomalies=entropy_anomalies,
            homoglyph_findings=homoglyphs,
            ngram_anomalies=ngram_anomalies,
            signals_triggered=signals_triggered,
            elapsed_ms=elapsed_ms,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Signal implementations
    # ------------------------------------------------------------------

    def _calculate_cosine_deviation(
        self,
        embedding: NDArray[np.float64],
        baseline: NDArray[np.float64],
    ) -> float:
        """Measure deviation of document embedding from baseline centroid.

        Args:
            embedding: 1-D document embedding.
            baseline: 2-D array of baseline embeddings.

        Returns:
            Cosine deviation (1 - similarity) in [0.0, 2.0].
        """
        centroid = baseline.mean(axis=0)
        dist = cosine_distance(embedding, centroid)
        return float(np.clip(dist, 0.0, 2.0))

    def _statistical_perplexity(self, text: str) -> float:
        """Compute statistical perplexity using character bigram frequencies.

        This is a lightweight proxy for LLM-based perplexity.  We build a
        bigram language model from the document itself and measure how
        "surprised" a uniform-prior model would be.  Adversarially crafted
        text often has atypical character distributions.

        Args:
            text: Document text.

        Returns:
            Perplexity score (>= 1.0).  Lower means more predictable.
        """
        if len(text) < 3:
            return 1.0

        text_lower = text.lower()

        # Character bigram model
        bigrams = [text_lower[i:i + 2] for i in range(len(text_lower) - 1)]
        total = len(bigrams)
        if total == 0:
            return 1.0

        bigram_counts = Counter(bigrams)
        # Unigram counts for conditional probability
        unigram_counts = Counter(text_lower)

        # Compute log-probability under bigram model with add-1 smoothing
        vocab_size = len(set(text_lower))
        log_prob_sum = 0.0

        for bigram, count in bigram_counts.items():
            first_char = bigram[0]
            # P(c2|c1) with add-1 smoothing
            p = (count + 1) / (unigram_counts[first_char] + vocab_size)
            log_prob_sum += count * math.log2(p)

        # Average log probability per bigram
        avg_log_prob = log_prob_sum / total
        # Perplexity = 2^(-avg_log_prob)
        perplexity = 2.0 ** (-avg_log_prob)

        return float(perplexity)

    def _semantic_coherence(self, text: str) -> float:
        """Measure intra-document semantic consistency using sliding window analysis.

        Computes character-level Shannon entropy in overlapping windows and
        measures the *consistency* (inverse of variance) of entropy across
        windows.  A coherent document has relatively uniform information
        density; an injected segment creates a spike.

        Args:
            text: Document text.

        Returns:
            Coherence score in [0.0, 1.0].  1.0 = perfectly uniform entropy.
        """
        if len(text) < 50:
            return 1.0

        window_size = min(256, len(text) // 4)
        step = max(1, window_size // 2)
        entropies: list[float] = []

        for start in range(0, len(text) - window_size + 1, step):
            window = text[start:start + window_size]
            entropies.append(self._shannon_entropy(window))

        if len(entropies) < 2:
            return 1.0

        arr = np.array(entropies)
        mean_e = float(np.mean(arr))
        if mean_e < 1e-12:
            return 1.0

        # Coefficient of variation -- lower means more coherent
        cv = float(np.std(arr)) / mean_e

        # Map CV to [0, 1] coherence score.  CV of 0 -> 1.0, CV >= 1.0 -> 0.0
        coherence = max(0.0, 1.0 - cv)
        return coherence

    def _detect_hidden_instructions(self, text: str) -> list[HiddenInstruction]:
        """Detect prompt injection patterns, invisible characters, and encoded instructions.

        Checks for:
        - Zero-width and invisible Unicode characters
        - RTL override attacks
        - Base64-encoded payloads
        - Common injection prefix patterns
        - LLM special tokens

        Args:
            text: Document text to scan.

        Returns:
            List of :class:`HiddenInstruction` findings.
        """
        findings: list[HiddenInstruction] = []

        # Check for invisible Unicode characters
        for i, char in enumerate(text):
            cp = ord(char)
            if cp in _INVISIBLE_CHARS:
                itype = (InstructionType.RTL_OVERRIDE if cp in _RTL_OVERRIDES
                         else InstructionType.ZERO_WIDTH)
                severity = Severity.HIGH if cp in _RTL_OVERRIDES else Severity.MEDIUM
                findings.append(HiddenInstruction(
                    instruction_type=itype,
                    matched_text=repr(char),
                    position=i,
                    decoded_content=unicodedata.name(char, f"U+{cp:04X}"),
                    severity=severity,
                ))

        # Check for base64 encoded payloads
        for match in _BASE64_PATTERN.finditer(text):
            candidate = match.group(1)
            try:
                decoded_bytes = base64.b64decode(candidate, validate=True)
                decoded_text = decoded_bytes.decode("utf-8", errors="replace")
                # Only flag if decoded content looks like text (not random bytes)
                printable_ratio = sum(
                    1 for c in decoded_text if c.isprintable() or c.isspace()
                ) / max(len(decoded_text), 1)
                if printable_ratio > 0.7 and len(decoded_text) > 5:
                    findings.append(HiddenInstruction(
                        instruction_type=InstructionType.BASE64_PAYLOAD,
                        matched_text=candidate[:80] + ("..." if len(candidate) > 80 else ""),
                        position=match.start(),
                        decoded_content=decoded_text[:200],
                        severity=Severity.HIGH,
                    ))
            except Exception:
                # Not valid base64 -- skip
                pass

        # Check for injection patterns
        for pattern, itype, severity in _INJECTION_PATTERNS:
            for match in pattern.finditer(text):
                findings.append(HiddenInstruction(
                    instruction_type=itype,
                    matched_text=match.group(0),
                    position=match.start(),
                    severity=severity,
                ))

        return findings

    def _entropy_analysis(
        self, text: str, window_size: int = 256,
    ) -> list[EntropyAnomaly]:
        """Sliding window entropy analysis to detect injected segments.

        Computes Shannon entropy in overlapping windows and flags windows
        whose entropy deviates significantly from the document mean.

        Args:
            text: Document text.
            window_size: Character width of each analysis window.

        Returns:
            List of :class:`EntropyAnomaly` for windows exceeding the
            z-score threshold.
        """
        if len(text) < window_size:
            return []

        step = max(1, window_size // 4)
        entropies: list[tuple[int, int, float]] = []

        for start in range(0, len(text) - window_size + 1, step):
            end = start + window_size
            e = self._shannon_entropy(text[start:end])
            entropies.append((start, end, e))

        if len(entropies) < 3:
            return []

        values = np.array([e for _, _, e in entropies])
        mean_e = float(np.mean(values))
        std_e = float(np.std(values))

        if std_e < 1e-12:
            return []

        anomalies: list[EntropyAnomaly] = []
        threshold = self._config.entropy_z_threshold

        for start, end, e in entropies:
            z = (e - mean_e) / std_e
            if abs(z) > threshold:
                severity = Severity.HIGH if abs(z) > 4.0 else Severity.MEDIUM
                anomalies.append(EntropyAnomaly(
                    start=start,
                    end=end,
                    entropy=e,
                    z_score=z,
                    severity=severity,
                ))

        return anomalies

    def _detect_homoglyphs(self, text: str) -> list[HomoglyphFinding]:
        """Detect Unicode homoglyph characters used for visual spoofing.

        Scans for characters from non-Latin scripts that visually resemble
        ASCII letters -- a technique used to bypass text-based filters.

        Args:
            text: Document text to scan.

        Returns:
            List of :class:`HomoglyphFinding` for each suspicious character.
        """
        findings: list[HomoglyphFinding] = []

        for i, char in enumerate(text):
            if char in _HOMOGLYPH_MAP:
                findings.append(HomoglyphFinding(
                    position=i,
                    character=char,
                    unicode_name=unicodedata.name(char, "UNKNOWN"),
                    codepoint=f"U+{ord(char):04X}",
                    lookalike=_HOMOGLYPH_MAP[char],
                ))

        return findings

    def _ngram_frequency_analysis(self, text: str) -> list[NGramAnomaly]:
        """Analyse n-gram frequency distributions for adversarial patterns.

        Adversarially constructed text often has n-gram distributions that
        diverge from natural language.  We flag n-grams whose frequency is
        unusually high or low relative to the document's own distribution.

        Args:
            text: Document text.

        Returns:
            List of :class:`NGramAnomaly` for anomalous n-grams.
        """
        if len(text) < 50:
            return []

        text_lower = text.lower()
        anomalies: list[NGramAnomaly] = []
        min_n, max_n = self._config.ngram_range

        for n in range(min_n, max_n + 1):
            ngrams = [text_lower[i:i + n] for i in range(len(text_lower) - n + 1)]
            if not ngrams:
                continue

            counts = Counter(ngrams)
            total = len(ngrams)
            freqs = np.array([c / total for c in counts.values()])

            if len(freqs) < 5:
                continue

            mean_f = float(np.mean(freqs))
            std_f = float(np.std(freqs))

            if std_f < 1e-12:
                continue

            for ngram, count in counts.items():
                freq = count / total
                z = (freq - mean_f) / std_f
                # Flag n-grams with unusually high frequency (> 3 sigma)
                if z > 3.0:
                    expected_high = mean_f + 2 * std_f
                    anomalies.append(NGramAnomaly(
                        ngram=ngram,
                        observed_freq=freq,
                        expected_range=(0.0, expected_high),
                        z_score=z,
                    ))

        return anomalies

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Compute Shannon entropy of a text string in bits.

        Args:
            text: Input string.

        Returns:
            Entropy in bits (>= 0).
        """
        if not text:
            return 0.0
        counts = Counter(text)
        total = len(text)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
