"""
Unified Threat Scoring Engine
==============================

Aggregates findings from all detection engines (vector analysis, RAG document
scanning, MCP tool auditing, provenance tracking) into a single prioritised
threat report per tenant.

The aggregator applies configurable weights to each engine's output, computes
a unified risk score, ranks individual threats by severity, and generates
recommended remediation actions.  It also maintains a rolling window of
historical scores so that trend analysis (improving / degrading / stable) can
be reported alongside the current snapshot.
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(str, Enum):
    """High-level category for a unified threat."""
    VECTOR_POISONING = "vector_poisoning"
    RAG_INJECTION = "rag_injection"
    MCP_TOOL_ATTACK = "mcp_tool_attack"
    DATA_CONTAMINATION = "data_contamination"
    SPLIT_VIEW_ATTACK = "split_view_attack"
    PROMPT_INJECTION = "prompt_injection"
    DATA_LAUNDERING = "data_laundering"


class TrendDirection(str, Enum):
    """Trend of the risk score relative to historical data."""
    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"
    INSUFFICIENT_DATA = "insufficient_data"


@dataclass(frozen=True, slots=True)
class AggregatorConfig:
    """Configuration for the threat aggregator.

    Attributes:
        vector_weight: Weight for vector analysis engine results.
        rag_weight: Weight for RAG document scan results.
        mcp_weight: Weight for MCP tool audit results.
        provenance_weight: Weight for provenance tracker results.
        critical_threshold: Unified score above which the report is CRITICAL.
        high_threshold: Unified score above which the report is HIGH.
        medium_threshold: Unified score above which the report is MEDIUM.
        trend_window_size: Number of historical scores to retain for trend
            analysis.
        trend_improvement_pct: Percentage decrease in score (relative to
            the mean of the window) required to classify the trend as
            "improving".
    """
    vector_weight: float = 0.30
    rag_weight: float = 0.25
    mcp_weight: float = 0.25
    provenance_weight: float = 0.20
    critical_threshold: float = 0.80
    high_threshold: float = 0.55
    medium_threshold: float = 0.30
    trend_window_size: int = 30
    trend_improvement_pct: float = 0.10


@dataclass(slots=True)
class UnifiedThreat:
    """A single threat extracted and normalised from an engine finding.

    Attributes:
        threat_id: Unique identifier for this threat instance.
        category: High-level threat category.
        severity: Assessed severity.
        score: Normalised risk score in [0.0, 1.0].
        source_engine: Name of the engine that produced the finding.
        title: Short human-readable title.
        description: Detailed description.
        evidence: Raw evidence string or structured data.
        recommended_action: Suggested remediation step.
    """
    threat_id: str
    category: ThreatCategory
    severity: Severity
    score: float
    source_engine: str
    title: str
    description: str
    evidence: str = ""
    recommended_action: str = ""


@dataclass(slots=True)
class EngineSummary:
    """Summary statistics for a single engine's contribution to the report.

    Attributes:
        engine_name: Name of the detection engine.
        finding_count: Total findings from this engine.
        critical_count: Number of CRITICAL findings.
        high_count: Number of HIGH findings.
        max_score: Highest individual finding score.
        weighted_contribution: This engine's weighted contribution to the
            unified score.
    """
    engine_name: str
    finding_count: int
    critical_count: int
    high_count: int
    max_score: float
    weighted_contribution: float


@dataclass(slots=True)
class ThreatReport:
    """Unified threat report aggregating all engine outputs.

    Attributes:
        tenant_id: Tenant this report belongs to.
        unified_score: Composite risk score in [0.0, 1.0].
        overall_severity: Derived severity classification.
        trend: Risk trend relative to historical data.
        threats: All individual threats, sorted by score descending.
        engine_summaries: Per-engine summary statistics.
        recommended_actions: Prioritised list of remediation steps.
        total_findings: Total number of findings across all engines.
        critical_count: Total CRITICAL findings.
        high_count: Total HIGH findings.
        generated_at: ISO-8601 timestamp.
        elapsed_ms: Wall-clock aggregation time in milliseconds.
        metadata: Arbitrary caller-supplied metadata.
    """
    tenant_id: str
    unified_score: float
    overall_severity: Severity
    trend: TrendDirection
    threats: list[UnifiedThreat]
    engine_summaries: list[EngineSummary]
    recommended_actions: list[str]
    total_findings: int
    critical_count: int
    high_count: int
    generated_at: str
    elapsed_ms: float
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Severity-to-score mapping
# ---------------------------------------------------------------------------

_SEVERITY_SCORES: dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.45,
    "low": 0.20,
}


def _severity_to_score(severity: str | Severity) -> float:
    """Convert a severity label to a numeric score."""
    key = severity.value if isinstance(severity, Severity) else severity.lower()
    return _SEVERITY_SCORES.get(key, 0.2)


def _score_to_severity(score: float, config: AggregatorConfig) -> Severity:
    """Map a numeric score to a severity classification."""
    if score >= config.critical_threshold:
        return Severity.CRITICAL
    if score >= config.high_threshold:
        return Severity.HIGH
    if score >= config.medium_threshold:
        return Severity.MEDIUM
    return Severity.LOW


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class ThreatAggregator:
    """Aggregates findings from all detection engines into unified threat scores.

    The aggregator is *mostly* stateless -- the only mutable state is a
    per-tenant ring buffer of historical unified scores used for trend
    analysis.  This buffer is not persisted; for durable trend data the
    caller should store :class:`ThreatReport` objects externally.

    Example::

        agg = ThreatAggregator()
        report = await agg.aggregate(
            tenant_id="tenant-123",
            vector_results=[...],
            rag_results=[...],
            mcp_results=[...],
            provenance_results=[...],
        )
        print(report.unified_score, report.overall_severity)
    """

    def __init__(self, config: AggregatorConfig | None = None) -> None:
        self._config = config or AggregatorConfig()
        # Per-tenant historical scores for trend analysis
        self._history: dict[str, list[float]] = defaultdict(list)
        logger.info(
            "ThreatAggregator initialised  weights=V%.2f R%.2f M%.2f P%.2f",
            self._config.vector_weight,
            self._config.rag_weight,
            self._config.mcp_weight,
            self._config.provenance_weight,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def aggregate(
        self,
        tenant_id: str,
        vector_results: list[dict[str, Any]],
        rag_results: list[dict[str, Any]],
        mcp_results: list[dict[str, Any]],
        provenance_results: list[dict[str, Any]],
        metadata: dict[str, Any] | None = None,
    ) -> ThreatReport:
        """Generate unified threat report with prioritised findings.

        Each ``*_results`` list contains dicts from the corresponding
        engine's report.  The expected keys per engine are documented below.

        Vector results dict keys:
            ``anomaly_score``, ``cosine_deviation``, ``reasons``, ``index``

        RAG results dict keys:
            ``risk_score``, ``signals_triggered``, ``hidden_instructions``,
            ``is_suspicious``

        MCP results dict keys:
            ``risk_score``, ``verdict``, ``findings``, ``tool_name``

        Provenance results dict keys:
            ``is_contaminated``, ``max_decayed_score``, ``dataset_id``,
            ``contamination_paths``

        Args:
            tenant_id: Tenant identifier for data isolation.
            vector_results: Findings from :class:`VectorIntegrityAnalyzer`.
            rag_results: Findings from :class:`RAGPoisoningDetector`.
            mcp_results: Findings from :class:`MCPToolAuditor`.
            provenance_results: Findings from :class:`ProvenanceTracker`.
            metadata: Arbitrary metadata echoed in the report.

        Returns:
            A :class:`ThreatReport` with all threats and recommendations.
        """
        t0 = time.perf_counter()
        metadata = metadata or {}
        all_threats: list[UnifiedThreat] = []
        threat_counter = 0

        # ---- Process vector results ----
        vector_scores: list[float] = []
        for vr in vector_results:
            score = float(vr.get("anomaly_score", 0.0))
            vector_scores.append(score)
            if score > 0.3:
                threat_counter += 1
                severity = self._score_to_finding_severity(score)
                reasons = vr.get("reasons", [])
                all_threats.append(UnifiedThreat(
                    threat_id=f"VEC-{threat_counter:04d}",
                    category=ThreatCategory.VECTOR_POISONING,
                    severity=severity,
                    score=score,
                    source_engine="vector_analyzer",
                    title=f"Anomalous embedding vector (index {vr.get('index', '?')})",
                    description="; ".join(reasons) if reasons else "Vector flagged by anomaly detection",
                    evidence=f"cosine_deviation={vr.get('cosine_deviation', 'N/A')}",
                    recommended_action="Quarantine the flagged vector and review the source document for adversarial content.",
                ))

        # ---- Process RAG results ----
        rag_scores: list[float] = []
        for rr in rag_results:
            score = float(rr.get("risk_score", 0.0))
            rag_scores.append(score)
            if rr.get("is_suspicious", False):
                threat_counter += 1
                severity = self._score_to_finding_severity(score)
                signals = rr.get("signals_triggered", [])
                hidden = rr.get("hidden_instructions", [])

                category = (
                    ThreatCategory.PROMPT_INJECTION if hidden
                    else ThreatCategory.RAG_INJECTION
                )

                all_threats.append(UnifiedThreat(
                    threat_id=f"RAG-{threat_counter:04d}",
                    category=category,
                    severity=severity,
                    score=score,
                    source_engine="rag_analyzer",
                    title="Suspicious RAG document detected",
                    description=f"Triggered signals: {', '.join(signals)}",
                    evidence=f"hidden_instructions={len(hidden)}",
                    recommended_action="Remove the document from the RAG index and audit its source.",
                ))

        # ---- Process MCP results ----
        mcp_scores: list[float] = []
        for mr in mcp_results:
            score = float(mr.get("risk_score", 0.0))
            mcp_scores.append(score)
            if score > 0.2:
                threat_counter += 1
                severity = self._score_to_finding_severity(score)
                tool_name = mr.get("tool_name", "unknown")
                verdict = mr.get("verdict", "")
                findings = mr.get("findings", [])

                all_threats.append(UnifiedThreat(
                    threat_id=f"MCP-{threat_counter:04d}",
                    category=ThreatCategory.MCP_TOOL_ATTACK,
                    severity=severity,
                    score=score,
                    source_engine="mcp_auditor",
                    title=f"Suspicious MCP tool: {tool_name}",
                    description=f"Verdict: {verdict}. {len(findings)} finding(s).",
                    evidence=f"tool={tool_name}",
                    recommended_action="Disable the tool immediately and audit its schema and provenance.",
                ))

        # ---- Process provenance results ----
        prov_scores: list[float] = []
        for pr in provenance_results:
            score = float(pr.get("max_decayed_score", 0.0))
            prov_scores.append(score)
            if pr.get("is_contaminated", False):
                threat_counter += 1
                severity = self._score_to_finding_severity(score)
                dataset_id = pr.get("dataset_id", "unknown")
                paths = pr.get("contamination_paths", [])

                all_threats.append(UnifiedThreat(
                    threat_id=f"PRV-{threat_counter:04d}",
                    category=ThreatCategory.DATA_CONTAMINATION,
                    severity=severity,
                    score=score,
                    source_engine="provenance_tracker",
                    title=f"Contaminated dataset: {dataset_id}",
                    description=f"{len(paths)} contamination path(s) detected in ancestry.",
                    evidence=f"dataset={dataset_id}",
                    recommended_action="Quarantine the dataset and all downstream derivatives. Retrain models that consumed it.",
                ))

        # ---- Compute per-engine summaries ----
        engine_summaries = self._build_engine_summaries(
            all_threats, vector_scores, rag_scores, mcp_scores, prov_scores,
        )

        # ---- Compute unified score ----
        vector_max = max(vector_scores) if vector_scores else 0.0
        rag_max = max(rag_scores) if rag_scores else 0.0
        mcp_max = max(mcp_scores) if mcp_scores else 0.0
        prov_max = max(prov_scores) if prov_scores else 0.0

        unified_score = (
            self._config.vector_weight * vector_max
            + self._config.rag_weight * rag_max
            + self._config.mcp_weight * mcp_max
            + self._config.provenance_weight * prov_max
        )
        unified_score = float(min(unified_score, 1.0))

        # ---- Trend analysis ----
        trend = self._compute_trend(tenant_id, unified_score)

        # ---- Sort threats by score descending ----
        all_threats.sort(key=lambda t: t.score, reverse=True)

        # ---- Generate recommended actions (deduplicated, ordered by priority) ----
        recommended_actions = self._generate_recommendations(all_threats)

        # ---- Counts ----
        critical_count = sum(1 for t in all_threats if t.severity == Severity.CRITICAL)
        high_count = sum(1 for t in all_threats if t.severity == Severity.HIGH)

        overall_severity = _score_to_severity(unified_score, self._config)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return ThreatReport(
            tenant_id=tenant_id,
            unified_score=round(unified_score, 4),
            overall_severity=overall_severity,
            trend=trend,
            threats=all_threats,
            engine_summaries=engine_summaries,
            recommended_actions=recommended_actions,
            total_findings=len(all_threats),
            critical_count=critical_count,
            high_count=high_count,
            generated_at=datetime.now(timezone.utc).isoformat(),
            elapsed_ms=elapsed_ms,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_engine_summaries(
        self,
        threats: list[UnifiedThreat],
        vector_scores: list[float],
        rag_scores: list[float],
        mcp_scores: list[float],
        prov_scores: list[float],
    ) -> list[EngineSummary]:
        """Build per-engine summary statistics.

        Args:
            threats: All unified threats.
            vector_scores: Raw scores from vector engine.
            rag_scores: Raw scores from RAG engine.
            mcp_scores: Raw scores from MCP engine.
            prov_scores: Raw scores from provenance engine.

        Returns:
            List of :class:`EngineSummary` objects.
        """
        engines = {
            "vector_analyzer": (vector_scores, self._config.vector_weight),
            "rag_analyzer": (rag_scores, self._config.rag_weight),
            "mcp_auditor": (mcp_scores, self._config.mcp_weight),
            "provenance_tracker": (prov_scores, self._config.provenance_weight),
        }

        summaries: list[EngineSummary] = []

        for engine_name, (scores, weight) in engines.items():
            engine_threats = [t for t in threats if t.source_engine == engine_name]
            max_score = max(scores) if scores else 0.0
            summaries.append(EngineSummary(
                engine_name=engine_name,
                finding_count=len(engine_threats),
                critical_count=sum(1 for t in engine_threats if t.severity == Severity.CRITICAL),
                high_count=sum(1 for t in engine_threats if t.severity == Severity.HIGH),
                max_score=round(max_score, 4),
                weighted_contribution=round(weight * max_score, 4),
            ))

        return summaries

    def _compute_trend(self, tenant_id: str, current_score: float) -> TrendDirection:
        """Compute risk trend for a tenant by comparing the current score to
        the historical rolling window.

        Args:
            tenant_id: Tenant identifier.
            current_score: Current unified score.

        Returns:
            A :class:`TrendDirection` value.
        """
        history = self._history[tenant_id]
        history.append(current_score)

        # Trim to window size
        max_window = self._config.trend_window_size
        if len(history) > max_window:
            self._history[tenant_id] = history[-max_window:]
            history = self._history[tenant_id]

        if len(history) < 3:
            return TrendDirection.INSUFFICIENT_DATA

        historical_mean = sum(history[:-1]) / len(history[:-1])
        if historical_mean < 1e-6:
            # All historical scores are effectively zero
            return TrendDirection.STABLE if current_score < 0.05 else TrendDirection.DEGRADING

        change_pct = (current_score - historical_mean) / historical_mean

        if change_pct < -self._config.trend_improvement_pct:
            return TrendDirection.IMPROVING
        if change_pct > self._config.trend_improvement_pct:
            return TrendDirection.DEGRADING
        return TrendDirection.STABLE

    @staticmethod
    def _score_to_finding_severity(score: float) -> Severity:
        """Map a raw finding score to a severity level.

        Args:
            score: Score in [0.0, 1.0].

        Returns:
            Severity classification.
        """
        if score >= 0.85:
            return Severity.CRITICAL
        if score >= 0.60:
            return Severity.HIGH
        if score >= 0.35:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _generate_recommendations(threats: list[UnifiedThreat]) -> list[str]:
        """Generate a deduplicated, priority-ordered list of recommended actions.

        Args:
            threats: Sorted list of unified threats.

        Returns:
            Unique recommended action strings, ordered by the highest-severity
            threat that suggested them.
        """
        seen: set[str] = set()
        actions: list[str] = []

        for threat in threats:
            action = threat.recommended_action
            if action and action not in seen:
                seen.add(action)
                actions.append(action)

        # Append generic recommendations if critical threats exist
        critical_count = sum(1 for t in threats if t.severity == Severity.CRITICAL)
        if critical_count > 0:
            generic = "Initiate incident response: isolate affected systems and notify the security team."
            if generic not in seen:
                actions.insert(0, generic)

        return actions
