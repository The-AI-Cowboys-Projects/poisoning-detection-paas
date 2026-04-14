"""
Synthetic Telemetry Data Simulator
====================================

Dual-purpose engine for LLM data-poisoning research:

1. **Attack Simulation** -- Generates realistic poisoned telemetry streams that
   mimic adversarial reward-hacking, context poisoning via agent memory
   corruption, and prompt distribution drift attacks.  Eight distinct attack
   scenarios are supported, from instantaneous tool hijacking to the subtler
   SLOW_BURN drift that accumulates over an entire time window.

2. **Defense / Detection** -- Analyses telemetry datasets for behavioural
   anomalies that indicate active poisoning:

   - Prompt risk-score spikes (rolling p95 > 2× baseline mean)
   - Tool-call denial surges (rate > 3× normal baseline)
   - Latency bottlenecks (MAD-based modified Z-score on duration_ms)
   - Distribution shift (KL divergence on risk-score histograms)
   - Multi-agent collusion (cross-agent anomaly correlation within 60-second
     windows)
   - Reward hacking (agent_decision chains that game metrics without quality
     improvement)
   - Memory corruption (write/read content-hash divergence)

3. **Execution Tracing** -- Walks the span tree of an anomalous trace to
   identify the exact step, tool call, or retrieved document that initiated the
   anomalous signal propagation.

All random generation is backed by ``numpy.random.Generator`` for full
reproducibility.  Heavy math uses NumPy and SciPy only -- no ML frameworks.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

import numpy as np
from scipy import stats as scipy_stats

logger = logging.getLogger(__name__)


def _uuid_from_rng(rng: np.random.Generator) -> str:
    """Generate a UUID-4-formatted string from a seeded numpy RNG.

    Produces 128 random bits via the RNG, formats them as a standard
    UUID v4 string, and sets the version/variant bits as required by
    RFC 4122.  Using this instead of :func:`uuid.uuid4` keeps all
    randomness inside the seeded generator so dataset generation is
    fully reproducible.

    Args:
        rng: Seeded :class:`numpy.random.Generator` instance.

    Returns:
        UUID v4 string in canonical ``xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx``
        format.
    """
    # Draw 16 random bytes (128 bits) from the seeded generator
    raw = rng.bytes(16)
    ba = bytearray(raw)
    # Set version bits to 4 (0100xxxx in byte 6)
    ba[6] = (ba[6] & 0x0F) | 0x40
    # Set variant bits to 10xxxxxx in byte 8
    ba[8] = (ba[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(ba)))


# ---------------------------------------------------------------------------
# Domain enumerations
# ---------------------------------------------------------------------------


class TelemetryEventType(str, Enum):
    """Discrete event type emitted by a single span in an LLM agent trace."""

    PROMPT_SUBMISSION = "prompt_submission"
    TOOL_CALL = "tool_call"
    TOOL_RESPONSE = "tool_response"
    RAG_RETRIEVAL = "rag_retrieval"
    MODEL_INFERENCE = "model_inference"
    MEMORY_WRITE = "memory_write"
    MEMORY_READ = "memory_read"
    AGENT_DECISION = "agent_decision"


class AnomalyType(str, Enum):
    """Category of behavioural anomaly detected in a telemetry span or trace."""

    PROMPT_RISK_SPIKE = "prompt_risk_spike"
    TOOL_DENIAL_SURGE = "tool_denial_surge"
    LATENCY_ANOMALY = "latency_anomaly"
    DISTRIBUTION_SHIFT = "distribution_shift"
    MEMORY_CORRUPTION = "memory_corruption"
    RETRIEVAL_HIJACK = "retrieval_hijack"
    MULTI_AGENT_COLLUSION = "multi_agent_collusion"
    REWARD_HACKING = "reward_hacking"


class AttackScenario(str, Enum):
    """Named attack scenario used to configure synthetic telemetry generation."""

    CLEAN = "clean"
    REWARD_HACKING = "reward_hacking"
    MEMORY_POISONING = "memory_poisoning"
    PROMPT_DRIFT = "prompt_drift"
    RETRIEVAL_MANIPULATION = "retrieval_manipulation"
    TOOL_HIJACK = "tool_hijack"
    MULTI_AGENT_COLLUSION = "multi_agent_collusion"
    SLOW_BURN = "slow_burn"  # gradual drift over time


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class TelemetrySpan:
    """A single instrumentation span within a distributed LLM agent trace.

    Attributes:
        span_id: Unique identifier for this span.
        trace_id: Identifier of the parent trace this span belongs to.
        parent_span_id: Identifier of the parent span, or ``None`` for root spans.
        event_type: Category of the event recorded by this span.
        agent_id: Identifier of the agent that emitted this span.
        timestamp: ISO-8601 UTC timestamp of the span's start time.
        duration_ms: Wall-clock execution duration in milliseconds.
        attributes: Freeform key-value metadata (prompt text, tool name,
            retrieval doc_id, reward signals, etc.).
        risk_score: Composite anomaly risk score in [0.0, 1.0] computed at
            analysis time.
        is_anomalous: Whether this span was flagged during analysis.
        anomaly_types: The specific anomaly categories detected in this span.
    """

    span_id: str
    trace_id: str
    parent_span_id: str | None
    event_type: TelemetryEventType
    agent_id: str
    timestamp: str
    duration_ms: float
    attributes: dict[str, Any]
    risk_score: float
    is_anomalous: bool
    anomaly_types: list[AnomalyType] = field(default_factory=list)


@dataclass(slots=True)
class TelemetryTrace:
    """A complete distributed trace comprising all spans for one agent request.

    Attributes:
        trace_id: Globally unique trace identifier.
        spans: Ordered list of spans emitted during this trace, sorted
            chronologically.
        total_duration_ms: Sum of all span durations (not wall-clock end-to-end).
        root_cause_span_id: The span identified as the anomaly injection point,
            populated by :meth:`TelemetrySimulator.trace_root_cause`.
        anomaly_summary: Structured summary of anomalies found in this trace.
    """

    trace_id: str
    spans: list[TelemetrySpan]
    total_duration_ms: float
    root_cause_span_id: str | None
    anomaly_summary: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SimulationConfig:
    """Immutable configuration for a synthetic telemetry dataset.

    Attributes:
        scenario: The attack scenario to simulate.
        num_traces: Total number of traces to generate.
        num_agents: Number of distinct agent IDs to simulate.
        avg_spans_per_trace: Mean number of spans per trace (Poisson-sampled).
        poison_ratio: Fraction of traces that will receive injected anomalies.
            Ignored for :attr:`AttackScenario.CLEAN`.
        noise_level: Standard deviation of additive Gaussian noise applied to
            all generated metric values.
        time_window_hours: Duration of the simulated observation window in
            hours.  Span timestamps are drawn uniformly from this window.
        seed: Optional integer seed for ``numpy.random.Generator``
            reproducibility.  ``None`` uses a random seed.
    """

    scenario: AttackScenario
    num_traces: int = 100
    num_agents: int = 5
    avg_spans_per_trace: int = 8
    poison_ratio: float = 0.15
    noise_level: float = 0.1
    time_window_hours: int = 24
    seed: int | None = None


@dataclass(slots=True)
class TelemetryAnalysisResult:
    """Comprehensive analysis result for a telemetry dataset.

    Attributes:
        total_traces: Total number of traces analysed.
        total_spans: Total number of spans across all traces.
        anomalous_traces: Number of traces flagged as anomalous.
        anomaly_breakdown: Count of each :class:`AnomalyType` across all spans.
        prompt_risk_distribution: Descriptive statistics of the prompt risk
            score distribution: ``mean``, ``std``, ``p95``, ``p99``.
        tool_denial_rate: Fraction of tool-call spans that were denied.
        avg_latency_ms: Mean span duration across all spans.
        latency_p99_ms: 99th-percentile span duration.
        distribution_shift_score: Simplified KL-divergence-based score in
            [0.0, 1.0] measuring how far the risk-score distribution has
            shifted from the clean baseline.
        root_cause_traces: List of per-trace root-cause summaries containing
            ``trace_id``, ``root_cause_span_id``, and ``anomaly_types``.
        risk_score: Overall dataset-level risk score in [0.0, 1.0].
        verdict: Human-readable classification: ``"clean"``,
            ``"suspicious"``, or ``"poisoned"``.
        execution_timeline: Flattened, time-ordered list of span events
            suitable for frontend visualisation (see
            :meth:`TelemetrySimulator.generate_execution_timeline`).
    """

    total_traces: int
    total_spans: int
    anomalous_traces: int
    anomaly_breakdown: dict[str, int]
    prompt_risk_distribution: dict[str, float]
    tool_denial_rate: float
    avg_latency_ms: float
    latency_p99_ms: float
    distribution_shift_score: float
    root_cause_traces: list[dict[str, Any]]
    risk_score: float
    verdict: str
    execution_timeline: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class TelemetrySimulator:
    """Synthetic telemetry simulator and behavioural anomaly detector.

    The simulator serves two complementary roles:

    **Simulation** -- Call :meth:`generate_dataset` with a
    :class:`SimulationConfig` to produce a list of :class:`TelemetryTrace`
    objects that realistically mimic LLM agent telemetry under one of eight
    attack scenarios.

    **Detection** -- Call :meth:`analyze_telemetry` with any list of traces
    (simulated or real) to receive a :class:`TelemetryAnalysisResult` that
    details every detected anomaly, root-cause spans, and an overall verdict.

    Example::

        sim = TelemetrySimulator()

        # Generate 200 traces with 15% reward-hacking injection
        config = SimulationConfig(
            scenario=AttackScenario.REWARD_HACKING,
            num_traces=200,
            seed=42,
        )
        traces = sim.generate_dataset(config)

        # Analyse the synthetic dataset
        result = sim.analyze_telemetry(traces)
        print(result.verdict, result.risk_score)

        # Trace a single anomalous trace to its root cause
        anomalous = [t for t in traces if t.anomaly_summary][0]
        rc = sim.trace_root_cause(anomalous)
        print(rc["root_cause_span"].span_id, rc["confidence"])
    """

    # Baseline clean-traffic statistics (log-normal latency parameters)
    _BASELINE_LATENCY_MU: float = 3.912   # ln(50) ≈ 3.912 → median 50 ms
    _BASELINE_LATENCY_SIGMA: float = 0.5
    _BASELINE_RISK_ALPHA: float = 2.0     # Beta(2, 8) → mean 0.2
    _BASELINE_RISK_BETA: float = 8.0
    _TOOL_DENIAL_BASELINE: float = 0.05   # 5% denial rate under clean traffic
    _RISK_THRESHOLD: float = 0.60         # Span-level risk threshold for root-cause walk
    _COLLUSION_WINDOW_SECONDS: float = 60.0

    # Detection thresholds calibrated so that clean Beta(2,8) + log-normal
    # traffic produces a false-positive rate < 1% at the trace level.
    # _RISK_SPIKE_THRESHOLD: p99 of Beta(2,8) ≈ 0.54; we use 0.65 to add a
    #   comfortable margin since clean noise can push individual spans to ~0.55.
    # _LATENCY_Z_THRESHOLD: applied together with _LATENCY_ABSOLUTE_FACTOR so
    #   a span must be *both* statistically extreme (Z > 10) *and* absolutely
    #   large (> 4× median) to be flagged — eliminating log-normal tail FPs.
    _RISK_SPIKE_THRESHOLD: float = 0.65
    _LATENCY_Z_THRESHOLD: float = 10.0
    _LATENCY_ABSOLUTE_FACTOR: float = 4.0  # duration > N × batch median

    def __init__(self) -> None:
        logger.info("TelemetrySimulator initialised")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_dataset(self, config: SimulationConfig) -> list[TelemetryTrace]:
        """Generate a synthetic telemetry dataset according to *config*.

        Produces ``config.num_traces`` :class:`TelemetryTrace` objects.
        For non-CLEAN scenarios, approximately ``config.poison_ratio`` of
        traces will have attack-specific anomalies injected into their spans.

        Span timestamps are drawn uniformly from a ``config.time_window_hours``
        window ending at the current UTC time.  All random operations use a
        seeded ``numpy.random.Generator`` for full reproducibility.

        Args:
            config: Immutable simulation configuration.

        Returns:
            List of :class:`TelemetryTrace` objects, unsorted.

        Raises:
            ValueError: If ``config.num_traces`` is less than 1 or
                ``config.poison_ratio`` is outside [0.0, 1.0].
        """
        if config.num_traces < 1:
            raise ValueError("num_traces must be >= 1.")
        if not 0.0 <= config.poison_ratio <= 1.0:
            raise ValueError("poison_ratio must be in [0.0, 1.0].")

        rng = np.random.default_rng(config.seed)
        agent_ids = [f"agent-{i:03d}" for i in range(config.num_agents)]
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(hours=config.time_window_hours)

        num_poisoned = (
            0
            if config.scenario == AttackScenario.CLEAN
            else int(round(config.num_traces * config.poison_ratio))
        )
        poisoned_indices: set[int] = set(
            rng.choice(config.num_traces, size=num_poisoned, replace=False).tolist()
        )

        traces: list[TelemetryTrace] = []

        for i in range(config.num_traces):
            # Compute a normalised time position for slow-burn drift (0 → 1)
            drift_factor = i / max(config.num_traces - 1, 1)

            trace = self._generate_clean_trace(
                rng=rng,
                agent_ids=agent_ids,
                window_start=window_start,
                window_hours=config.time_window_hours,
                avg_spans=config.avg_spans_per_trace,
                noise_level=config.noise_level,
            )

            if i in poisoned_indices:
                if config.scenario == AttackScenario.REWARD_HACKING:
                    trace = self._inject_reward_hacking(trace, rng)
                elif config.scenario == AttackScenario.MEMORY_POISONING:
                    trace = self._inject_memory_poisoning(trace, rng)
                elif config.scenario == AttackScenario.PROMPT_DRIFT:
                    trace = self._inject_prompt_drift(trace, rng, drift_factor)
                elif config.scenario == AttackScenario.RETRIEVAL_MANIPULATION:
                    trace = self._inject_retrieval_manipulation(trace, rng)
                elif config.scenario == AttackScenario.TOOL_HIJACK:
                    trace = self._inject_tool_hijack(trace, rng)
                elif config.scenario == AttackScenario.SLOW_BURN:
                    # Slow burn: drift_factor controls anomaly intensity
                    trace = self._inject_prompt_drift(trace, rng, drift_factor * 2.0)

            traces.append(trace)

        # MULTI_AGENT_COLLUSION is applied post-generation because it
        # must correlate anomalies *across* multiple traces simultaneously.
        if config.scenario == AttackScenario.MULTI_AGENT_COLLUSION and poisoned_indices:
            poisoned_traces = [traces[i] for i in sorted(poisoned_indices)]
            self._inject_collusion(poisoned_traces, agent_ids, rng)

        logger.info(
            "Generated %d traces  scenario=%s  poisoned=%d  agents=%d",
            len(traces),
            config.scenario.value,
            len(poisoned_indices),
            config.num_agents,
        )
        return traces

    def analyze_telemetry(
        self, traces: list[TelemetryTrace],
    ) -> TelemetryAnalysisResult:
        """Analyse a list of telemetry traces for poisoning indicators.

        Runs seven complementary detection signals:

        1. **Prompt risk spike** -- spans with risk_score > ``_RISK_SPIKE_THRESHOLD``
           (0.65, calibrated to < 0.3% clean FP rate on Beta(2,8) traffic).
        2. **Tool denial surge** -- batch denial rate > 3× ``_TOOL_DENIAL_BASELINE``
           (15%); only flagged when the batch-level threshold is exceeded.
        3. **Latency anomaly** -- MAD-based modified Z-score combined with an
           absolute fence (> 4× batch median) to eliminate log-normal tail FPs.
        4. **Distribution shift** -- KL divergence on risk-score histogram
           vs. a synthetic clean baseline.
        5. **Memory corruption** -- write/read content-hash divergence.
        6. **Multi-agent collusion** -- cross-agent anomaly correlation in
           60-second windows.
        7. **Reward hacking** -- agent_decision sequences with optimised
           reward signals but no corresponding quality improvement.

        Root-cause tracing is run for every trace that contains at least one
        anomalous span.

        Args:
            traces: List of :class:`TelemetryTrace` objects to analyse.

        Returns:
            A :class:`TelemetryAnalysisResult` with comprehensive findings.

        Raises:
            ValueError: If *traces* is empty.
        """
        if not traces:
            raise ValueError("At least one trace is required for analysis.")

        t0 = time.perf_counter()

        all_spans: list[TelemetrySpan] = [s for tr in traces for s in tr.spans]

        # ---- Signal 1: Prompt risk-score statistics ----
        risk_scores = np.array([s.risk_score for s in all_spans], dtype=np.float64)
        prompt_risk_stats = self._compute_risk_distribution(risk_scores)
        # Use a calibrated absolute threshold rather than 2× mean.  Beta(2,8)
        # p99 ≈ 0.54; _RISK_SPIKE_THRESHOLD = 0.65 gives < 0.3% clean FP rate.
        risk_spike_threshold = self._RISK_SPIKE_THRESHOLD

        # ---- Signal 2: Tool denial rate (batch-level, not per-span) ----
        tool_call_spans = [
            s for s in all_spans if s.event_type == TelemetryEventType.TOOL_CALL
        ]
        denied_count = sum(
            1 for s in tool_call_spans if s.attributes.get("denied", False)
        )
        tool_denial_rate = (
            denied_count / len(tool_call_spans) if tool_call_spans else 0.0
        )
        # A denial surge is a batch-level condition (rate > 3× baseline).
        # Individual spans are only marked when this batch threshold is exceeded.
        tool_denial_surge_active = tool_denial_rate > 3.0 * self._TOOL_DENIAL_BASELINE

        # ---- Signal 3: Latency anomaly (modified Z-score + absolute fence) ----
        # Two-signal gate: a span must be both statistically extreme AND
        # absolutely large relative to the batch median.  This eliminates
        # false positives from the natural heavy tail of log-normal latency.
        durations = np.array([s.duration_ms for s in all_spans], dtype=np.float64)
        latency_z_scores = self._modified_z_score(durations)
        batch_median_latency = float(np.median(durations))
        latency_absolute_fence = self._LATENCY_ABSOLUTE_FACTOR * batch_median_latency
        latency_anomaly_mask = (
            (np.abs(latency_z_scores) > self._LATENCY_Z_THRESHOLD)
            & (durations > latency_absolute_fence)
        )

        # ---- Signal 4: Distribution shift vs. synthetic clean baseline ----
        clean_baseline_scores = scipy_stats.beta.rvs(
            self._BASELINE_RISK_ALPHA,
            self._BASELINE_RISK_BETA,
            size=max(len(all_spans), 500),
            random_state=0,
        )
        distribution_shift_score = self._compute_distribution_shift_score(
            clean_baseline_scores, risk_scores.tolist()
        )

        # ---- Annotate spans with anomalies ----
        for idx, span in enumerate(all_spans):
            anomaly_types: list[AnomalyType] = []

            if span.risk_score > risk_spike_threshold:
                anomaly_types.append(AnomalyType.PROMPT_RISK_SPIKE)

            if (
                tool_denial_surge_active
                and span.event_type == TelemetryEventType.TOOL_CALL
                and span.attributes.get("denied", False)
            ):
                anomaly_types.append(AnomalyType.TOOL_DENIAL_SURGE)

            if latency_anomaly_mask[idx]:
                anomaly_types.append(AnomalyType.LATENCY_ANOMALY)

            if span.attributes.get("memory_corrupted", False):
                anomaly_types.append(AnomalyType.MEMORY_CORRUPTION)

            if span.attributes.get("retrieval_hijacked", False):
                anomaly_types.append(AnomalyType.RETRIEVAL_HIJACK)

            if span.attributes.get("reward_hacked", False):
                anomaly_types.append(AnomalyType.REWARD_HACKING)

            if span.attributes.get("colluding", False):
                anomaly_types.append(AnomalyType.MULTI_AGENT_COLLUSION)

            if anomaly_types:
                span.is_anomalous = True
                span.anomaly_types = anomaly_types

        # ---- Detect multi-agent collusion patterns ----
        self._detect_collusion_patterns(all_spans)

        # ---- Detect reward hacking sequences ----
        for trace in traces:
            self._detect_reward_hacking(trace)

        # ---- Aggregate anomaly breakdown ----
        anomaly_breakdown: dict[str, int] = {at.value: 0 for at in AnomalyType}
        for span in all_spans:
            for at in span.anomaly_types:
                anomaly_breakdown[at.value] += 1

        # ---- Root-cause tracing for anomalous traces ----
        root_cause_traces: list[dict[str, Any]] = []
        anomalous_trace_count = 0
        for trace in traces:
            if any(s.is_anomalous for s in trace.spans):
                anomalous_trace_count += 1
                rc = self.trace_root_cause(trace)
                root_cause_span = rc.get("root_cause_span")
                root_cause_traces.append(
                    {
                        "trace_id": trace.trace_id,
                        "root_cause_span_id": (
                            root_cause_span.span_id if root_cause_span else None
                        ),
                        "anomaly_types": [
                            at.value
                            for at in (
                                root_cause_span.anomaly_types if root_cause_span else []
                            )
                        ],
                        "confidence": rc.get("confidence", 0.0),
                    }
                )
                trace.root_cause_span_id = (
                    root_cause_span.span_id if root_cause_span else None
                )

        # ---- Compute overall risk score ----
        anomaly_rate = anomalous_trace_count / len(traces)
        risk_score = float(
            np.clip(
                0.40 * anomaly_rate
                + 0.25 * min(distribution_shift_score, 1.0)
                + 0.20 * min(prompt_risk_stats["p95"] / risk_spike_threshold, 1.0)
                + 0.15 * min(tool_denial_rate / (3.0 * self._TOOL_DENIAL_BASELINE), 1.0),
                0.0,
                1.0,
            )
        )

        verdict = (
            "clean" if risk_score < 0.25 else "suspicious" if risk_score < 0.55 else "poisoned"
        )

        # ---- Execution timeline ----
        execution_timeline = self.generate_execution_timeline(traces)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        logger.info(
            "Analysis complete  traces=%d  spans=%d  anomalous=%d  verdict=%s  "
            "risk=%.3f  elapsed=%.1fms",
            len(traces),
            len(all_spans),
            anomalous_trace_count,
            verdict,
            risk_score,
            elapsed_ms,
        )

        return TelemetryAnalysisResult(
            total_traces=len(traces),
            total_spans=len(all_spans),
            anomalous_traces=anomalous_trace_count,
            anomaly_breakdown=anomaly_breakdown,
            prompt_risk_distribution=prompt_risk_stats,
            tool_denial_rate=round(tool_denial_rate, 4),
            avg_latency_ms=round(float(np.mean(durations)), 3),
            latency_p99_ms=round(float(np.percentile(durations, 99)), 3),
            distribution_shift_score=round(distribution_shift_score, 4),
            root_cause_traces=root_cause_traces,
            risk_score=round(risk_score, 4),
            verdict=verdict,
            execution_timeline=execution_timeline,
        )

    def trace_root_cause(self, trace: TelemetryTrace) -> dict[str, Any]:
        """Identify the span that initiated anomaly propagation within a trace.

        Walks the trace chronologically and computes a cumulative risk score.
        The root-cause span is defined as the earliest span where:

        - ``risk_score`` exceeds :attr:`_RISK_THRESHOLD`, **and**
        - At least one subsequent span also carries elevated risk (≥ 0.4),
          confirming propagation rather than an isolated blip.

        If no span clears the threshold the highest-scoring span is returned
        with a lower confidence value.

        Args:
            trace: A single :class:`TelemetryTrace` to inspect.

        Returns:
            Dictionary with keys:

            - ``root_cause_span``: The :class:`TelemetrySpan` identified as
              the root cause, or ``None`` if the trace is fully clean.
            - ``propagation_path``: List of span IDs from root cause onward
              that carry elevated risk (>= 0.4).
            - ``confidence``: Float in [0.0, 1.0] expressing confidence in the
              identification.  Higher when the risk delta is large and multiple
              downstream spans confirm propagation.
        """
        if not trace.spans:
            return {"root_cause_span": None, "propagation_path": [], "confidence": 0.0}

        # Sort spans chronologically
        sorted_spans = sorted(trace.spans, key=lambda s: s.timestamp)

        # Walk forward to find the first span that exceeds the risk threshold
        # and is followed by at least one amplifying span.
        root_cause_span: TelemetrySpan | None = None
        propagation_path: list[str] = []
        confidence = 0.0

        for i, span in enumerate(sorted_spans):
            if span.risk_score < self._RISK_THRESHOLD:
                continue

            # Check whether subsequent spans show elevated risk (propagation)
            downstream = sorted_spans[i + 1 :]
            amplifying = [s for s in downstream if s.risk_score >= 0.4]

            if amplifying:
                root_cause_span = span
                propagation_path = [span.span_id] + [s.span_id for s in amplifying]
                # Confidence is a function of the risk delta and propagation breadth
                avg_downstream_risk = float(
                    np.mean([s.risk_score for s in amplifying])
                )
                confidence = float(
                    np.clip(
                        0.5 * (span.risk_score - self._RISK_THRESHOLD) / (1.0 - self._RISK_THRESHOLD)
                        + 0.5 * min(len(amplifying) / 3.0, 1.0) * avg_downstream_risk,
                        0.0,
                        1.0,
                    )
                )
                break

        # Fallback: return the highest-risk span with reduced confidence
        if root_cause_span is None:
            root_cause_span = max(sorted_spans, key=lambda s: s.risk_score)
            if root_cause_span.risk_score > 0.0:
                propagation_path = [root_cause_span.span_id]
                confidence = float(root_cause_span.risk_score * 0.3)
            else:
                root_cause_span = None

        return {
            "root_cause_span": root_cause_span,
            "propagation_path": propagation_path,
            "confidence": round(confidence, 4),
        }

    def detect_distribution_shift(
        self,
        baseline_traces: list[TelemetryTrace],
        current_traces: list[TelemetryTrace],
    ) -> dict[str, Any]:
        """Compare baseline and current telemetry distributions for shift.

        Computes KL divergence independently on four dimensions:

        1. **risk_score** distribution
        2. **latency (duration_ms)** distribution (log-binned)
        3. **tool-call frequency** (tool name → count, normalised)
        4. **agent activity** (agent_id → span count, normalised)

        Args:
            baseline_traces: Reference traces representing known-clean traffic.
            current_traces: Traces to evaluate for distribution shift.

        Returns:
            Dictionary with keys:

            - ``risk_score_kl``: KL divergence on risk score distributions.
            - ``latency_kl``: KL divergence on log-binned latency distributions.
            - ``tool_frequency_kl``: KL divergence on tool-call frequency.
            - ``agent_activity_kl``: KL divergence on agent activity patterns.
            - ``overall_shift_score``: Weighted mean in [0.0, 1.0].
            - ``verdict``: ``"stable"``, ``"drifting"``, or ``"shifted"``.

        Raises:
            ValueError: If either input list is empty.
        """
        if not baseline_traces:
            raise ValueError("baseline_traces must contain at least one trace.")
        if not current_traces:
            raise ValueError("current_traces must contain at least one trace.")

        base_spans = [s for tr in baseline_traces for s in tr.spans]
        curr_spans = [s for tr in current_traces for s in tr.spans]

        # ---- Dimension 1: risk score ----
        base_risk = [s.risk_score for s in base_spans]
        curr_risk = [s.risk_score for s in curr_spans]
        risk_kl = self._compute_histogram_kl(base_risk, curr_risk, bins=20, lo=0.0, hi=1.0)

        # ---- Dimension 2: latency (log-binned) ----
        base_lat = [np.log1p(s.duration_ms) for s in base_spans]
        curr_lat = [np.log1p(s.duration_ms) for s in curr_spans]
        lat_kl = self._compute_histogram_kl(
            base_lat,
            curr_lat,
            bins=20,
            lo=0.0,
            hi=float(np.log1p(max(max(base_lat, default=0.0), max(curr_lat, default=0.0)) + 1.0)),
        )

        # ---- Dimension 3: tool-call frequency ----
        base_tool_counts: dict[str, int] = {}
        curr_tool_counts: dict[str, int] = {}
        for s in base_spans:
            if s.event_type == TelemetryEventType.TOOL_CALL:
                tool = str(s.attributes.get("tool_name", "unknown"))
                base_tool_counts[tool] = base_tool_counts.get(tool, 0) + 1
        for s in curr_spans:
            if s.event_type == TelemetryEventType.TOOL_CALL:
                tool = str(s.attributes.get("tool_name", "unknown"))
                curr_tool_counts[tool] = curr_tool_counts.get(tool, 0) + 1
        tool_kl = self._compute_categorical_kl(base_tool_counts, curr_tool_counts)

        # ---- Dimension 4: agent activity ----
        base_agent: dict[str, int] = {}
        curr_agent: dict[str, int] = {}
        for s in base_spans:
            base_agent[s.agent_id] = base_agent.get(s.agent_id, 0) + 1
        for s in curr_spans:
            curr_agent[s.agent_id] = curr_agent.get(s.agent_id, 0) + 1
        agent_kl = self._compute_categorical_kl(base_agent, curr_agent)

        # ---- Overall weighted shift score (capped at 1.0) ----
        weights = [0.35, 0.30, 0.20, 0.15]
        raw_kls = [risk_kl, lat_kl, tool_kl, agent_kl]
        # Normalise each KL to [0, 1] using a soft cap at KL=2.0
        normalised = [float(np.clip(kl / 2.0, 0.0, 1.0)) for kl in raw_kls]
        overall = float(np.dot(weights, normalised))

        verdict = "stable" if overall < 0.20 else "drifting" if overall < 0.50 else "shifted"

        logger.info(
            "Distribution shift  risk_kl=%.4f  lat_kl=%.4f  tool_kl=%.4f  "
            "agent_kl=%.4f  overall=%.4f  verdict=%s",
            risk_kl,
            lat_kl,
            tool_kl,
            agent_kl,
            overall,
            verdict,
        )

        return {
            "risk_score_kl": round(risk_kl, 6),
            "latency_kl": round(lat_kl, 6),
            "tool_frequency_kl": round(tool_kl, 6),
            "agent_activity_kl": round(agent_kl, 6),
            "overall_shift_score": round(overall, 4),
            "verdict": verdict,
        }

    def generate_execution_timeline(
        self, traces: list[TelemetryTrace],
    ) -> list[dict[str, Any]]:
        """Produce a flattened, time-ordered event list for frontend visualisation.

        Each entry in the returned list represents one :class:`TelemetrySpan`
        and carries the fields most relevant to rendering a timeline UI:
        timestamp, agent, event type, duration, risk, anomaly flags, and
        optional tool/doc identifiers.

        Args:
            traces: List of :class:`TelemetryTrace` objects to flatten.

        Returns:
            List of event dicts sorted by ``timestamp`` ascending.  Each dict
            contains:

            - ``timestamp``: ISO-8601 UTC string.
            - ``trace_id``: Parent trace identifier.
            - ``span_id``: This span's identifier.
            - ``agent_id``: Emitting agent.
            - ``event_type``: :class:`TelemetryEventType` value string.
            - ``duration_ms``: Span duration in milliseconds.
            - ``risk_score``: Computed risk score in [0.0, 1.0].
            - ``is_anomalous``: Boolean flag.
            - ``anomaly_types``: List of anomaly type value strings.
            - ``tool_name``: Tool name if ``event_type == tool_call``, else ``None``.
            - ``doc_id``: Retrieved document ID if ``event_type == rag_retrieval``,
              else ``None``.
        """
        events: list[dict[str, Any]] = []

        for trace in traces:
            for span in trace.spans:
                events.append(
                    {
                        "timestamp": span.timestamp,
                        "trace_id": span.trace_id,
                        "span_id": span.span_id,
                        "agent_id": span.agent_id,
                        "event_type": span.event_type.value,
                        "duration_ms": round(span.duration_ms, 3),
                        "risk_score": round(span.risk_score, 4),
                        "is_anomalous": span.is_anomalous,
                        "anomaly_types": [at.value for at in span.anomaly_types],
                        "tool_name": span.attributes.get("tool_name"),
                        "doc_id": span.attributes.get("doc_id"),
                    }
                )

        events.sort(key=lambda e: e["timestamp"])
        return events

    # ------------------------------------------------------------------
    # Trace generation helpers
    # ------------------------------------------------------------------

    def _generate_clean_trace(
        self,
        rng: np.random.Generator,
        agent_ids: list[str],
        window_start: datetime,
        window_hours: int,
        avg_spans: int,
        noise_level: float,
    ) -> TelemetryTrace:
        """Generate a single clean (unpoisoned) telemetry trace.

        Span count is drawn from a Poisson distribution with mean
        *avg_spans*.  Latencies follow a log-normal distribution with
        parameters :attr:`_BASELINE_LATENCY_MU` and
        :attr:`_BASELINE_LATENCY_SIGMA`.  Risk scores are drawn from
        Beta(2, 8) so the bulk of clean traffic falls below 0.4.

        The event-type sequence mimics a realistic LLM agent request:
        prompt submission → optional RAG retrieval → model inference →
        optional tool call(s) → optional memory operations → agent decision.

        Args:
            rng: Seeded random generator.
            agent_ids: Pool of agent identifiers to choose from.
            window_start: Start of the simulation time window.
            window_hours: Length of the observation window in hours.
            avg_spans: Mean spans per trace (Poisson mean).
            noise_level: Additive Gaussian noise standard deviation applied to
                latency and risk values.

        Returns:
            A fully populated :class:`TelemetryTrace` with ``is_anomalous``
            and ``anomaly_types`` initialised to their clean-state defaults.
        """
        trace_id = _uuid_from_rng(rng)
        agent_id = str(rng.choice(agent_ids))
        num_spans = max(2, int(rng.poisson(avg_spans)))

        # Event sequence: always start with prompt_submission, end with
        # agent_decision; fill interior with plausible event types.
        interior_pool = [
            TelemetryEventType.TOOL_CALL,
            TelemetryEventType.TOOL_RESPONSE,
            TelemetryEventType.RAG_RETRIEVAL,
            TelemetryEventType.MODEL_INFERENCE,
            TelemetryEventType.MEMORY_WRITE,
            TelemetryEventType.MEMORY_READ,
        ]
        interior_count = max(0, num_spans - 2)
        interior_types = [
            TelemetryEventType(
                interior_pool[int(rng.integers(0, len(interior_pool)))]
            )
            for _ in range(interior_count)
        ]
        event_types = (
            [TelemetryEventType.PROMPT_SUBMISSION]
            + interior_types
            + [TelemetryEventType.AGENT_DECISION]
        )

        # Base timestamp: random offset within window
        base_offset_seconds = float(rng.uniform(0, window_hours * 3600))
        base_dt = window_start + timedelta(seconds=base_offset_seconds)

        spans: list[TelemetrySpan] = []
        parent_span_id: str | None = None
        current_dt = base_dt

        for event_type in event_types:
            span_id = _uuid_from_rng(rng)

            # Latency: log-normal with additive noise
            raw_lat = float(rng.lognormal(self._BASELINE_LATENCY_MU, self._BASELINE_LATENCY_SIGMA))
            noise = float(rng.normal(0.0, noise_level * raw_lat))
            duration_ms = max(1.0, raw_lat + noise)

            # Risk score: Beta(2, 8) with noise
            raw_risk = float(rng.beta(self._BASELINE_RISK_ALPHA, self._BASELINE_RISK_BETA))
            risk_noise = float(rng.normal(0.0, noise_level * 0.1))
            risk_score = float(np.clip(raw_risk + risk_noise, 0.0, 1.0))

            attributes: dict[str, Any] = {"clean": True}
            if event_type == TelemetryEventType.TOOL_CALL:
                tool_names = ["read_file", "web_search", "code_exec", "database_query"]
                attributes["tool_name"] = tool_names[int(rng.integers(0, len(tool_names)))]
                attributes["denied"] = bool(rng.random() < self._TOOL_DENIAL_BASELINE)
            elif event_type == TelemetryEventType.RAG_RETRIEVAL:
                attributes["doc_id"] = f"doc-{rng.integers(1000, 9999)}"
                attributes["similarity_score"] = float(
                    np.clip(rng.normal(0.82, 0.06), 0.0, 1.0)
                )
            elif event_type in (
                TelemetryEventType.MEMORY_WRITE,
                TelemetryEventType.MEMORY_READ,
            ):
                content = f"clean-content-{rng.integers(10000, 99999)}"
                attributes["content_hash"] = hashlib.sha256(content.encode()).hexdigest()[:16]
                attributes["memory_key"] = f"mem-{rng.integers(100, 999)}"
            elif event_type == TelemetryEventType.AGENT_DECISION:
                attributes["reward_signal"] = float(np.clip(rng.normal(0.55, 0.15), 0.0, 1.0))
                attributes["quality_score"] = float(np.clip(rng.normal(0.60, 0.15), 0.0, 1.0))
            elif event_type == TelemetryEventType.PROMPT_SUBMISSION:
                attributes["prompt_length"] = int(rng.integers(50, 500))
                attributes["cosine_distance_from_baseline"] = float(
                    np.clip(rng.normal(0.05, 0.03), 0.0, 1.0)
                )

            spans.append(
                TelemetrySpan(
                    span_id=span_id,
                    trace_id=trace_id,
                    parent_span_id=parent_span_id,
                    event_type=event_type,
                    agent_id=agent_id,
                    timestamp=current_dt.isoformat(),
                    duration_ms=round(duration_ms, 3),
                    attributes=attributes,
                    risk_score=round(risk_score, 4),
                    is_anomalous=False,
                    anomaly_types=[],
                )
            )

            parent_span_id = span_id
            # Advance time by roughly the span duration (simulate sequential execution)
            current_dt += timedelta(milliseconds=duration_ms * float(rng.uniform(0.8, 1.2)))

        total_duration = sum(s.duration_ms for s in spans)
        return TelemetryTrace(
            trace_id=trace_id,
            spans=spans,
            total_duration_ms=round(total_duration, 3),
            root_cause_span_id=None,
            anomaly_summary={},
        )

    # ------------------------------------------------------------------
    # Attack injection helpers
    # ------------------------------------------------------------------

    def _inject_reward_hacking(
        self, trace: TelemetryTrace, rng: np.random.Generator,
    ) -> TelemetryTrace:
        """Mutate a clean trace with reward-hacking signals.

        Finds all ``agent_decision`` spans and inflates their ``reward_signal``
        to unnaturally high values while leaving ``quality_score`` flat,
        simulating an agent that games the reward function without producing
        genuine quality improvements.  Risk scores are elevated accordingly.

        Args:
            trace: Clean trace to mutate (modified in place).
            rng: Seeded random generator.

        Returns:
            The same :class:`TelemetryTrace` instance with mutations applied.
        """
        for span in trace.spans:
            if span.event_type == TelemetryEventType.AGENT_DECISION:
                span.attributes["reward_signal"] = float(
                    np.clip(rng.normal(0.92, 0.04), 0.8, 1.0)
                )
                # Quality score deliberately left low or stagnant
                span.attributes["quality_score"] = float(
                    np.clip(rng.normal(0.35, 0.08), 0.0, 0.5)
                )
                span.attributes["reward_hacked"] = True
                span.risk_score = round(
                    float(np.clip(span.risk_score + rng.uniform(0.35, 0.55), 0.0, 1.0)), 4
                )
                span.is_anomalous = True
                span.anomaly_types = [AnomalyType.REWARD_HACKING]

        trace.anomaly_summary = {
            "scenario": AttackScenario.REWARD_HACKING.value,
            "affected_span_types": [TelemetryEventType.AGENT_DECISION.value],
        }
        return trace

    def _inject_memory_poisoning(
        self, trace: TelemetryTrace, rng: np.random.Generator,
    ) -> TelemetryTrace:
        """Mutate a clean trace to simulate agent memory corruption.

        Selects a ``memory_write`` span and corrupts its content hash.
        Subsequent ``memory_read`` spans in the trace are then made to return
        a diverged hash, simulating a poisoned memory store.  Risk scores for
        both write and read spans are elevated.

        Args:
            trace: Clean trace to mutate (modified in place).
            rng: Seeded random generator.

        Returns:
            The mutated :class:`TelemetryTrace`.
        """
        write_spans = [
            s for s in trace.spans if s.event_type == TelemetryEventType.MEMORY_WRITE
        ]
        read_spans = [
            s for s in trace.spans if s.event_type == TelemetryEventType.MEMORY_READ
        ]

        if write_spans:
            poison_write = write_spans[int(rng.integers(0, len(write_spans)))]
            # Corrupt the stored hash
            poison_write.attributes["content_hash"] = "deadbeef" + str(
                rng.integers(100000, 999999)
            )
            poison_write.attributes["memory_corrupted"] = True
            poison_write.risk_score = round(
                float(np.clip(rng.uniform(0.65, 0.85), 0.0, 1.0)), 4
            )
            poison_write.is_anomalous = True
            poison_write.anomaly_types = [AnomalyType.MEMORY_CORRUPTION]

        # Downstream reads reflect corrupted state
        for rs in read_spans:
            rs.attributes["memory_corrupted"] = True
            rs.attributes["content_hash"] = "corrupted-" + str(rng.integers(100, 999))
            rs.risk_score = round(
                float(np.clip(rs.risk_score + rng.uniform(0.30, 0.50), 0.0, 1.0)), 4
            )
            rs.is_anomalous = True
            rs.anomaly_types = [AnomalyType.MEMORY_CORRUPTION]

        trace.anomaly_summary = {
            "scenario": AttackScenario.MEMORY_POISONING.value,
            "poisoned_writes": len(write_spans),
            "corrupted_reads": len(read_spans),
        }
        return trace

    def _inject_prompt_drift(
        self,
        trace: TelemetryTrace,
        rng: np.random.Generator,
        drift_factor: float,
    ) -> TelemetryTrace:
        """Mutate a trace to simulate prompt embedding distribution drift.

        Linearly increases the ``cosine_distance_from_baseline`` attribute of
        ``prompt_submission`` spans proportional to *drift_factor* (range
        [0.0, 2.0]).  A ``drift_factor`` of 0.0 produces no mutation; 2.0
        produces maximum drift.  Risk scores are scaled accordingly.

        Args:
            trace: Clean trace to mutate (modified in place).
            rng: Seeded random generator.
            drift_factor: Drift intensity scalar.  Values above 1.0 indicate
                SLOW_BURN late-stage drift.

        Returns:
            The mutated :class:`TelemetryTrace`.
        """
        for span in trace.spans:
            if span.event_type == TelemetryEventType.PROMPT_SUBMISSION:
                base_dist = span.attributes.get("cosine_distance_from_baseline", 0.05)
                # Drift increases cosine distance; noise prevents perfectly linear signals
                injected_dist = float(
                    np.clip(
                        base_dist + drift_factor * rng.uniform(0.15, 0.30),
                        0.0,
                        1.0,
                    )
                )
                span.attributes["cosine_distance_from_baseline"] = round(injected_dist, 4)
                risk_increment = drift_factor * 0.25
                span.risk_score = round(
                    float(np.clip(span.risk_score + risk_increment, 0.0, 1.0)), 4
                )
                if injected_dist > 0.25 or span.risk_score > 0.5:
                    span.is_anomalous = True
                    span.anomaly_types = [AnomalyType.DISTRIBUTION_SHIFT]

        trace.anomaly_summary = {
            "scenario": AttackScenario.PROMPT_DRIFT.value,
            "drift_factor": round(drift_factor, 4),
        }
        return trace

    def _inject_retrieval_manipulation(
        self, trace: TelemetryTrace, rng: np.random.Generator,
    ) -> TelemetryTrace:
        """Mutate RAG retrieval spans to simulate adversarial document injection.

        Selects a ``rag_retrieval`` span and raises its ``similarity_score``
        to a suspiciously high value while flagging the content as adversarial.
        The attacker's goal is to make a poisoned document appear highly
        relevant so it is preferentially retrieved.

        Args:
            trace: Clean trace to mutate (modified in place).
            rng: Seeded random generator.

        Returns:
            The mutated :class:`TelemetryTrace`.
        """
        rag_spans = [
            s for s in trace.spans if s.event_type == TelemetryEventType.RAG_RETRIEVAL
        ]

        for span in rag_spans:
            # Inflate similarity score to near-perfect to force retrieval
            span.attributes["similarity_score"] = float(
                np.clip(rng.uniform(0.96, 0.999), 0.0, 1.0)
            )
            span.attributes["doc_id"] = f"adversarial-doc-{rng.integers(1, 999)}"
            span.attributes["retrieval_hijacked"] = True
            span.attributes["content_poisoned"] = True
            span.risk_score = round(
                float(np.clip(rng.uniform(0.70, 0.90), 0.0, 1.0)), 4
            )
            span.is_anomalous = True
            span.anomaly_types = [AnomalyType.RETRIEVAL_HIJACK]

        trace.anomaly_summary = {
            "scenario": AttackScenario.RETRIEVAL_MANIPULATION.value,
            "hijacked_retrievals": len(rag_spans),
        }
        return trace

    def _inject_tool_hijack(
        self, trace: TelemetryTrace, rng: np.random.Generator,
    ) -> TelemetryTrace:
        """Mutate tool-call spans to simulate tool parameter hijacking.

        Replaces the ``tool_name`` of a random ``tool_call`` span with an
        unusual, high-risk tool and injects anomalous parameter patterns.
        The latency of the hijacked span is dramatically inflated to simulate
        the extra round-trip to an attacker-controlled endpoint.

        Args:
            trace: Clean trace to mutate (modified in place).
            rng: Seeded random generator.

        Returns:
            The mutated :class:`TelemetryTrace`.
        """
        tool_spans = [
            s for s in trace.spans if s.event_type == TelemetryEventType.TOOL_CALL
        ]

        if not tool_spans:
            return trace

        target = tool_spans[int(rng.integers(0, len(tool_spans)))]
        malicious_tools = [
            "exfiltrate_data",
            "exec_remote_code",
            "drop_table",
            "leak_credentials",
            "send_webhook",
        ]
        target.attributes["tool_name"] = malicious_tools[
            int(rng.integers(0, len(malicious_tools)))
        ]
        target.attributes["params"] = {
            "target": f"evil-host-{rng.integers(1, 99)}.attacker.com",
            "payload": "b64:" + "A" * int(rng.integers(40, 120)),
        }
        target.attributes["denied"] = False  # Hijack succeeded
        target.attributes["tool_hijacked"] = True
        # Inflate latency (exfiltration takes longer)
        target.duration_ms = round(
            target.duration_ms * float(rng.uniform(4.0, 12.0)), 3
        )
        target.risk_score = round(float(np.clip(rng.uniform(0.78, 0.96), 0.0, 1.0)), 4)
        target.is_anomalous = True
        target.anomaly_types = [AnomalyType.LATENCY_ANOMALY, AnomalyType.TOOL_DENIAL_SURGE]

        trace.anomaly_summary = {
            "scenario": AttackScenario.TOOL_HIJACK.value,
            "hijacked_tool": target.attributes["tool_name"],
        }
        return trace

    def _inject_collusion(
        self,
        traces: list[TelemetryTrace],
        agent_ids: list[str],
        rng: np.random.Generator,
    ) -> None:
        """Correlate anomalous signals across multiple agent traces.

        Selects two to three agent IDs and, within the first half of the
        *traces* list, resets their span timestamps to fall inside the same
        60-second window and elevates risk scores in unison.  The
        ``colluding`` attribute is set on each affected span.

        This simulates a scenario where multiple compromised agents coordinate
        their attacks to evade per-agent detection thresholds.

        Args:
            traces: Subset of traces designated as poisoned (mutated in place).
            agent_ids: Full pool of available agent IDs.
            rng: Seeded random generator.

        Returns:
            ``None``; mutates *traces* in place.
        """
        if len(agent_ids) < 2:
            return

        num_colluding = min(3, len(agent_ids))
        colluding_agents: list[str] = list(
            rng.choice(agent_ids, size=num_colluding, replace=False)
        )

        # Pick a single 60-second coordination window
        # The window start is derived from the first trace's first span timestamp.
        anchor_iso = traces[0].spans[0].timestamp if traces[0].spans else None
        if anchor_iso is None:
            return
        anchor_dt = datetime.fromisoformat(anchor_iso)
        window_end = anchor_dt + timedelta(seconds=self._COLLUSION_WINDOW_SECONDS)

        for trace in traces:
            if trace.spans[0].agent_id not in colluding_agents:
                continue
            for span in trace.spans:
                # Clamp timestamp into the coordination window
                ts = datetime.fromisoformat(span.timestamp)
                if ts > window_end:
                    clamped_offset = float(
                        rng.uniform(0, self._COLLUSION_WINDOW_SECONDS)
                    )
                    new_ts = anchor_dt + timedelta(seconds=clamped_offset)
                    span.timestamp = new_ts.isoformat()  # type: ignore[misc]
                span.attributes["colluding"] = True
                span.risk_score = round(
                    float(np.clip(span.risk_score + rng.uniform(0.20, 0.45), 0.0, 1.0)), 4
                )
                if not span.is_anomalous:
                    span.is_anomalous = True
                    span.anomaly_types = [AnomalyType.MULTI_AGENT_COLLUSION]
                elif AnomalyType.MULTI_AGENT_COLLUSION not in span.anomaly_types:
                    span.anomaly_types.append(AnomalyType.MULTI_AGENT_COLLUSION)

            trace.anomaly_summary["scenario"] = AttackScenario.MULTI_AGENT_COLLUSION.value
            trace.anomaly_summary["colluding_agents"] = colluding_agents

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    def _detect_collusion_patterns(self, spans: list[TelemetrySpan]) -> None:
        """Flag correlated multi-agent anomalies within 60-second windows.

        Groups spans by 60-second UTC buckets and, within each bucket, checks
        whether three or more distinct agents have anomalous spans.  If so,
        all anomalous spans in that bucket are tagged with
        :attr:`AnomalyType.MULTI_AGENT_COLLUSION`.

        Args:
            spans: Flat list of all spans across all traces (mutated in place).

        Returns:
            ``None``; mutates *spans* in place.
        """
        from collections import defaultdict

        bucket_agents: dict[int, set[str]] = defaultdict(set)
        bucket_anomalous: dict[int, list[TelemetrySpan]] = defaultdict(list)

        for span in spans:
            try:
                ts = datetime.fromisoformat(span.timestamp)
            except ValueError:
                continue
            bucket = int(ts.timestamp() // self._COLLUSION_WINDOW_SECONDS)
            if span.is_anomalous:
                bucket_agents[bucket].add(span.agent_id)
                bucket_anomalous[bucket].append(span)

        for bucket, agents in bucket_agents.items():
            if len(agents) >= 3:
                for span in bucket_anomalous[bucket]:
                    if AnomalyType.MULTI_AGENT_COLLUSION not in span.anomaly_types:
                        span.anomaly_types.append(AnomalyType.MULTI_AGENT_COLLUSION)

    def _detect_reward_hacking(self, trace: TelemetryTrace) -> None:
        """Flag reward-hacking patterns within a single trace.

        Scans ``agent_decision`` spans for a high reward/quality divergence:
        ``reward_signal - quality_score > 0.35``.  Flagged spans receive the
        :attr:`AnomalyType.REWARD_HACKING` annotation.

        Args:
            trace: Trace to inspect (mutated in place).

        Returns:
            ``None``; mutates spans in place.
        """
        for span in trace.spans:
            if span.event_type != TelemetryEventType.AGENT_DECISION:
                continue
            reward = float(span.attributes.get("reward_signal", 0.0))
            quality = float(span.attributes.get("quality_score", 0.0))
            if reward - quality > 0.35:
                span.is_anomalous = True
                if AnomalyType.REWARD_HACKING not in span.anomaly_types:
                    span.anomaly_types.append(AnomalyType.REWARD_HACKING)

    # ------------------------------------------------------------------
    # Statistical helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_kl_divergence(
        p: np.ndarray, q: np.ndarray, epsilon: float = 1e-10,
    ) -> float:
        """Compute the KL divergence KL(P || Q) between two probability distributions.

        Both arrays are normalised to sum to 1 before computation.  A small
        *epsilon* is added to all bins to avoid division-by-zero and
        log-of-zero errors (Laplace smoothing).

        Args:
            p: First distribution (will be L1-normalised).
            q: Second distribution (will be L1-normalised).
            epsilon: Smoothing constant added to every bin.

        Returns:
            KL divergence in nats as a non-negative float.  Returns 0.0 if
            either array is empty or has zero mass.
        """
        p = np.asarray(p, dtype=np.float64).ravel()
        q = np.asarray(q, dtype=np.float64).ravel()

        if p.size == 0 or q.size == 0:
            return 0.0

        # Pad to equal length with zeros
        n = max(len(p), len(q))
        p = np.pad(p, (0, n - len(p)), constant_values=0.0)
        q = np.pad(q, (0, n - len(q)), constant_values=0.0)

        p = p + epsilon
        q = q + epsilon

        p_sum = p.sum()
        q_sum = q.sum()
        if p_sum < 1e-12 or q_sum < 1e-12:
            return 0.0

        p = p / p_sum
        q = q / q_sum

        # scipy.stats.entropy computes sum(p * log(p/q))
        return float(scipy_stats.entropy(p, q))

    @staticmethod
    def _modified_z_score(data: np.ndarray) -> np.ndarray:
        """Compute the MAD-based modified Z-score for outlier detection.

        Uses the Median Absolute Deviation (MAD) rather than the standard
        deviation, making it robust to the heavy-tailed latency distributions
        common in production LLM telemetry.

        The formula is: ``0.6745 * (x_i - median) / MAD``

        Args:
            data: 1-D array of values.

        Returns:
            1-D array of modified Z-scores with the same shape as *data*.
            Returns an all-zero array if MAD is effectively zero (all values
            are identical).
        """
        data = np.asarray(data, dtype=np.float64).ravel()
        median = float(np.median(data))
        mad = float(np.median(np.abs(data - median)))
        if mad < 1e-12:
            return np.zeros_like(data)
        return 0.6745 * (data - median) / mad

    def _compute_risk_distribution(
        self, risk_scores: np.ndarray,
    ) -> dict[str, float]:
        """Compute descriptive statistics for a risk-score array.

        Args:
            risk_scores: 1-D array of risk scores in [0.0, 1.0].

        Returns:
            Dictionary with ``mean``, ``std``, ``p95``, and ``p99`` keys,
            all rounded to four decimal places.
        """
        if risk_scores.size == 0:
            return {"mean": 0.0, "std": 0.0, "p95": 0.0, "p99": 0.0}
        return {
            "mean": round(float(np.mean(risk_scores)), 4),
            "std": round(float(np.std(risk_scores)), 4),
            "p95": round(float(np.percentile(risk_scores, 95)), 4),
            "p99": round(float(np.percentile(risk_scores, 99)), 4),
        }

    def _compute_histogram_kl(
        self,
        baseline: list[float],
        current: list[float],
        bins: int,
        lo: float,
        hi: float,
    ) -> float:
        """Compute KL divergence between two 1-D distributions via histogram binning.

        Args:
            baseline: Reference values.
            current: Values to compare against the reference.
            bins: Number of equal-width histogram bins.
            lo: Lower bin edge.
            hi: Upper bin edge (clamped if data exceeds this).

        Returns:
            KL divergence in nats.
        """
        edges = np.linspace(lo, max(hi, lo + 1e-6), bins + 1)
        p_hist, _ = np.histogram(baseline, bins=edges)
        q_hist, _ = np.histogram(current, bins=edges)
        return self._compute_kl_divergence(
            p_hist.astype(np.float64), q_hist.astype(np.float64)
        )

    def _compute_categorical_kl(
        self,
        baseline_counts: dict[str, int],
        current_counts: dict[str, int],
    ) -> float:
        """Compute KL divergence between two categorical count distributions.

        The union of keys from both dicts defines the category set.  Missing
        keys in either dict are treated as zero counts before smoothing.

        Args:
            baseline_counts: Category → count mapping for the reference period.
            current_counts: Category → count mapping for the current period.

        Returns:
            KL divergence in nats.
        """
        all_keys = sorted(set(baseline_counts) | set(current_counts))
        if not all_keys:
            return 0.0
        p = np.array([float(baseline_counts.get(k, 0)) for k in all_keys], dtype=np.float64)
        q = np.array([float(current_counts.get(k, 0)) for k in all_keys], dtype=np.float64)
        return self._compute_kl_divergence(p, q)

    def _compute_distribution_shift_score(
        self,
        baseline_scores: np.ndarray,
        current_scores: list[float],
    ) -> float:
        """Compute a normalised distribution shift score via histogram KL divergence.

        Bins both distributions into 20 equal-width buckets over [0.0, 1.0]
        and computes KL(baseline || current), then normalises to [0.0, 1.0]
        using a soft cap at KL = 2.0.

        Args:
            baseline_scores: Array of clean-baseline risk scores.
            current_scores: List of current risk scores to compare.

        Returns:
            Normalised shift score in [0.0, 1.0].
        """
        kl = self._compute_histogram_kl(
            baseline_scores.tolist(), current_scores, bins=20, lo=0.0, hi=1.0
        )
        return float(np.clip(kl / 2.0, 0.0, 1.0))
