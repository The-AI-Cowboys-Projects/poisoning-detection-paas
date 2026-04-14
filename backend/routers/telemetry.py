"""
Synthetic Telemetry Data Simulator router.

POST /api/v1/telemetry/simulate           — generate a synthetic telemetry dataset
POST /api/v1/telemetry/analyze            — analyze provided telemetry trace data
POST /api/v1/telemetry/distribution-shift — compare baseline vs current telemetry
GET  /api/v1/telemetry/scenarios          — list available attack scenarios with descriptions
GET  /api/v1/telemetry/timeline/{simulation_id} — get execution timeline for visualization
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.config import get_settings

logger = logging.getLogger(__name__)
router = APIRouter()

# ---------------------------------------------------------------------------
# Simulator service — lazy-imported so the router loads even if the service
# module is not yet present (matches the scaffold pattern in main.py).
# ---------------------------------------------------------------------------

_simulator = None


def _get_simulator() -> Any:
    """
    Return the module-level simulator singleton.

    Instantiated once on first call and reused for all subsequent requests.
    Raises HTTPException 503 if the service module cannot be imported so that
    the rest of the API surface remains healthy.
    """
    global _simulator  # noqa: PLW0603
    if _simulator is not None:
        return _simulator
    try:
        from backend.services.telemetry_simulator import TelemetrySimulator  # type: ignore[import]

        _simulator = TelemetrySimulator()
        logger.info("TelemetrySimulator instantiated successfully.")
        return _simulator
    except ImportError as exc:
        logger.error("TelemetrySimulator service not available: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Telemetry simulator service is not available.",
        ) from exc


# ---------------------------------------------------------------------------
# Attack scenario registry
# ---------------------------------------------------------------------------

_SCENARIO_REGISTRY: list[dict[str, Any]] = [
    {
        "name": "clean",
        "description": "Normal operational telemetry with no adversarial activity",
        "typical_indicators": [],
    },
    {
        "name": "reward_hacking",
        "description": "Agent manipulates reward signals to game metrics without fulfilling actual intent",
        "typical_indicators": [
            "anomalously high reward scores on low-complexity tasks",
            "divergence between stated goal completion and actual output quality",
            "reward signal spikes uncorrelated with task difficulty",
        ],
    },
    {
        "name": "memory_poisoning",
        "description": "Attacker corrupts agent long-term memory via tampered telemetry stream",
        "typical_indicators": [
            "sudden retrieval of previously unseen high-confidence memories",
            "memory write spans with elevated risk scores",
            "cross-session context bleed between unrelated tasks",
        ],
    },
    {
        "name": "prompt_drift",
        "description": "Gradual shift in prompt distribution indicating subtle context manipulation",
        "typical_indicators": [
            "increasing distribution shift score over time",
            "slow migration of token distributions away from baseline",
            "low per-span anomaly score masking cumulative drift",
        ],
    },
    {
        "name": "retrieval_manipulation",
        "description": "Adversarial documents injected into RAG retrieval pipeline",
        "typical_indicators": [
            "retrieval spans returning documents with anomalous embedding distance",
            "high-confidence retrievals for queries with no historical match",
            "tool_denial_rate spike following retrieval events",
        ],
    },
    {
        "name": "tool_hijack",
        "description": "MCP tool calls redirected or parameters manipulated mid-execution",
        "typical_indicators": [
            "parameter value drift between span creation and execution",
            "tool call latency outliers suggesting interception",
            "unexpected tool substitution within a single trace",
        ],
    },
    {
        "name": "multi_agent_collusion",
        "description": "Coordinated anomalous behavior across multiple agents",
        "typical_indicators": [
            "synchronized anomaly timestamps across distinct agent IDs",
            "correlated risk score spikes in otherwise independent agents",
            "unusual cross-agent message volume during attack window",
        ],
    },
    {
        "name": "slow_burn",
        "description": "Very gradual poisoning that accumulates over extended time windows",
        "typical_indicators": [
            "individually sub-threshold spans that aggregate above detection threshold",
            "monotonic increase in distribution shift score over 24+ hours",
            "anomaly_types list growing longer over successive traces",
        ],
    },
]

# Build a fast lookup by name for internal use
_SCENARIO_BY_NAME: dict[str, dict[str, Any]] = {s["name"]: s for s in _SCENARIO_REGISTRY}

# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------


class SimulationRequest(BaseModel):
    """Parameters controlling the synthetic telemetry generation run."""

    scenario: str = Field(
        default="clean",
        description=(
            "Attack scenario to simulate. One of: clean, reward_hacking, "
            "memory_poisoning, prompt_drift, retrieval_manipulation, "
            "tool_hijack, multi_agent_collusion, slow_burn."
        ),
    )
    num_traces: int = Field(default=100, ge=10, le=10000)
    num_agents: int = Field(default=5, ge=1, le=50)
    avg_spans_per_trace: int = Field(default=8, ge=3, le=30)
    poison_ratio: float = Field(default=0.15, ge=0.0, le=1.0)
    noise_level: float = Field(default=0.1, ge=0.0, le=1.0)
    time_window_hours: int = Field(default=24, ge=1, le=168)
    seed: int | None = Field(
        default=None,
        description="Random seed for reproducibility. Omit for a non-deterministic run.",
    )


class TelemetrySpanResponse(BaseModel):
    """A single instrumentation span within a telemetry trace."""

    span_id: str
    trace_id: str
    parent_span_id: str | None = None
    event_type: str
    agent_id: str
    timestamp: str
    duration_ms: float
    risk_score: float
    is_anomalous: bool
    anomaly_types: list[str]
    attributes: dict[str, Any]


class TelemetryTraceResponse(BaseModel):
    """A complete execution trace composed of one or more spans."""

    trace_id: str
    spans: list[TelemetrySpanResponse]
    total_duration_ms: float
    root_cause_span_id: str | None = None
    anomaly_summary: dict[str, Any]


class SimulationResponse(BaseModel):
    """
    Result of a /simulate call.

    Contains the analysis of the full generated dataset plus the first five
    sample traces for immediate inspection.  The full dataset is not returned
    inline to keep response sizes reasonable.
    """

    simulation_id: str
    scenario: str
    traces_generated: int
    analysis: dict[str, Any]
    sample_traces: list[TelemetryTraceResponse]
    generated_at: str


class AnalysisRequest(BaseModel):
    """Raw telemetry trace data submitted for analysis."""

    traces: list[dict[str, Any]] = Field(
        description="List of raw trace dicts as returned by the simulator or an external collector."
    )
    baseline_traces: list[dict[str, Any]] | None = Field(
        default=None,
        description=(
            "Optional clean-baseline traces. When provided, a distribution "
            "shift score is computed in addition to the standard analysis."
        ),
    )


class AnalysisResponse(BaseModel):
    """Comprehensive anomaly analysis report for a submitted trace dataset."""

    analysis_id: str
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
    analyzed_at: str


class DistributionShiftRequest(BaseModel):
    """Pair of trace datasets to compare for distribution shift."""

    baseline_traces: list[dict[str, Any]] = Field(
        description="Reference (clean) trace dataset."
    )
    current_traces: list[dict[str, Any]] = Field(
        description="Current operational trace dataset to compare against the baseline."
    )


class DistributionShiftResponse(BaseModel):
    """Per-dimension and overall distribution shift scores."""

    shift_id: str
    overall_shift_score: float
    dimension_scores: dict[str, float]
    verdict: str
    analyzed_at: str


class ScenarioListResponse(BaseModel):
    """Available attack scenario descriptions."""

    scenarios: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# Helper — convert simulator-native trace objects to response models
# ---------------------------------------------------------------------------


def _span_to_response(span: Any) -> TelemetrySpanResponse:
    """
    Coerce a simulator span object or plain dict into a TelemetrySpanResponse.

    The simulator may return either dataclass instances or plain dicts
    depending on version; this helper handles both cases uniformly.
    """
    if isinstance(span, dict):
        return TelemetrySpanResponse(
            span_id=str(span.get("span_id", "")),
            trace_id=str(span.get("trace_id", "")),
            parent_span_id=span.get("parent_span_id"),
            event_type=str(span.get("event_type", "unknown")),
            agent_id=str(span.get("agent_id", "")),
            timestamp=str(span.get("timestamp", "")),
            duration_ms=float(span.get("duration_ms", 0.0)),
            risk_score=float(span.get("risk_score", 0.0)),
            is_anomalous=bool(span.get("is_anomalous", False)),
            anomaly_types=list(span.get("anomaly_types", [])),
            attributes=dict(span.get("attributes", {})),
        )
    # Dataclass / object path
    return TelemetrySpanResponse(
        span_id=str(getattr(span, "span_id", "")),
        trace_id=str(getattr(span, "trace_id", "")),
        parent_span_id=getattr(span, "parent_span_id", None),
        event_type=str(getattr(span, "event_type", "unknown")),
        agent_id=str(getattr(span, "agent_id", "")),
        timestamp=str(getattr(span, "timestamp", "")),
        duration_ms=float(getattr(span, "duration_ms", 0.0)),
        risk_score=float(getattr(span, "risk_score", 0.0)),
        is_anomalous=bool(getattr(span, "is_anomalous", False)),
        anomaly_types=list(getattr(span, "anomaly_types", [])),
        attributes=dict(getattr(span, "attributes", {})),
    )


def _trace_to_response(trace: Any) -> TelemetryTraceResponse:
    """
    Coerce a simulator trace object or plain dict into a TelemetryTraceResponse.
    """
    if isinstance(trace, dict):
        spans = [_span_to_response(s) for s in trace.get("spans", [])]
        return TelemetryTraceResponse(
            trace_id=str(trace.get("trace_id", "")),
            spans=spans,
            total_duration_ms=float(trace.get("total_duration_ms", 0.0)),
            root_cause_span_id=trace.get("root_cause_span_id"),
            anomaly_summary=dict(trace.get("anomaly_summary", {})),
        )
    spans = [_span_to_response(s) for s in getattr(trace, "spans", [])]
    return TelemetryTraceResponse(
        trace_id=str(getattr(trace, "trace_id", "")),
        spans=spans,
        total_duration_ms=float(getattr(trace, "total_duration_ms", 0.0)),
        root_cause_span_id=getattr(trace, "root_cause_span_id", None),
        anomaly_summary=dict(getattr(trace, "anomaly_summary", {})),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/simulate",
    response_model=SimulationResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Generate a synthetic telemetry dataset for a named attack scenario",
)
async def simulate_telemetry(body: SimulationRequest) -> SimulationResponse:
    """
    Generate a fully labelled synthetic telemetry dataset.

    The simulator produces `num_traces` execution traces across `num_agents`
    agents, injecting poisoned spans according to `poison_ratio` for the
    requested `scenario`.  Gaussian noise at `noise_level` is applied to all
    numeric signal fields to model realistic measurement jitter.

    The response includes:
    - `analysis` — full TelemetryAnalysisResult as a plain dict
    - `sample_traces` — the first 5 generated traces for immediate inspection

    A 202 is returned because generation is synchronous but may take several
    hundred milliseconds for large datasets (num_traces > 1000).
    """
    if body.scenario not in _SCENARIO_BY_NAME:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Unknown scenario '{body.scenario}'. "
                f"Valid values: {', '.join(_SCENARIO_BY_NAME.keys())}."
            ),
        )

    simulator = _get_simulator()

    try:
        # Build SimulationConfig from the request.  The simulator service
        # accepts either a dataclass or keyword arguments; we pass a dict
        # and let it normalise internally.
        config = {
            "scenario": body.scenario,
            "num_traces": body.num_traces,
            "num_agents": body.num_agents,
            "avg_spans_per_trace": body.avg_spans_per_trace,
            "poison_ratio": body.poison_ratio,
            "noise_level": body.noise_level,
            "time_window_hours": body.time_window_hours,
            "seed": body.seed,
        }

        dataset = simulator.generate_dataset(config)
        analysis_result = simulator.analyze_telemetry(dataset)

    except Exception as exc:
        logger.error("Telemetry simulation failed for scenario '%s': %s", body.scenario, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Simulation failed. Check server logs for details.",
        ) from exc

    # Normalise analysis result to plain dict
    if isinstance(analysis_result, dict):
        analysis_dict = analysis_result
    else:
        try:
            analysis_dict = analysis_result.__dict__
        except AttributeError:
            analysis_dict = {}

    # Collect traces — dataset may be a list, a dict with a 'traces' key,
    # or an object with a .traces attribute.
    if isinstance(dataset, dict):
        all_traces = dataset.get("traces", [])
    elif isinstance(dataset, list):
        all_traces = dataset
    else:
        all_traces = getattr(dataset, "traces", [])

    sample_traces = [_trace_to_response(t) for t in all_traces[:5]]

    return SimulationResponse(
        simulation_id=str(uuid.uuid4()),
        scenario=body.scenario,
        traces_generated=len(all_traces),
        analysis=analysis_dict,
        sample_traces=sample_traces,
        generated_at=datetime.now(tz=timezone.utc).isoformat(),
    )


@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze a provided set of telemetry traces for poisoning indicators",
)
async def analyze_telemetry(body: AnalysisRequest) -> AnalysisResponse:
    """
    Analyze caller-supplied telemetry traces.

    The service reconstructs TelemetryTrace objects from the provided dicts,
    runs the full anomaly-detection pipeline, and — when `baseline_traces` is
    supplied — appends a distribution shift score computed against that clean
    reference window.

    This endpoint is useful for integrating production collectors: pipe live
    OTEL spans through this route to get a real-time risk verdict.
    """
    if not body.traces:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one trace is required for analysis.",
        )

    simulator = _get_simulator()

    try:
        analysis_result = simulator.analyze_telemetry(body.traces)
    except Exception as exc:
        logger.error("Telemetry analysis failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis failed. Check server logs for details.",
        ) from exc

    # Compute distribution shift if baseline provided
    shift_score = 0.0
    if body.baseline_traces:
        try:
            shift_result = simulator.detect_distribution_shift(
                body.baseline_traces, body.traces
            )
            if isinstance(shift_result, dict):
                shift_score = float(shift_result.get("overall_shift_score", 0.0))
            else:
                shift_score = float(getattr(shift_result, "overall_shift_score", 0.0))
        except Exception as exc:
            logger.warning(
                "Distribution shift detection failed (non-fatal, defaulting to 0.0): %s", exc
            )

    # Normalise analysis result
    if isinstance(analysis_result, dict):
        r = analysis_result
    else:
        try:
            r = analysis_result.__dict__
        except AttributeError:
            r = {}

    return AnalysisResponse(
        analysis_id=str(uuid.uuid4()),
        total_traces=int(r.get("total_traces", len(body.traces))),
        total_spans=int(r.get("total_spans", 0)),
        anomalous_traces=int(r.get("anomalous_traces", 0)),
        anomaly_breakdown=dict(r.get("anomaly_breakdown", {})),
        prompt_risk_distribution=dict(r.get("prompt_risk_distribution", {})),
        tool_denial_rate=float(r.get("tool_denial_rate", 0.0)),
        avg_latency_ms=float(r.get("avg_latency_ms", 0.0)),
        latency_p99_ms=float(r.get("latency_p99_ms", 0.0)),
        distribution_shift_score=shift_score if shift_score else float(r.get("distribution_shift_score", 0.0)),
        root_cause_traces=list(r.get("root_cause_traces", [])),
        risk_score=float(r.get("risk_score", 0.0)),
        verdict=str(r.get("verdict", "unknown")),
        execution_timeline=list(r.get("execution_timeline", [])),
        analyzed_at=datetime.now(tz=timezone.utc).isoformat(),
    )


@router.post(
    "/distribution-shift",
    response_model=DistributionShiftResponse,
    status_code=status.HTTP_200_OK,
    summary="Compute distribution shift between baseline and current telemetry",
)
async def detect_distribution_shift(body: DistributionShiftRequest) -> DistributionShiftResponse:
    """
    Compare a baseline (clean) trace window against a current operational window.

    Returns per-dimension shift scores (e.g. latency, risk_score, anomaly_rate)
    and an overall Jensen-Shannon or Wasserstein distance depending on the
    simulator's implementation.

    A verdict of 'drifting' or 'shifted' indicates that the current telemetry
    distribution has moved significantly from the reference baseline, which may
    signal an ongoing slow-burn or prompt-drift attack.
    """
    if not body.baseline_traces:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="baseline_traces must not be empty.",
        )
    if not body.current_traces:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="current_traces must not be empty.",
        )

    simulator = _get_simulator()

    try:
        result = simulator.detect_distribution_shift(
            body.baseline_traces, body.current_traces
        )
    except Exception as exc:
        logger.error("Distribution shift detection failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Distribution shift computation failed. Check server logs for details.",
        ) from exc

    if isinstance(result, dict):
        r = result
    else:
        try:
            r = result.__dict__
        except AttributeError:
            r = {}

    return DistributionShiftResponse(
        shift_id=str(uuid.uuid4()),
        overall_shift_score=float(r.get("overall_shift_score", 0.0)),
        dimension_scores=dict(r.get("dimension_scores", {})),
        verdict=str(r.get("verdict", "unknown")),
        analyzed_at=datetime.now(tz=timezone.utc).isoformat(),
    )


@router.get(
    "/scenarios",
    response_model=ScenarioListResponse,
    status_code=status.HTTP_200_OK,
    summary="List all available attack scenarios with descriptions and typical indicators",
)
async def list_scenarios() -> ScenarioListResponse:
    """
    Return the full catalogue of supported attack scenarios.

    Each entry includes:
    - `name`               — the string value accepted by the `scenario` field on /simulate
    - `description`        — one-sentence summary of the attack class
    - `typical_indicators` — observable signals that characterise this scenario

    This endpoint requires no authentication and is suitable for populating
    scenario picker UI components.
    """
    return ScenarioListResponse(scenarios=_SCENARIO_REGISTRY)


@router.get(
    "/timeline/{simulation_id}",
    response_model=list[dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="Retrieve the execution timeline for a simulation (placeholder)",
)
async def get_simulation_timeline(simulation_id: str) -> list[dict[str, Any]]:
    """
    Return the execution timeline for a previously run simulation.

    The /simulate endpoint returns the full execution timeline inline in the
    `analysis.execution_timeline` field of the SimulationResponse.  Simulation
    results are not currently persisted server-side, so this endpoint returns a
    placeholder response indicating where to find the inline data.

    A future revision will persist results to the database and return the
    stored timeline here, enabling deferred retrieval for large datasets.
    """
    # Validate that the ID looks like a UUID to avoid log-injection from
    # arbitrary path parameters.
    try:
        uuid.UUID(simulation_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="simulation_id must be a valid UUID v4.",
        )

    logger.info("Timeline requested for simulation %s (not persisted — returning placeholder)", simulation_id)

    return [
        {
            "simulation_id": simulation_id,
            "note": (
                "Simulation results are not currently persisted server-side. "
                "The full execution timeline is available in the 'analysis.execution_timeline' "
                "field of the POST /simulate response."
            ),
            "status": "not_persisted",
            "retrieved_at": datetime.now(tz=timezone.utc).isoformat(),
        }
    ]
