"""
FastAPI route definitions for the LLM Data Poisoning Detection PaaS.

All versioned routes live under /api/v1.  Health/readiness probes are mounted
at the root level via health_router (no version prefix).

Service layer classes are injected via Depends() — see dependencies.py.
Auth is enforced through the get_current_tenant dependency on every protected
endpoint.  Background tasks are used for scan workloads that exceed ~200 ms so
that the HTTP response can be returned immediately with a scan_id for polling.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator

from backend.api.dependencies import (
    get_current_tenant,
    get_mcp_auditor,
    get_provenance_tracker,
    get_rag_detector,
    get_threat_aggregator,
    get_vector_analyzer,
)
from backend.services.mcp_auditor import MCPToolAuditor
from backend.services.provenance_tracker import ProvenanceTracker
from backend.services.rag_analyzer import RAGPoisoningDetector
from backend.services.threat_aggregator import ThreatAggregator
from backend.services.vector_analyzer import VectorIntegrityAnalyzer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Router definitions
# ---------------------------------------------------------------------------

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])
vectors_router = APIRouter(prefix="/vectors", tags=["Vector Analysis"])
rag_router = APIRouter(prefix="/rag", tags=["RAG Document Scanning"])
tools_router = APIRouter(prefix="/tools", tags=["MCP Tool Auditing"])
provenance_router = APIRouter(prefix="/provenance", tags=["Provenance Tracking"])
dashboard_router = APIRouter(prefix="/dashboard", tags=["Dashboard & Metrics"])
health_router = APIRouter(tags=["Health"])

_bearer_scheme = HTTPBearer(auto_error=False)

# ---------------------------------------------------------------------------
# Shared type aliases
# ---------------------------------------------------------------------------

CurrentTenant = Annotated[dict[str, Any], Depends(get_current_tenant)]
VectorAnalyzer = Annotated[VectorIntegrityAnalyzer, Depends(get_vector_analyzer)]
RAGDetector = Annotated[RAGPoisoningDetector, Depends(get_rag_detector)]
MCPAuditor = Annotated[MCPToolAuditor, Depends(get_mcp_auditor)]
ProvTracker = Annotated[ProvenanceTracker, Depends(get_provenance_tracker)]
ThreatAgg = Annotated[ThreatAggregator, Depends(get_threat_aggregator)]

# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------

# --- Auth ---


class TenantRegisterRequest(BaseModel):
    """Body for POST /auth/register."""

    organization_name: str = Field(
        ..., min_length=2, max_length=120, description="Legal or display name of the registering organization."
    )
    email: str = Field(..., description="Contact email for the tenant account.")
    tier: str = Field(
        default="free",
        pattern="^(free|starter|professional|enterprise)$",
        description="Subscription tier governing rate limits.",
    )

    model_config = {"json_schema_extra": {"example": {"organization_name": "Acme AI", "email": "ops@acme.ai", "tier": "starter"}}}


class TenantRegisterResponse(BaseModel):
    tenant_id: str
    organization_name: str
    api_key: str = Field(..., description="Raw API key — shown only once. Store securely.")
    tier: str
    created_at: datetime


class TokenRequest(BaseModel):
    """Body for POST /auth/token."""

    api_key: str = Field(..., min_length=32, description="API key obtained at registration.")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Seconds until the token expires.")


class TenantInfoResponse(BaseModel):
    tenant_id: str
    organization_name: str
    email: str
    tier: str
    created_at: datetime
    scan_count: int
    rate_limit_rpm: int


# --- Vector Analysis ---


class VectorMetadata(BaseModel):
    source: str | None = Field(default=None, description="Descriptive label for the embedding source.")
    model: str | None = Field(default=None, description="Embedding model name, e.g. 'text-embedding-3-large'.")
    dimension: int | None = Field(default=None, ge=1)
    extra: dict[str, Any] = Field(default_factory=dict)


class VectorSubmission(BaseModel):
    """Body for POST /vectors/analyze."""

    vectors: list[list[float]] = Field(
        ...,
        min_length=1,
        max_length=50_000,
        description="Flat list of embedding vectors. All vectors must share the same dimension.",
    )
    metadata: VectorMetadata = Field(default_factory=VectorMetadata)
    compare_to_baseline: bool = Field(
        default=True,
        description="Whether to compare against the tenant's stored clean-vector baseline.",
    )

    @field_validator("vectors")
    @classmethod
    def validate_uniform_dimension(cls, v: list[list[float]]) -> list[list[float]]:
        if not v:
            return v
        dim = len(v[0])
        if any(len(vec) != dim for vec in v):
            raise ValueError("All vectors in a submission must share the same dimension.")
        return v


class VectorAnalysisResponse(BaseModel):
    scan_id: str
    status: str = Field(..., description="'queued' | 'processing' | 'complete' | 'error'")
    submitted_at: datetime
    vector_count: int
    message: str


class VectorResultResponse(BaseModel):
    scan_id: str
    tenant_id: str
    status: str
    verdict: str | None = Field(default=None, description="'clean' | 'suspicious' | 'poisoned' | 'insufficient_data'")
    outlier_count: int | None = None
    outlier_indices: list[int] | None = None
    dispersion_score: float | None = None
    cosine_similarity_mean: float | None = None
    confidence: float | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    completed_at: datetime | None = None


class BaselineStatusResponse(BaseModel):
    tenant_id: str
    baseline_vector_count: int
    last_updated: datetime | None
    is_sufficient: bool
    minimum_required: int
    dimension: int | None


class BaselineUpdateRequest(BaseModel):
    """Body for POST /vectors/baseline/update."""

    vectors: list[list[float]] = Field(..., min_length=1, max_length=50_000)
    metadata: VectorMetadata = Field(default_factory=VectorMetadata)
    replace_existing: bool = Field(
        default=False,
        description="If True, replaces the entire existing baseline. If False, appends.",
    )

    @field_validator("vectors")
    @classmethod
    def validate_uniform_dimension(cls, v: list[list[float]]) -> list[list[float]]:
        if not v:
            return v
        dim = len(v[0])
        if any(len(vec) != dim for vec in v):
            raise ValueError("All baseline vectors must share the same dimension.")
        return v


class BaselineUpdateResponse(BaseModel):
    tenant_id: str
    vectors_added: int
    total_baseline_count: int
    updated_at: datetime


# --- RAG Document Scanning ---


class RAGDocumentRequest(BaseModel):
    """Body for POST /rag/scan."""

    content: str = Field(..., min_length=1, max_length=1_000_000, description="Raw text content of the document to scan.")
    document_id: str | None = Field(default=None, description="Caller-supplied stable identifier for this document.")
    embedding: list[float] | None = Field(
        default=None,
        description="Pre-computed embedding for the document. If omitted the service computes one.",
    )
    source_url: str | None = Field(default=None, description="Origin URL for provenance recording.")
    tags: list[str] = Field(default_factory=list, max_length=20)


class RAGBatchRequest(BaseModel):
    """Body for POST /rag/scan/batch."""

    documents: list[RAGDocumentRequest] = Field(..., min_length=1, max_length=500)
    fail_fast: bool = Field(
        default=False,
        description="Abort batch on first poisoning detection.",
    )


class RAGScanResponse(BaseModel):
    scan_id: str
    status: str
    document_id: str | None
    submitted_at: datetime
    message: str


class RAGBatchResponse(BaseModel):
    batch_id: str
    document_count: int
    status: str
    submitted_at: datetime
    message: str


class RAGResultResponse(BaseModel):
    scan_id: str
    tenant_id: str
    status: str
    verdict: str | None = None
    threat_types: list[str] = Field(default_factory=list)
    confidence: float | None = None
    cosine_deviation: float | None = None
    suspicious_spans: list[dict[str, Any]] = Field(default_factory=list)
    entropy_score: float | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    completed_at: datetime | None = None


# --- MCP Tool Auditing ---


class MCPToolAuditRequest(BaseModel):
    """Body for POST /tools/audit."""

    tool_name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=10_000)
    schema: dict[str, Any] = Field(..., description="Full JSON Schema object for the tool's parameters.")
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Actual parameter values or examples to evaluate alongside the schema.",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)
    source_registry: str | None = Field(default=None, description="Registry or marketplace the tool originates from.")


class MCPAuditResponse(BaseModel):
    audit_id: str
    status: str
    tool_name: str
    submitted_at: datetime
    message: str


class MCPAuditResultResponse(BaseModel):
    audit_id: str
    tenant_id: str
    tool_name: str
    status: str
    verdict: str | None = Field(default=None, description="'safe' | 'suspicious' | 'malicious'")
    risk_score: float | None = Field(default=None, ge=0.0, le=1.0)
    threat_indicators: list[str] = Field(default_factory=list)
    matched_patterns: list[str] = Field(default_factory=list)
    schema_depth: int | None = None
    description_length: int | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    completed_at: datetime | None = None


class KnownThreatPattern(BaseModel):
    pattern_id: str
    name: str
    category: str
    description: str
    severity: str
    regex: str | None = None
    added_at: datetime


class KnownThreatsResponse(BaseModel):
    total: int
    patterns: list[KnownThreatPattern]
    last_updated: datetime


# --- Provenance Tracking ---


class ProvenanceRegisterRequest(BaseModel):
    """Body for POST /provenance/register."""

    dataset_id: str = Field(..., min_length=1, max_length=200, description="Caller-assigned stable dataset identifier.")
    name: str = Field(..., min_length=1, max_length=200)
    source_uri: str | None = Field(default=None, description="URI where the dataset was fetched from.")
    parent_ids: list[str] = Field(
        default_factory=list,
        description="IDs of upstream datasets this one derives from.",
    )
    schema_hash: str | None = Field(default=None, description="SHA-256 of the dataset's schema for tamper detection.")
    content_hash: str | None = Field(default=None, description="SHA-256 of the dataset content.")
    tags: dict[str, str] = Field(default_factory=dict)


class ProvenanceRegisterResponse(BaseModel):
    record_id: str
    dataset_id: str
    registered_at: datetime
    graph_node_id: str


class ContaminationReport(BaseModel):
    dataset_id: str
    is_contaminated: bool
    contamination_source: str | None = None
    propagation_depth: int | None = None
    affected_downstream_count: int | None = None
    confidence: float | None = None
    checked_at: datetime


class LineageGraph(BaseModel):
    dataset_id: str
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    total_nodes: int
    total_edges: int
    max_depth: int


class FlagDatasetRequest(BaseModel):
    """Body for POST /provenance/flag."""

    dataset_id: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=5, max_length=2000)
    evidence: dict[str, Any] = Field(default_factory=dict)
    propagate: bool = Field(
        default=True,
        description="If True, marks all downstream derived datasets as potentially contaminated.",
    )


class FlagDatasetResponse(BaseModel):
    dataset_id: str
    flagged: bool
    downstream_affected: int
    flagged_at: datetime


# --- Dashboard / Metrics ---


class ThreatTimelineEntry(BaseModel):
    timestamp: datetime
    threat_type: str
    count: int
    severity: str


class ThreatBreakdownEntry(BaseModel):
    threat_type: str
    count: int
    percentage: float
    severity_distribution: dict[str, int]


class DashboardMetricsResponse(BaseModel):
    tenant_id: str
    period_start: datetime
    period_end: datetime
    total_scans: int
    clean_count: int
    suspicious_count: int
    poisoned_count: int
    error_count: int
    vector_scans: int
    rag_scans: int
    mcp_audits: int
    provenance_checks: int
    avg_confidence: float | None
    top_threat_types: list[str]
    generated_at: datetime


class ThreatTimelineResponse(BaseModel):
    tenant_id: str
    period_start: datetime
    period_end: datetime
    granularity: str
    entries: list[ThreatTimelineEntry]
    total_events: int


class ThreatBreakdownResponse(BaseModel):
    tenant_id: str
    period_start: datetime
    period_end: datetime
    total_threats: int
    breakdown: list[ThreatBreakdownEntry]


# --- Health ---


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: datetime


class ReadinessResponse(BaseModel):
    status: str
    checks: dict[str, str]
    timestamp: datetime


# ---------------------------------------------------------------------------
# Health routes  (no auth, no /api/v1 prefix — mounted at root)
# ---------------------------------------------------------------------------


@health_router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness probe",
    description="Returns 200 when the process is alive. No dependency checks.",
)
async def health_check() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version="0.1.0",
        timestamp=datetime.now(tz=timezone.utc),
    )


@health_router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Readiness probe",
    description="Returns 200 only when all downstream dependencies are reachable.",
)
async def readiness_check() -> ReadinessResponse:
    from backend.models.database import check_db_connection

    checks: dict[str, str] = {}

    db_ok = await check_db_connection()
    checks["postgres"] = "ok" if db_ok else "unreachable"

    overall = "ok" if all(v == "ok" for v in checks.values()) else "degraded"
    status_code = status.HTTP_200_OK if overall == "ok" else status.HTTP_503_SERVICE_UNAVAILABLE

    response = ReadinessResponse(
        status=overall,
        checks=checks,
        timestamp=datetime.now(tz=timezone.utc),
    )

    if overall != "ok":
        raise HTTPException(status_code=status_code, detail=response.model_dump())

    return response


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------


@auth_router.post(
    "/register",
    response_model=TenantRegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new tenant",
    description=(
        "Creates a tenant account and returns a single-use API key. "
        "The raw key is shown only in this response — store it securely."
    ),
)
async def register_tenant(body: TenantRegisterRequest) -> TenantRegisterResponse:
    from backend.services.auth import AuthService

    logger.info("Tenant registration request — org=%s tier=%s", body.organization_name, body.tier)

    try:
        result = await AuthService.register_tenant(
            organization_name=body.organization_name,
            email=body.email,
            tier=body.tier,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    logger.info("Tenant registered — tenant_id=%s", result["tenant_id"])
    return TenantRegisterResponse(**result)


@auth_router.post(
    "/token",
    response_model=TokenResponse,
    summary="Exchange API key for JWT",
    description="Validates the supplied API key and returns a short-lived JWT bearer token.",
)
async def get_token(body: TokenRequest) -> TokenResponse:
    from backend.services.auth import AuthService

    try:
        result = await AuthService.issue_token(api_key=body.api_key)
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    return TokenResponse(**result)


@auth_router.get(
    "/me",
    response_model=TenantInfoResponse,
    summary="Get current tenant info",
)
async def get_me(tenant: CurrentTenant) -> TenantInfoResponse:
    return TenantInfoResponse(**tenant)


# ---------------------------------------------------------------------------
# Vector Analysis routes
# ---------------------------------------------------------------------------


async def _run_vector_analysis(
    scan_id: str,
    vectors: list[list[float]],
    metadata: dict[str, Any],
    tenant_id: str,
    analyzer: VectorIntegrityAnalyzer,
) -> None:
    """Background task that runs the heavy vector analysis and persists the result."""
    logger.info("Starting vector analysis — scan_id=%s tenant_id=%s count=%d", scan_id, tenant_id, len(vectors))
    try:
        report = await analyzer.analyze_batch(vectors=vectors, metadata=metadata)
        await analyzer.persist_result(scan_id=scan_id, tenant_id=tenant_id, report=report)
        logger.info("Vector analysis complete — scan_id=%s verdict=%s", scan_id, report.verdict)
    except Exception as exc:
        logger.exception("Vector analysis failed — scan_id=%s error=%s", scan_id, exc)
        await analyzer.persist_error(scan_id=scan_id, tenant_id=tenant_id, error=str(exc))


@vectors_router.post(
    "/analyze",
    response_model=VectorAnalysisResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit embedding vectors for poisoning analysis",
    description=(
        "Accepts a batch of embedding vectors and queues asynchronous cosine-dispersion "
        "and outlier analysis. Returns a scan_id for polling the result."
    ),
)
async def analyze_vectors(
    body: VectorSubmission,
    background_tasks: BackgroundTasks,
    tenant: CurrentTenant,
    analyzer: VectorAnalyzer,
) -> VectorAnalysisResponse:
    scan_id = str(uuid.uuid4())
    submitted_at = datetime.now(tz=timezone.utc)

    logger.info(
        "Vector analysis submission — tenant_id=%s scan_id=%s vectors=%d",
        tenant["tenant_id"],
        scan_id,
        len(body.vectors),
    )

    background_tasks.add_task(
        _run_vector_analysis,
        scan_id=scan_id,
        vectors=body.vectors,
        metadata=body.metadata.model_dump(),
        tenant_id=tenant["tenant_id"],
        analyzer=analyzer,
    )

    return VectorAnalysisResponse(
        scan_id=scan_id,
        status="queued",
        submitted_at=submitted_at,
        vector_count=len(body.vectors),
        message="Analysis queued. Poll GET /api/v1/vectors/results/{scan_id} for status.",
    )


@vectors_router.get(
    "/results/{scan_id}",
    response_model=VectorResultResponse,
    summary="Get vector analysis results",
)
async def get_vector_results(
    scan_id: str,
    tenant: CurrentTenant,
    analyzer: VectorAnalyzer,
) -> VectorResultResponse:
    result = await analyzer.get_result(scan_id=scan_id, tenant_id=tenant["tenant_id"])

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No scan found with id '{scan_id}' for this tenant.",
        )

    return VectorResultResponse(**result)


@vectors_router.get(
    "/baseline/status",
    response_model=BaselineStatusResponse,
    summary="Get baseline dataset status",
    description="Returns the current state of the clean-vector baseline for the authenticated tenant.",
)
async def get_baseline_status(
    tenant: CurrentTenant,
    analyzer: VectorAnalyzer,
) -> BaselineStatusResponse:
    status_data = await analyzer.get_baseline_status(tenant_id=tenant["tenant_id"])
    return BaselineStatusResponse(**status_data)


@vectors_router.post(
    "/baseline/update",
    response_model=BaselineUpdateResponse,
    status_code=status.HTTP_200_OK,
    summary="Submit clean vectors to update baseline",
    description=(
        "Appends (or replaces) the clean-vector baseline used for anomaly comparisons. "
        "Only submit vectors confirmed to be from a trusted, uncontaminated source."
    ),
)
async def update_baseline(
    body: BaselineUpdateRequest,
    tenant: CurrentTenant,
    analyzer: VectorAnalyzer,
) -> BaselineUpdateResponse:
    logger.info(
        "Baseline update — tenant_id=%s vectors=%d replace=%s",
        tenant["tenant_id"],
        len(body.vectors),
        body.replace_existing,
    )

    result = await analyzer.update_baseline(
        tenant_id=tenant["tenant_id"],
        vectors=body.vectors,
        metadata=body.metadata.model_dump(),
        replace_existing=body.replace_existing,
    )

    return BaselineUpdateResponse(**result)


# ---------------------------------------------------------------------------
# RAG Document Scanning routes
# ---------------------------------------------------------------------------


async def _run_rag_scan(
    scan_id: str,
    content: str,
    embedding: list[float] | None,
    baseline: list[list[float]] | None,
    tenant_id: str,
    metadata: dict[str, Any],
    detector: RAGPoisoningDetector,
) -> None:
    logger.info("Starting RAG scan — scan_id=%s tenant_id=%s", scan_id, tenant_id)
    try:
        result = await detector.analyze_document(content=content, embedding=embedding, baseline=baseline)
        await detector.persist_result(scan_id=scan_id, tenant_id=tenant_id, result=result, metadata=metadata)
        logger.info("RAG scan complete — scan_id=%s verdict=%s", scan_id, result.verdict)
    except Exception as exc:
        logger.exception("RAG scan failed — scan_id=%s error=%s", scan_id, exc)
        await detector.persist_error(scan_id=scan_id, tenant_id=tenant_id, error=str(exc))


@rag_router.post(
    "/scan",
    response_model=RAGScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit RAG document for poisoning scan",
    description=(
        "Queues a single document for full poisoning analysis: cosine deviation, "
        "hidden-instruction detection, unicode homoglyph detection, base64 injection "
        "detection, and entropy anomaly scoring."
    ),
)
async def scan_rag_document(
    body: RAGDocumentRequest,
    background_tasks: BackgroundTasks,
    tenant: CurrentTenant,
    detector: RAGDetector,
) -> RAGScanResponse:
    scan_id = str(uuid.uuid4())
    submitted_at = datetime.now(tz=timezone.utc)

    logger.info(
        "RAG scan submission — tenant_id=%s scan_id=%s doc_id=%s",
        tenant["tenant_id"],
        scan_id,
        body.document_id,
    )

    background_tasks.add_task(
        _run_rag_scan,
        scan_id=scan_id,
        content=body.content,
        embedding=body.embedding,
        baseline=None,
        tenant_id=tenant["tenant_id"],
        metadata={"source_url": body.source_url, "tags": body.tags, "document_id": body.document_id},
        detector=detector,
    )

    return RAGScanResponse(
        scan_id=scan_id,
        status="queued",
        document_id=body.document_id,
        submitted_at=submitted_at,
        message="Scan queued. Poll GET /api/v1/rag/results/{scan_id} for status.",
    )


@rag_router.post(
    "/scan/batch",
    response_model=RAGBatchResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Batch scan multiple RAG documents",
    description="Queues up to 500 documents for concurrent poisoning scans.",
)
async def scan_rag_batch(
    body: RAGBatchRequest,
    background_tasks: BackgroundTasks,
    tenant: CurrentTenant,
    detector: RAGDetector,
) -> RAGBatchResponse:
    batch_id = str(uuid.uuid4())
    submitted_at = datetime.now(tz=timezone.utc)

    logger.info(
        "RAG batch scan submission — tenant_id=%s batch_id=%s doc_count=%d fail_fast=%s",
        tenant["tenant_id"],
        batch_id,
        len(body.documents),
        body.fail_fast,
    )

    for doc in body.documents:
        scan_id = str(uuid.uuid4())
        background_tasks.add_task(
            _run_rag_scan,
            scan_id=scan_id,
            content=doc.content,
            embedding=doc.embedding,
            baseline=None,
            tenant_id=tenant["tenant_id"],
            metadata={
                "batch_id": batch_id,
                "source_url": doc.source_url,
                "tags": doc.tags,
                "document_id": doc.document_id,
                "fail_fast": body.fail_fast,
            },
            detector=detector,
        )

    return RAGBatchResponse(
        batch_id=batch_id,
        document_count=len(body.documents),
        status="queued",
        submitted_at=submitted_at,
        message=f"{len(body.documents)} documents queued under batch_id '{batch_id}'.",
    )


@rag_router.get(
    "/results/{scan_id}",
    response_model=RAGResultResponse,
    summary="Get RAG scan results",
)
async def get_rag_results(
    scan_id: str,
    tenant: CurrentTenant,
    detector: RAGDetector,
) -> RAGResultResponse:
    result = await detector.get_result(scan_id=scan_id, tenant_id=tenant["tenant_id"])

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No RAG scan found with id '{scan_id}' for this tenant.",
        )

    return RAGResultResponse(**result)


# ---------------------------------------------------------------------------
# MCP Tool Auditing routes
# ---------------------------------------------------------------------------


async def _run_mcp_audit(
    audit_id: str,
    name: str,
    description: str,
    schema: dict[str, Any],
    parameters: dict[str, Any],
    metadata: dict[str, Any],
    tenant_id: str,
    auditor: MCPToolAuditor,
) -> None:
    logger.info("Starting MCP audit — audit_id=%s tenant_id=%s tool=%s", audit_id, tenant_id, name)
    try:
        report = await auditor.audit_tool(
            name=name,
            description=description,
            schema=schema,
            parameters=parameters,
        )
        await auditor.persist_result(audit_id=audit_id, tenant_id=tenant_id, report=report, metadata=metadata)
        logger.info("MCP audit complete — audit_id=%s verdict=%s", audit_id, report.verdict)
    except Exception as exc:
        logger.exception("MCP audit failed — audit_id=%s error=%s", audit_id, exc)
        await auditor.persist_error(audit_id=audit_id, tenant_id=tenant_id, error=str(exc))


@tools_router.post(
    "/audit",
    response_model=MCPAuditResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit MCP tool schema for audit",
    description=(
        "Queues an MCP tool schema for comprehensive security audit: hidden-instruction "
        "detection, base64 payload scanning, schema complexity analysis, and rug-pull "
        "indicator checks."
    ),
)
async def audit_mcp_tool(
    body: MCPToolAuditRequest,
    background_tasks: BackgroundTasks,
    tenant: CurrentTenant,
    auditor: MCPAuditor,
) -> MCPAuditResponse:
    audit_id = str(uuid.uuid4())
    submitted_at = datetime.now(tz=timezone.utc)

    logger.info(
        "MCP audit submission — tenant_id=%s audit_id=%s tool=%s",
        tenant["tenant_id"],
        audit_id,
        body.tool_name,
    )

    background_tasks.add_task(
        _run_mcp_audit,
        audit_id=audit_id,
        name=body.tool_name,
        description=body.description,
        schema=body.schema,
        parameters=body.parameters,
        metadata={"source_registry": body.source_registry, **body.metadata},
        tenant_id=tenant["tenant_id"],
        auditor=auditor,
    )

    return MCPAuditResponse(
        audit_id=audit_id,
        status="queued",
        tool_name=body.tool_name,
        submitted_at=submitted_at,
        message="Audit queued. Poll GET /api/v1/tools/results/{audit_id} for status.",
    )


@tools_router.get(
    "/results/{audit_id}",
    response_model=MCPAuditResultResponse,
    summary="Get MCP tool audit results",
)
async def get_mcp_audit_results(
    audit_id: str,
    tenant: CurrentTenant,
    auditor: MCPAuditor,
) -> MCPAuditResultResponse:
    result = await auditor.get_result(audit_id=audit_id, tenant_id=tenant["tenant_id"])

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No audit found with id '{audit_id}' for this tenant.",
        )

    return MCPAuditResultResponse(**result)


@tools_router.get(
    "/known-threats",
    response_model=KnownThreatsResponse,
    summary="List known malicious tool patterns",
    description=(
        "Returns the current threat-pattern catalogue used by the MCP auditor. "
        "Patterns are sourced from the AI Cowboys threat intelligence feed."
    ),
)
async def list_known_threats(
    tenant: CurrentTenant,
    auditor: MCPAuditor,
    category: str | None = Query(default=None, description="Filter by threat category."),
    severity: str | None = Query(default=None, pattern="^(low|medium|high|critical)$"),
) -> KnownThreatsResponse:
    patterns = await auditor.get_known_threat_patterns(category=category, severity=severity)
    return KnownThreatsResponse(
        total=len(patterns),
        patterns=[KnownThreatPattern(**p) for p in patterns],
        last_updated=datetime.now(tz=timezone.utc),
    )


# ---------------------------------------------------------------------------
# Provenance Tracking routes
# ---------------------------------------------------------------------------


@provenance_router.post(
    "/register",
    response_model=ProvenanceRegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register dataset in lineage graph",
    description=(
        "Registers a dataset as a node in the provenance lineage graph. "
        "Parent relationships are recorded as directed edges so contamination "
        "can propagate and be traced upstream."
    ),
)
async def register_dataset(
    body: ProvenanceRegisterRequest,
    tenant: CurrentTenant,
    tracker: ProvTracker,
) -> ProvenanceRegisterResponse:
    logger.info(
        "Provenance registration — tenant_id=%s dataset_id=%s",
        tenant["tenant_id"],
        body.dataset_id,
    )

    try:
        record = await tracker.register_dataset(
            tenant_id=tenant["tenant_id"],
            dataset_id=body.dataset_id,
            name=body.name,
            source_uri=body.source_uri,
            parent_ids=body.parent_ids,
            schema_hash=body.schema_hash,
            content_hash=body.content_hash,
            tags=body.tags,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    return ProvenanceRegisterResponse(**record)


@provenance_router.get(
    "/check/{dataset_id}",
    response_model=ContaminationReport,
    summary="Check dataset contamination status",
    description=(
        "Traverses the lineage graph upstream from the given dataset to detect "
        "whether any ancestor is flagged as contaminated."
    ),
)
async def check_contamination(
    dataset_id: str,
    tenant: CurrentTenant,
    tracker: ProvTracker,
) -> ContaminationReport:
    report = await tracker.check_contamination(dataset_id=dataset_id, tenant_id=tenant["tenant_id"])

    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset '{dataset_id}' not found for this tenant.",
        )

    return ContaminationReport(**report)


@provenance_router.get(
    "/lineage/{dataset_id}",
    response_model=LineageGraph,
    summary="Get full lineage graph",
    description="Returns the full directed acyclic graph of ancestors and descendants for a dataset.",
)
async def get_lineage(
    dataset_id: str,
    tenant: CurrentTenant,
    tracker: ProvTracker,
    depth: int = Query(default=10, ge=1, le=50, description="Maximum graph traversal depth."),
) -> LineageGraph:
    graph = await tracker.get_lineage(
        dataset_id=dataset_id,
        tenant_id=tenant["tenant_id"],
        depth=depth,
    )

    if graph is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset '{dataset_id}' not found for this tenant.",
        )

    return LineageGraph(**graph)


@provenance_router.post(
    "/flag",
    response_model=FlagDatasetResponse,
    summary="Flag dataset as contaminated",
    description=(
        "Marks a dataset as contaminated in the lineage graph. "
        "When propagate=True all downstream derived datasets are also marked "
        "as potentially contaminated."
    ),
)
async def flag_dataset(
    body: FlagDatasetRequest,
    tenant: CurrentTenant,
    tracker: ProvTracker,
) -> FlagDatasetResponse:
    logger.warning(
        "Dataset flagged as contaminated — tenant_id=%s dataset_id=%s propagate=%s",
        tenant["tenant_id"],
        body.dataset_id,
        body.propagate,
    )

    result = await tracker.flag_contaminated(
        dataset_id=body.dataset_id,
        tenant_id=tenant["tenant_id"],
        reason=body.reason,
        evidence=body.evidence,
        propagate=body.propagate,
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset '{body.dataset_id}' not found for this tenant.",
        )

    return FlagDatasetResponse(**result)


# ---------------------------------------------------------------------------
# Dashboard / Metrics routes
# ---------------------------------------------------------------------------


@dashboard_router.get(
    "/metrics",
    response_model=DashboardMetricsResponse,
    summary="Get aggregated AI-SPM metrics",
    description="Returns aggregated scan counts and threat metrics for the tenant.",
)
async def get_dashboard_metrics(
    tenant: CurrentTenant,
    aggregator: ThreatAgg,
    hours: int = Query(default=24, ge=1, le=720, description="Lookback window in hours."),
) -> DashboardMetricsResponse:
    metrics = await aggregator.get_dashboard_metrics(
        tenant_id=tenant["tenant_id"],
        lookback_hours=hours,
    )
    return DashboardMetricsResponse(**metrics)


@dashboard_router.get(
    "/threats/timeline",
    response_model=ThreatTimelineResponse,
    summary="Time-series threat data",
    description="Returns a bucketed time series of detected threats over the lookback window.",
)
async def get_threat_timeline(
    tenant: CurrentTenant,
    aggregator: ThreatAgg,
    hours: int = Query(default=24, ge=1, le=720),
    granularity: str = Query(
        default="hour",
        pattern="^(minute|hour|day)$",
        description="Bucket granularity: 'minute', 'hour', or 'day'.",
    ),
) -> ThreatTimelineResponse:
    data = await aggregator.get_threat_timeline(
        tenant_id=tenant["tenant_id"],
        lookback_hours=hours,
        granularity=granularity,
    )
    return ThreatTimelineResponse(**data)


@dashboard_router.get(
    "/threats/breakdown",
    response_model=ThreatBreakdownResponse,
    summary="Threat type breakdown",
    description="Returns counts and percentages for each threat type detected within the window.",
)
async def get_threat_breakdown(
    tenant: CurrentTenant,
    aggregator: ThreatAgg,
    hours: int = Query(default=24, ge=1, le=720),
) -> ThreatBreakdownResponse:
    data = await aggregator.get_threat_breakdown(
        tenant_id=tenant["tenant_id"],
        lookback_hours=hours,
    )
    return ThreatBreakdownResponse(**data)
