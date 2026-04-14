"""
Pydantic v2 request/response schemas.

Rules applied throughout:
- All IDs are UUID — never sequential integers in public APIs.
- Sensitive fields (api_key_hash, raw keys) are write-only; never appear in
  response schemas.
- Timestamps are always UTC-aware datetime objects.
- Vector data uses list[list[float]] — callers are responsible for
  normalisation; the service validates shape only.
- Strict mode is NOT used globally because float/int coercion is intentional
  for embedding coordinates.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from backend.models.detection import MCPVerdict, SourceType, VectorStatus

# ---------------------------------------------------------------------------
# Shared base
# ---------------------------------------------------------------------------


class _Base(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,          # ORM -> Pydantic conversion
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_assignment=True,
    )


# ---------------------------------------------------------------------------
# Tenant schemas
# ---------------------------------------------------------------------------


class TenantCreate(_Base):
    """Request body for POST /api/v1/tenants."""

    name: str = Field(
        ...,
        min_length=2,
        max_length=255,
        description="Organisation display name. Must be unique.",
        examples=["Acme Corp"],
    )
    tier: Literal["free", "starter", "professional", "enterprise"] = Field(
        default="free",
        description="Billing tier controlling rate limits and feature access.",
    )


class TenantResponse(_Base):
    """Response body for tenant read operations."""

    id: uuid.UUID
    name: str
    tier: str
    created_at: datetime
    is_active: bool

    # api_key_hash deliberately omitted — never exposed after creation


class TenantAPIKeyCreate(_Base):
    """Request body for POST /api/v1/tenants/{id}/keys."""

    description: str | None = Field(
        default=None,
        max_length=255,
        description="Optional human label for the key (e.g. 'CI pipeline').",
    )
    expires_in_days: int | None = Field(
        default=None,
        ge=1,
        le=365,
        description="Key TTL in days from now. NULL creates a non-expiring key.",
    )


class TenantAPIKeyResponse(_Base):
    """
    Response body for API key creation.

    raw_key is ONLY present immediately after creation.  Subsequent reads
    return None — store it securely on receipt.
    """

    id: uuid.UUID
    tenant_id: uuid.UUID
    prefix: str
    created_at: datetime
    expires_at: datetime | None
    is_revoked: bool
    description: str | None
    raw_key: str | None = Field(
        default=None,
        description="Plaintext key — shown once at creation. Store it now.",
    )


# ---------------------------------------------------------------------------
# Vector analysis schemas
# ---------------------------------------------------------------------------


class VectorSubmission(_Base):
    """
    Request body for POST /api/v1/vectors/analyze.

    vectors: list of embedding vectors; all must share the same dimension.
    dataset_id: caller-supplied label; used to correlate results.
    """

    vectors: list[list[float]] = Field(
        ...,
        min_length=1,
        description="Batch of embedding vectors. All must share identical dimension.",
        examples=[[[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]]],
    )
    dataset_id: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Caller-supplied label for this vector batch.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary key-value metadata attached to the analysis record.",
    )

    @field_validator("vectors")
    @classmethod
    def vectors_consistent_dimension(cls, v: list[list[float]]) -> list[list[float]]:
        if not v:
            return v
        dim = len(v[0])
        if dim == 0:
            raise ValueError("Embedding dimension must be at least 1.")
        for i, vec in enumerate(v[1:], start=1):
            if len(vec) != dim:
                raise ValueError(
                    f"Vector at index {i} has dimension {len(vec)}, expected {dim}."
                )
        return v

    @property
    def dimension(self) -> int:
        return len(self.vectors[0]) if self.vectors else 0


# ---------------------------------------------------------------------------
# MCP tool audit schemas
# ---------------------------------------------------------------------------


class MCPToolSubmission(_Base):
    """
    Request body for POST /api/v1/tools/audit.

    Mirrors the structure of an MCP tool manifest entry.
    """

    tool_name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Tool name as declared in the MCP manifest.",
        examples=["web_search"],
    )
    description: str = Field(
        ...,
        min_length=1,
        description="Tool description text — primary injection surface.",
    )
    tool_uri: str | None = Field(
        default=None,
        max_length=2048,
        description="Optional URI identifying the tool's endpoint.",
    )
    schema: dict[str, Any] = Field(
        default_factory=dict,
        description="JSON Schema object describing the tool's input/output.",
    )
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Parameter definitions (may duplicate schema for older manifests).",
    )


# ---------------------------------------------------------------------------
# RAG document schemas
# ---------------------------------------------------------------------------


class RAGDocumentSubmission(_Base):
    """
    Request body for POST /api/v1/rag/scan.

    Callers provide both the raw text and its pre-computed embedding so the
    service can run both lexical and geometric contamination checks.
    """

    document_id: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Unique identifier for the document chunk.",
    )
    content: str = Field(
        ...,
        min_length=1,
        description="Raw document text to analyse for injection patterns.",
    )
    embedding: list[float] = Field(
        ...,
        min_length=1,
        description="Pre-computed embedding for geometric anomaly detection.",
    )
    source_uri: str | None = Field(
        default=None,
        max_length=2048,
        description="Origin URI of the document.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary metadata (chunk index, document title, etc.).",
    )


# ---------------------------------------------------------------------------
# Provenance schemas
# ---------------------------------------------------------------------------


class ProvenanceSubmission(_Base):
    """
    Request body for POST /api/v1/provenance/register.

    Registers a new node in the dataset lineage tree.
    """

    dataset_id: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Unique identifier for the dataset version being registered.",
    )
    parent_dataset_id: str | None = Field(
        default=None,
        max_length=255,
        description="Parent dataset ID; omit for root (original source) datasets.",
    )
    source_type: SourceType = Field(
        default=SourceType.UNKNOWN,
        description="Data origin classification.",
    )
    generation: int = Field(
        default=0,
        ge=0,
        description="Tree depth from root. Automatically derived if parent is provided.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary metadata (size, format, collection_date, etc.).",
    )


class ProvenanceNodeResponse(_Base):
    """Response schema for a single provenance node."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    dataset_id: str
    parent_id: uuid.UUID | None
    generation: int
    source_type: str
    contamination_score: float
    created_at: datetime
    metadata: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Generic detection response
# ---------------------------------------------------------------------------


class Finding(_Base):
    """A single finding within a detection scan result."""

    rule: str = Field(description="Name of the rule that triggered.")
    severity: Literal["info", "low", "medium", "high", "critical"]
    excerpt: str | None = Field(
        default=None,
        max_length=500,
        description="Relevant excerpt from the audited artifact.",
    )
    position: int | None = Field(
        default=None,
        description="Character offset or vector index where the issue was detected.",
    )
    details: dict[str, Any] = Field(default_factory=dict)


class DetectionResponse(_Base):
    """
    Unified response envelope returned by all detection endpoints.

    scan_id is the UUID of the persisted result record — use it to retrieve
    detailed results via GET /api/v1/{resource}/{scan_id}.
    """

    scan_id: uuid.UUID
    status: VectorStatus | MCPVerdict | str = Field(
        description="Verdict enum value; type varies by detection surface.",
    )
    risk_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Normalised risk score [0, 1].",
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="Ordered list of findings (highest severity first).",
    )
    timestamp: datetime
    dataset_id: str | None = None
    tool_name: str | None = None
    document_id: str | None = None


# ---------------------------------------------------------------------------
# Dashboard metrics
# ---------------------------------------------------------------------------


class ThreatBreakdown(_Base):
    """Per-category threat counts for the dashboard."""

    vector_poisoning: int = 0
    mcp_injections: int = 0
    rag_contamination: int = 0
    provenance_anomalies: int = 0


class DashboardMetrics(_Base):
    """
    Response schema for GET /api/v1/dashboard/metrics.

    scan_velocity: scans per hour (rolling 1-hour window).
    threat_breakdown: per-category detection counts (rolling 24-hour window).
    """

    total_scans: int = Field(description="All-time scan count for the tenant.")
    threats_detected: int = Field(
        description="All-time count of scans that returned non-clean verdicts."
    )
    active_tenants: int = Field(
        description="Platform-wide active tenant count (admin only; 0 for tenant scope).",
    )
    scan_velocity: float = Field(
        description="Scans per hour in the rolling 1-hour window.",
    )
    threat_breakdown: ThreatBreakdown = Field(
        default_factory=ThreatBreakdown,
        description="Per-surface threat counts (rolling 24-hour window).",
    )
    last_scan_at: datetime | None = Field(
        default=None,
        description="UTC timestamp of the most recent scan for this tenant.",
    )
    clean_rate: float = Field(
        ge=0.0,
        le=1.0,
        description="Fraction of all scans that returned a clean verdict.",
    )


# ---------------------------------------------------------------------------
# Pagination wrapper (used by list endpoints)
# ---------------------------------------------------------------------------


class PaginatedResponse(_Base):
    """Generic paginated response envelope."""

    items: list[Any]
    total: int
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=1000)
    total_pages: int

    @model_validator(mode="after")
    def compute_total_pages(self) -> PaginatedResponse:
        import math
        object.__setattr__(
            self,
            "total_pages",
            max(1, math.ceil(self.total / self.page_size)),
        )
        return self


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


class HealthStatus(_Base):
    """Response schema for GET /health."""

    status: Literal["healthy", "degraded", "unhealthy"]
    version: str
    environment: str
    checks: dict[str, bool] = Field(
        description="Component-level health booleans (db, redis, kafka, neo4j).",
    )
    timestamp: datetime
