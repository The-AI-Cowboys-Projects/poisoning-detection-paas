"""
Detection result ORM models.

Each table represents a different attack surface:
- VectorAnalysisResult  — embedding-space dispersion anomaly detection
- MCPToolAuditResult    — MCP tool schema / description auditing
- RAGDocumentScan       — RAG pipeline document contamination
- ProvenanceNode        — Dataset lineage graph node (self-referential tree)

All tables carry tenant_id for row-level security enforcement.
JSON columns use native PostgreSQL JSONB for indexing capability.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.models.database import Base

if TYPE_CHECKING:
    from backend.models.tenant import Tenant


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class VectorStatus(str, enum.Enum):
    """Outcome verdict for a vector-space analysis run."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    POISONED = "poisoned"
    INSUFFICIENT_DATA = "insufficient_data"
    ERROR = "error"


class MCPVerdict(str, enum.Enum):
    """Risk verdict for an MCP tool schema audit."""

    SAFE = "safe"
    WARNING = "warning"
    CRITICAL = "critical"


class SourceType(str, enum.Enum):
    """Origin classification for provenance lineage nodes."""

    HUMAN = "human"
    SYNTHETIC = "synthetic"
    MIXED = "mixed"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# VectorAnalysisResult
# ---------------------------------------------------------------------------


class VectorAnalysisResult(Base):
    """
    Stores the outcome of a cosine-dispersion analysis run on a vector batch.

    Key metrics:
    - mean_dispersion: average 1 - cosine_similarity across all vectors
    - max_dispersion: worst-case outlier distance
    - anomaly_score: normalised [0,1] composite score; >0.7 is flagged
    - flagged_vectors: count of embeddings exceeding the configured threshold
    - details: JSONB — per-vector breakdown, centroid coords, sigma bands
    """

    __tablename__ = "vector_analysis_results"
    __table_args__ = (
        Index("ix_var_tenant_id", "tenant_id"),
        Index("ix_var_dataset_id", "dataset_id"),
        Index("ix_var_status", "status"),
        Index("ix_var_timestamp", "timestamp"),
        Index("ix_var_tenant_status", "tenant_id", "status"),
        Index("ix_var_anomaly_score", "anomaly_score"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    dataset_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Caller-supplied identifier for the vector dataset.",
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="UTC time the analysis completed.",
    )
    total_vectors: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Total number of vectors in the submitted batch.",
    )
    flagged_vectors: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Vectors whose dispersion exceeded the configured threshold.",
    )
    mean_dispersion: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Mean 1 - cosine_similarity across all vectors vs centroid.",
    )
    max_dispersion: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Maximum dispersion value observed (worst-case outlier).",
    )
    anomaly_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Normalised composite anomaly score [0, 1].",
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=VectorStatus.CLEAN.value,
        comment="Verdict: clean | suspicious | poisoned | insufficient_data | error",
    )
    details: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="JSONB blob: per-vector scores, centroid, sigma bands, top outliers.",
    )

    # Relationship
    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="vector_results")


# ---------------------------------------------------------------------------
# MCPToolAuditResult
# ---------------------------------------------------------------------------


class MCPToolAuditResult(Base):
    """
    Stores the outcome of auditing a single MCP tool's schema and description.

    Checks performed:
    1. Description length — long descriptions often smuggle injection payloads
    2. Base64 token ratio — exfiltration attempts use encoded blobs
    3. Hidden instruction regex matching — prompt-injection patterns
    4. Schema complexity — excessive nesting / field count anomalies
    5. Parameter URI analysis — SSRF / data-exfiltration via callback URIs

    findings: JSONB array of {rule, severity, excerpt, position} dicts
    hidden_instructions: extracted verbatim instruction fragments
    schema_anomalies: list of {field_path, anomaly_type} strings
    """

    __tablename__ = "mcp_tool_audit_results"
    __table_args__ = (
        Index("ix_mtar_tenant_id", "tenant_id"),
        Index("ix_mtar_tool_name", "tool_name"),
        Index("ix_mtar_timestamp", "timestamp"),
        Index("ix_mtar_verdict", "verdict"),
        Index("ix_mtar_tenant_verdict", "tenant_id", "verdict"),
        Index("ix_mtar_risk_score", "risk_score"),
        Index("ix_mtar_base64_detected", "base64_detected"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    tool_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="MCP tool name as declared in its manifest.",
    )
    tool_uri: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Optional URI identifying the tool's endpoint or package.",
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    risk_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Composite risk score [0, 1]; >=0.7 triggers CRITICAL verdict.",
    )
    findings: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Array of {rule, severity, excerpt, position} finding objects.",
    )
    hidden_instructions: Mapped[list[str] | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Verbatim text fragments that matched injection-pattern regexes.",
    )
    base64_detected: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        comment="True if base64 token ratio exceeded the configured threshold.",
    )
    schema_anomalies: Mapped[list[str] | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="List of {field_path, anomaly_type} strings from schema analysis.",
    )
    verdict: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=MCPVerdict.SAFE.value,
        comment="Verdict: safe | warning | critical",
    )

    # Relationship
    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="mcp_results")


# ---------------------------------------------------------------------------
# RAGDocumentScan
# ---------------------------------------------------------------------------


class RAGDocumentScan(Base):
    """
    Stores contamination-detection results for a single RAG pipeline document.

    Three independent signals are combined into a flagging decision:
    - cosine_deviation: how far this document's embedding sits from its
      cluster centroid (high = potential poisoning insert)
    - perplexity_score: LM-estimated perplexity; adversarially crafted text
      often has anomalously low perplexity (memorised patterns)
    - semantic_coherence: embedding-space coherence with neighbouring docs;
      low coherence indicates a topically out-of-place injection

    attack_type_detected: populated when a known attack signature is
    recognised, e.g. "gradient_attack", "bad_actor_insert", "anchor_poisoning"
    """

    __tablename__ = "rag_document_scans"
    __table_args__ = (
        Index("ix_rds_tenant_id", "tenant_id"),
        Index("ix_rds_document_id", "document_id"),
        Index("ix_rds_timestamp", "timestamp"),
        Index("ix_rds_is_flagged", "is_flagged"),
        Index("ix_rds_tenant_flagged", "tenant_id", "is_flagged"),
        Index("ix_rds_attack_type", "attack_type_detected"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    document_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Caller-supplied document identifier (e.g. chunk hash, URI fragment).",
    )
    source_uri: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Origin URI of the document (s3://, https://, file://, etc.).",
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    cosine_deviation: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Distance from document embedding to cluster centroid [0, 1].",
    )
    perplexity_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Language-model perplexity estimate of the document text.",
    )
    semantic_coherence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Coherence with neighbouring documents in the RAG index [0, 1].",
    )
    is_flagged: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        comment="True if any signal exceeded its detection threshold.",
    )
    attack_type_detected: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        comment="Named attack type if a known signature matched, else NULL.",
    )

    # Relationship
    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="rag_scans")


# ---------------------------------------------------------------------------
# ProvenanceNode
# ---------------------------------------------------------------------------


class ProvenanceNode(Base):
    """
    A node in the dataset provenance lineage graph.

    Represents a single dataset generation step.  The tree is stored
    adjacency-list style (parent_id self-reference) with generation tracking.

    For deep lineage queries, mirror this table into Neo4j where Cypher
    traversal outperforms recursive CTEs at scale.

    contamination_score: cumulative poisoning signal propagated up the
    lineage tree — a node inherits contamination from its ancestors.
    """

    __tablename__ = "provenance_nodes"
    __table_args__ = (
        Index("ix_pn_tenant_id", "tenant_id"),
        Index("ix_pn_dataset_id", "dataset_id"),
        Index("ix_pn_parent_id", "parent_id"),
        Index("ix_pn_generation", "generation"),
        Index("ix_pn_source_type", "source_type"),
        Index("ix_pn_contamination_score", "contamination_score"),
        Index("ix_pn_tenant_dataset", "tenant_id", "dataset_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    dataset_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Unique identifier for this dataset version.",
    )
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("provenance_nodes.id", ondelete="SET NULL"),
        nullable=True,
        comment="Parent node in the lineage tree; NULL for root datasets.",
    )
    generation: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Tree depth from root (0 = original source dataset).",
    )
    source_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=SourceType.UNKNOWN.value,
        comment="Data origin classification: human | synthetic | mixed | unknown",
    )
    contamination_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        comment="Cumulative contamination signal [0, 1]; inherited + locally detected.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    metadata_: Mapped[dict[str, Any] | None] = mapped_column(
        "metadata",
        JSONB,
        nullable=True,
        comment="Arbitrary caller-supplied metadata (size, format, collection date, etc.).",
    )

    # Self-referential relationships
    parent: Mapped[ProvenanceNode | None] = relationship(
        "ProvenanceNode",
        remote_side="ProvenanceNode.id",
        back_populates="children",
        lazy="select",
    )
    children: Mapped[list[ProvenanceNode]] = relationship(
        "ProvenanceNode",
        back_populates="parent",
        lazy="select",
    )

    # Relationship to owning tenant
    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="provenance_nodes")
