"""
Multi-tenant isolation models.

Design decisions:
- UUIDs for all primary keys — safe for distributed generation, no sequential
  leakage, and opaque in URLs.
- api_key_hash stores bcrypt digest only — plaintext never persists beyond the
  creation response.
- Row-level security (RLS) is enforced at the PostgreSQL layer; these models
  carry tenant_id on every child table so policies can filter efficiently.
- Indexes are explicit and named so Alembic autogenerate stays deterministic.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.models.database import Base

if TYPE_CHECKING:
    from backend.models.detection import (
        MCPToolAuditResult,
        ProvenanceNode,
        RAGDocumentScan,
        VectorAnalysisResult,
    )

# ---------------------------------------------------------------------------
# Tenant tiers — sync with TenantSettings.rate_limit_for_tier()
# ---------------------------------------------------------------------------
VALID_TIERS = frozenset({"free", "starter", "professional", "enterprise"})


class Tenant(Base):
    """
    Root entity for multi-tenant isolation.

    Every child record (detection results, API keys, scans) carries a
    tenant_id FK back to this table.  PostgreSQL RLS policies use that column
    to ensure a tenant can never read another tenant's data even if a query
    bug forgets the WHERE clause.
    """

    __tablename__ = "tenants"
    __table_args__ = (
        UniqueConstraint("name", name="uq_tenants_name"),
        Index("ix_tenants_api_key_hash", "api_key_hash"),
        Index("ix_tenants_is_active", "is_active"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
        comment="Tenant primary key — UUID v4.",
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Human-readable organisation name.",
    )
    # Stored as bcrypt hash; prefix stored separately in TenantAPIKey for
    # fast lookup without exposing the full hash surface.
    api_key_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="bcrypt hash of the primary API key.",
    )
    tier: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="free",
        server_default="free",
        comment="Billing tier — controls rate limits and feature access.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="UTC timestamp of tenant registration.",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
        comment="Soft-delete / suspension flag.",
    )

    # Relationships
    api_keys: Mapped[list[TenantAPIKey]] = relationship(
        "TenantAPIKey",
        back_populates="tenant",
        cascade="all, delete-orphan",
        lazy="select",
    )
    vector_results: Mapped[list[VectorAnalysisResult]] = relationship(
        "VectorAnalysisResult",
        back_populates="tenant",
        cascade="all, delete-orphan",
        lazy="select",
    )
    mcp_results: Mapped[list[MCPToolAuditResult]] = relationship(
        "MCPToolAuditResult",
        back_populates="tenant",
        cascade="all, delete-orphan",
        lazy="select",
    )
    rag_scans: Mapped[list[RAGDocumentScan]] = relationship(
        "RAGDocumentScan",
        back_populates="tenant",
        cascade="all, delete-orphan",
        lazy="select",
    )
    provenance_nodes: Mapped[list[ProvenanceNode]] = relationship(
        "ProvenanceNode",
        back_populates="tenant",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def validate_tier(self) -> None:
        if self.tier not in VALID_TIERS:
            raise ValueError(f"Invalid tier '{self.tier}'. Must be one of {VALID_TIERS}.")


class TenantAPIKey(Base):
    """
    Rotatable API keys scoped to a single tenant.

    - key_hash: bcrypt of the full key — used for constant-time verification.
    - prefix: first 8 characters of the raw key — stored in plaintext so
      operators can identify keys in logs without exposing secrets.
    - expires_at: NULL means non-expiring (enterprise use-case); set for
      time-bound integrations.
    - is_revoked: immediate invalidation without waiting for expiry.

    Index strategy:
    - ix_tenant_api_keys_key_hash — lookup path for every authenticated request.
    - ix_tenant_api_keys_tenant_id — used by tenant-scoped key listing queries.
    - ix_tenant_api_keys_prefix — helps operators search by known prefix.
    """

    __tablename__ = "tenant_api_keys"
    __table_args__ = (
        Index("ix_tenant_api_keys_key_hash", "key_hash", unique=True),
        Index("ix_tenant_api_keys_tenant_id", "tenant_id"),
        Index("ix_tenant_api_keys_prefix", "prefix"),
        Index("ix_tenant_api_keys_is_revoked", "is_revoked"),
        # Partial index for fast "find active keys for tenant" queries
        Index(
            "ix_tenant_api_keys_active",
            "tenant_id",
            "is_revoked",
            postgresql_where="is_revoked = false",
        ),
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
        comment="Owning tenant.",
    )
    key_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="bcrypt hash of the full API key.",
    )
    prefix: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        comment="First 8 characters of the raw key for identification in logs.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="NULL means the key does not expire.",
    )
    is_revoked: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Updated asynchronously on authenticated requests (best-effort).",
    )
    description: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Optional human label, e.g. 'CI pipeline key'.",
    )

    # Relationships
    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="api_keys")

    @property
    def is_valid(self) -> bool:
        """True if key is not revoked and not expired."""
        from datetime import timezone

        if self.is_revoked:
            return False
        if self.expires_at is not None:
            return datetime.now(tz=timezone.utc) < self.expires_at
        return True
