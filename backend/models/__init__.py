"""
Models package — exports all ORM models and Pydantic schemas.

Import order matters for SQLAlchemy relationship resolution:
  database -> tenant -> detection -> schemas
"""

from backend.models.database import Base, get_db, async_session_factory
from backend.models.tenant import Tenant, TenantAPIKey
from backend.models.detection import (
    VectorAnalysisResult,
    MCPToolAuditResult,
    RAGDocumentScan,
    ProvenanceNode,
    VectorStatus,
    MCPVerdict,
    SourceType,
)
from backend.models.schemas import (
    TenantCreate,
    TenantResponse,
    VectorSubmission,
    MCPToolSubmission,
    RAGDocumentSubmission,
    ProvenanceSubmission,
    DetectionResponse,
    DashboardMetrics,
)

__all__ = [
    # Database infrastructure
    "Base",
    "get_db",
    "async_session_factory",
    # ORM models
    "Tenant",
    "TenantAPIKey",
    "VectorAnalysisResult",
    "MCPToolAuditResult",
    "RAGDocumentScan",
    "ProvenanceNode",
    # Enums
    "VectorStatus",
    "MCPVerdict",
    "SourceType",
    # Pydantic schemas
    "TenantCreate",
    "TenantResponse",
    "VectorSubmission",
    "MCPToolSubmission",
    "RAGDocumentSubmission",
    "ProvenanceSubmission",
    "DetectionResponse",
    "DashboardMetrics",
]
