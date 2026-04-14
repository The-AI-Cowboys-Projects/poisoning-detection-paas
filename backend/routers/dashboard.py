"""
Dashboard metrics router.

GET /api/v1/dashboard/metrics — aggregate detection metrics for the current tenant
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.middleware.auth import get_current_tenant
from backend.models.database import get_db
from backend.models.detection import (
    MCPToolAuditResult,
    MCPVerdict,
    ProvenanceNode,
    RAGDocumentScan,
    VectorAnalysisResult,
    VectorStatus,
)
from backend.models.schemas import DashboardMetrics, ThreatBreakdown
from backend.models.tenant import Tenant

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get(
    "/metrics",
    response_model=DashboardMetrics,
    summary="Get aggregate detection metrics for the current tenant",
)
async def get_metrics(
    tenant: Annotated[Tenant, Depends(get_current_tenant)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> DashboardMetrics:
    """
    Returns all-time totals, rolling 24-hour threat breakdown, and 1-hour
    scan velocity for the authenticated tenant.

    All queries are parameterised and tenant-scoped — cross-tenant leakage
    is impossible at the query level.
    """
    now = datetime.now(tz=timezone.utc)
    window_24h = now - timedelta(hours=24)
    window_1h = now - timedelta(hours=1)

    # --- All-time totals ---
    vec_total = await db.execute(
        select(func.count()).select_from(VectorAnalysisResult).where(
            VectorAnalysisResult.tenant_id == tenant.id
        )
    )
    mcp_total = await db.execute(
        select(func.count()).select_from(MCPToolAuditResult).where(
            MCPToolAuditResult.tenant_id == tenant.id
        )
    )
    rag_total = await db.execute(
        select(func.count()).select_from(RAGDocumentScan).where(
            RAGDocumentScan.tenant_id == tenant.id
        )
    )
    prov_total = await db.execute(
        select(func.count()).select_from(ProvenanceNode).where(
            ProvenanceNode.tenant_id == tenant.id
        )
    )

    total_scans = (
        (vec_total.scalar_one() or 0)
        + (mcp_total.scalar_one() or 0)
        + (rag_total.scalar_one() or 0)
    )

    # --- All-time threats ---
    vec_threats = await db.execute(
        select(func.count()).select_from(VectorAnalysisResult).where(
            VectorAnalysisResult.tenant_id == tenant.id,
            VectorAnalysisResult.status.in_(
                [VectorStatus.SUSPICIOUS.value, VectorStatus.POISONED.value]
            ),
        )
    )
    mcp_threats = await db.execute(
        select(func.count()).select_from(MCPToolAuditResult).where(
            MCPToolAuditResult.tenant_id == tenant.id,
            MCPToolAuditResult.verdict.in_(
                [MCPVerdict.WARNING.value, MCPVerdict.CRITICAL.value]
            ),
        )
    )
    rag_threats = await db.execute(
        select(func.count()).select_from(RAGDocumentScan).where(
            RAGDocumentScan.tenant_id == tenant.id,
            RAGDocumentScan.is_flagged.is_(True),
        )
    )
    prov_threats = await db.execute(
        select(func.count()).select_from(ProvenanceNode).where(
            ProvenanceNode.tenant_id == tenant.id,
            ProvenanceNode.contamination_score > 0.3,
        )
    )

    threats_detected = (
        (vec_threats.scalar_one() or 0)
        + (mcp_threats.scalar_one() or 0)
        + (rag_threats.scalar_one() or 0)
    )

    # --- 24-hour threat breakdown ---
    vec_24h = await db.execute(
        select(func.count()).select_from(VectorAnalysisResult).where(
            VectorAnalysisResult.tenant_id == tenant.id,
            VectorAnalysisResult.timestamp >= window_24h,
            VectorAnalysisResult.status.in_(
                [VectorStatus.SUSPICIOUS.value, VectorStatus.POISONED.value]
            ),
        )
    )
    mcp_24h = await db.execute(
        select(func.count()).select_from(MCPToolAuditResult).where(
            MCPToolAuditResult.tenant_id == tenant.id,
            MCPToolAuditResult.timestamp >= window_24h,
            MCPToolAuditResult.verdict.in_(
                [MCPVerdict.WARNING.value, MCPVerdict.CRITICAL.value]
            ),
        )
    )
    rag_24h = await db.execute(
        select(func.count()).select_from(RAGDocumentScan).where(
            RAGDocumentScan.tenant_id == tenant.id,
            RAGDocumentScan.timestamp >= window_24h,
            RAGDocumentScan.is_flagged.is_(True),
        )
    )
    prov_24h = await db.execute(
        select(func.count()).select_from(ProvenanceNode).where(
            ProvenanceNode.tenant_id == tenant.id,
            ProvenanceNode.created_at >= window_24h,
            ProvenanceNode.contamination_score > 0.3,
        )
    )

    threat_breakdown = ThreatBreakdown(
        vector_poisoning=vec_24h.scalar_one() or 0,
        mcp_injections=mcp_24h.scalar_one() or 0,
        rag_contamination=rag_24h.scalar_one() or 0,
        provenance_anomalies=prov_24h.scalar_one() or 0,
    )

    # --- 1-hour scan velocity ---
    vec_1h = await db.execute(
        select(func.count()).select_from(VectorAnalysisResult).where(
            VectorAnalysisResult.tenant_id == tenant.id,
            VectorAnalysisResult.timestamp >= window_1h,
        )
    )
    mcp_1h = await db.execute(
        select(func.count()).select_from(MCPToolAuditResult).where(
            MCPToolAuditResult.tenant_id == tenant.id,
            MCPToolAuditResult.timestamp >= window_1h,
        )
    )
    rag_1h = await db.execute(
        select(func.count()).select_from(RAGDocumentScan).where(
            RAGDocumentScan.tenant_id == tenant.id,
            RAGDocumentScan.timestamp >= window_1h,
        )
    )
    scan_velocity = float(
        (vec_1h.scalar_one() or 0)
        + (mcp_1h.scalar_one() or 0)
        + (rag_1h.scalar_one() or 0)
    )

    # --- Last scan timestamp ---
    last_vec = await db.execute(
        select(func.max(VectorAnalysisResult.timestamp)).where(
            VectorAnalysisResult.tenant_id == tenant.id
        )
    )
    last_mcp = await db.execute(
        select(func.max(MCPToolAuditResult.timestamp)).where(
            MCPToolAuditResult.tenant_id == tenant.id
        )
    )
    last_rag = await db.execute(
        select(func.max(RAGDocumentScan.timestamp)).where(
            RAGDocumentScan.tenant_id == tenant.id
        )
    )
    timestamps = [
        t for t in [
            last_vec.scalar_one(),
            last_mcp.scalar_one(),
            last_rag.scalar_one(),
        ]
        if t is not None
    ]
    last_scan_at = max(timestamps) if timestamps else None

    # --- Clean rate ---
    clean_rate = (
        (total_scans - threats_detected) / total_scans if total_scans > 0 else 1.0
    )

    return DashboardMetrics(
        total_scans=total_scans,
        threats_detected=threats_detected,
        active_tenants=0,  # admin-only; zero for tenant-scoped requests
        scan_velocity=scan_velocity,
        threat_breakdown=threat_breakdown,
        last_scan_at=last_scan_at,
        clean_rate=clean_rate,
    )
