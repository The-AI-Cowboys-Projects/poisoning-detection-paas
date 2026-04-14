"""
Dataset provenance router.

POST /api/v1/provenance/register          — register a lineage node
GET  /api/v1/provenance/{node_id}         — retrieve a node
GET  /api/v1/provenance/{node_id}/lineage — walk ancestor chain
GET  /api/v1/provenance                   — list nodes (paginated)
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.middleware.auth import get_current_tenant, rate_limiter
from backend.models.database import get_db
from backend.models.detection import ProvenanceNode
from backend.models.schemas import (
    PaginatedResponse,
    ProvenanceNodeResponse,
    ProvenanceSubmission,
)
from backend.models.tenant import Tenant

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/register",
    response_model=ProvenanceNodeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a dataset lineage node",
)
async def register_node(
    body: ProvenanceSubmission,
    request: Annotated[object, Depends(lambda r: r)],
    tenant: Annotated[Tenant, Depends(get_current_tenant)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ProvenanceNodeResponse:
    """
    Register a new node in the dataset provenance lineage tree.

    If parent_dataset_id is provided, the service resolves the parent node
    and increments the generation counter automatically.
    """
    from fastapi import Request

    if isinstance(request, Request):
        await rate_limiter.check(tenant, request)

    parent_node: ProvenanceNode | None = None
    generation = body.generation

    if body.parent_dataset_id is not None:
        parent_result = await db.execute(
            select(ProvenanceNode).where(
                ProvenanceNode.dataset_id == body.parent_dataset_id,
                ProvenanceNode.tenant_id == tenant.id,
            )
        )
        parent_node = parent_result.scalar_one_or_none()
        if parent_node is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Parent dataset '{body.parent_dataset_id}' not found for this tenant.",
            )
        generation = parent_node.generation + 1

    node = ProvenanceNode(
        tenant_id=tenant.id,
        dataset_id=body.dataset_id,
        parent_id=parent_node.id if parent_node else None,
        generation=generation,
        source_type=body.source_type.value,
        contamination_score=0.0,
        created_at=datetime.now(tz=timezone.utc),
        metadata_=body.metadata if body.metadata else None,
    )
    db.add(node)
    await db.commit()
    await db.refresh(node)

    return ProvenanceNodeResponse(
        id=node.id,
        tenant_id=node.tenant_id,
        dataset_id=node.dataset_id,
        parent_id=node.parent_id,
        generation=node.generation,
        source_type=node.source_type,
        contamination_score=node.contamination_score,
        created_at=node.created_at,
        metadata=node.metadata_,
    )


@router.get(
    "/{node_id}",
    response_model=ProvenanceNodeResponse,
    summary="Retrieve a provenance node",
)
async def get_node(
    node_id: uuid.UUID,
    tenant: Annotated[Tenant, Depends(get_current_tenant)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ProvenanceNodeResponse:
    result = await db.execute(
        select(ProvenanceNode).where(
            ProvenanceNode.id == node_id,
            ProvenanceNode.tenant_id == tenant.id,
        )
    )
    node = result.scalar_one_or_none()
    if node is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found.")

    return ProvenanceNodeResponse(
        id=node.id,
        tenant_id=node.tenant_id,
        dataset_id=node.dataset_id,
        parent_id=node.parent_id,
        generation=node.generation,
        source_type=node.source_type,
        contamination_score=node.contamination_score,
        created_at=node.created_at,
        metadata=node.metadata_,
    )


@router.get(
    "/{node_id}/lineage",
    response_model=list[ProvenanceNodeResponse],
    summary="Walk the ancestor chain of a provenance node",
)
async def get_lineage(
    node_id: uuid.UUID,
    tenant: Annotated[Tenant, Depends(get_current_tenant)],
    db: Annotated[AsyncSession, Depends(get_db)],
    max_depth: int = Query(default=20, ge=1, le=100),
) -> list[ProvenanceNodeResponse]:
    """
    Return the ancestor chain from the requested node back to the root dataset.

    Traversal is performed iteratively (not recursively) to avoid Python
    stack overflow on deep lineages.  For production deployments with deep
    graphs, use the Neo4j Cypher endpoint instead.
    """
    result = await db.execute(
        select(ProvenanceNode).where(
            ProvenanceNode.id == node_id,
            ProvenanceNode.tenant_id == tenant.id,
        )
    )
    current = result.scalar_one_or_none()
    if current is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found.")

    chain: list[ProvenanceNodeResponse] = []
    visited: set[uuid.UUID] = set()
    depth = 0

    while current is not None and depth < max_depth:
        if current.id in visited:
            # Cycle guard — should never happen but defensive
            break
        visited.add(current.id)
        chain.append(
            ProvenanceNodeResponse(
                id=current.id,
                tenant_id=current.tenant_id,
                dataset_id=current.dataset_id,
                parent_id=current.parent_id,
                generation=current.generation,
                source_type=current.source_type,
                contamination_score=current.contamination_score,
                created_at=current.created_at,
                metadata=current.metadata_,
            )
        )
        if current.parent_id is None:
            break
        parent_result = await db.execute(
            select(ProvenanceNode).where(
                ProvenanceNode.id == current.parent_id,
                ProvenanceNode.tenant_id == tenant.id,
            )
        )
        current = parent_result.scalar_one_or_none()
        depth += 1

    return chain


@router.get(
    "",
    response_model=PaginatedResponse,
    summary="List provenance nodes for current tenant",
)
async def list_nodes(
    tenant: Annotated[Tenant, Depends(get_current_tenant)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> PaginatedResponse:
    from sqlalchemy import func

    offset = (page - 1) * page_size

    count_result = await db.execute(
        select(func.count()).select_from(ProvenanceNode).where(
            ProvenanceNode.tenant_id == tenant.id
        )
    )
    total = count_result.scalar_one()

    rows_result = await db.execute(
        select(ProvenanceNode)
        .where(ProvenanceNode.tenant_id == tenant.id)
        .order_by(ProvenanceNode.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    rows = list(rows_result.scalars().all())

    items = [
        ProvenanceNodeResponse(
            id=r.id,
            tenant_id=r.tenant_id,
            dataset_id=r.dataset_id,
            parent_id=r.parent_id,
            generation=r.generation,
            source_type=r.source_type,
            contamination_score=r.contamination_score,
            created_at=r.created_at,
            metadata=r.metadata_,
        )
        for r in rows
    ]

    return PaginatedResponse(items=items, total=total, page=page, page_size=page_size, total_pages=1)
