"""
Tenant management router.

POST   /api/v1/tenants              — register new tenant
GET    /api/v1/tenants/me           — current tenant info
POST   /api/v1/tenants/{id}/keys    — create API key
DELETE /api/v1/tenants/{id}/keys/{key_id} — revoke API key
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.middleware.auth import generate_api_key, get_current_tenant, hash_api_key
from backend.models.database import get_db
from backend.models.schemas import TenantAPIKeyCreate, TenantAPIKeyResponse, TenantCreate, TenantResponse
from backend.models.tenant import Tenant, TenantAPIKey

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "",
    response_model=TenantAPIKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new tenant and receive an initial API key",
)
async def register_tenant(
    body: TenantCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TenantAPIKeyResponse:
    """
    Create a new tenant.  Returns the tenant record and an initial API key.

    The raw API key is shown ONCE in the response — store it immediately.
    Subsequent reads of TenantAPIKey records only expose the prefix.
    """
    from backend.config import get_settings

    settings = get_settings()

    # Enforce unique name
    existing = await db.execute(select(Tenant).where(Tenant.name == body.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A tenant named '{body.name}' already exists.",
        )

    # Generate initial API key
    raw_key, prefix = generate_api_key(
        prefix_length=settings.tenant.api_key_prefix_length,
        total_length=settings.tenant.api_key_total_length,
    )
    key_hash = hash_api_key(raw_key)

    tenant = Tenant(
        name=body.name,
        api_key_hash=key_hash,
        tier=body.tier,
    )
    db.add(tenant)
    await db.flush()  # get the generated id before creating the key

    api_key = TenantAPIKey(
        tenant_id=tenant.id,
        key_hash=key_hash,
        prefix=prefix,
        description="Initial key",
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    return TenantAPIKeyResponse(
        id=api_key.id,
        tenant_id=tenant.id,
        prefix=prefix,
        created_at=api_key.created_at,
        expires_at=api_key.expires_at,
        is_revoked=api_key.is_revoked,
        description=api_key.description,
        raw_key=raw_key,
    )


@router.get(
    "/me",
    response_model=TenantResponse,
    summary="Get current tenant information",
)
async def get_me(
    tenant: Annotated[Tenant, Depends(get_current_tenant)],
) -> TenantResponse:
    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        tier=tenant.tier,
        created_at=tenant.created_at,
        is_active=tenant.is_active,
    )


@router.post(
    "/{tenant_id}/keys",
    response_model=TenantAPIKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create additional API key for tenant",
)
async def create_api_key(
    tenant_id: uuid.UUID,
    body: TenantAPIKeyCreate,
    tenant: Annotated[Tenant, Depends(get_current_tenant)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TenantAPIKeyResponse:
    """
    Create an additional API key.  Tenants may only manage their own keys.
    """
    from backend.config import get_settings

    if tenant.id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You may only manage keys for your own tenant.",
        )

    settings = get_settings()

    # Enforce per-tenant key limit
    count_result = await db.execute(
        select(TenantAPIKey).where(
            TenantAPIKey.tenant_id == tenant.id,
            TenantAPIKey.is_revoked.is_(False),
        )
    )
    active_keys = list(count_result.scalars().all())
    if len(active_keys) >= settings.tenant.api_key_max_per_tenant:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Maximum of {settings.tenant.api_key_max_per_tenant} active keys reached. "
                "Revoke an existing key first."
            ),
        )

    raw_key, prefix = generate_api_key(
        prefix_length=settings.tenant.api_key_prefix_length,
        total_length=settings.tenant.api_key_total_length,
    )
    key_hash = hash_api_key(raw_key)

    expires_at: datetime | None = None
    if body.expires_in_days is not None:
        expires_at = datetime.now(tz=timezone.utc) + timedelta(days=body.expires_in_days)

    api_key = TenantAPIKey(
        tenant_id=tenant.id,
        key_hash=key_hash,
        prefix=prefix,
        expires_at=expires_at,
        description=body.description,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    return TenantAPIKeyResponse(
        id=api_key.id,
        tenant_id=tenant.id,
        prefix=prefix,
        created_at=api_key.created_at,
        expires_at=api_key.expires_at,
        is_revoked=api_key.is_revoked,
        description=api_key.description,
        raw_key=raw_key,
    )


@router.delete(
    "/{tenant_id}/keys/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke an API key",
)
async def revoke_api_key(
    tenant_id: uuid.UUID,
    key_id: uuid.UUID,
    tenant: Annotated[Tenant, Depends(get_current_tenant)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    if tenant.id != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden.")

    result = await db.execute(
        select(TenantAPIKey).where(
            TenantAPIKey.id == key_id,
            TenantAPIKey.tenant_id == tenant.id,
        )
    )
    key = result.scalar_one_or_none()
    if key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found.")

    key.is_revoked = True
    await db.commit()
