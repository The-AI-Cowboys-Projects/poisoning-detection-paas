"""
Authentication router — login, token refresh, tenant self-registration.

POST /api/v1/auth/login       — exchange API key for JWT access + refresh tokens
POST /api/v1/auth/refresh     — exchange refresh token for new access token
POST /api/v1/auth/logout      — revoke refresh token (Redis blocklist)
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.middleware.auth import (
    create_access_token,
    create_refresh_token,
    verify_access_token,
    verify_api_key,
)
from backend.models.database import get_db
from backend.models.tenant import Tenant, TenantAPIKey

logger = logging.getLogger(__name__)
router = APIRouter()


class LoginRequest(BaseModel):
    api_key: str = Field(..., min_length=16, description="Raw API key.")


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Access token TTL in seconds.")


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Exchange API key for JWT tokens",
    responses={
        401: {"description": "Invalid or expired API key."},
    },
)
async def login(
    body: LoginRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenResponse:
    """
    Authenticate with an API key and receive short-lived JWT access and
    long-lived refresh tokens.

    The access token is valid for the duration configured in JWTSettings.
    Present it as `Authorization: Bearer <token>` on subsequent requests.
    """
    from backend.config import get_settings

    raw_key = body.api_key
    settings = get_settings()
    prefix = raw_key[: settings.tenant.api_key_prefix_length]

    result = await db.execute(
        select(TenantAPIKey)
        .where(TenantAPIKey.prefix == prefix, TenantAPIKey.is_revoked.is_(False))
        .limit(settings.tenant.api_key_max_per_tenant)
    )
    candidates = list(result.scalars().all())

    matched: TenantAPIKey | None = None
    for candidate in candidates:
        if verify_api_key(raw_key, candidate.key_hash) and candidate.is_valid:
            matched = candidate
            break

    if matched is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key.",
        )

    tenant_result = await db.execute(
        select(Tenant).where(Tenant.id == matched.tenant_id, Tenant.is_active.is_(True))
    )
    tenant = tenant_result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tenant not found or inactive.",
        )

    access = create_access_token(str(tenant.id), tenant.tier)
    refresh = create_refresh_token(str(tenant.id))

    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.jwt.access_token_expire_minutes * 60,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
)
async def refresh_token(
    body: RefreshRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenResponse:
    """Exchange a valid refresh token for a new access token."""
    from backend.config import get_settings
    from jose import JWTError, jwt

    settings = get_settings()
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token.",
    )
    try:
        payload = jwt.decode(
            body.refresh_token,
            settings.jwt.secret_key,
            algorithms=[settings.jwt.algorithm],
        )
    except JWTError:
        raise credentials_error

    if payload.get("type") != "refresh":
        raise credentials_error

    tenant_id = payload.get("sub")
    result = await db.execute(
        select(Tenant).where(Tenant.id == tenant_id, Tenant.is_active.is_(True))
    )
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise credentials_error

    access = create_access_token(str(tenant.id), tenant.tier)
    new_refresh = create_refresh_token(str(tenant.id))

    return TokenResponse(
        access_token=access,
        refresh_token=new_refresh,
        expires_in=settings.jwt.access_token_expire_minutes * 60,
    )
