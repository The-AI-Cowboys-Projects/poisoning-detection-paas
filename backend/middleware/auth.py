"""
Authentication and rate-limiting middleware.

Authentication flow:
1. Request arrives with either:
   a. Authorization: Bearer <JWT>  — used by the web dashboard
   b. X-API-Key: <raw_key>         — used by programmatic integrations

2. For JWT: verify signature + expiry, extract tenant_id from claims.
3. For API key: extract prefix (first 8 chars), look up candidate rows,
   bcrypt-verify against stored hash.  Use constant-time comparison to
   prevent timing attacks.
4. Resolved tenant is injected as a FastAPI dependency.

Rate limiting:
- Redis sliding-window counter keyed on tenant_id + tier.
- Window = 60 seconds; ceiling from TenantSettings.
- Exceeding the limit returns 429 with Retry-After header.
- Best-effort: if Redis is unreachable, fail-open with a warning log.
"""

from __future__ import annotations

import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

import redis.asyncio as aioredis
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import get_settings
from backend.models.database import get_db
from backend.models.tenant import Tenant, TenantAPIKey

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ALGORITHM_CHOICES = {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512"}
_BEARER_SCHEME = HTTPBearer(auto_error=False)
_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# bcrypt context — 12 rounds is the OWASP minimum for 2024.
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

# ---------------------------------------------------------------------------
# Redis connection (module-level singleton)
# ---------------------------------------------------------------------------

_redis_client: aioredis.Redis | None = None


async def _get_redis() -> aioredis.Redis | None:
    """Return the module-level Redis client, initialising it on first call."""
    global _redis_client
    if _redis_client is None:
        settings = get_settings()
        try:
            _redis_client = aioredis.from_url(
                str(settings.db.redis_url),
                max_connections=settings.db.redis_max_connections,
                socket_timeout=settings.db.redis_socket_timeout,
                socket_connect_timeout=settings.db.redis_socket_connect_timeout,
                decode_responses=True,
            )
        except Exception as exc:
            logger.error("Failed to initialise Redis client: %s", exc)
            return None
    return _redis_client


# ---------------------------------------------------------------------------
# JWT utilities
# ---------------------------------------------------------------------------


def create_access_token(
    tenant_id: str,
    tier: str,
    additional_claims: dict[str, Any] | None = None,
) -> str:
    """
    Create a signed JWT access token for a tenant.

    Claims:
    - sub: tenant UUID string
    - tier: billing tier (used for rate-limit decisions without a DB hit)
    - iat: issued-at (UTC epoch)
    - exp: expiry (UTC epoch)
    - type: "access"
    """
    settings = get_settings()
    now = datetime.now(tz=timezone.utc)
    expire = now + timedelta(minutes=settings.jwt.access_token_expire_minutes)

    payload: dict[str, Any] = {
        "sub": tenant_id,
        "tier": tier,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "type": "access",
        "jti": secrets.token_hex(16),  # unique token ID for potential revocation
    }
    if additional_claims:
        # Prevent callers from overriding reserved claims
        reserved = {"sub", "iat", "exp", "type", "jti"}
        for key, value in additional_claims.items():
            if key not in reserved:
                payload[key] = value

    return jwt.encode(
        payload,
        settings.jwt.secret_key,
        algorithm=settings.jwt.algorithm,
    )


def create_refresh_token(tenant_id: str) -> str:
    """
    Create a long-lived refresh token.

    Refresh tokens carry minimal claims — only sub + exp + type.
    They must be exchanged for a new access token via POST /api/v1/auth/refresh.
    """
    settings = get_settings()
    now = datetime.now(tz=timezone.utc)
    expire = now + timedelta(days=settings.jwt.refresh_token_expire_days)

    payload: dict[str, Any] = {
        "sub": tenant_id,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "type": "refresh",
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(
        payload,
        settings.jwt.secret_key,
        algorithm=settings.jwt.algorithm,
    )


def verify_access_token(token: str) -> dict[str, Any]:
    """
    Verify and decode a JWT access token.

    Raises HTTPException 401 on any verification failure.
    Never raises JWTError to callers — always converts to HTTPException.
    """
    settings = get_settings()
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.jwt.secret_key,
            algorithms=[settings.jwt.algorithm],
        )
    except JWTError as exc:
        logger.debug("JWT verification failed: %s", exc)
        raise credentials_error from exc

    if payload.get("type") != "access":
        raise credentials_error

    sub = payload.get("sub")
    if not sub:
        raise credentials_error

    return payload


# ---------------------------------------------------------------------------
# API key utilities
# ---------------------------------------------------------------------------


def hash_api_key(raw_key: str) -> str:
    """Return bcrypt hash of the raw API key."""
    return _pwd_context.hash(raw_key)


def verify_api_key(raw_key: str, stored_hash: str) -> bool:
    """Constant-time bcrypt verification of a raw API key against its hash."""
    return _pwd_context.verify(raw_key, stored_hash)


def generate_api_key(prefix_length: int = 8, total_length: int = 48) -> tuple[str, str]:
    """
    Generate a cryptographically secure API key.

    Returns (raw_key, prefix) where:
    - raw_key: full key to be shown once to the user
    - prefix: first prefix_length characters for log identification
    """
    body_length = total_length - prefix_length
    prefix = secrets.token_urlsafe(prefix_length)[:prefix_length]
    body = secrets.token_urlsafe(body_length)[:body_length]
    raw_key = f"{prefix}{body}"
    return raw_key, prefix


# ---------------------------------------------------------------------------
# Database lookup helpers
# ---------------------------------------------------------------------------


async def _resolve_tenant_from_jwt(
    payload: dict[str, Any],
    db: AsyncSession,
) -> Tenant:
    """Load tenant from DB using the sub claim from a verified JWT payload."""
    tenant_id = payload.get("sub")
    result = await db.execute(
        select(Tenant).where(
            Tenant.id == tenant_id,
            Tenant.is_active.is_(True),
        )
    )
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tenant not found or inactive.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return tenant


async def _resolve_tenant_from_api_key(
    raw_key: str,
    db: AsyncSession,
) -> Tenant:
    """
    Resolve a tenant from a raw API key.

    Strategy:
    1. Extract the prefix (first 8 chars) to narrow DB lookup.
    2. Load all non-revoked keys for that prefix.
    3. bcrypt-verify the raw key against each candidate (constant-time).
    4. If a match is found and is_valid, load and return the tenant.

    This avoids a full-table scan while keeping timing safe.
    """
    settings = get_settings()
    prefix = raw_key[: settings.tenant.api_key_prefix_length]

    result = await db.execute(
        select(TenantAPIKey)
        .where(
            TenantAPIKey.prefix == prefix,
            TenantAPIKey.is_revoked.is_(False),
        )
        .limit(settings.tenant.api_key_max_per_tenant)
    )
    candidates: list[TenantAPIKey] = list(result.scalars().all())

    matched_key: TenantAPIKey | None = None
    for candidate in candidates:
        if verify_api_key(raw_key, candidate.key_hash):
            matched_key = candidate
            break

    if matched_key is None or not matched_key.is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key.",
            headers={"WWW-Authenticate": "API-Key"},
        )

    # Load the tenant in the same transaction
    tenant_result = await db.execute(
        select(Tenant).where(
            Tenant.id == matched_key.tenant_id,
            Tenant.is_active.is_(True),
        )
    )
    tenant = tenant_result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tenant not found or inactive.",
        )
    return tenant


# ---------------------------------------------------------------------------
# Main authentication dependency
# ---------------------------------------------------------------------------


async def authenticate_request(
    bearer: Annotated[HTTPAuthorizationCredentials | None, Depends(_BEARER_SCHEME)],
    api_key: Annotated[str | None, Security(_API_KEY_HEADER)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Tenant:
    """
    FastAPI dependency that resolves the authenticated Tenant from either a
    Bearer JWT or an X-API-Key header.

    Preference: Bearer JWT > X-API-Key (to allow both on the same request
    without error, while honouring the stronger auth mechanism).
    """
    if bearer is not None:
        payload = verify_access_token(bearer.credentials)
        return await _resolve_tenant_from_jwt(payload, db)

    if api_key is not None:
        return await _resolve_tenant_from_api_key(api_key, db)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide Bearer token or X-API-Key.",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_tenant(
    tenant: Annotated[Tenant, Depends(authenticate_request)],
) -> Tenant:
    """
    Thin dependency alias used by route handlers.

        @router.get("/protected")
        async def handler(tenant: Tenant = Depends(get_current_tenant)):
            ...
    """
    return tenant


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """
    Sliding-window rate limiter backed by Redis.

    Uses an atomic Lua script to implement a sliding-window counter with
    microsecond precision.  This avoids the race condition in naive
    INCR/EXPIRE approaches.

    If Redis is unavailable, the limiter fails-open (logs a warning but
    does not block the request) to avoid cascading failures.
    """

    _LUA_SCRIPT = """
    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local limit = tonumber(ARGV[3])
    local window_start = now - window

    -- Remove expired entries
    redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

    -- Count current entries
    local count = redis.call('ZCARD', key)

    if count < limit then
        -- Add current request
        redis.call('ZADD', key, now, now .. '-' .. math.random(1, 1000000))
        redis.call('EXPIRE', key, window + 1)
        return {1, limit - count - 1}
    else
        -- Find oldest entry to calculate retry-after
        local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
        local retry_after = 0
        if #oldest > 0 then
            retry_after = math.ceil((tonumber(oldest[2]) + window - now) / 1000)
        end
        return {0, retry_after}
    end
    """

    def __init__(self) -> None:
        self._script_sha: str | None = None

    async def _load_script(self, redis: aioredis.Redis) -> str:
        """Load the Lua script into Redis and cache the SHA."""
        if self._script_sha is None:
            self._script_sha = await redis.script_load(self._LUA_SCRIPT)
        return self._script_sha

    async def check(self, tenant: Tenant, request: Request) -> None:
        """
        Check whether the tenant has exceeded their tier rate limit.

        Raises HTTPException 429 if the limit is exceeded.
        Fails-open if Redis is unavailable.
        """
        settings = get_settings()
        limit = settings.rate_limit_for_tier(tenant.tier)
        window_ms = 60_000  # 60-second sliding window in milliseconds

        redis = await _get_redis()
        if redis is None:
            logger.warning(
                "Redis unavailable — rate limiting skipped for tenant %s", tenant.id
            )
            return

        key = f"rl:{tenant.id}:{tenant.tier}"
        now_ms = int(time.time() * 1000)

        try:
            sha = await self._load_script(redis)
            result: list[int] = await redis.evalsha(
                sha,
                1,        # number of keys
                key,      # KEYS[1]
                now_ms,   # ARGV[1]
                window_ms,  # ARGV[2]
                limit,    # ARGV[3]
            )

            allowed, remaining_or_retry = result[0], result[1]
            if not allowed:
                retry_after = max(1, remaining_or_retry)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Retry after {retry_after} seconds.",
                    headers={
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(limit),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(int(time.time()) + retry_after),
                    },
                )

            # Attach rate-limit headers to the response (best-effort)
            if hasattr(request.state, "rate_limit_remaining"):
                request.state.rate_limit_remaining = remaining_or_retry

        except HTTPException:
            raise
        except Exception as exc:
            logger.warning(
                "Rate-limiter Redis error for tenant %s: %s — failing open",
                tenant.id,
                exc,
            )


# Module-level singleton — prevents script SHA being re-loaded on every request
rate_limiter = RateLimiter()
