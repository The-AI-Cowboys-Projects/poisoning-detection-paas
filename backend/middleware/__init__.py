"""
Middleware package.

Exports:
- auth: JWT creation/verification, API key authentication, tenant dependency
- RateLimiter: per-tenant tier rate limiter
"""

from backend.middleware.auth import (
    authenticate_request,
    create_access_token,
    create_refresh_token,
    get_current_tenant,
    RateLimiter,
    verify_access_token,
)

__all__ = [
    "authenticate_request",
    "create_access_token",
    "create_refresh_token",
    "get_current_tenant",
    "RateLimiter",
    "verify_access_token",
]
