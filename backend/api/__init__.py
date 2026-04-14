"""
API package — mounts all versioned routers onto the FastAPI application.

Router registration order determines OpenAPI tag ordering in /docs.
All routers share the /api/v1 prefix applied in main.py via include_router.
"""

from backend.api.routes import (
    auth_router,
    vectors_router,
    rag_router,
    tools_router,
    provenance_router,
    dashboard_router,
    health_router,
)

__all__ = [
    "auth_router",
    "vectors_router",
    "rag_router",
    "tools_router",
    "provenance_router",
    "dashboard_router",
    "health_router",
]
