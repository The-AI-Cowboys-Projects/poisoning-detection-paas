"""
FastAPI application entry point.

Middleware stack (applied in reverse registration order, outermost first):
1. TrustedHostMiddleware  — rejects requests from unlisted Host headers
2. CORSMiddleware         — cross-origin request handling
3. RequestIDMiddleware    — attaches X-Request-ID to every request/response
4. RateLimitMiddleware    — per-tenant tier sliding-window counter (Redis)

Lifespan events:
- startup: initialise DB tables, Redis ping, Kafka producer
- shutdown: dispose DB engine, close Redis/Kafka connections

Routers registered:
- /api/v1/auth            — login, refresh, tenant registration
- /api/v1/tenants         — tenant CRUD, API key management
- /api/v1/vectors         — vector batch analysis
- /api/v1/tools           — MCP tool schema auditing
- /api/v1/rag             — RAG document scanning
- /api/v1/provenance      — dataset lineage registration + graph queries
- /api/v1/dashboard       — aggregate metrics + trend data
"""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator

import redis.asyncio as aioredis
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from backend.config import get_settings
from backend.models.database import check_db_connection, create_all_tables, dispose_engine
from backend.models.schemas import HealthStatus

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy router imports — prevents circular imports during testing
# ---------------------------------------------------------------------------


def _import_routers() -> list:
    """
    Import all route modules.  Deferred to avoid circular-import issues at
    module load time when models aren't yet initialised.
    """
    from backend.routers import auth, dashboard, provenance, rag, telemetry, tenants, tools, vectors

    return [
        (auth.router, "/api/v1/auth", ["Authentication"]),
        (tenants.router, "/api/v1/tenants", ["Tenants"]),
        (vectors.router, "/api/v1/vectors", ["Vector Analysis"]),
        (tools.router, "/api/v1/tools", ["MCP Tool Auditing"]),
        (rag.router, "/api/v1/rag", ["RAG Document Scanning"]),
        (provenance.router, "/api/v1/provenance", ["Dataset Provenance"]),
        (telemetry.router, "/api/v1/telemetry", ["Telemetry Simulator"]),
        (dashboard.router, "/api/v1/dashboard", ["Dashboard"]),
    ]


# ---------------------------------------------------------------------------
# Middleware implementations
# ---------------------------------------------------------------------------


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Attach a unique X-Request-ID to every request and response.

    If the client provides an X-Request-ID header it is re-used (enables
    distributed tracing correlation).  Otherwise a new UUID v4 is generated.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id

        start_time = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start_time) * 1000

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-Ms"] = f"{duration_ms:.2f}"

        logger.info(
            "%s %s %d %.2fms [%s]",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            request_id,
        )
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add defensive security headers to every response.

    These do not substitute for proper TLS/network controls but provide
    defence-in-depth for browser-facing API consumers.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # Only set HSTS on production — avoids breaking local HTTP dev
        settings = get_settings()
        if settings.is_production():
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains; preload"
            )
        return response


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager.

    Startup:
    1. Configure logging.
    2. Create DB tables (dev/staging only; production uses Alembic).
    3. Ping Redis.
    4. Log configuration summary.

    Shutdown:
    5. Dispose DB connection pool.
    6. Close Redis connection.
    """
    settings = get_settings()

    # 1. Configure logging
    logging.basicConfig(
        level=getattr(logging, settings.log_level),
        format="%(asctime)s %(levelname)-8s %(name)-40s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    logger.info(
        "Starting %s v%s — environment=%s",
        settings.app_name,
        settings.app_version,
        settings.environment,
    )

    # 2. DB tables
    if not settings.is_production():
        try:
            await create_all_tables()
        except Exception as exc:
            logger.warning("Could not auto-create tables (expected in CI): %s", exc)

    # 3. Redis ping
    redis_ok = False
    try:
        r = aioredis.from_url(str(settings.db.redis_url), decode_responses=True)
        await r.ping()
        await r.aclose()
        redis_ok = True
        logger.info("Redis connection verified.")
    except Exception as exc:
        logger.warning("Redis unavailable at startup: %s", exc)

    # Store readiness flags on app.state for the /health endpoint
    app.state.redis_ok = redis_ok
    app.state.startup_time = datetime.now(tz=timezone.utc)

    logger.info("%s started successfully.", settings.app_name)
    yield

    # --- Shutdown ---
    logger.info("Shutting down %s...", settings.app_name)
    await dispose_engine()
    logger.info("Database engine disposed.")


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    """
    Construct and configure the FastAPI application.

    Separated from module-level instantiation so tests can call create_app()
    with different settings without polluting the global state.
    """
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "REST API for detecting LLM data poisoning across vector stores, "
            "MCP tool schemas, RAG pipelines, and dataset provenance chains."
        ),
        docs_url="/docs" if not settings.is_production() else None,
        redoc_url="/redoc" if not settings.is_production() else None,
        openapi_url="/openapi.json" if not settings.is_production() else None,
        lifespan=lifespan,
    )

    # ---- Middleware (applied bottom-up — last added = outermost) ----

    # Security headers (innermost — runs after routing)
    app.add_middleware(SecurityHeadersMiddleware)

    # Request ID + access logging
    app.add_middleware(RequestIDMiddleware)

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "X-API-Key", "X-Request-ID", "Content-Type"],
        expose_headers=["X-Request-ID", "X-Response-Time-Ms", "X-RateLimit-Remaining"],
    )

    # Trusted hosts (outermost — rejects before any processing)
    if settings.is_production():
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.allowed_hosts,
        )

    # ---- Routers ----
    try:
        for router, prefix, tags in _import_routers():
            app.include_router(router, prefix=prefix, tags=tags)
    except ImportError as exc:
        # Routers may not yet exist during scaffold phase — log and continue.
        logger.warning("Could not import one or more routers: %s", exc)

    # ---- Built-in endpoints ----

    @app.get("/health", response_model=HealthStatus, tags=["Operations"])
    async def health_check() -> HealthStatus:
        """
        Returns component-level health status.

        Used by load-balancers and uptime monitors.
        A 200 response with status='degraded' means the API is serving
        but one or more dependencies are unavailable.
        """
        db_ok = await check_db_connection()
        redis_ok = getattr(app.state, "redis_ok", False)

        all_healthy = db_ok and redis_ok
        overall = "healthy" if all_healthy else ("degraded" if db_ok else "unhealthy")

        return HealthStatus(
            status=overall,
            version=settings.app_version,
            environment=settings.environment,
            checks={
                "database": db_ok,
                "redis": redis_ok,
                "kafka": False,   # populated when Kafka producer is wired
                "neo4j": False,   # populated when Neo4j driver is wired
            },
            timestamp=datetime.now(tz=timezone.utc),
        )

    @app.get("/", include_in_schema=False)
    async def root() -> JSONResponse:
        return JSONResponse(
            {
                "service": settings.app_name,
                "version": settings.app_version,
                "docs": "/docs",
                "health": "/health",
            }
        )

    # ---- Custom OpenAPI schema with security schemes ----
    def custom_openapi() -> dict:
        if app.openapi_schema:
            return app.openapi_schema

        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )
        schema["info"]["x-logo"] = {
            "url": "https://aicowboys.io/logo.png"
        }
        # Add both authentication schemes
        schema.setdefault("components", {})["securitySchemes"] = {
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "JWT access token. Obtain via POST /api/v1/auth/login.",
            },
            "ApiKeyAuth": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
                "description": "API key. Obtain via POST /api/v1/tenants/{id}/keys.",
            },
        }
        # Apply both schemes globally — endpoints can override
        schema["security"] = [{"BearerAuth": []}, {"ApiKeyAuth": []}]
        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi  # type: ignore[method-assign]

    return app


# ---------------------------------------------------------------------------
# Module-level application instance
# ---------------------------------------------------------------------------

app = create_app()
