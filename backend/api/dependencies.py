"""
FastAPI dependency injection providers.

Every dependency in this module is a callable compatible with Depends().
Service instances are constructed lazily and cached where safe to do so
(pure-stateless services use module-level singletons; stateful DB-backed
services receive a fresh session per request via get_db()).

Auth dependency chain:
    HTTP Authorization header
        -> _extract_bearer_token()
        -> _decode_jwt()
        -> get_current_tenant()  (raises 401/403 on failure)

Service dependency chain:
    get_<service>() returns a singleton instance wired to the shared engine.
    In tests these are overridden via app.dependency_overrides.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.config import get_settings
from backend.services.mcp_auditor import MCPToolAuditor
from backend.services.provenance_tracker import ProvenanceTracker
from backend.services.rag_analyzer import RAGPoisoningDetector
from backend.services.threat_aggregator import ThreatAggregator
from backend.services.vector_analyzer import VectorIntegrityAnalyzer

logger = logging.getLogger(__name__)

_bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


async def get_current_tenant(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
) -> dict[str, Any]:
    """
    Validate a JWT bearer token and return the decoded tenant payload.

    Raises HTTP 401 when no token is supplied or the token is invalid/expired.
    Raises HTTP 403 when the token is structurally valid but the tenant is
    suspended or missing required claims.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Supply a Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    settings = get_settings()
    token = credentials.credentials

    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            settings.jwt.secret_key,
            algorithms=[settings.jwt.algorithm],
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    required_claims = {"tenant_id", "organization_name", "tier", "email"}
    missing = required_claims - payload.keys()
    if missing:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Token is missing required claims: {missing}",
        )

    if payload.get("suspended", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant account is suspended.",
        )

    return payload


# ---------------------------------------------------------------------------
# Service instance providers
#
# Each get_*() function is decorated with @lru_cache so a single instance
# is shared across the process lifetime.  This is appropriate for stateless
# or internally-pooled services.  For DB-session-bound objects, a new
# instance is created per request (no cache).
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def get_vector_analyzer() -> VectorIntegrityAnalyzer:
    """
    Return the module-level singleton VectorIntegrityAnalyzer.

    The analyzer owns an internal numpy baseline cache; sharing the instance
    avoids re-loading large baseline arrays on every request.  The service uses
    an AnalyzerConfig dataclass for construction — parameters are read from
    AppSettings and passed through that config object.
    """
    from backend.services.vector_analyzer import AnalyzerConfig

    settings = get_settings()
    v = settings.vector
    config = AnalyzerConfig(
        cosine_similarity_threshold=v.cosine_similarity_threshold,
        dispersion_sigma=v.dispersion_sigma,
        min_baseline_samples=v.min_baseline_samples,
    )
    logger.debug("Constructing VectorIntegrityAnalyzer singleton.")
    return VectorIntegrityAnalyzer(config=config)


@lru_cache(maxsize=1)
def get_rag_detector() -> RAGPoisoningDetector:
    """
    Return the module-level singleton RAGPoisoningDetector.

    The detector pre-compiles regex patterns at construction time via its
    default RAGAnalyzerConfig; caching avoids repeat compilation on each request.
    """
    logger.debug("Constructing RAGPoisoningDetector singleton.")
    return RAGPoisoningDetector()


@lru_cache(maxsize=1)
def get_mcp_auditor() -> MCPToolAuditor:
    """
    Return the module-level singleton MCPToolAuditor.

    The auditor uses an MCPAuditConfig dataclass.  Parameters are sourced from
    AppSettings; the tuple conversion matches the dataclass field type.
    """
    from backend.services.mcp_auditor import MCPAuditConfig

    settings = get_settings()
    m = settings.mcp
    config = MCPAuditConfig(
        max_description_length=m.max_description_length,
        max_schema_depth=m.max_parameter_depth,
        max_schema_fields=m.max_schema_fields,
        suspicious_patterns=tuple(m.suspicious_instruction_patterns),
    )
    logger.debug("Constructing MCPToolAuditor singleton.")
    return MCPToolAuditor(config=config)


@lru_cache(maxsize=1)
def get_provenance_tracker() -> ProvenanceTracker:
    """
    Return the module-level singleton ProvenanceTracker.

    ProvenanceTracker takes a neo4j.AsyncDriver instance (not raw URI strings).
    The driver is created here and owned for the process lifetime.  It is closed
    during application shutdown via dispose_engine() or a separate lifespan event.

    The tracker holds the connection pool; sharing the singleton instance
    prevents pool exhaustion under concurrent requests.
    """
    from backend.services.provenance_tracker import ProvenanceConfig

    try:
        from neo4j import AsyncGraphDatabase
        settings = get_settings()
        db = settings.db
        neo4j_driver = AsyncGraphDatabase.driver(
            db.neo4j_uri,
            auth=(db.neo4j_user, db.neo4j_password),
            max_connection_lifetime=db.neo4j_max_connection_lifetime,
            max_connection_pool_size=db.neo4j_max_connection_pool_size,
        )
        logger.debug("Constructing ProvenanceTracker singleton with live Neo4j driver.")
        return ProvenanceTracker(
            neo4j_driver=neo4j_driver,
            config=ProvenanceConfig(),
            database=db.neo4j_database,
        )
    except ImportError:
        # neo4j driver not installed (e.g. unit-test environment without Neo4j deps)
        logger.warning("neo4j package not available — ProvenanceTracker will use a null driver.")
        return ProvenanceTracker(
            neo4j_driver=None,
            config=ProvenanceConfig(),
        )


@lru_cache(maxsize=1)
def get_threat_aggregator() -> ThreatAggregator:
    """
    Return the module-level singleton ThreatAggregator.

    The aggregator queries both PostgreSQL (scan records) and Redis
    (real-time counters).  The shared instance reuses both connection pools.
    """
    logger.debug("Constructing ThreatAggregator singleton.")
    return ThreatAggregator()


# ---------------------------------------------------------------------------
# Convenience type aliases for use in route signatures
# ---------------------------------------------------------------------------

CurrentTenant = Annotated[dict[str, Any], Depends(get_current_tenant)]
VectorAnalyzerDep = Annotated[VectorIntegrityAnalyzer, Depends(get_vector_analyzer)]
RAGDetectorDep = Annotated[RAGPoisoningDetector, Depends(get_rag_detector)]
MCPAuditorDep = Annotated[MCPToolAuditor, Depends(get_mcp_auditor)]
ProvTrackerDep = Annotated[ProvenanceTracker, Depends(get_provenance_tracker)]
ThreatAggDep = Annotated[ThreatAggregator, Depends(get_threat_aggregator)]
