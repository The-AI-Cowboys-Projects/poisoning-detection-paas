"""
Async SQLAlchemy database infrastructure.

Provides:
- AsyncEngine configured from AppSettings
- AsyncSession factory (scoped per-request via get_db dependency)
- Declarative Base for all ORM models
- Connection health-check utility
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, MappedColumn
from sqlalchemy.pool import NullPool

from backend.config import get_settings

logger = logging.getLogger(__name__)

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _build_engine() -> AsyncEngine:
    """
    Construct the AsyncEngine with pool settings from AppSettings.

    NullPool is used for testing environments to avoid cross-test connection
    leakage; production uses QueuePool via the default pool_class.
    """
    settings = get_settings()
    db = settings.db

    connect_args: dict[str, Any] = {
        # asyncpg-specific: statement cache is safe to disable for PgBouncer
        # transaction-mode pooling; harmless otherwise.
        "statement_cache_size": 0,
        "prepared_statement_cache_size": 0,
    }

    engine_kwargs: dict[str, Any] = {
        "echo": settings.debug,
        "echo_pool": settings.debug,
        "connect_args": connect_args,
    }

    if settings.environment == "testing":
        # NullPool avoids asyncpg background task leakage between pytest fixtures
        engine_kwargs["poolclass"] = NullPool
    else:
        engine_kwargs.update(
            {
                "pool_size": db.postgres_pool_size,
                "max_overflow": db.postgres_max_overflow,
                "pool_timeout": db.postgres_pool_timeout,
                "pool_recycle": db.postgres_pool_recycle,
                "pool_pre_ping": True,
            }
        )

    engine = create_async_engine(str(db.postgres_url), **engine_kwargs)

    @event.listens_for(engine.sync_engine, "connect")
    def set_search_path(dbapi_connection: Any, connection_record: Any) -> None:
        """Pin search_path to public so all queries stay within the expected schema."""
        cursor = dbapi_connection.cursor()
        cursor.execute("SET search_path TO public")
        cursor.close()

    logger.info("AsyncEngine created — pool_size=%d", db.postgres_pool_size)
    return engine


def get_engine() -> AsyncEngine:
    """Return the module-level singleton AsyncEngine, creating it on first call."""
    global _engine
    if _engine is None:
        _engine = _build_engine()
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the module-level singleton session factory."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )
    return _session_factory


# Convenience alias used by models/__init__.py
async_session_factory = get_session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields a per-request AsyncSession.

    Usage:
        @router.get("/example")
        async def handler(db: AsyncSession = Depends(get_db)):
            ...

    The session is rolled back on exception and always closed on exit.
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def check_db_connection() -> bool:
    """
    Execute a trivial query to verify database reachability.
    Used by the /health endpoint.
    """
    try:
        engine = get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.error("Database health-check failed: %s", exc)
        return False


async def create_all_tables() -> None:
    """
    Create all tables defined via the ORM Base.
    Called during application startup in non-migration workflows.
    In production, use Alembic instead.
    """
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("All ORM tables created (or already exist).")


async def dispose_engine() -> None:
    """
    Gracefully close all pooled connections.
    Called during application shutdown.
    """
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
        logger.info("AsyncEngine disposed.")


class Base(DeclarativeBase):
    """
    Declarative base shared by all ORM models.

    Provides a consistent __repr__ implementation and enforces the naming
    convention required by Alembic autogenerate.
    """

    def __repr__(self) -> str:
        pk_cols = [
            col.key
            for col in self.__mapper__.columns
            if col.primary_key
        ]
        pk_values = ", ".join(
            f"{k}={getattr(self, k, '?')!r}" for k in pk_cols
        )
        return f"<{self.__class__.__name__} {pk_values}>"
