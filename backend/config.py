"""
Application configuration loaded from environment variables via pydantic-settings.

All secrets must be supplied via environment or a .env file — never hardcoded here.
Defaults are safe for local development; override every value in production.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Literal

from pydantic import Field, PostgresDsn, RedisDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DB_", extra="ignore")

    # PostgreSQL (primary relational store — tenants, results, audit log)
    postgres_url: PostgresDsn = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/poisoning_detection",
        description="Async SQLAlchemy DSN for PostgreSQL.",
    )
    postgres_pool_size: int = Field(default=10, ge=2, le=100)
    postgres_max_overflow: int = Field(default=20, ge=0, le=200)
    postgres_pool_timeout: int = Field(default=30, ge=5)
    postgres_pool_recycle: int = Field(default=1800, ge=60)

    # Redis (rate-limit counters, ephemeral caches, scan-status pub/sub)
    redis_url: RedisDsn = Field(
        default="redis://localhost:6379/0",
        description="Redis DSN used for rate limiting and caching.",
    )
    redis_max_connections: int = Field(default=50, ge=5, le=500)
    redis_socket_timeout: float = Field(default=5.0, ge=0.5)
    redis_socket_connect_timeout: float = Field(default=2.0, ge=0.5)

    # Neo4j (provenance lineage graph)
    neo4j_uri: str = Field(
        default="bolt://localhost:7687",
        description="Neo4j Bolt URI for provenance graph queries.",
    )
    neo4j_user: str = Field(default="neo4j")
    neo4j_password: str = Field(default="neo4j_dev_password")
    neo4j_database: str = Field(default="poisoning")
    neo4j_max_connection_lifetime: int = Field(default=3600)
    neo4j_max_connection_pool_size: int = Field(default=50, ge=5)


class KafkaSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KAFKA_", extra="ignore")

    broker_url: str = Field(
        default="localhost:9092",
        description="Comma-separated Kafka broker list.",
    )
    scan_requests_topic: str = Field(default="scan-requests")
    scan_results_topic: str = Field(default="scan-results")
    audit_events_topic: str = Field(default="audit-events")
    consumer_group_id: str = Field(default="poisoning-detection-workers")
    # Retention is a broker-side concern; this drives producer config only.
    producer_acks: Literal["0", "1", "all"] = Field(default="all")
    producer_compression_type: Literal["none", "gzip", "snappy", "lz4", "zstd"] = Field(
        default="snappy"
    )
    producer_max_batch_size: int = Field(default=16384, ge=1024)
    producer_linger_ms: int = Field(default=5, ge=0)
    consumer_max_poll_records: int = Field(default=100, ge=1, le=1000)
    consumer_auto_offset_reset: Literal["earliest", "latest", "none"] = Field(
        default="earliest"
    )
    consumer_enable_auto_commit: bool = Field(default=False)


class JWTSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="JWT_", extra="ignore")

    secret_key: str = Field(
        default="CHANGE_ME_IN_PRODUCTION_USE_AT_LEAST_32_RANDOM_BYTES",
        description="HS256 signing secret — rotate via key-versioning in prod.",
    )
    algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=60, ge=5, le=1440)
    refresh_token_expire_days: int = Field(default=30, ge=1, le=90)

    @field_validator("secret_key")
    @classmethod
    def secret_key_min_length(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("JWT secret_key must be at least 32 characters.")
        return v


class VectorAnalysisSettings(BaseSettings):
    """
    Thresholds governing the cosine-dispersion anomaly detector.

    cosine_similarity_threshold: vectors below this similarity to the centroid
        are flagged as outliers — potential poisoning candidates.
    dispersion_sigma: z-score cutoff; embeddings beyond N std-devs from the
        mean dispersion distribution trigger a 'suspicious' verdict.
    min_baseline_samples: minimum clean-baseline vectors required before the
        detector will emit a 'poisoned' (rather than 'insufficient_data') verdict.
    """

    model_config = SettingsConfigDict(env_prefix="VECTOR_", extra="ignore")

    cosine_similarity_threshold: float = Field(
        default=0.85, ge=0.0, le=1.0,
        description="Flag vectors whose cosine similarity to centroid is below this value.",
    )
    dispersion_sigma: float = Field(
        default=3.0, ge=1.0, le=10.0,
        description="Z-score cutoff for dispersion-based outlier detection.",
    )
    min_baseline_samples: int = Field(
        default=100, ge=10,
        description="Minimum clean-baseline vectors before emitting a definitive verdict.",
    )
    max_vectors_per_submission: int = Field(
        default=50_000, ge=100,
        description="Hard cap on vectors per single API submission.",
    )
    embedding_dimension_min: int = Field(default=64, ge=1)
    embedding_dimension_max: int = Field(default=8192, ge=64)


class MCPAuditSettings(BaseSettings):
    """
    Thresholds for the MCP tool schema auditor.

    max_description_length: descriptions exceeding this length are flagged —
        prompt-injection attacks typically pack instructions into long descriptions.
    base64_pattern_threshold: if the fraction of tokens matching base64 regex
        exceeds this ratio, exfiltration payload injection is suspected.
    """

    model_config = SettingsConfigDict(env_prefix="MCP_", extra="ignore")

    max_description_length: int = Field(
        default=2000, ge=100,
        description="Flag tool descriptions longer than this character count.",
    )
    base64_pattern_threshold: float = Field(
        default=0.3, ge=0.0, le=1.0,
        description="Fraction of base64-looking tokens that triggers an alert.",
    )
    max_parameter_depth: int = Field(
        default=5, ge=1, le=20,
        description="Maximum JSON schema nesting depth before flagging complexity abuse.",
    )
    suspicious_instruction_patterns: list[str] = Field(
        default=[
            r"ignore (previous|all|above|prior) instructions",
            r"system prompt",
            r"you are now",
            r"disregard",
            r"<\|.*\|>",          # special tokens (GPT-style)
            r"\[INST\]",           # Llama instruction tags
            r"### (human|assistant|system):",
        ],
        description="Regex patterns that flag hidden-instruction injection attempts.",
    )
    max_schema_fields: int = Field(
        default=50, ge=5,
        description="Schemas with more fields than this are flagged for review.",
    )


class TenantSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TENANT_", extra="ignore")

    # Tier definitions control rate-limit windows (requests per minute)
    free_tier_rpm: int = Field(default=10, ge=1)
    starter_tier_rpm: int = Field(default=100, ge=1)
    professional_tier_rpm: int = Field(default=1000, ge=1)
    enterprise_tier_rpm: int = Field(default=10_000, ge=1)

    # API key configuration
    api_key_prefix_length: int = Field(default=8)
    api_key_total_length: int = Field(default=48)
    api_key_max_per_tenant: int = Field(default=10, ge=1, le=100)

    # Data isolation
    row_level_security_enabled: bool = Field(default=True)
    cross_tenant_query_allowed: bool = Field(default=False)


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Application metadata ---
    app_name: str = Field(default="LLM Poisoning Detection PaaS")
    app_version: str = Field(default="0.1.0")
    environment: Literal["development", "staging", "production"] = Field(
        default="development"
    )
    debug: bool = Field(default=False)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO"
    )

    # --- CORS ---
    allowed_origins: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:5173"],
        description="Allowed CORS origins. Restrict tightly in production.",
    )
    allowed_hosts: list[str] = Field(
        default=["localhost", "127.0.0.1"],
        description="Trusted Host middleware allowlist.",
    )

    # --- Sub-settings (delegated to specialised classes) ---
    db: DatabaseSettings = Field(default_factory=DatabaseSettings)
    kafka: KafkaSettings = Field(default_factory=KafkaSettings)
    jwt: JWTSettings = Field(default_factory=JWTSettings)
    vector: VectorAnalysisSettings = Field(default_factory=VectorAnalysisSettings)
    mcp: MCPAuditSettings = Field(default_factory=MCPAuditSettings)
    tenant: TenantSettings = Field(default_factory=TenantSettings)

    @field_validator("environment")
    @classmethod
    def warn_debug_in_production(cls, v: str) -> str:
        return v

    def is_production(self) -> bool:
        return self.environment == "production"

    def rate_limit_for_tier(self, tier: str) -> int:
        """Return requests-per-minute ceiling for the given tenant tier."""
        mapping = {
            "free": self.tenant.free_tier_rpm,
            "starter": self.tenant.starter_tier_rpm,
            "professional": self.tenant.professional_tier_rpm,
            "enterprise": self.tenant.enterprise_tier_rpm,
        }
        return mapping.get(tier, self.tenant.free_tier_rpm)


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    """
    Return the singleton AppSettings instance.

    Cached after first call — callers use:
        from backend.config import get_settings
        settings = get_settings()
    """
    settings = AppSettings()
    logger.info(
        "Configuration loaded — environment=%s debug=%s",
        settings.environment,
        settings.debug,
    )
    return settings
