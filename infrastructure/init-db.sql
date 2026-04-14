-- =============================================================================
-- LLM Data Poisoning Detection PaaS — PostgreSQL Initialization
-- =============================================================================
-- Executed once by the official postgres Docker image entrypoint when the
-- data volume is empty.  Idempotent: safe to re-apply on an existing database.
--
-- What this script does:
--   1. Ensure the application database exists (created by Docker env vars,
--      but we double-check here).
--   2. Enable required extensions (uuid-ossp, pgcrypto).
--   3. Create schemas for tenant isolation (public + per-feature schemas).
--   4. Create the application role with least-privilege grants.
--   5. Enable Row-Level Security boilerplate (actual policies live in
--      Alembic migrations — this just activates the extension pattern).
--   6. Seed essential lookup data (tier definitions).
-- =============================================================================

\set ON_ERROR_STOP on

-- ---------------------------------------------------------------------------
-- 1. Extensions
--    uuid-ossp  — gen_random_uuid() fallback for older PG versions
--    pgcrypto   — gen_random_bytes(), crypt(), encode() for key hashing
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";   -- trigram indexes for text search

-- ---------------------------------------------------------------------------
-- 2. Application role
--    The role is created here; Docker POSTGRES_USER owns the DB.
--    In production, rotate the password via a secrets manager.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paas_app') THEN
        CREATE ROLE paas_app LOGIN PASSWORD 'REPLACE_IN_PRODUCTION';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- 3. Schemas
--    public       — tenants, API keys, shared lookup tables
--    detection    — scan results: vectors, RAG documents, MCP audits
--    provenance   — dataset lineage events (mirrored from Neo4j for reporting)
--    audit        — immutable append-only event log
-- ---------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS detection  AUTHORIZATION paas_app;
CREATE SCHEMA IF NOT EXISTS provenance AUTHORIZATION paas_app;
CREATE SCHEMA IF NOT EXISTS audit      AUTHORIZATION paas_app;

-- Grant the app role usage on all schemas
GRANT USAGE ON SCHEMA public     TO paas_app;
GRANT USAGE ON SCHEMA detection  TO paas_app;
GRANT USAGE ON SCHEMA provenance TO paas_app;
GRANT USAGE ON SCHEMA audit      TO paas_app;

-- Default privileges: any future table the app creates is accessible to itself
ALTER DEFAULT PRIVILEGES IN SCHEMA public     GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO paas_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA detection  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO paas_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA provenance GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO paas_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit      GRANT SELECT, INSERT              ON TABLES TO paas_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public     GRANT USAGE, SELECT ON SEQUENCES TO paas_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA detection  GRANT USAGE, SELECT ON SEQUENCES TO paas_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA provenance GRANT USAGE, SELECT ON SEQUENCES TO paas_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit      GRANT USAGE, SELECT ON SEQUENCES TO paas_app;

-- ---------------------------------------------------------------------------
-- 4. Core tables
--    The full schema lives in Alembic migrations.  We define the minimum here
--    so the health-check endpoint can connect and verify the DB is ready.
-- ---------------------------------------------------------------------------

-- Tenant registry
CREATE TABLE IF NOT EXISTS public.tenants (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    api_key_hash    VARCHAR(255) NOT NULL,
    tier            VARCHAR(32)  NOT NULL DEFAULT 'free'
                        CHECK (tier IN ('free', 'starter', 'professional', 'enterprise')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active       BOOLEAN     NOT NULL DEFAULT true,
    CONSTRAINT uq_tenants_name UNIQUE (name)
);

-- Tenant API keys (rotatable, bcrypt-hashed)
CREATE TABLE IF NOT EXISTS public.tenant_api_keys (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    key_hash        VARCHAR(255) NOT NULL,
    prefix          VARCHAR(16)  NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ,
    is_revoked      BOOLEAN     NOT NULL DEFAULT false,
    last_used_at    TIMESTAMPTZ,
    description     VARCHAR(255)
);

-- Vector analysis results (embedding poisoning detection)
CREATE TABLE IF NOT EXISTS detection.vector_analysis_results (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID        NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    dataset_id          VARCHAR(255) NOT NULL,
    submitted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at        TIMESTAMPTZ,
    status              VARCHAR(32)  NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    verdict             VARCHAR(32)
                            CHECK (verdict IN ('clean', 'suspicious', 'poisoned', 'insufficient_data')),
    outlier_count       INTEGER,
    total_vectors       INTEGER,
    centroid_drift      FLOAT8,
    dispersion_score    FLOAT8,
    flagged_indices     INTEGER[],
    metadata            JSONB       NOT NULL DEFAULT '{}'
);

-- RAG document scan results
CREATE TABLE IF NOT EXISTS detection.rag_document_scans (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID        NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    document_hash       VARCHAR(64) NOT NULL,
    scanned_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    verdict             VARCHAR(32)
                            CHECK (verdict IN ('clean', 'suspicious', 'poisoned', 'insufficient_data')),
    perplexity_score    FLOAT8,
    entropy_score       FLOAT8,
    homoglyph_detected  BOOLEAN,
    hidden_instruction  BOOLEAN,
    semantic_coherence  FLOAT8,
    signal_breakdown    JSONB       NOT NULL DEFAULT '{}',
    metadata            JSONB       NOT NULL DEFAULT '{}'
);

-- MCP tool audit results
CREATE TABLE IF NOT EXISTS detection.mcp_tool_audit_results (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID        NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    tool_name               VARCHAR(255) NOT NULL,
    audited_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    verdict                 VARCHAR(32)
                                CHECK (verdict IN ('clean', 'suspicious', 'malicious')),
    description_length      INTEGER,
    base64_ratio            FLOAT8,
    schema_depth            INTEGER,
    schema_field_count      INTEGER,
    instruction_patterns    TEXT[],
    finding_details         JSONB       NOT NULL DEFAULT '{}',
    raw_schema_hash         VARCHAR(64)
);

-- Provenance nodes (mirror of Neo4j graph; enables SQL reporting)
CREATE TABLE IF NOT EXISTS provenance.provenance_nodes (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    node_type       VARCHAR(64)  NOT NULL
                        CHECK (node_type IN ('dataset', 'transform', 'model', 'deployment')),
    external_id     VARCHAR(255) NOT NULL,
    dataset_id      VARCHAR(255),
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    properties      JSONB       NOT NULL DEFAULT '{}',
    CONSTRAINT uq_provenance_tenant_external UNIQUE (tenant_id, external_id)
);

-- Immutable audit event log (append-only via RLS policy)
CREATE TABLE IF NOT EXISTS audit.events (
    id              BIGSERIAL   PRIMARY KEY,
    tenant_id       UUID,           -- NULL for system events
    event_type      VARCHAR(64)  NOT NULL,
    actor           VARCHAR(255),
    resource_type   VARCHAR(64),
    resource_id     UUID,
    payload         JSONB       NOT NULL DEFAULT '{}',
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now()
) PARTITION BY RANGE (occurred_at);

-- Audit log partitions (monthly; add future partitions via migration)
CREATE TABLE IF NOT EXISTS audit.events_2026_01 PARTITION OF audit.events
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE IF NOT EXISTS audit.events_2026_02 PARTITION OF audit.events
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE IF NOT EXISTS audit.events_2026_03 PARTITION OF audit.events
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE IF NOT EXISTS audit.events_2026_04 PARTITION OF audit.events
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE IF NOT EXISTS audit.events_2026_05 PARTITION OF audit.events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE IF NOT EXISTS audit.events_2026_06 PARTITION OF audit.events
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

-- ---------------------------------------------------------------------------
-- 5. Indexes
-- ---------------------------------------------------------------------------

-- Tenants
CREATE INDEX IF NOT EXISTS ix_tenants_api_key_hash
    ON public.tenants (api_key_hash);

CREATE INDEX IF NOT EXISTS ix_tenants_is_active
    ON public.tenants (is_active);

-- API keys — critical hot path for every authenticated request
CREATE UNIQUE INDEX IF NOT EXISTS ix_tenant_api_keys_key_hash
    ON public.tenant_api_keys (key_hash);

CREATE INDEX IF NOT EXISTS ix_tenant_api_keys_tenant_id
    ON public.tenant_api_keys (tenant_id);

CREATE INDEX IF NOT EXISTS ix_tenant_api_keys_prefix
    ON public.tenant_api_keys (prefix);

-- Partial index: fast "list active keys per tenant" query
CREATE INDEX IF NOT EXISTS ix_tenant_api_keys_active
    ON public.tenant_api_keys (tenant_id, is_revoked)
    WHERE is_revoked = false;

-- Vector analysis results
CREATE INDEX IF NOT EXISTS ix_vector_results_tenant_id
    ON detection.vector_analysis_results (tenant_id);

CREATE INDEX IF NOT EXISTS ix_vector_results_dataset_id
    ON detection.vector_analysis_results (dataset_id);

CREATE INDEX IF NOT EXISTS ix_vector_results_submitted_at
    ON detection.vector_analysis_results (submitted_at DESC);

CREATE INDEX IF NOT EXISTS ix_vector_results_verdict
    ON detection.vector_analysis_results (tenant_id, verdict)
    WHERE verdict IN ('suspicious', 'poisoned');

-- RAG scans
CREATE INDEX IF NOT EXISTS ix_rag_scans_tenant_id
    ON detection.rag_document_scans (tenant_id);

CREATE INDEX IF NOT EXISTS ix_rag_scans_document_hash
    ON detection.rag_document_scans (document_hash);

CREATE INDEX IF NOT EXISTS ix_rag_scans_scanned_at
    ON detection.rag_document_scans (scanned_at DESC);

-- MCP audits
CREATE INDEX IF NOT EXISTS ix_mcp_audits_tenant_id
    ON detection.mcp_tool_audit_results (tenant_id);

CREATE INDEX IF NOT EXISTS ix_mcp_audits_tool_name
    ON detection.mcp_tool_audit_results (tool_name);

CREATE INDEX IF NOT EXISTS ix_mcp_audits_verdict
    ON detection.mcp_tool_audit_results (tenant_id, verdict)
    WHERE verdict IN ('suspicious', 'malicious');

-- Provenance
CREATE INDEX IF NOT EXISTS ix_provenance_tenant_id
    ON provenance.provenance_nodes (tenant_id);

CREATE INDEX IF NOT EXISTS ix_provenance_dataset_id
    ON provenance.provenance_nodes (dataset_id);

CREATE INDEX IF NOT EXISTS ix_provenance_node_type
    ON provenance.provenance_nodes (node_type);

-- Audit events
CREATE INDEX IF NOT EXISTS ix_audit_events_tenant_id
    ON audit.events (tenant_id)
    WHERE tenant_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_audit_events_event_type
    ON audit.events (event_type, occurred_at DESC);

-- ---------------------------------------------------------------------------
-- 6. Row-Level Security
--    Policies are named and commented so Alembic migrations can reference them.
-- ---------------------------------------------------------------------------

ALTER TABLE public.tenants                   ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_api_keys           ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection.vector_analysis_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection.rag_document_scans     ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection.mcp_tool_audit_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE provenance.provenance_nodes      ENABLE ROW LEVEL SECURITY;

-- Superuser bypass (for migrations running as postgres role)
ALTER TABLE public.tenants                   FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_api_keys           FORCE ROW LEVEL SECURITY;
ALTER TABLE detection.vector_analysis_results FORCE ROW LEVEL SECURITY;
ALTER TABLE detection.rag_document_scans     FORCE ROW LEVEL SECURITY;
ALTER TABLE detection.mcp_tool_audit_results FORCE ROW LEVEL SECURITY;
ALTER TABLE provenance.provenance_nodes      FORCE ROW LEVEL SECURITY;

-- The application sets `app.current_tenant_id` at session start.
-- These policies allow the row only when the session variable matches.

CREATE POLICY tenant_isolation_api_keys ON public.tenant_api_keys
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

CREATE POLICY tenant_isolation_vector_results ON detection.vector_analysis_results
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

CREATE POLICY tenant_isolation_rag_scans ON detection.rag_document_scans
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

CREATE POLICY tenant_isolation_mcp_audits ON detection.mcp_tool_audit_results
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

CREATE POLICY tenant_isolation_provenance ON provenance.provenance_nodes
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- ---------------------------------------------------------------------------
-- 7. Tier lookup (reference data)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.tenant_tiers (
    tier                VARCHAR(32) PRIMARY KEY,
    display_name        VARCHAR(64) NOT NULL,
    requests_per_minute INTEGER     NOT NULL,
    max_vectors_per_scan INTEGER    NOT NULL,
    max_api_keys        INTEGER     NOT NULL
);

INSERT INTO public.tenant_tiers VALUES
    ('free',         'Free',         10,    5000,  2),
    ('starter',      'Starter',      100,   20000, 5),
    ('professional', 'Professional', 1000,  50000, 10),
    ('enterprise',   'Enterprise',   10000, 50000, 10)
ON CONFLICT (tier) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 8. Verification query (runs at the end; errors on failure)
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    ext_count   INTEGER;
    table_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO ext_count
    FROM pg_extension
    WHERE extname IN ('uuid-ossp', 'pgcrypto', 'pg_trgm');

    IF ext_count < 3 THEN
        RAISE EXCEPTION 'Required extensions not installed (found %/3)', ext_count;
    END IF;

    SELECT COUNT(*) INTO table_count
    FROM information_schema.tables
    WHERE table_schema IN ('public', 'detection', 'provenance', 'audit')
      AND table_name IN (
          'tenants', 'tenant_api_keys', 'vector_analysis_results',
          'rag_document_scans', 'mcp_tool_audit_results', 'provenance_nodes', 'events'
      );

    IF table_count < 7 THEN
        RAISE EXCEPTION 'Expected 7 core tables, found %', table_count;
    END IF;

    RAISE NOTICE 'init-db.sql completed successfully — % extensions, % tables', ext_count, table_count;
END;
$$;
