-- =============================================================================
-- Migration: 00002_telemetry_tables.sql
-- Synthetic Data Platform Integration — Telemetry Ingestion Tables
-- PostgreSQL 17 / Supabase
-- =============================================================================
-- Adds five new tables for ingesting rich telemetry from an external synthetic
-- data platform, plus three RPC functions for operational queries.
--
-- New tables:
--   1. ml_telemetry         — ML model inference records with drift/anomaly signals
--   2. llm_telemetry        — LLM inference records with poisoning/hallucination risk
--   3. ground_truth         — Actual outcomes for validating ml/llm predictions
--   4. drift_baselines      — Training-time reference distributions per feature
--   5. detection_policies   — Governance rules and thresholds per application
--
-- New functions:
--   get_telemetry_summary    — Aggregate stats across both telemetry tables (p_hours window)
--   get_drift_status         — Per-feature PSI comparison against stored baselines
--   get_poisoning_timeline   — Daily poisoning risk and anomaly aggregates (p_days window)
-- =============================================================================


-- ---------------------------------------------------------------------------
-- 1. ml_telemetry
--    One row per ML model inference call. Captures the full inference context:
--    inputs, outputs, resource utilization, and any anomaly/drift signals that
--    were detected at ingest time by the synthetic data platform.
-- ---------------------------------------------------------------------------
create table public.ml_telemetry (
  id                    uuid        primary key default gen_random_uuid(),
  tenant_id             uuid        not null references public.tenants(id) on delete cascade,
  scan_id               uuid        references public.scans(id) on delete set null,
  application_id        text        not null,
  model_name            text        not null,
  model_version         text,

  -- Inference identity
  inference_id          uuid        not null default gen_random_uuid(),

  -- Prediction outputs
  prediction_class      text,
  prediction_score      float,
  confidence_score      float,

  -- Raw payloads (stored as-is from the platform)
  raw_input_payload     jsonb,
  feature_vector        float8[],
  raw_output_payload    jsonb,

  -- Explainability
  feature_importances   jsonb,                          -- SHAP values: {"feature_name": weight, ...}

  -- Business decision
  decision              text,
  decision_threshold    float,
  rules_applied         text[],

  -- Resource utilization at inference time
  cpu_utilization_pct   float,
  gpu_utilization_pct   float,
  memory_used_mb        float,

  -- Latency breakdown (ms)
  total_latency_ms      float,
  queue_wait_ms         float,
  model_inference_ms    float,

  -- Anomaly and drift signals
  is_anomalous          boolean     not null default false,
  anomaly_score         float       not null default 0,
  drift_detected        boolean     not null default false,
  drift_type            text,

  created_at            timestamptz not null default now()
);

-- Chronological fan-out per tenant (primary time-series scan pattern)
create index idx_ml_telemetry_tenant_time
  on public.ml_telemetry(tenant_id, created_at desc);

-- Application-scoped filtering (per-app dashboards / policy lookups)
create index idx_ml_telemetry_tenant_app
  on public.ml_telemetry(tenant_id, application_id);

-- Sparse index: anomaly triage queue — only rows that actually fired
create index idx_ml_telemetry_anomalous
  on public.ml_telemetry(tenant_id, created_at desc)
  where is_anomalous = true;


-- ---------------------------------------------------------------------------
-- 2. llm_telemetry
--    One row per LLM inference call. Extends the ML telemetry concept with
--    token economics, quality scores, embedding vectors for semantic drift
--    detection, and a first-class poisoning_risk signal.
-- ---------------------------------------------------------------------------
create table public.llm_telemetry (
  id                      uuid        primary key default gen_random_uuid(),
  tenant_id               uuid        not null references public.tenants(id) on delete cascade,
  scan_id                 uuid        references public.scans(id) on delete set null,
  application_id          text        not null,
  model_name              text        not null,
  model_version           text,

  -- Prompt content
  system_prompt           text,
  user_prompt             text        not null,
  response_text           text,
  finish_reason           text,

  -- Token counts and economics
  input_tokens            int,
  output_tokens           int,
  context_tokens          int,
  tokens_per_second       float,
  estimated_cost_usd      float,

  -- Quality scores (0–1 scale, higher = better unless named otherwise)
  coherence_score         float,
  relevance_score         float,
  fluency_score           float,
  toxicity_score          float,        -- higher = more toxic
  hallucination_risk      float,        -- higher = more risk
  factual_consistency     float,
  completeness_score      float,

  -- Semantic embedding vectors (used for drift and similarity calculations)
  input_embedding         float8[],
  output_embedding        float8[],
  semantic_similarity     float,

  -- Resource utilization
  gpu_utilization_pct     float,
  gpu_memory_used_gb      float,

  -- Latency breakdown (ms)
  total_latency_ms        float,
  time_to_first_token_ms  float,

  -- Poisoning and anomaly signals
  is_anomalous            boolean     not null default false,
  anomaly_type            text,
  poisoning_risk          float       not null default 0,
  flags                   text[],

  created_at              timestamptz not null default now()
);

-- Chronological fan-out per tenant
create index idx_llm_telemetry_tenant_time
  on public.llm_telemetry(tenant_id, created_at desc);

-- Application-scoped filtering
create index idx_llm_telemetry_tenant_app
  on public.llm_telemetry(tenant_id, application_id);

-- Sparse index: high-risk poisoning candidates (threshold 0.3 is configurable
-- but 0.3 is a reasonable operational default for alert triage)
create index idx_llm_telemetry_poisoning_risk
  on public.llm_telemetry(tenant_id, poisoning_risk desc)
  where poisoning_risk > 0.3;

-- Sparse index: hallucination investigation queue
create index idx_llm_telemetry_hallucination_risk
  on public.llm_telemetry(tenant_id, hallucination_risk desc)
  where hallucination_risk > 0.5;


-- ---------------------------------------------------------------------------
-- 3. ground_truth
--    Actual outcomes returned after an inference event resolves. Joins back to
--    either ml_telemetry or llm_telemetry via (telemetry_type, telemetry_id).
--    Used to compute precision/recall, calibration curves, and model drift
--    in the validation pipeline.
--
--    NOTE: telemetry_id is intentionally untyped (no FK) because it references
--    one of two tables depending on telemetry_type. The application layer is
--    responsible for maintaining referential consistency.
-- ---------------------------------------------------------------------------
create table public.ground_truth (
  id                  uuid        primary key default gen_random_uuid(),
  tenant_id           uuid        not null references public.tenants(id) on delete cascade,

  -- Polymorphic reference to ml_telemetry or llm_telemetry
  telemetry_id        uuid,
  telemetry_type      text        not null check (telemetry_type in ('ml', 'llm')),
  inference_id        uuid,

  -- Prediction that was made at inference time (denormalized for query convenience)
  predicted_class     text,
  predicted_score     float,

  -- What actually happened
  actual_class        text,
  actual_value        float,
  prediction_correct  boolean,

  -- Label provenance
  outcome_timestamp   timestamptz,
  label_source        text,           -- e.g. 'human_reviewer', 'automated_pipeline', 'user_feedback'
  label_confidence    float,

  -- Arbitrary additional context
  metadata            jsonb,

  created_at          timestamptz not null default now()
);

-- Primary lookup: find all outcomes for a given telemetry record
create index idx_ground_truth_telemetry
  on public.ground_truth(tenant_id, telemetry_type, telemetry_id);

-- Validation pipeline scan: chronological sweep per tenant
create index idx_ground_truth_tenant_time
  on public.ground_truth(tenant_id, created_at desc);


-- ---------------------------------------------------------------------------
-- 4. drift_baselines
--    One row per (tenant, application, feature) representing the reference
--    distribution captured at training time. The drift detection service
--    computes PSI against these values for incoming inference batches.
--
--    Only one active baseline is allowed per (tenant, application, feature)
--    at any time — enforced by the partial unique index below.
-- ---------------------------------------------------------------------------
create table public.drift_baselines (
  id                   uuid        primary key default gen_random_uuid(),
  tenant_id            uuid        not null references public.tenants(id) on delete cascade,
  application_id       text        not null,
  feature_name         text        not null,

  -- Summary statistics from the training distribution
  mean_value           float,
  std_dev              float,
  min_value            float,
  max_value            float,

  -- Quantile reference points
  p25                  float,
  p50                  float,
  p75                  float,
  p95                  float,
  p99                  float,

  -- Distribution shape metadata
  distribution_type    text        not null default 'normal',
  distribution_params  jsonb,      -- extra params (e.g. shape/scale for beta, lambda for poisson)

  -- PSI thresholds for alerting
  psi_warning          float       not null default 0.1,
  psi_critical         float       not null default 0.2,

  is_active            boolean     not null default true,
  created_at           timestamptz not null default now(),
  updated_at           timestamptz not null default now()
);

-- Enforce a single active baseline per feature per application per tenant.
-- When replacing a baseline, set is_active = false on the old row first.
create unique index idx_drift_baselines_active_unique
  on public.drift_baselines(tenant_id, application_id, feature_name)
  where is_active = true;

-- Bulk retrieval of all active baselines for an application
create index idx_drift_baselines_app
  on public.drift_baselines(tenant_id, application_id)
  where is_active = true;

-- updated_at maintenance
create trigger trg_drift_baselines_updated_at
  before update on public.drift_baselines
  for each row execute function public.set_updated_at();


-- ---------------------------------------------------------------------------
-- 5. detection_policies
--    Governance rules and threshold configuration per tenant (and optionally
--    scoped to a specific application). The JSONB columns allow flexible
--    schema evolution without additional migrations as policy needs change.
-- ---------------------------------------------------------------------------
create table public.detection_policies (
  id                  uuid        primary key default gen_random_uuid(),
  tenant_id           uuid        not null references public.tenants(id) on delete cascade,
  application_id      text,           -- null = tenant-wide default policy

  -- Policy identity
  policy_type         text        not null,   -- e.g. 'poisoning', 'drift', 'hallucination', 'cost'
  name                text        not null,

  -- Configuration blobs (kept as JSONB for forward compatibility)
  decision_thresholds jsonb,      -- {"poisoning_risk": 0.7, "anomaly_score": 0.8, ...}
  business_rules      jsonb,      -- structured rule tree evaluated by the policy engine
  risk_tolerances     jsonb,      -- {"false_positive_rate": 0.05, "false_negative_rate": 0.01}
  drift_config        jsonb,      -- {"features": [...], "window_hours": 24, "min_samples": 100}

  version             int         not null default 1,
  is_active           boolean     not null default true,

  created_at          timestamptz not null default now(),
  updated_at          timestamptz not null default now()
);

-- Active policy lookup (hot path: called on every scored inference)
create index idx_detection_policies_tenant_app
  on public.detection_policies(tenant_id, application_id)
  where is_active = true;

-- updated_at maintenance
create trigger trg_detection_policies_updated_at
  before update on public.detection_policies
  for each row execute function public.set_updated_at();


-- ===========================================================================
-- Row-Level Security
-- ===========================================================================

alter table public.ml_telemetry enable row level security;
create policy "Tenant isolation" on public.ml_telemetry
  for all using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

alter table public.llm_telemetry enable row level security;
create policy "Tenant isolation" on public.llm_telemetry
  for all using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

alter table public.ground_truth enable row level security;
create policy "Tenant isolation" on public.ground_truth
  for all using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

alter table public.drift_baselines enable row level security;
create policy "Tenant isolation" on public.drift_baselines
  for all using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

alter table public.detection_policies enable row level security;
create policy "Tenant isolation" on public.detection_policies
  for all using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);


-- ===========================================================================
-- RPC Functions
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- get_telemetry_summary
--
-- Returns a single JSON object with aggregate stats across both telemetry
-- tables for the given tenant over the last p_hours hours.
--
-- Usage:
--   select get_telemetry_summary('tenant-uuid', 24);
-- ---------------------------------------------------------------------------
create or replace function public.get_telemetry_summary(
  p_tenant_id uuid,
  p_hours     int default 24
)
returns jsonb
language plpgsql
stable
security definer
as $$
declare
  v_since              timestamptz := now() - (p_hours || ' hours')::interval;
  v_total_ml           bigint;
  v_total_llm          bigint;
  v_ml_anomaly_count   bigint;
  v_llm_anomaly_count  bigint;
  v_avg_ml_latency     numeric;
  v_avg_llm_latency    numeric;
  v_poisoning_risk_avg numeric;
  v_hallucination_avg  numeric;
  v_drift_count        bigint;
begin
  -- ML inference counts
  select
    count(*),
    count(*) filter (where is_anomalous = true),
    round(avg(total_latency_ms)::numeric, 2),
    count(*) filter (where drift_detected = true)
  into v_total_ml, v_ml_anomaly_count, v_avg_ml_latency, v_drift_count
  from public.ml_telemetry
  where tenant_id = p_tenant_id
    and created_at >= v_since;

  -- LLM inference counts
  select
    count(*),
    count(*) filter (where is_anomalous = true),
    round(avg(total_latency_ms)::numeric, 2),
    round(avg(poisoning_risk)::numeric, 4),
    round(avg(hallucination_risk)::numeric, 4)
  into v_total_llm, v_llm_anomaly_count, v_avg_llm_latency,
       v_poisoning_risk_avg, v_hallucination_avg
  from public.llm_telemetry
  where tenant_id = p_tenant_id
    and created_at >= v_since;

  return jsonb_build_object(
    'window_hours',          p_hours,
    'since',                 v_since,
    'total_ml_inferences',   coalesce(v_total_ml, 0),
    'total_llm_inferences',  coalesce(v_total_llm, 0),
    'ml_anomaly_count',      coalesce(v_ml_anomaly_count, 0),
    'llm_anomaly_count',     coalesce(v_llm_anomaly_count, 0),
    'avg_ml_latency_ms',     coalesce(v_avg_ml_latency, 0),
    'avg_llm_latency_ms',    coalesce(v_avg_llm_latency, 0),
    'poisoning_risk_avg',    coalesce(v_poisoning_risk_avg, 0),
    'hallucination_risk_avg',coalesce(v_hallucination_avg, 0),
    'drift_detected_count',  coalesce(v_drift_count, 0)
  );
end;
$$;


-- ---------------------------------------------------------------------------
-- get_drift_status
--
-- For every active baseline belonging to (p_tenant_id, p_application_id),
-- computes a naive PSI approximation from the last 500 ML telemetry rows
-- (using anomaly_score as a proxy scalar when the feature is not directly
-- addressable in the unstructured feature_importances JSONB).
--
-- For each feature the function returns:
--   feature_name      — baseline feature key
--   baseline_mean     — stored reference mean
--   baseline_std      — stored reference std dev
--   current_mean      — observed mean over recent inferences
--   current_std       — observed std dev over recent inferences
--   sample_count      — number of recent rows used
--   psi_estimate      — simplified PSI estimate (|current_mean - baseline_mean| / baseline_std)
--   status            — 'ok' | 'warning' | 'critical'
--
-- NOTE: This is a lightweight PSI proxy. For production-grade PSI, push
-- binned distributions from the platform and compare histograms directly.
--
-- Usage:
--   select get_drift_status('tenant-uuid', 'fraud-scorer-v2');
-- ---------------------------------------------------------------------------
create or replace function public.get_drift_status(
  p_tenant_id      uuid,
  p_application_id text
)
returns jsonb
language plpgsql
stable
security definer
as $$
declare
  v_result jsonb;
begin
  select coalesce(jsonb_agg(row_to_json(t)::jsonb order by t.psi_estimate desc), '[]'::jsonb)
  into v_result
  from (
    select
      b.feature_name,
      b.mean_value                                        as baseline_mean,
      b.std_dev                                           as baseline_std,
      b.psi_warning,
      b.psi_critical,

      -- Pull recent observations for this feature from the importances JSONB.
      -- Falls back to anomaly_score as a scalar proxy when the key is absent.
      round(avg(
        coalesce(
          (m.feature_importances ->> b.feature_name)::float,
          m.anomaly_score
        )
      )::numeric, 6)                                      as current_mean,

      round(stddev(
        coalesce(
          (m.feature_importances ->> b.feature_name)::float,
          m.anomaly_score
        )
      )::numeric, 6)                                      as current_std,

      count(m.id)                                         as sample_count,

      -- Simplified PSI proxy: normalised mean shift
      -- A proper PSI requires histogram bins; use this for fast triage only.
      case
        when b.std_dev is null or b.std_dev = 0 then null
        else round(
          abs(
            avg(
              coalesce(
                (m.feature_importances ->> b.feature_name)::float,
                m.anomaly_score
              )
            ) - b.mean_value
          )::numeric / b.std_dev, 4
        )
      end                                                 as psi_estimate,

      case
        when b.std_dev is null or b.std_dev = 0 then 'unknown'
        when abs(
          avg(
            coalesce(
              (m.feature_importances ->> b.feature_name)::float,
              m.anomaly_score
            )
          ) - b.mean_value
        ) / b.std_dev >= b.psi_critical                   then 'critical'
        when abs(
          avg(
            coalesce(
              (m.feature_importances ->> b.feature_name)::float,
              m.anomaly_score
            )
          ) - b.mean_value
        ) / b.std_dev >= b.psi_warning                    then 'warning'
        else 'ok'
      end                                                 as status

    from public.drift_baselines b
    -- Only pull the most recent 500 inferences to keep this query cheap.
    -- The caller can increase this by re-implementing with a window parameter.
    left join lateral (
      select id, feature_importances, anomaly_score
      from public.ml_telemetry
      where tenant_id = p_tenant_id
        and application_id = p_application_id
      order by created_at desc
      limit 500
    ) m on true

    where b.tenant_id      = p_tenant_id
      and b.application_id = p_application_id
      and b.is_active      = true

    group by
      b.feature_name,
      b.mean_value,
      b.std_dev,
      b.psi_warning,
      b.psi_critical
  ) t;

  return v_result;
end;
$$;


-- ---------------------------------------------------------------------------
-- get_poisoning_timeline
--
-- Returns one row per calendar day for the last p_days days, aggregating
-- poisoning risk and anomaly activity across llm_telemetry.
--
-- Each row contains:
--   date                — calendar date (UTC)
--   llm_inferences      — total LLM inferences that day
--   avg_poisoning_risk  — mean poisoning_risk score
--   max_poisoning_risk  — peak poisoning_risk score (useful for spike detection)
--   high_risk_count     — inferences where poisoning_risk > 0.5
--   anomaly_count       — inferences flagged is_anomalous
--   poisoned_verdict    — inferences linked to a scan with verdict = 'poisoned'
--
-- Usage:
--   select get_poisoning_timeline('tenant-uuid', 7);
-- ---------------------------------------------------------------------------
create or replace function public.get_poisoning_timeline(
  p_tenant_id uuid,
  p_days      int default 7
)
returns jsonb
language plpgsql
stable
security definer
as $$
declare
  v_result jsonb;
begin
  select coalesce(jsonb_agg(row_to_json(t)::jsonb order by t.date), '[]'::jsonb)
  into v_result
  from (
    select
      d::date                                                    as date,

      coalesce(s.llm_inferences, 0)                             as llm_inferences,
      coalesce(round(s.avg_poisoning_risk::numeric, 4), 0)      as avg_poisoning_risk,
      coalesce(round(s.max_poisoning_risk::numeric, 4), 0)      as max_poisoning_risk,
      coalesce(s.high_risk_count, 0)                            as high_risk_count,
      coalesce(s.anomaly_count, 0)                              as anomaly_count,
      coalesce(s.poisoned_verdict, 0)                           as poisoned_verdict

    from generate_series(
      (now() - (p_days || ' days')::interval)::date,
      now()::date,
      '1 day'
    ) d

    left join (
      select
        lt.created_at::date                                          as inference_date,
        count(lt.id)                                                 as llm_inferences,
        avg(lt.poisoning_risk)                                       as avg_poisoning_risk,
        max(lt.poisoning_risk)                                       as max_poisoning_risk,
        count(*) filter (where lt.poisoning_risk > 0.5)             as high_risk_count,
        count(*) filter (where lt.is_anomalous = true)              as anomaly_count,
        count(*) filter (
          where sc.verdict = 'poisoned'
        )                                                            as poisoned_verdict
      from public.llm_telemetry lt
      left join public.scans sc
        on sc.id = lt.scan_id
       and sc.tenant_id = lt.tenant_id
      where lt.tenant_id = p_tenant_id
        and lt.created_at >= now() - (p_days || ' days')::interval
      group by lt.created_at::date
    ) s on s.inference_date = d::date
  ) t;

  return v_result;
end;
$$;
