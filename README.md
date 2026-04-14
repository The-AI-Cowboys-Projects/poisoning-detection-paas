# LLM Data Poisoning Detection PaaS

A production-grade, multi-tenant SaaS platform for detecting data poisoning attacks across the entire LLM supply chain — from training data and vector stores to RAG pipelines, MCP tool registries, and live agent telemetry.

**Live:** [poisoning-detection-paas.vercel.app](https://poisoning-detection-paas.vercel.app)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Detection Engines](#detection-engines)
- [Red Team Poison Generator](#red-team-poison-generator)
- [Tech Stack](#tech-stack)
- [Frontend Pages](#frontend-pages)
- [API Reference](#api-reference)
- [Database Schema](#database-schema)
- [Edge Functions](#edge-functions)
- [Infrastructure](#infrastructure)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [Deployment](#deployment)
- [Project Structure](#project-structure)

---

## Overview

LLM data poisoning is the emerging attack surface where adversaries inject malicious data into training sets, retrieval corpora, tool schemas, or agent memory to manipulate model behavior. This platform provides six specialized detection engines plus an autonomous red team generator that operate across the full ML pipeline:

| Engine | Attack Surface | Detection Method |
|--------|---------------|------------------|
| **Vector Analyzer** | Embedding stores | Cosine dispersion, centroid drift, z-score outliers, split-view detection |
| **RAG Detector** | Retrieval corpora | Shannon entropy, bigram perplexity, homoglyph detection, hidden instruction matching |
| **MCP Auditor** | Tool registries | Invisible character detection, base64 payload scanning, schema violation analysis |
| **Provenance Tracker** | Training lineage | DAG contamination propagation, recursive upstream traversal |
| **Telemetry Simulator** | Agent behavior | Synthetic attack traces, anomaly scoring across 8 attack scenarios |
| **Threat Aggregator** | Cross-engine | Weighted fusion scoring with configurable engine importance |
| **Poison Generator** | Red team | AutoBackdoor, DDIPE, VIA simulation, ASCII smuggling, adversarial decoding |

---

## Architecture

```
                          ┌─────────────────────────────────────────────────┐
                          │              VERCEL (Frontend)                  │
                          │         Next.js 14 + Tailwind + Recharts       │
                          │                                                │
                          │  ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
                          │  │Dashboard │ │ Vectors  │ │     RAG      │   │
                          │  │ Metrics  │ │ Scatter  │ │  Batch Scan  │   │
                          │  └────┬─────┘ └────┬─────┘ └──────┬───────┘   │
                          │       │            │              │            │
                          │  ┌────┴─────┐ ┌────┴─────┐ ┌─────┴────────┐  │
                          │  │  Tools   │ │Provenance│ │  Telemetry   │  │
                          │  │  Audit   │ │   DAG    │ │  Simulator   │  │
                          │  └────┬─────┘ └────┬─────┘ └──────┬───────┘  │
                          │       │            │              │           │
                          │       └────────────┼──────────────┘           │
                          │                    │                          │
                          │            ┌───────┴───────┐                  │
                          │            │  api.ts Layer  │                  │
                          │            │ (RPC + REST)   │                  │
                          │            └───────┬───────┘                  │
                          └────────────────────┼──────────────────────────┘
                                               │
                          ┌────────────────────┼──────────────────────────┐
                          │           SUPABASE │(Backend)                 │
                          │                    │                          │
                          │   ┌────────────────┼────────────────────┐    │
                          │   │         PostgREST API               │    │
                          │   │    /rest/v1/rpc/* + /rest/v1/*      │    │
                          │   └────────────────┬────────────────────┘    │
                          │                    │                          │
                          │   ┌────────────────┼────────────────────┐    │
                          │   │     8 Edge Functions (Deno)         │    │
                          │   │                                     │    │
                          │   │  dashboard-summary  scan-vectors    │    │
                          │   │  scan-rag           audit-tool      │    │
                          │   │  provenance         threat-report   │    │
                          │   │  simulate-telemetry ingest-telemetry│    │
                          │   └────────────────┬────────────────────┘    │
                          │                    │                          │
                          │   ┌────────────────┼────────────────────┐    │
                          │   │       PostgreSQL 16 + RLS           │    │
                          │   │                                     │    │
                          │   │  17 tables · 7 RPC functions        │    │
                          │   │  Row-Level Security per tenant      │    │
                          │   │  Partitioned audit log (monthly)    │    │
                          │   └─────────────────────────────────────┘    │
                          └─────────────────────────────────────────────┘

                          ┌─────────────────────────────────────────────────┐
                          │        DOCKER COMPOSE (Self-Hosted Option)      │
                          │                                                 │
                          │  ┌──────────┐  ┌───────┐  ┌───────┐  ┌──────┐ │
                          │  │PostgreSQL│  │ Redis │  │ Neo4j │  │Kafka │ │
                          │  │   16     │  │   7   │  │   5   │  │KRaft │ │
                          │  └──────────┘  └───────┘  └───────┘  └──────┘ │
                          │                    │                            │
                          │         ┌──────────┴──────────┐                │
                          │         │   FastAPI Backend    │                │
                          │         │   (14,726 LOC)       │                │
                          │         │  SQLAlchemy + asyncpg│                │
                          │         └─────────────────────┘                │
                          └─────────────────────────────────────────────────┘
```

### Data Flow

1. **Frontend** renders server components that call Supabase PostgREST RPCs for read operations
2. **Client components** (forms, simulators) call Supabase Edge Functions for write/compute operations
3. **Edge Functions** perform analysis (entropy, cosine similarity, schema auditing) and persist results
4. **RPC Functions** (`SECURITY DEFINER`) aggregate data across tables for dashboard views
5. **RLS Policies** enforce tenant isolation at the database level

---

## Detection Engines

### Vector Analyzer
Detects poisoned embeddings in vector stores by computing:
- **Cosine dispersion** — flags vectors deviating beyond 0.85 similarity threshold
- **Centroid drift** — measures population-level embedding shift
- **Z-score outliers** — statistical outlier detection (|z| > 2)
- **Split-view detection** — identifies bimodal cluster separation indicating targeted poisoning

### RAG Detector
Scans retrieval-augmented generation corpora for:
- **Shannon entropy anomalies** — detects artificially low (<2.0) or high (>6.0) bits/char
- **Bigram perplexity** — flags documents with unusual language patterns (>600 threshold)
- **Homoglyph attacks** — identifies Cyrillic/Greek character substitutions (a→a, e→e, o→o)
- **Hidden instructions** — 16 regex patterns matching prompt injection (IGNORE PREVIOUS, [SYSTEM], base64 payloads)

### MCP Tool Auditor
Inspects Model Context Protocol tool schemas for:
- **Invisible Unicode** — 12 character types (zero-width joiners, RTL marks, soft hyphens)
- **Base64 payloads** — hidden encoded instructions in descriptions
- **Schema violations** — missing required fields, unsafe defaults
- **Behavioral instructions** — embedded directives ("always", "never", "must")
- **Rug-pull indicators** — suspicious update patterns

### Provenance Tracker
Maintains a directed acyclic graph of dataset/model lineage:
- **Node types:** dataset, model, transform, deployment, output
- **Edge types:** DERIVED_FROM, TRAINED_ON, FINE_TUNED_FROM, SERVED_BY, CONTAMINATED_BY
- **Contamination propagation** — recursive upstream/downstream traversal
- **Generation depth indicator** — visual depth-based contamination heatmap

### Telemetry Simulator
Generates synthetic agent behavior traces across 8 attack scenarios:
- `clean` — baseline normal behavior
- `prompt_injection` — injected system prompt overrides
- `reward_hacking` — exploited reward signals
- `memory_poisoning` — corrupted agent memory writes
- `prompt_drift` — gradual prompt degradation
- `retrieval_manipulation` — poisoned RAG retrieval results
- `tool_hijack` — compromised tool call chains
- `multi_agent_collusion` — coordinated multi-agent attacks
- `slow_burn` — low-and-slow poisoning over time

### Threat Aggregator
Unified cross-engine threat scoring:
- **Engine weights:** Vector (0.30), RAG (0.25), MCP (0.25), Provenance (0.20)
- **Severity mapping:** >=0.8 critical, >=0.55 high, >=0.3 medium, <0.3 low
- **Trend analysis** and actionable remediation recommendations

---

## Red Team Poison Generator

An autonomous adversarial engine for generating state-of-the-art synthetic poisoning data to test and validate LLM/SLM resilience. This internal red team module produces sophisticated sample data across 8 attack categories:

| Category | Technique | Description |
|----------|-----------|-------------|
| **Training Data Poisoning** | AutoBackdoor agent pipelines | Malicious instruction-response pairs with gradient-aligned payloads and epoch-targeted drift |
| **Prompt Injection** | Direct override, context switching | Inputs designed to override system prompts via delimiter attacks, encoded payloads, and role-play |
| **RAG Document Poisoning** | DDIPE, adversarial decoding | Documents with hidden instructions optimized for cosine similarity maximization during retrieval |
| **Embedding Manipulation** | Perturbation attacks, cluster drift | Vectors crafted to cluster near targets, misleading similarity search with calibrated cosine drift |
| **Backdoor Triggers** | Semantic/token triggers | Sleeper agent samples with hidden activation phrases and configurable activation rates |
| **Instruction Hijacking** | VIA simulation, gradual drift | Fine-tuning data that progressively shifts instruction-following alignment over training epochs |
| **Data Exfiltration** | Role-play, encoding tricks | Inputs that cause models to leak system prompts, training data, or internal configurations |
| **Alignment Subversion** | ASCII smuggling, Unicode tags | Subtle samples that erode safety guardrails using invisible Unicode characters and boundary erosion |

### Generator Features

- **4 subtlety levels:** Obvious (easy to detect) → Moderate → Subtle → Stealth (near-undetectable)
- **7 target model types:** LLM general/chat/instruct, SLM edge/embedded, code generation, multimodal
- **Clean sample mixing:** 0-80% clean decoy samples for realistic poisoned dataset composition
- **Deterministic PRNG:** Seeded generation for reproducible experiments
- **Detection difficulty scoring:** Per-sample calibrated difficulty (0 = trivial, 1 = undetectable)
- **Export formats:** JSONL, JSON, CSV with one-click download
- **Domain targeting:** Optional domain context (finance, healthcare, legal, etc.)

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | Next.js 14, React 18, TypeScript 5.4 | Server/client components, App Router |
| **Styling** | Tailwind CSS 3.4, custom threat palette | Dark theme, responsive design |
| **Charts** | Recharts 2.12 | Scatter plots, histograms, time series |
| **Icons** | Lucide React | Consistent iconography |
| **Auth** | Supabase Auth, @supabase/ssr | Cookie-based server-side auth |
| **Database** | PostgreSQL 16 (Supabase) | Multi-tenant with RLS |
| **Edge Functions** | Deno (Supabase Functions) | Serverless analysis compute |
| **Backend (alt)** | FastAPI, SQLAlchemy, asyncpg | Self-hosted REST API option |
| **Graph DB** | Neo4j 5 | Provenance lineage (self-hosted) |
| **Cache** | Redis 7 | Rate limiting, pub/sub (self-hosted) |
| **Streaming** | Kafka (KRaft) | Async scan pipeline (self-hosted) |
| **Deploy** | Vercel | Frontend CDN + edge |
| **Containers** | Docker Compose | Full-stack self-hosted option |

---

## Frontend Pages

| Route | Page | Description |
|-------|------|-------------|
| `/` | Dashboard | KPI cards, threat timeline chart, threat breakdown pie, recent alerts table |
| `/vectors` | Vector Integrity | 2D scatter plot, anomaly histogram, cosine baseline, paginated results table |
| `/rag` | RAG Poisoning | Cosine deviation histogram, hidden instruction findings, batch upload form, results table |
| `/tools` | MCP Auditor | Tool audit cards with findings, known threat pattern database |
| `/provenance` | Provenance Tracker | Interactive DAG visualization, contamination panel, depth indicator, dataset registration form |
| `/telemetry` | Telemetry | 8-scenario simulator panel, attack trace visualization, anomaly detection |
| `/generator` | Poison Generator | Red team synthetic data generation — 8 attack categories, 4 subtlety levels, JSONL/JSON/CSV export |
| `/login` | Authentication | Supabase Auth login form |

---

## API Reference

### Dashboard RPCs (PostgREST)

```
POST /rest/v1/rpc/get_dashboard_summary     { p_tenant_id }
POST /rest/v1/rpc/get_dashboard_timeline     { p_tenant_id, p_days }
POST /rest/v1/rpc/get_threat_breakdown       { p_tenant_id }
POST /rest/v1/rpc/get_recent_alerts          { p_tenant_id, p_limit }
```

### Telemetry RPCs

```
POST /rest/v1/rpc/get_telemetry_summary      { p_tenant_id, p_hours }
POST /rest/v1/rpc/get_drift_status           { p_tenant_id, p_application_id }
POST /rest/v1/rpc/get_poisoning_timeline     { p_tenant_id, p_days }
```

### Table Queries (PostgREST)

```
GET /rest/v1/vector_analyses?tenant_id=eq.{id}&select=*&order=created_at.desc
GET /rest/v1/rag_scans?tenant_id=eq.{id}&select=*&order=created_at.desc
GET /rest/v1/mcp_audits?tenant_id=eq.{id}&select=*&order=created_at.desc
GET /rest/v1/provenance_nodes?tenant_id=eq.{id}&select=*
GET /rest/v1/provenance_edges?tenant_id=eq.{id}&select=*
GET /rest/v1/alerts?tenant_id=eq.{id}&order=created_at.desc
GET /rest/v1/threat_reports?tenant_id=eq.{id}&order=created_at.desc&limit=1
GET /rest/v1/telemetry_simulations?tenant_id=eq.{id}&order=created_at.desc
```

### Edge Functions

```
POST /functions/v1/scan-vectors       { dataset_id, vectors[][], baseline_vectors? }
POST /functions/v1/scan-rag           { document_id, content, source? }
POST /functions/v1/audit-tool         { tool_name, tool_version, schema, description? }
POST /functions/v1/provenance         { node_type, label, attributes? }
POST /functions/v1/simulate-telemetry { scenario, num_traces, num_agents, poison_ratio }
POST /functions/v1/ingest-telemetry   { type, application_id, records[] }
GET  /functions/v1/dashboard-summary  ?days=7
GET  /functions/v1/threat-report
```

---

## Database Schema

### Core Tables (17)

```
tenants              — Multi-tenant isolation
api_keys             — Hashed API key management
scans                — Master scan records (6 engines)
vector_analyses      — Vector poisoning detection results
rag_scans            — RAG document scan results
mcp_audits           — MCP tool audit results
provenance_nodes     — Lineage graph nodes (5 types)
provenance_edges     — Lineage graph edges (5 types)
threat_reports       — Unified threat summaries
alerts               — Severity-sorted alert records
audit_log            — Monthly-partitioned audit trail
telemetry_simulations— Attack scenario simulations
ml_telemetry         — ML inference telemetry
llm_telemetry        — LLM inference telemetry
ground_truth         — Validation outcomes
drift_baselines      — Reference distributions for PSI
detection_policies   — Governance rules and thresholds
```

### Security Model

- **Row-Level Security (RLS)** on all tables — tenant isolation enforced at DB level
- **SECURITY DEFINER** RPC functions for cross-tenant aggregations
- **Anon read policies** scoped to demo tenant for public preview
- **Partitioned audit log** — monthly partitions for performance
- **API key hashing** — keys stored as SHA-256 hashes, never plaintext

---

## Edge Functions

| Function | Method | Purpose |
|----------|--------|---------|
| `dashboard-summary` | GET | Parallel RPC aggregation (4 RPCs) |
| `scan-vectors` | POST | Vector cosine/centroid/z-score analysis |
| `scan-rag` | POST | Entropy + perplexity + homoglyph + hidden instruction detection |
| `audit-tool` | POST | Unicode + base64 + schema + behavioral analysis |
| `provenance` | POST/GET | DAG node/edge management |
| `simulate-telemetry` | POST | Seeded PRNG synthetic trace generation |
| `ingest-telemetry` | POST | Bulk ML/LLM telemetry ingestion |
| `threat-report` | GET | Weighted multi-engine threat fusion |

---

## Infrastructure

### Docker Compose (Self-Hosted)

```yaml
services:
  postgres:   PostgreSQL 16 — Primary data store
  redis:      Redis 7 — Rate limiting, caching (256 MB LRU)
  neo4j:      Neo4j 5 — Provenance graph database
  kafka:      Kafka (KRaft) — Async scan pipeline
  api:        FastAPI — REST backend (port 8000)
  frontend:   Next.js — Dashboard (port 3000)
```

Network: isolated bridge `172.28.0.0/16` with healthchecks on all services.

### Supabase (Managed)

- **Project:** `zrnpxfztyzlhyapnbrbc`
- **Edge Functions:** 8 deployed Deno functions
- **Database:** PostgreSQL 16 with 17 tables, 7 RPCs, RLS policies
- **Auth:** Supabase Auth with cookie-based SSR

---

## Getting Started

### Prerequisites

- Node.js 20+
- npm or yarn
- Supabase account (or Docker for self-hosted)

### Quick Start (Supabase)

```bash
# Clone
git clone https://github.com/iaintheardofu/platform.git
cd platform/frontend

# Install dependencies
npm install

# Configure environment
cp .env.local.example .env.local
# Edit .env.local with your Supabase project URL and anon key

# Run development server
npm run dev
```

### Quick Start (Docker)

```bash
# Clone
git clone https://github.com/iaintheardofu/platform.git
cd platform

# Start all services
make dev

# Or use Docker Compose directly
cd infrastructure && docker compose up -d

# Run database migrations
make migrate

# Seed test data
cd scripts && npm install && npm run seed
```

### Makefile Commands

```bash
make dev              # Start all Docker services
make stop             # Stop all services
make psql             # PostgreSQL shell
make redis-cli        # Redis shell
make cypher-shell     # Neo4j shell
make migrate          # Run database migrations
make test             # Run backend tests
make lint             # Lint all code
make build            # Build production images
make ci               # Full CI pipeline (lint + type-check + test)
```

---

## Environment Variables

### Frontend (`frontend/.env.local`)

```bash
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...your-anon-key
NEXT_PUBLIC_API_URL=http://localhost:8000  # Optional: self-hosted backend
```

### Supabase Edge Functions

```bash
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=eyJ...
SUPABASE_SERVICE_ROLE_KEY=eyJ...  # For elevated operations
```

### Docker (.env)

See `infrastructure/.env.example` for the full list (50+ variables).

---

## Deployment

### Vercel (Frontend)

The frontend deploys automatically from the `main` branch:

```bash
# Manual deploy
cd frontend
npx vercel --prod
```

Set environment variables in Vercel project settings:
- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_ANON_KEY`

### Supabase (Backend)

```bash
# Deploy edge functions
supabase functions deploy scan-vectors
supabase functions deploy scan-rag
supabase functions deploy audit-tool
supabase functions deploy provenance
supabase functions deploy dashboard-summary
supabase functions deploy threat-report
supabase functions deploy simulate-telemetry
supabase functions deploy ingest-telemetry

# Apply migrations
supabase db push
```

---

## Project Structure

```
poisoning-detection-paas/
├── frontend/                    # Next.js 14 dashboard
│   ├── src/
│   │   ├── app/                 # App Router pages
│   │   │   ├── page.tsx         # Dashboard (KPIs, charts, alerts)
│   │   │   ├── vectors/         # Vector integrity analysis
│   │   │   ├── rag/             # RAG poisoning detection
│   │   │   ├── tools/           # MCP tool auditor
│   │   │   ├── provenance/      # Lineage DAG + contamination
│   │   │   ├── telemetry/       # Telemetry simulator
│   │   │   ├── generator/       # Red team synthetic poison generator
│   │   │   ├── login/           # Authentication
│   │   │   └── auth/callback/   # OAuth callback
│   │   ├── components/          # Shared UI (Sidebar, MetricCard, etc.)
│   │   └── lib/                 # API client, Supabase clients, types
│   ├── public/                  # Static assets
│   ├── tailwind.config.ts       # Threat severity color palette
│   ├── next.config.mjs          # Security headers, image optimization
│   └── vercel.json              # Vercel deployment config
│
├── backend/                     # FastAPI REST API (self-hosted option)
│   ├── main.py                  # App entry, middleware, lifespan
│   ├── config.py                # Pydantic settings
│   ├── api/                     # Route aggregation, dependencies
│   ├── routers/                 # Endpoint handlers (8 routers)
│   ├── services/                # Business logic (6 analyzers)
│   ├── models/                  # SQLAlchemy ORM + Pydantic schemas
│   ├── middleware/              # Auth middleware
│   └── tests/                   # pytest test suite
│
├── supabase/                    # Supabase configuration
│   ├── functions/               # 8 Edge Functions (Deno/TypeScript)
│   │   ├── dashboard-summary/   # Parallel RPC aggregation
│   │   ├── scan-vectors/        # Vector analysis engine
│   │   ├── scan-rag/            # RAG poisoning detector
│   │   ├── audit-tool/          # MCP schema auditor
│   │   ├── provenance/          # Lineage graph operations
│   │   ├── simulate-telemetry/  # Synthetic trace generator
│   │   ├── ingest-telemetry/    # Bulk telemetry ingestion
│   │   ├── threat-report/       # Weighted threat fusion
│   │   └── _shared/             # Supabase client + tenant auth
│   └── migrations/              # PostgreSQL schema + seed data
│       ├── 00001_initial_schema.sql  # Core tables, RPCs, RLS
│       └── 00002_telemetry_tables.sql # Telemetry, drift, policies
│
├── infrastructure/              # Docker deployment
│   ├── docker-compose.yml       # Full stack (6 services)
│   ├── Dockerfile.backend       # Multi-stage Python build
│   ├── Dockerfile.frontend      # Multi-stage Node.js build
│   ├── init-db.sql              # PostgreSQL init script
│   ├── neo4j-init.cypher        # Neo4j graph init
│   └── .env.example             # Environment template
│
├── scripts/                     # Utilities
│   └── seed-database.ts         # Database seeding script
│
├── docs/                        # Documentation
├── Makefile                     # 40+ dev/build/test targets
└── README.md                    # This file
```

---

## License

Proprietary. All rights reserved.

---

Built by [AI Cowboys](https://github.com/The-AI-Cowboys-Projects) | Powered by Supabase + Vercel
