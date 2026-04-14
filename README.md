# LLM Data Poisoning Detection PaaS

A multi-tenant, production-grade platform for detecting adversarial data poisoning attacks across the full LLM supply chain: training datasets, RAG retrieval corpora, fine-tuning pipelines, and MCP tool registries.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Detection Engines](#detection-engines)
4. [Quick Start](#quick-start)
5. [API Documentation](#api-documentation)
6. [Configuration Reference](#configuration-reference)
7. [Development Setup](#development-setup)
8. [Testing](#testing)
9. [Deployment](#deployment)

---

## Overview

### Problem

Modern LLM systems are composed of many untrusted inputs: public training corpora, third-party RAG documents, open-source model weights, and externally-defined MCP tool schemas. Any of these surfaces can be poisoned to:

- Induce targeted misclassifications (backdoor triggers)
- Exfiltrate context via MCP tool descriptions containing hidden instructions
- Bias model outputs toward attacker-controlled content
- Contaminate fine-tuning data through supply-chain compromise

### Solution

This PaaS exposes six detection engines behind a unified REST API, protected by multi-tenant API key authentication and per-tier rate limiting:

| Engine | Attack Surface | Method |
|--------|---------------|--------|
| Vector Integrity Analyzer | Embedding stores, RAG indices | Cosine-dispersion outlier detection |
| RAG Poisoning Detector | Retrieval corpora | Perplexity, entropy, homoglyph, hidden-instruction signals |
| MCP Tool Auditor | Tool schema registries | Static analysis for injection patterns, base64 payloads |
| Provenance Tracker | Dataset lineage graphs | Neo4j contamination propagation tracing |
| Telemetry Simulator | Agent telemetry streams | Synthetic attack generation, behavioral anomaly detection, execution tracing |
| Threat Aggregator | All surfaces | Weighted fusion into a single prioritised threat report |

---

## Architecture

```
                          +------------------+
                          |   Browser / CLI  |
                          +--------+---------+
                                   |
                          +--------v---------+
                          |  Next.js 14      |  port 3000
                          |  AI-SPM Dashboard|
                          +--------+---------+
                                   | REST
                          +--------v---------+
                          |  FastAPI Backend |  port 8000
                          |                  |
                          |  +------------+  |
                          |  | Auth Layer |  |  JWT + API keys
                          |  +-----+------+  |
                          |        |          |
                          |  +-----v------+  |
                          |  | API Router |  |  /api/v1/*
                          |  +-----+------+  |
                          |        |          |
                    +-----+--------+----------+-----+
                    |     |        |           |     |
              +-----v--+  |   +---v----+  +---v---+ |
              |Vector  |  |   |RAG     |  |MCP    | |
              |Analyzer|  |   |Detector|  |Auditor| |
              +-----+--+  |   +---+----+  +---+---+ |
                    |     |       |            |     |
                    +-----+-------+------------+     |
                          |                          |
               +----------v-----------+   +----------v--+
               | Threat Aggregator    |   | Provenance  |
               | (weighted fusion)    |   | Tracker     |
               +----------+-----------+   +------+------+
                          |                      |
          +---------------+-------+    +---------+--------+
          |               |       |    |                  |
    +-----v----+   +------v-+  +--v---v+         +-------v------+
    |PostgreSQL|   | Redis  |  | Kafka |         |   Neo4j 5    |
    |    16    |   |   7    |  |KRaft  |         | (Provenance) |
    +----------+   +--------+  +-------+         +--------------+
    Tenants,        Rate        Async              Lineage graph
    Results,        limit       scan               Contamination
    Audit log       cache       pipeline           propagation
```

### Data Flow — Scan Request

```
Client                  API               Kafka           Worker
  |                      |                  |                |
  |-- POST /scans ------->|                  |                |
  |                      |-- Publish(req) -->|                |
  |<-- 202 Accepted ------|                  |                |
  |                      |                  |-- Consume(req)->|
  |                      |                  |                 |-- Run detection
  |                      |                  |                 |-- Write results
  |                      |                  |<-- Publish(res)-|
  |                      |<-- Consume(res) --|                |
  |-- GET /scans/:id ---->|                  |                |
  |<-- 200 {results} -----|                  |                |
```

---

## Detection Engines

### 1. Vector Integrity Analyzer

Detects embedding poisoning in RAG vector stores and training datasets.

**Method:** Computes the cluster centroid of submitted embeddings, then flags vectors whose cosine similarity to the centroid falls below `VECTOR_COSINE_THRESHOLD` (default 0.85). A dispersion z-score is also computed; vectors beyond `VECTOR_DISPERSION_SIGMA` standard deviations (default 3.0) are tagged as outliers.

**Inputs:** Batch of embedding vectors (float arrays), optional clean baseline.

**Outputs:** Verdict (`clean` / `suspicious` / `poisoned`), list of flagged vector indices, centroid drift metric, dispersion score.

**Limitations:** Requires `VECTOR_MIN_BASELINE_SAMPLES` (default 100) clean vectors before emitting a definitive verdict; returns `insufficient_data` otherwise.

---

### 2. RAG Poisoning Detector

Multi-signal scanner for documents in retrieval corpora.

**Signals:**

| Signal | Description | Threshold |
|--------|-------------|-----------|
| Perplexity | Language model perplexity vs. corpus baseline | Z-score > 3.0 |
| Shannon entropy | Character-level entropy vs. baseline | Z-score > 3.0 |
| Homoglyph detection | Unicode lookalike substitution (е vs e) | Any match |
| Hidden instruction | Regex patterns matching prompt-injection syntax | Any match |
| Semantic coherence | Embedding similarity to surrounding context | Cosine < 0.6 |

**Fusion:** Any two signals triggering = `suspicious`; three or more = `poisoned`.

---

### 3. MCP Tool Auditor

Static analysis of Model Context Protocol tool definitions for:

- **Prompt injection:** Descriptions containing `ignore previous instructions`, role-play resets, system prompt overrides
- **Base64 exfiltration payloads:** High ratio of base64-decodable tokens (threshold: 30%)
- **Schema complexity abuse:** Excessively deep nesting (`MCP_MAX_PARAMETER_DEPTH`) or excessive field counts
- **Special token injection:** GPT-style `<|...|>` tokens, Llama `[INST]` tags

**Output:** Verdict per tool, per-finding breakdown with matched pattern details.

---

### 4. Provenance Tracker

Neo4j-backed lineage graph for tracking dataset contamination propagation.

- Nodes: `Dataset`, `Transform`, `Model`, `Deployment`
- Edges: `DERIVED_FROM`, `TRAINED_ON`, `FINE_TUNED_FROM`, `SERVED_BY`, `CONTAMINATED_BY`
- Supports upstream blast-radius queries: given a poisoned dataset, identify all models and deployments in its downstream lineage
- Shortest-path contamination routing between any two nodes

---

### 5. Threat Aggregator

Fuses outputs from all engines into a single ranked threat report per tenant:

- Normalises scores to [0, 1]
- Applies configurable per-engine weights
- Produces a `ThreatReport` with severity level, affected resources, recommended mitigations

---

## Quick Start

### Prerequisites

- Docker >= 24.0
- Docker Compose >= 2.20
- Make

### Steps

```bash
# 1. Clone and enter the project
git clone https://github.com/ai-cowboys/poisoning-detection-paas
cd poisoning-detection-paas

# 2. Configure environment
cp infrastructure/.env.example infrastructure/.env
# Edit infrastructure/.env — set all CHANGE_ME values

# 3. Start the full stack
make dev

# 4. Verify all services are healthy
docker compose -f infrastructure/docker-compose.yml ps

# 5. Open the dashboard
open http://localhost:3000

# 6. Call the API
curl http://localhost:8000/health
```

---

## API Documentation

Interactive docs are served by FastAPI at `http://localhost:8000/docs` (Swagger UI) and `http://localhost:8000/redoc` (ReDoc).

### Authentication

All endpoints (except `/health` and `/auth/token`) require an `Authorization: Bearer <token>` header.

Obtain a token:

```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "your-api-key"}'
```

### Core Endpoints

#### Vector Analysis

```
POST   /api/v1/vectors/analyze
       Submit a batch of embedding vectors for poisoning analysis.

GET    /api/v1/vectors/{scan_id}
       Retrieve analysis results by scan ID.

GET    /api/v1/vectors/
       List recent scans for the authenticated tenant.
```

Request body (`POST /api/v1/vectors/analyze`):

```json
{
  "dataset_id": "my-rag-index-v3",
  "vectors": [[0.12, 0.34, ...], ...],
  "baseline_vectors": [[...], ...],
  "metadata": {"description": "nightly RAG index snapshot"}
}
```

#### RAG Document Scanning

```
POST   /api/v1/rag/scan
       Submit a document or document batch for poisoning signals.

GET    /api/v1/rag/{scan_id}
       Retrieve scan results.
```

#### MCP Tool Auditing

```
POST   /api/v1/tools/audit
       Submit an MCP tool schema definition for static analysis.

GET    /api/v1/tools/{audit_id}
       Retrieve audit results.

GET    /api/v1/tools/
       List recent audits for the authenticated tenant.
```

Request body (`POST /api/v1/tools/audit`):

```json
{
  "tool_name": "send_email",
  "description": "Sends an email to the specified address.",
  "parameters": {
    "type": "object",
    "properties": {
      "to":      {"type": "string"},
      "subject": {"type": "string"},
      "body":    {"type": "string"}
    }
  }
}
```

#### Provenance

```
POST   /api/v1/provenance/nodes
       Register a new provenance node (dataset, transform, model, deployment).

POST   /api/v1/provenance/edges
       Add a lineage edge between two existing nodes.

GET    /api/v1/provenance/{node_id}/lineage
       Retrieve full upstream lineage chain for a node.

GET    /api/v1/provenance/{node_id}/blast-radius
       Identify all downstream nodes reachable from a poisoned node.
```

#### Telemetry Simulator

```
POST   /api/v1/telemetry/simulate
       Generate synthetic telemetry dataset with configurable attack scenarios.

POST   /api/v1/telemetry/analyze
       Analyze provided telemetry data for behavioral anomalies.

POST   /api/v1/telemetry/distribution-shift
       Compare baseline vs current telemetry distributions (KL divergence).

GET    /api/v1/telemetry/scenarios
       List available attack scenarios with descriptions and indicators.
```

#### Dashboard

```
GET    /api/v1/dashboard/summary
       Tenant-scoped threat summary (counts by verdict, engine, severity).

GET    /api/v1/dashboard/timeline
       Recent detection events ordered by severity.
```

#### Health

```
GET    /health
       Liveness probe — returns 200 if the server is running.

GET    /health/ready
       Readiness probe — checks Postgres, Redis, Neo4j connectivity.
```

---

## Configuration Reference

All configuration is loaded from environment variables. See `infrastructure/.env.example` for a fully-annotated template.

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `development` | One of `development`, `staging`, `production` |
| `LOG_LEVEL` | `INFO` | Python logging level |
| `DATABASE_URL` | — | Async PostgreSQL DSN (`postgresql+asyncpg://...`) |
| `REDIS_URL` | — | Redis DSN (`redis://:password@host:port/db`) |
| `NEO4J_URI` | — | Neo4j Bolt URI (`bolt://host:port`) |
| `KAFKA_BOOTSTRAP_SERVERS` | — | Comma-separated broker addresses |
| `JWT_SECRET` | — | HS256 signing secret (min 32 chars) |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `JWT_EXPIRY_MINUTES` | `60` | Access token expiry |
| `VECTOR_COSINE_THRESHOLD` | `0.85` | Cosine similarity floor for outlier flagging |
| `VECTOR_DISPERSION_SIGMA` | `3.0` | Z-score cutoff for dispersion anomalies |
| `MCP_MAX_DESCRIPTION_LENGTH` | `2000` | Character limit on tool descriptions |
| `API_RATE_LIMIT_PER_MINUTE` | `100` | Default rate limit (starter tier) |

Full reference: `backend/config.py` — the Pydantic settings classes are the authoritative source of truth.

---

## Development Setup

### Local (no Docker)

Requirements: Python 3.12+, Node.js 20+, PostgreSQL 16, Redis 7, Neo4j 5, Kafka (KRaft)

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
cp ../infrastructure/.env.example ../.env
uvicorn backend.main:app --reload --port 8000

# Frontend
cd frontend
npm ci
npm run dev
```

### Docker (recommended)

```bash
make dev          # Start full stack
make logs         # Tail all container logs
make shell-api    # Open a shell in the API container
make psql         # Connect to Postgres via psql
```

---

## Testing

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run a specific test file
make test FILE=backend/tests/test_vector_analyzer.py

# Lint
make lint

# Type check
make type-check
```

Test structure:

```
backend/tests/
  unit/
    test_vector_analyzer.py    # Pure-math helpers, no I/O
    test_rag_detector.py
    test_mcp_auditor.py
  integration/
    test_api_vectors.py        # Full HTTP round-trip via httpx
    test_api_auth.py
    test_provenance.py
  conftest.py                  # Fixtures: TestClient, in-memory DB
```

---

## Deployment

### Docker Compose (staging)

```bash
ENVIRONMENT=staging docker compose \
  -f infrastructure/docker-compose.yml \
  up -d --build
```

### Kubernetes (production)

Helm chart is located in `deploy/helm/`. See `deploy/helm/README.md` for values reference.

```bash
helm upgrade --install poisoning-detection deploy/helm/ \
  --namespace poisoning-detection \
  --set image.tag=$(git rev-parse --short HEAD) \
  --set environment=production \
  --values deploy/helm/values-production.yaml
```

### Database migrations

```bash
# Generate a new migration
make migration MSG="add scan_metadata column"

# Apply migrations
make migrate

# Rollback one step
make migrate-down
```
