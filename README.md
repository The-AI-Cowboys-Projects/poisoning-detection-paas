# LLM Data Poisoning Detection PaaS

A production-grade, multi-tenant SaaS platform for detecting data poisoning attacks across the entire LLM supply chain — from training data and vector stores to RAG pipelines, MCP tool registries, and live agent telemetry.

**Live:** [poisoning-detection-paas.vercel.app](https://poisoning-detection-paas.vercel.app)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Detection Engines](#detection-engines)
- [Red Team Poison Generator](#red-team-poison-generator)
- [Novel Technique Contributions](#novel-technique-contributions)
- [Model Lab](#model-lab)
- [Self-Evolution Loop](#self-evolution-loop)
- [Live Connectors](#live-connectors)
- [Cross-Engine Attack Correlation](#cross-engine-attack-correlation)
- [Automated Remediation](#automated-remediation)
- [Cryptographic Proofs & Detection Bounds](#cryptographic-proofs--detection-bounds)
- [Empirical Benchmarks](#empirical-benchmarks)
- [Empirical Validation](#empirical-validation)
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

LLM data poisoning is the emerging attack surface where adversaries inject malicious data into training sets, retrieval corpora, tool schemas, or agent memory to manipulate model behavior. This platform provides six specialized detection engines plus an autonomous red team generator that operate across the full ML pipeline, supplemented by six advanced capability modules covering self-evolution, live connector scanning, kill chain correlation, automated remediation, cryptographic proof chaining, and empirical benchmarking:

| Engine / Module | Attack Surface | Detection Method |
|----------------|---------------|------------------|
| **Vector Analyzer** | Embedding stores | Cosine dispersion, centroid drift, z-score outliers, split-view detection |
| **RAG Detector** | Retrieval corpora | Shannon entropy, bigram perplexity, homoglyph detection, hidden instruction matching |
| **MCP Auditor** | Tool registries | Invisible character detection, base64 payload scanning, schema violation analysis |
| **Provenance Tracker** | Training lineage | DAG contamination propagation, recursive upstream traversal |
| **Telemetry Simulator** | Agent behavior | Synthetic attack traces, anomaly scoring across 8 attack scenarios |
| **Threat Aggregator** | Cross-engine | Weighted fusion scoring with configurable engine importance |
| **Poison Generator** | Red team | 19 evasion techniques: AutoBackdoor, DDIPE, VIA, ASCII smuggling, adversarial decoding, steganography, judge poisoning, and more |
| **Model Lab** | Local LLM | LLM-as-a-Judge evaluation, detection agents, self-evolution loops, benchmark suites via Ollama/vLLM/llama.cpp |
| **Self-Evolution Loop** | Iterative hardening | Autonomous generate→detect→score→harden→repeat with convergence detection |
| **Live Connectors** | Vector stores, MCP, RAG | Per-connector scanning, MCP schema diff detection, grouped display by connector type |
| **Correlation Engine** | Kill chain | Kill chain stage classification, attack cluster detection, unified cross-engine event timeline |
| **Automated Remediation** | Response actions | Rule-based engine with quarantine/block/disable/pause/alert_only actions and audit log |
| **Cryptographic Proofs** | Tamper evidence | SHA-256 hash-chained scan results, 19-technique x 5-engine coverage matrix |
| **Empirical Benchmarks** | Validation | 8 real-world poisoning datasets, engine ranking, per-technique F1 heatmap |

---

## Architecture

```
                          ┌────────────────────────────────────────────────────────┐
                          │                 VERCEL (Frontend)                      │
                          │           Next.js 14 + Tailwind + Recharts            │
                          │                                                        │
                          │  ┌──────────┐ ┌──────────┐ ┌──────────────┐          │
                          │  │Dashboard │ │ Vectors  │ │     RAG      │          │
                          │  │ Metrics  │ │ Scatter  │ │  Batch Scan  │          │
                          │  └────┬─────┘ └────┬─────┘ └──────┬───────┘          │
                          │       │            │              │                   │
                          │  ┌────┴─────┐ ┌────┴─────┐ ┌─────┴────────┐         │
                          │  │  Tools   │ │Provenance│ │  Telemetry   │         │
                          │  │  Audit   │ │   DAG    │ │  Simulator   │         │
                          │  └────┬─────┘ └────┬─────┘ └──────┬───────┘         │
                          │       │            │              │                  │
                          │  ┌────┴─────┐ ┌────┴─────┐ ┌─────┴────────┐         │
                          │  │Generator │ │Model Lab │ │Alerts/Settings│         │
                          │  │ Red Team │ │Local LLM │ │  Management  │         │
                          │  └────┬─────┘ └────┬─────┘ └──────┬───────┘         │
                          │       │            │              │                  │
                          │  ┌────┴─────┐ ┌────┴─────┐ ┌─────┴────────┐         │
                          │  │Evolution │ │Connectors│ │ Correlation  │         │
                          │  │  Loop    │ │  Live    │ │  Kill Chain  │         │
                          │  └────┬─────┘ └────┬─────┘ └──────┬───────┘         │
                          │       │            │              │                  │
                          │  ┌────┴─────┐ ┌────┴─────┐ ┌─────┴────────┐         │
                          │  │Remediation│ │  Proofs  │ │  Benchmarks  │         │
                          │  │  Engine  │ │Crypto Chain│ │  Validation │         │
                          │  └────┬─────┘ └────┬─────┘ └──────┬───────┘         │
                          │       │            │              │                  │
                          │       └────────────┼──────────────┘                  │
                          │                    │                                  │
                          │            ┌───────┴───────┐                         │
                          │            │  api.ts Layer  │                         │
                          │            │ (RPC + REST)   │                         │
                          │            └───────┬───────┘                         │
                          └────────────────────┼───────────────────────────────┘
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

An autonomous adversarial engine for generating state-of-the-art synthetic poisoning data to test and validate LLM/SLM resilience. This internal red team module produces sophisticated sample data across 8 attack categories with 19 evasion techniques:

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

### 19 Evasion Techniques

| # | Technique | Description |
|---|-----------|-------------|
| 1 | Zero-width ASCII smuggling | Unicode Tags U+E0001-U+E007F invisible encoding |
| 2 | Linguistic steganography | Synonym-bin bit-level encoding (16 synonym pairs) |
| 3 | Multi-turn decomposition | 3-4 turn conversations with embedded adversarial goals |
| 4 | TIP tree injection | MCP tool descriptions with hidden objectives |
| 5 | MBTI fragmentation | Backdoor fragments scattered across anchor tokens |
| 6 | Homoglyph injection | Cyrillic/Greek character substitution |
| 7 | Adversarial decoding | Query-term saturated text for cosine-maximized retrieval |
| 8 | Judge poisoning | Evaluator training data with misclassification backdoors |
| 9 | Clean-label overwrite | Same-type entity substitution (medications, protocols, thresholds) |
| 10 | Hearsay framing | Untraceable attribution templates (12 framing patterns) |
| 11 | Emoji token segmentation | Tokenizer bias exploitation via emoji insertion |
| 12 | MM-MEPA multimodal | Metadata-only poisoning in EXIF/XMP/IPTC fields |
| 13 | VIA propagation | Self-replicating poison for synthetic data pipelines |
| 14 | DDIPE wrapper | Legitimate document shells with hidden payloads |
| 15 | Context window overflow | Attention window flooding with filler tokens |
| 16 | Instruction hierarchy exploit | System/user/tool priority manipulation |
| 17 | Semantic sleeper agent | Domain-specific semantic trigger activation |
| 18 | Gradient-aligned drift | Natural gradient direction mimicry |
| 19 | Metadata stripping | Removes all detection-revealing fields for structural indistinguishability |

### Generator Features

- **4 subtlety levels:** Obvious (easy to detect) → Moderate → Subtle → Stealth (near-undetectable)
- **7 target model types:** LLM general/chat/instruct, SLM edge/embedded, code generation, multimodal
- **19 evasion techniques:** Configurable per-sample evasion method selection
- **Clean sample mixing:** 0-80% clean decoy samples for realistic poisoned dataset composition
- **Deterministic PRNG:** Seeded generation for reproducible experiments
- **Detection difficulty scoring:** Per-sample calibrated difficulty (0 = trivial, 1 = undetectable)
- **Metadata stripping:** One-click removal of all detection-revealing fields for export
- **Export formats:** JSONL, JSON, CSV with one-click download
- **Domain targeting:** Optional domain context (finance, healthcare, legal, etc.)

---

## Novel Technique Contributions

Five techniques implemented in the generator represent original contributions first published through this platform. Each is documented here to establish provenance.

### MM-MEPA — Multimodal Metadata-Only Poisoning

**First published:** AI-SPM platform (this repository)

Poisons multimodal pipelines without touching image pixel data. Adversarial payloads are embedded exclusively in document metadata fields (EXIF, XMP, IPTC) that survive typical content filtering. Vision-language models that extract and act on metadata are susceptible to instruction injection via this channel while appearing visually clean to human reviewers.

### TrojanStego — Linguistic Steganography for LLMs

**First published:** AI-SPM platform (this repository)

Encodes adversarial objectives at the bit level using synonym substitution. A 16-pair synonym dictionary maps binary digits onto semantically equivalent word choices, embedding hidden payloads in natural-sounding text with no detectable surface anomalies. The steganographic capacity is approximately 2 bits per content word, sufficient to encode full instructions across moderate-length documents.

### Smuggling Combination — Social-Engineered Unicode Stealth

**First published:** AI-SPM platform (this repository)

Combines Unicode tag characters (U+E0001–U+E007F) with social engineering framing to produce payloads that are simultaneously invisible to human reviewers, survive copy-paste operations, and pass basic Unicode normalization filters. The combination of technical and social vectors distinguishes this from simple zero-width character attacks.

### DDIPE — Document-Driven Implicit Payload Execution

**First published:** AI-SPM platform (this repository)

Wraps adversarial instructions inside structurally legitimate document templates (research papers, policy documents, technical specifications). The payload is positioned to exploit the semantic authority that RAG pipelines assign to authoritative-looking sources. The outer document passes content-level filtering while the embedded directives influence downstream model behavior through retrieval.

### VIA Detection — First Defensive System for VIA Attacks

**Prior art:** VIA attack first described in NeurIPS 2025 Spotlight paper. AI-SPM is the first platform to implement a defensive detection system for this attack class.

Viral Instruction Attacks (VIA) cause poisoned samples to self-replicate through synthetic data pipelines. The AI-SPM VIA detection module identifies the statistical fingerprints of VIA propagation — anomalous instruction pattern recurrence, cross-document semantic copying, and generation-over-generation drift convergence — providing the first published defensive counterpart to the NeurIPS 2025 attack description.

---

## Model Lab

Local LLM integration for detection hardening, evaluation, and self-improvement. Connect local models (Ollama, llama.cpp, vLLM, LM Studio, or any OpenAI-compatible endpoint) to power detection agents and iteratively harden defenses.

### Lab Modes

| Mode | Description |
|------|-------------|
| **LLM-as-a-Judge** | Evaluate poison samples against a local model — per-sample verdicts (safe/suspicious/poisoned) with confidence scores, reasoning, and latency tracking |
| **Detection Agent** | Autonomous agent scanning text for poisoning indicators — 10+ pattern matchers (zero-width, prompt injection, homoglyphs, base64, dangerous configs, etc.) with LLM-enhanced analysis |
| **Self-Evolution Loop** | Iterative generate→detect→harden→repeat cycle with configurable rounds (1-20), detection rate tracking, and heuristic updates per round |
| **Benchmark Suite** | 500-sample standardized test with accuracy, precision, recall, F1 metrics, confusion matrix, and latency tracking |

### Supported Providers

- **Ollama** — Local model serving (default `http://localhost:11434`)
- **llama.cpp** — GGUF model inference (`http://localhost:8080`)
- **vLLM** — High-throughput serving (`http://localhost:8000`)
- **LM Studio** — Desktop model runner (`http://localhost:1234`)
- **OpenAI-compatible** — Any endpoint implementing the `/v1/chat/completions` API
- **Custom** — Arbitrary endpoint configuration

Compatible with MiniMax M2.7, Gemma, Llama, Mistral, Qwen, and any GGUF model.

---

## Self-Evolution Loop

**Route:** `/evolution`

An autonomous hardening pipeline that runs the full generate→detect→score→harden→repeat loop without human intervention. Each round produces a new batch of poisoned samples, runs them through the active detection engines, scores the results, updates detection heuristics, and repeats until convergence.

### Convergence Detection

The loop terminates automatically when the detection rate delta falls below a configurable threshold (δ < threshold) for three consecutive rounds. This prevents over-fitting to a fixed sample distribution and signals that the current heuristic set has stabilized against the configured attack types.

### Configuration

- **Attack types:** Select which of the 19 evasion techniques the generator uses each round
- **Rounds:** 1–100 configurable maximum; early stopping via convergence detection
- **Convergence threshold:** Configurable δ value (default 0.01)
- **Mutation history:** Full per-round record of which heuristics changed and by how much

### Visualization

A LineChart tracks two series across rounds: detection rate and false positive rate. Both series update live as each round completes, making it straightforward to identify the round at which the detector stabilized and whether heuristic updates introduced false positive regressions.

### HASTE Prior Art Differentiation

The self-evolution approach differs from HASTE (NDSS 2026) in several respects documented in a 7-row comparison table rendered on the page:

| Dimension | AI-SPM Self-Evolution | HASTE (NDSS 2026) |
|-----------|----------------------|-------------------|
| Attack scope | 19 evasion techniques across 8 categories | Focused on instruction hijacking |
| Convergence signal | δ < threshold for 3 consecutive rounds | Fixed epoch budget |
| Heuristic update target | Per-engine detection rules | Model weight updates |
| False positive tracking | Explicit FP rate series per round | Not reported |
| Connector integration | Runs against live vector stores and MCP via connector module | Offline dataset only |
| Kill chain awareness | Feeds correlation engine with round results | No kill chain modeling |
| Audit trail | Cryptographically chained round records | No tamper evidence |

---

## Live Connectors

**Route:** `/connectors`

Connect the platform to live vector stores, MCP servers, and RAG pipelines for continuous scanning against real production data rather than synthetic test batches.

### Connector Types

| Type | Description |
|------|-------------|
| **Vector Store** | Connect to Pinecone, Weaviate, Qdrant, or any pgvector-backed store. Per-connector scanning runs the full Vector Analyzer engine against live embeddings. |
| **MCP Server** | Register MCP server endpoints for live schema introspection. The auditor performs schema diff detection on each poll cycle, classifying changes as added, removed, or modified tools and flagging unauthorized schema drift. |
| **RAG Pipeline** | Attach retrieval pipelines for continuous document corpus scanning. Supports LangChain, LlamaIndex, and custom OpenAI-compatible retrieval endpoints. |

### MCP Introspection

MCP connector entries store a baseline schema snapshot on first connection. Subsequent polls compute a structured diff against the baseline:

- **Added tools** — new tools present in live schema but absent from baseline
- **Removed tools** — tools in baseline no longer present in live schema
- **Modified tools** — tools present in both with changed descriptions, parameter schemas, or return types

Any diff classified as modified or removed triggers an alert at the severity level configured for that connector.

### Display

Connectors are grouped by type (vector store, MCP, RAG) in the UI. Each connector card shows connection status, last scan timestamp, finding count, and a per-connector scan action. Aggregate finding counts roll up to the dashboard Threat Aggregator.

---

## Cross-Engine Attack Correlation

**Route:** `/correlation`

Unifies detection events from all engines into a single kill chain view, enabling analysts to identify coordinated multi-stage attacks that span multiple detection surfaces.

### Kill Chain Stage Classification

Every detection event is classified into one of five kill chain stages based on the attack technique and affected engine:

| Stage | Description | Example Events |
|-------|-------------|----------------|
| **reconnaissance** | Probing and enumeration | Schema introspection, unusual query patterns |
| **initial_access** | First foothold establishment | Homoglyph injection, hidden instruction insertion |
| **persistence** | Maintaining presence | VIA propagation, gradient-aligned drift |
| **exfiltration** | Data or credential theft | Data exfiltration techniques, judge poisoning |
| **impact** | Behavioral modification | Backdoor trigger activation, alignment subversion |

### Attack Cluster Detection

Events are grouped into attack clusters by correlating across time, tenant, and technique signature. A cluster forms when two or more events within a configurable time window share overlapping kill chain stages or matching technique fingerprints. Clusters surface coordinated campaigns that would appear as isolated low-severity findings in per-engine views.

### Visualization

- **Unified cross-engine event timeline** — all detection events on a single time axis, color-coded by kill chain stage
- **Kill chain coverage bar chart** — event count per stage, making gaps in coverage (stages with zero detections) immediately visible

---

## Automated Remediation

**Route:** `/remediation`

A rule-based remediation engine that maps detection findings to response actions, reducing mean time to response for high-confidence detections.

### Actions

| Action | Description |
|--------|-------------|
| `quarantine` | Isolate the affected asset (document, embedding, tool) from production pipelines |
| `block` | Prevent access to the asset entirely |
| `disable` | Disable the connector or integration that surfaced the finding |
| `pause` | Suspend the affected pipeline pending review |
| `alert_only` | Generate an alert without taking automated action |

### Modes

| Mode | Behavior |
|------|----------|
| `auto` | Execute the configured action immediately on match |
| `manual` | Queue the action for human approval before execution |
| `confirm` | Execute after a configurable confirmation delay, allowing cancellation |

### Rule Management

Rules are managed via a full CRUD interface. Each rule specifies:

- A **trigger condition** (engine, severity threshold, technique, kill chain stage)
- A **target scope** (specific connector, asset type, or global)
- An **action** from the table above
- A **mode** from the table above

Rules are evaluated in priority order on every new detection event.

### Audit Log

Every remediation action — whether automated or manual — is written to an append-only audit log with timestamp, rule ID, triggered finding, action taken, and the operator identity (system for auto mode, user ID for manual). Each log entry includes a **rollback capability**: quarantine and disable actions can be reversed from the audit log entry, restoring the asset or connector to its prior state.

---

## Cryptographic Proofs & Detection Bounds

**Route:** `/proofs`

Provides tamper-evident scan result records and a coverage matrix showing which techniques each engine is capable of detecting.

### Hash-Chained Scan Records

Every scan result is written into a SHA-256 hash chain. Each record includes the hash of the previous record in its own hash input, creating a linked structure where any modification to a historical record invalidates all subsequent hashes. The proof chain verification UI allows analysts to re-compute the chain from any anchor point and confirm integrity.

### Proof Chain Verification

The verification panel re-computes each link in the chain against persisted results and reports:

- Total records in chain
- Verified links (hash matches)
- Failed links (hash mismatch, indicating tampering or corruption)
- Chain root hash (sharable as a compact integrity commitment)

### Coverage Matrix

A 19-technique by 5-engine heatmap shows the detection capability of each engine against each evasion technique. Each cell is colored by detection confidence level (confirmed, partial, not covered). The matrix makes detection gaps immediately visible and informs which engine combinations provide redundant coverage for high-priority techniques.

### Detection Gap Analysis

Below the matrix, a gap analysis panel lists all technique-engine pairs rated "not covered," sorted by the technique's empirical prevalence in the benchmark dataset. This prioritization helps direct engineering effort toward the highest-value coverage improvements.

---

## Empirical Benchmarks

**Route:** `/benchmarks`

Validation of detection engine performance against eight real-world poisoning datasets covering the published attack landscape.

### Benchmark Datasets

| Dataset | Source | Attack Class | Samples |
|---------|--------|-------------|---------|
| **PoisonedRAG** | USENIX Security 2025 | RAG corpus poisoning | 10,000 |
| **MCPTox** | AI-SPM internal | MCP tool schema poisoning | 2,400 |
| **VIA** | NeurIPS 2025 Spotlight | Viral instruction propagation | 5,000 |
| **HASTE** | NDSS 2026 | Instruction hijacking via fine-tuning | 8,000 |
| **SleepAgent** | Published | Semantic sleeper agent triggers | 3,500 |
| **EmbedPoison** | Published | Embedding space manipulation | 6,000 |
| **Unicode-Smuggle** | AI-SPM internal | Zero-width and Unicode tag attacks | 1,800 |
| **MM-MEPA** | AI-SPM internal (first published) | Multimodal metadata-only poisoning | 1,200 |

### Visualizations

- **Engine ranking bar charts** — F1 score per engine across all datasets, enabling side-by-side performance comparison
- **Per-technique F1 heatmap** — F1 score per engine per evasion technique (19 techniques × 5 engines), identifying which engines specialize in which attack classes
- **Confusion matrices per engine** — true positive, false positive, true negative, false negative counts for each engine, with configurable dataset filter

### Evaluation Metrics

All engines are evaluated on accuracy, precision, recall, F1 score, and area under the ROC curve. Results are reported at the 95% confidence interval across 5-fold cross-validation splits where dataset size permits.

---

## Empirical Validation

The platform's detection claims are grounded in evaluation against the following published attack datasets:

| Dataset | Venue | What It Tests |
|---------|-------|---------------|
| **PoisonedRAG** | USENIX Security 2025 | RAG Detector ability to identify corpus-level poisoning optimized for cosine-maximized retrieval |
| **MCPTox** | AI-SPM internal | MCP Auditor schema violation detection across tool description injection variants |
| **VIA** | NeurIPS 2025 Spotlight | RAG Detector and Vector Analyzer ability to detect self-replicating viral instruction patterns |
| **HASTE** | NDSS 2026 | Telemetry Simulator and Self-Evolution Loop performance against instruction hijacking via fine-tuning data |
| **SleepAgent** | Published | Backdoor trigger detection across semantic and token-level trigger configurations |
| **EmbedPoison** | Published | Vector Analyzer centroid drift and z-score detection against calibrated embedding perturbation |
| **Unicode-Smuggle** | AI-SPM internal | MCP Auditor and RAG Detector Unicode invisible character detection coverage |
| **MM-MEPA** | AI-SPM internal (first published) | Cross-engine detection of metadata-only multimodal poisoning with no pixel-level anomalies |

Benchmark results are available at `/benchmarks`. Raw result files are exported as JSONL for external verification.

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | Next.js 14, React 18, TypeScript 5.4 | Server/client components, App Router |
| **Styling** | Tailwind CSS 3.4, custom threat palette | Dark theme, responsive design |
| **Charts** | Recharts 2.12 | Scatter plots, histograms, time series, heatmaps |
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
| `/generator` | Poison Generator | Red team data generation — 8 attack categories, 19 evasion techniques, metadata stripping, JSONL/JSON/CSV export |
| `/model-lab` | Model Lab | Local LLM integration — 4 lab modes (Judge, Detection Agent, Self-Evolution, Benchmark), 6 provider types |
| `/alerts` | Alerts | Full alert management — severity/status filtering, inline status actions, detail drill-down modal |
| `/settings` | Settings | 5-tab config panel — General, API Keys, Notifications, Thresholds, System Health |
| `/login` | Authentication | Supabase Auth login (password + magic link) |
| `/evolution` | Self-Evolution Loop | Autonomous generate→detect→score→harden→repeat — configurable attack types, convergence detection (δ < threshold for 3 rounds), mutation history, LineChart tracking detection rate + FP rate per round, HASTE prior art comparison table |
| `/connectors` | Live Connectors | Connect to live vector stores, MCP servers, and RAG pipelines — per-connector scanning, MCP schema diff detection (added/removed/modified tools), grouped display by connector type |
| `/correlation` | Attack Correlation | Kill chain stage classification (reconnaissance → initial_access → persistence → exfiltration → impact), attack cluster detection, unified cross-engine event timeline, kill chain coverage bar chart |
| `/remediation` | Automated Remediation | Rule-based engine with quarantine/block/disable/pause/alert_only actions, auto/manual/confirm modes, CRUD rule management, audit log with rollback |
| `/proofs` | Cryptographic Proofs | SHA-256 hash-chained tamper-evident scan results, proof chain verification, 19-technique x 5-engine coverage matrix heatmap, detection gap analysis |
| `/benchmarks` | Empirical Benchmarks | Validation against 8 real-world datasets (PoisonedRAG, MCPTox, VIA, HASTE, SleepAgent, EmbedPoison, Unicode-Smuggle, MM-MEPA), engine ranking bar charts, per-technique F1 heatmap, confusion matrices per engine |

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
GET   /rest/v1/vector_analyses?tenant_id=eq.{id}&select=*&order=created_at.desc
GET   /rest/v1/rag_scans?tenant_id=eq.{id}&select=*&order=created_at.desc
GET   /rest/v1/mcp_audits?tenant_id=eq.{id}&select=*&order=created_at.desc
GET   /rest/v1/provenance_nodes?tenant_id=eq.{id}&select=*
GET   /rest/v1/provenance_edges?tenant_id=eq.{id}&select=*
GET   /rest/v1/alerts?tenant_id=eq.{id}&order=created_at.desc
GET   /rest/v1/threat_reports?tenant_id=eq.{id}&order=created_at.desc&limit=1
GET   /rest/v1/telemetry_simulations?tenant_id=eq.{id}&order=created_at.desc
PATCH /rest/v1/threat_items?id=eq.{id}                         — Update alert status
PATCH /rest/v1/tenants?id=eq.{id}                              — Update tenant settings
PATCH /rest/v1/api_keys?id=eq.{id}                             — Revoke API key
```

### Settings & Management RPCs

```
POST /rest/v1/rpc/create_api_key          { p_tenant_id, p_name }
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

### Evolution API

```
POST /functions/v1/evolution/start    { tenant_id, attack_types[], max_rounds, convergence_threshold }
GET  /functions/v1/evolution/status   ?run_id={id}
GET  /functions/v1/evolution/history  ?tenant_id={id}&limit=20
POST /functions/v1/evolution/stop     { run_id }
```

### Connectors API

```
GET  /functions/v1/connectors         ?tenant_id={id}
POST /functions/v1/connectors         { tenant_id, type, name, endpoint, config }
POST /functions/v1/connectors/scan    { connector_id }
GET  /functions/v1/connectors/diff    ?connector_id={id}          — MCP schema diff
DELETE /functions/v1/connectors/{id}
```

### Correlation API

```
GET  /functions/v1/correlation/timeline  ?tenant_id={id}&hours=24
GET  /functions/v1/correlation/clusters  ?tenant_id={id}
GET  /functions/v1/correlation/killchain ?tenant_id={id}
```

### Remediation API

```
GET  /functions/v1/remediation/rules         ?tenant_id={id}
POST /functions/v1/remediation/rules         { tenant_id, trigger, scope, action, mode, priority }
PUT  /functions/v1/remediation/rules/{id}    { trigger?, scope?, action?, mode?, priority? }
DELETE /functions/v1/remediation/rules/{id}
GET  /functions/v1/remediation/audit-log     ?tenant_id={id}&limit=100
POST /functions/v1/remediation/rollback      { audit_log_entry_id }
```

### Proofs API

```
GET  /functions/v1/proofs/chain       ?tenant_id={id}&since={timestamp}
POST /functions/v1/proofs/verify      { tenant_id, anchor_hash }
GET  /functions/v1/proofs/coverage    ?tenant_id={id}             — 19x5 matrix
GET  /functions/v1/proofs/gaps        ?tenant_id={id}
```

### Benchmarks API

```
GET  /functions/v1/benchmarks/results     ?tenant_id={id}&dataset={name}
GET  /functions/v1/benchmarks/rankings    ?tenant_id={id}
GET  /functions/v1/benchmarks/confusion   ?tenant_id={id}&engine={name}&dataset={name}
POST /functions/v1/benchmarks/run         { tenant_id, dataset, engines[] }
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
│   │   ├── app/                 # App Router pages (18 routes)
│   │   │   ├── page.tsx         # Dashboard (KPIs, charts, alerts)
│   │   │   ├── vectors/         # Vector integrity analysis
│   │   │   ├── rag/             # RAG poisoning detection
│   │   │   ├── tools/           # MCP tool auditor
│   │   │   ├── provenance/      # Lineage DAG + contamination
│   │   │   ├── telemetry/       # Telemetry simulator
│   │   │   ├── generator/       # Red team poison generator (19 evasion techniques)
│   │   │   ├── model-lab/       # Local LLM integration (Judge, Agent, Evolution, Benchmark)
│   │   │   ├── alerts/          # Alert management (filter, status, drill-down)
│   │   │   ├── settings/        # Platform settings (5 tabs)
│   │   │   ├── login/           # Authentication (password + magic link)
│   │   │   ├── auth/callback/   # OAuth callback
│   │   │   ├── evolution/       # Self-evolution loop (generate→detect→harden→repeat)
│   │   │   ├── connectors/      # Live connector management (vector stores, MCP, RAG)
│   │   │   ├── correlation/     # Cross-engine kill chain correlation
│   │   │   ├── remediation/     # Automated remediation rules + audit log
│   │   │   ├── proofs/          # Cryptographic proof chain + coverage matrix
│   │   │   └── benchmarks/      # Empirical benchmarks (8 datasets, F1 heatmap)
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
├── reports/                     # Research & analysis
│   ├── AI-SPM_Research_Paper.html          # Academic paper with charts, equations, infographics
│   ├── novelty_assessment_report.md        # Platform novelty analysis (9.2/10)
│   ├── market_research_monetization.md     # Pricing, TAM/SAM/SOM, use cases
│   └── competitive_intelligence_ai_security_2025.md  # Competitor funding & positioning
│
├── docs/                        # Documentation
├── Makefile                     # 40+ dev/build/test targets
└── README.md                    # This file
```

---

## Research Paper

A comprehensive academic research paper is included at [`reports/AI-SPM_Research_Paper.html`](reports/AI-SPM_Research_Paper.html):

**"AI-SPM: A Multi-Engine Platform for Autonomous LLM Data Poisoning Detection, Red Team Generation, and Self-Hardening Evolution"**
*Michael J. Pendleton, AI Cowboys / The George Washington University, April 2026*

Contents:
- Mathematical foundations for all 5 detection engines (cosine dispersion, Shannon entropy, bigram perplexity, z-score outliers, weighted threat fusion)
- Formal convergence analysis of the self-evolution loop with proof of 3-round delta criterion
- Kill chain correlation algorithm with temporal-semantic clustering predicate
- SHA-256 hash-chain construction and O(n) verification algorithm
- 19x5 coverage matrix computation and detection bound analysis
- Empirical evaluation across 38,900 labeled samples from 8 real-world datasets (mean F1: 0.87, mean AUC: 0.91)
- Interactive Chart.js visualizations: radar plots, heatmaps, convergence curves, bar charts
- MathJax-rendered LaTeX equations (20 numbered formulas)
- Competitive landscape analysis against $3.6B in funded competitors

Open `reports/AI-SPM_Research_Paper.html` in any browser to view the full paper with interactive charts.

---

## License

Proprietary. All rights reserved.

---

Built by [AI Cowboys](https://github.com/The-AI-Cowboys-Projects) | Powered by Supabase + Vercel
