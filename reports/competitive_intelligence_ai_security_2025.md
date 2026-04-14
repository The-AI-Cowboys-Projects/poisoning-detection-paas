# Competitive Intelligence Report: AI Security & LLM Data Poisoning Detection
**Prepared for:** Poisoning Detection PaaS — AI Cowboys
**Date:** April 14, 2026
**Classification:** Internal Strategic Use Only
**Analyst:** Competitive Intelligence Division

---

## Executive Summary

The AI security market has undergone a violent consolidation cycle in 2024–2025. Of the 15 competitors profiled here, **7 have been acquired** by large strategic buyers (Cisco, Palo Alto Networks, SentinelOne, F5, Zscaler, CrowdStrike, Snyk), and **2 more are on M&A watch lists**. Total cybersecurity M&A reached a record $102 billion in 2025. AI security funding jumped from $2.16B in 2024 to $6.34B in 2025 — a 193% increase in a single year.

**The single most important strategic finding:** Data poisoning detection — the specific threat vector this platform addresses — remains critically underserved. Of all 15 competitors surveyed, fewer than 4 treat data poisoning as a primary product focus. Most treat it as a secondary feature or do not address it at all. This represents a clear white space.

**Key strategic implications:**
- The consolidation wave has reduced the number of pure-play AI security independents. The acquirers (Palo Alto, Cisco, CrowdStrike, SentinelOne) now own broad platforms but lack deep poisoning-detection specificity.
- Gartner predicted by 2028 that LLM observability investments will represent 50% of secure GenAI deployments, up from 15% today. The regulatory window (EU AI Act Aug 2026 high-risk enforcement, NIST AI RMF adoption) creates immediate enterprise demand.
- The funding gap to compete at Series A is approximately $15M–$30M. To reach the scale of remaining independents (Noma, Lasso, Cranium), $30M–$60M total is the relevant benchmark.

---

## Part I: Competitor Profiles

### 1. Noma Security
**Status:** Independent (fastest-growing in category)
**Founded:** 2023
**Headquarters:** Tel Aviv, Israel (with North America and EMEA GTM)

**Funding:**
- Seed + Series A (Oct 2024): $32M — Ballistic Ventures, Glilot Capital
- Series B (July 2025): $100M — Evolution Equity Partners (lead), Ballistic, Glilot
- **Total raised: $132M**
- ARR growth: 1,300%+ in one year
- Named 2025 Gartner Cool Vendor in AI Security

**Product Features:**
- AI Asset Discovery: scans environments to inventory all AI models, agents, MCP servers, data sources
- Agentic Risk Map: visual blast-radius mapping showing what each agent can touch
- Runtime Protection: real-time policy enforcement blocking unauthorized actions before execution
- Red Teaming: automated prompt injection, jailbreak, and adversarial validation
- Policy governance for agent permissions and data access controls

**Known Customers:** Dozens of enterprise customers across financial services, life sciences, retail, and big tech. One Fortune 100 financial institution CIO explicitly cited Noma as a prerequisite for enterprise agent deployment.

**Pricing:** Not publicly disclosed; enterprise custom pricing model.

**Positioning:** "Agentic AI security" — the fastest pivot to agent-specific threats. Primary differentiator is the risk map for autonomous agent blast radius.

**Data Poisoning Coverage:** Partial. Runtime protection addresses some poisoning vectors at inference time, but no stated focus on training-time or supply chain poisoning detection.

**Threat Level to Poisoning PaaS:** Medium. Noma is the best-capitalized independent but focuses primarily on agent runtime, not the training pipeline or RAG poisoning layer where this platform plays.

---

### 2. Cisco AI Defense (formerly Robust Intelligence)
**Status:** Acquired by Cisco (Oct 2024)
**Acquisition Price:** ~$400M (estimated; Cisco did not disclose)

**Background:**
- Robust Intelligence was founded by Prof. Yaron Singer (Harvard) and team
- Pioneer of the "AI Firewall" concept and algorithmic red teaming
- Acquisition closed October 2024

**Product Capabilities (now integrated into Cisco AI Defense):**
- AI Firewall: sits inline, inspects all AI traffic
- Algorithmic red teaming: automated adversarial testing
- Protection scope: prompt injection, data poisoning, jailbreaking, unintentional model outcomes
- Integrates natively into Cisco's security and networking product suite (Cisco Security Cloud)
- Provides visibility into all customer AI traffic across Cisco's existing data flows

**Target Market:** Large enterprises already on the Cisco security platform; "land and expand" via existing Cisco relationships.

**Pricing:** Bundled into Cisco Security Cloud platform pricing; not independently priced. Enterprise contracts in the $100K–$500K+ annual range are typical for Cisco security bundles.

**Data Poisoning Coverage:** YES — explicitly listed as a protected threat vector. This is one of the most direct competitors on the poisoning dimension.

**Threat Level to Poisoning PaaS:** High. Cisco's distribution reach is enormous, but the poisoning feature is bundled inside a $400M platform play. Pure-play poisoning-focused buyers who are not Cisco shops will not be served.

---

### 3. HiddenLayer
**Status:** Independent
**Founded:** 2022
**Headquarters:** Austin, TX

**Funding:**
- Seed (July 2022): $6M
- Series A (2023): $50M — M12 (Microsoft Ventures), Moore Strategic Ventures, Booz Allen Ventures, IBM Ventures, Capital One Ventures, Ten Eleven Ventures
- **Total raised: $56M**

**Government Contracts:**
- AFWERX STTR Phase II contract: $1.8M — Department of the Air Force AI Detection & Response
- Selected for Missile Defense Agency SHIELD IDIQ (ceiling value $151B — multi-awardee vehicle)
- Active federal contracts with DoD and U.S. Intelligence Community (USIC)
- Listed on AWS Marketplace for the U.S. Intelligence Community (ICMP)
- Selected as the sole scanning tool in Microsoft's AI Studio catalog (via M12 partnership)

**Known Customers:** Microsoft (via M12 strategic partnership), Booz Allen Hamilton (via investor relationship), Capital One (via investor relationship), DoD agencies.

**Product Scope:**
- AI Detection and Response (AIDR) — primary product category
- Model scanning for adversarial inputs, backdoors, and malicious artifacts
- Supply chain security for ML models
- Integration with Azure AI Studio as embedded scanner

**Pricing:** Not publicly disclosed; enterprise custom pricing.

**Data Poisoning Coverage:** YES — model scanning explicitly covers backdoor implantation and adversarial data injection, which are core poisoning attack vectors.

**Threat Level to Poisoning PaaS:** High on government segment. HiddenLayer has the deepest DoD penetration of any pure-play AI security vendor. On commercial side, less of a direct threat given their Microsoft-centric positioning.

---

### 4. Protect AI
**Status:** ACQUIRED by Palo Alto Networks (April 28, 2025)
**Acquisition Price:** $500M+
**Founded:** 2022
**Headquarters:** Seattle, WA

**Pre-Acquisition Funding:**
- Series A: $35M
- Series B (Aug 2024): $60M — Evolution Equity Partners, Samsung, Salesforce Ventures, 01 Advisors
- **Total raised: $108.5M**

**Guardian Product Features:**
- Scans 35+ model formats (PyTorch, TensorFlow, ONNX, Keras, Pickle, GGUF, Safetensors, etc.)
- Detects deserialization/serialization attacks — malicious code embedded in model files
- Architectural backdoor detection
- CI/CD pipeline integration for shift-left scanning
- LLM Guard (acquired from Laiyer AI): open-source runtime input/output guardrails
- Recon: automated LLM red teaming

**Government Presence:** Partnership with Leidos announced April 2025 to secure AI across U.S. Government systems (announced days before the Palo Alto acquisition closed).

**Integration into Palo Alto Prisma AIRS:** Protect AI is now the cornerstone of Palo Alto's Prisma AI Runtime Security (AIRS) platform — one of the most comprehensive enterprise AI security offerings on the market.

**Pricing (post-acquisition):** Folded into Palo Alto platform pricing; enterprise contracts typically $200K–$2M+ annually for Palo Alto security bundles.

**Data Poisoning Coverage:** YES — model serialization attack detection is a direct proxy for supply chain poisoning. Guardian is one of the most technically sophisticated tools in this category.

**Threat Level to Poisoning PaaS:** High on model-file-level poisoning. However, Palo Alto's focus is broad platform security; training-data poisoning and RAG poisoning are less developed within their stack.

---

### 5. Lakera
**Status:** Independent
**Founded:** 2022
**Headquarters:** Zurich, Switzerland

**Funding:**
- Seed: ~$4.5M
- Series A (July 2024): $20M — Atomico (lead)
- **Total raised: ~$24.5M**

**Pricing (Published):**
- Community: FREE — up to 10,000 API requests/month
- Business: Custom pricing (contact sales)
- Enterprise: Custom pricing
- Model: API-call/usage-based; Lakera publishes the most transparent pricing of any competitor in this space

**Known Customers:** Dropbox, Citi, and undisclosed Fortune 100 tech and finance companies.

**Products:**
- Lakera Guard: real-time API-based firewall between applications and LLMs — inspects prompts in and responses out
- Lakera Red: AI-powered red teaming to find vulnerabilities

**Data Poisoning Coverage:** NONE explicitly. Lakera's stated product scope does not include model vulnerability scanning, supply chain poisoning, or training data poisoning detection. Their focus is prompt injection and data leakage at runtime.

**Pricing Model Signal:** Usage-based API pricing (per-call) is the model to watch. Lakera demonstrates this can work at the free tier for developer adoption and convert to enterprise contracts.

**Threat Level to Poisoning PaaS:** Low on direct poisoning detection. However, Lakera's developer-centric freemium model is the most directly analogous pricing strategy for a poisoning detection API product.

---

### 6. SPLX AI / Zscaler
**Status:** ACQUIRED by Zscaler (November 2025)
**Acquisition Price:** Not disclosed

**Background:**
- SPLX was a pre-acquisition AI security startup focused on AI red teaming, asset management, and governance
- Acquired November 3, 2025, integrated into Zscaler Zero Trust Exchange

**Capabilities Brought to Zscaler:**
- AI Asset Discovery: extends beyond public GenAI to include models, workflows, code repos, RAG systems, MCP servers in public and private deployments
- Automated AI Red Teaming: 5,000+ purpose-built attack simulations for risk and vulnerability discovery with real-time remediation
- Prompt hardening and governance
- Shift-left AI security from development through deployment

**Market Context:** Zscaler cited $250B+ in projected AI infrastructure spending by end of 2025 as the driver. Target is shadow AI sprawl, unmanaged models, and emerging attack surfaces.

**Threat Level to Poisoning PaaS:** Low-to-Medium. Zscaler's integration absorbs SPLX into a Zero Trust networking product; poisoning detection is not a stated primary capability.

---

### 7. Prompt Security
**Status:** ACQUIRED by SentinelOne (August 5, 2025)
**Acquisition Price:** ~$250M
**Founded:** 2023 (emerged from stealth Jan 2024)
**Total Pre-Acquisition Funding:** $23M ($5M seed + $18M Series A)

**Series A Details (Nov 2024):** Jump Capital (lead), Hetz Ventures, Ridge Ventures, Okta, F5 — $18M

**Product Scope:**
- Secures every AI touchpoint: browsers, copilots, coding assistants, homegrown applications
- Inspects prompts and responses: prevents data leaks, blocks harmful content
- Coverage: shadow AI, prompt injection, jailbreaks, GenAI governance
- Policy enforcement and full visibility across AI tools in the organization

**Integration into SentinelOne Singularity Platform:** Extends SentinelOne's platform to secure GenAI and agentic AI use in the workplace — real-time visibility into AI tool access, data sharing, and automated enforcement.

**Data Poisoning Coverage:** NONE stated. Focus is runtime prompt and response inspection, not training or supply chain poisoning.

**Threat Level to Poisoning PaaS:** Low on direct poisoning. High as a signal: a $23M company was acquired for $250M (10.8x revenue multiple if at $23M ARR), validating the category's acquisition premiums.

---

### 8. Lasso Security
**Status:** Independent (M&A watch list per Israeli press)
**Founded:** 2023
**Headquarters:** Israel

**Funding:**
- Seed (Nov 2023): $6M — Entrée Capital, Samsung Next
- Seed extension (Jan 2025): $8.5M — CyberArk Ventures, AWS, CrowdStrike Accelerator participants
- **Total raised: $14.5M**

**Product:**
- Shadow AI Discovery
- LLM Data-Flow Monitoring and Observability
- Real-time Detection and Alerting for: model theft, malicious code generation, prompt injection, data poisoning, supply chain attacks

**Data Poisoning Coverage:** YES — explicitly listed as one of Lasso's six named threat categories.

**Pricing:** Not publicly disclosed.

**M&A Signal:** Following SentinelOne's $250M Prompt acquisition, Israeli press identified Lasso (along with Aim and Pillar) as next likely acquisition targets.

**Threat Level to Poisoning PaaS:** Medium. Lasso is one of the few competitors that names data poisoning as a primary threat, but is a small team and underfunded relative to the space. Likely to be acquired in 2025–2026.

---

### 9. CalypsoAI
**Status:** ACQUIRED by F5 (closed ~Sept/Oct 2025)
**Acquisition Price:** $180M
**Founded:** 2018
**Headquarters:** Washington, D.C. (with Dublin, Ireland operations)

**Pre-Acquisition Funding:** ~$40M+
- Paladin Capital Group, Lockheed Martin Ventures, Lightspeed Venture Partners, 8VC, Hakluyt Capital, Empros Capital

**Government Contracts:**
- Department of Defense Chief Data and Artificial Intelligence Office (CDAO)
- U.S. Air Force
- Department of Homeland Security
- Palantir FedStart program partner (U.S. government agencies)
- Top-Two Finalist, 2025 RSAC Innovation Sandbox
- Supports FedRAMP-compliant and air-gapped deployments

**Products (now F5 AI Guardrails and F5 AI Red Team):**
- Inference Red Team: adversarial testing against 10,000+ new attack prompts monthly
- Inference Defend: real-time threat detection and prevention
- Inference Observe: enterprise oversight and monitoring
- Moderator: real-time AI policy enforcement and content filtering

**Data Poisoning Coverage:** Limited — primary focus is inference-time threats. Red teaming covers adversarial inputs but not training-stage poisoning.

**Threat Level to Poisoning PaaS:** Low-to-Medium on poisoning specifically. High as a signal for government market: the fact that Lockheed Martin Ventures and Paladin Capital backed CalypsoAI confirms defense/intel is a premium-paying customer segment for AI security.

---

### 10. Pangea
**Status:** ACQUIRED by CrowdStrike (September 17, 2025)
**Acquisition Price:** ~$260M
**Founded:** ~2022
**Total Pre-Acquisition Funding:** $52M (Series B: $26M from GV, Decibel, Okta Ventures)

**Product (now CrowdStrike Falcon AI Detection and Response / AIDR):**
- AI Guardrail Platform: developer-first API-based security guardrails
- Covers 8 of 10 OWASP Top 10 LLM risks
- Claims 99% bad prompt detection with sub-30ms response time
- Security gateway or embedded SDK (few lines of code integration)
- Runtime visibility and control for security teams

**Integration into CrowdStrike:** The Falcon platform delivers the industry's first complete AI Detection and Response (AIDR) — securing data, models, agents, identities, infrastructure, and interactions.

**Data Poisoning Coverage:** NONE explicitly stated. Focus is on runtime prompt security and data leakage prevention.

**Threat Level to Poisoning PaaS:** Low on poisoning. Moderate as a market signal: developer-first API security with a freemium/usage model is proven to reach enterprise contracts (Pangea's $26M Series B from GV validates this).

---

### 11. Invariant Labs
**Status:** ACQUIRED by Snyk (June 24, 2025)
**Acquisition Price:** Not disclosed
**Founded:** 2024
**Headquarters:** Zurich, Switzerland (ETH spin-off)

**Background:**
- Founded by Professors Martin Vechev and Florian Tramèr (ETH Zurich) and three graduates
- Published seminal research on MCP vulnerabilities; coined "tool poisoning" terminology
- Approximately 10 employees; no disclosed outside funding prior to acquisition
- Less than one year old at time of acquisition

**Product (Guardrails):**
- Transparent security layer at LLM and agent level
- Takes into account: contextual information, static scans of agent tools/implementations, runtime information, human annotations, incident databases
- Allows inspection and observation of agent behavior
- Enforces contextual security rules on agent systems
- Scans MCP servers for vulnerabilities

**Data Poisoning Coverage:** YES — "tool poisoning" is Invariant's named research contribution. MCP server scanning for poisoned tool definitions is a specific capability.

**Strategic Significance:** Snyk acquired Invariant to launch Snyk Labs, a new AI security research arm. This represents a developer-tool company (Snyk) buying deep AI security research capability.

**Threat Level to Poisoning PaaS:** Medium-to-High on MCP/tool-level poisoning specifically. Now inside Snyk, they will reach millions of developers. Training-data poisoning is not their focus.

---

### 12. Arthur AI
**Status:** Independent
**Founded:** 2018
**Headquarters:** New York, NY

**Funding:**
- Series A (Dec 2020): $15M
- Series B (Sept 2022): $42M — Index Ventures, Work-Bench, Acrew Capital
- **Total raised: ~$63M**

**Products:**
- Agent Discovery & Governance (ADG): launched Dec 2025 — comprehensive agent inventory, evals, guardrails, observability
- LLM Observability: monitoring prompts, responses, latency, cost
- ML Model Monitoring: drift detection, performance degradation, fairness metrics
- Arthur Shield: real-time LLM guardrails
- Open-sourced real-time AI evaluation engine (April 2025)

**Pricing:** Subscription-based with tiered plans (annual and monthly). No public pricing; enterprise custom contracts.

**Data Poisoning Coverage:** NONE directly. Arthur's focus is model performance drift and observability — drift detection could surface downstream effects of poisoning but is not a poisoning-specific detection capability.

**Threat Level to Poisoning PaaS:** Low. Arthur occupies the MLOps/observability lane, not the security/adversarial lane. Different buyer (data science team vs. security team).

---

### 13. Fiddler AI
**Status:** Independent
**Founded:** 2018
**Headquarters:** Menlo Park, CA

**Funding:**
- Multiple rounds totaling ~$68.6M through Series B Prime (Dec 2024)
- Series B Prime (Dec 2024): $18.6M — Lightspeed, Lux Capital, Insight Partners, Capgemini Ventures, Mozilla Ventures
- Series C (early 2026): $30M — RPS Ventures (lead), plus existing investors and LG Technology Ventures
- **Total raised: ~$98.6M**

**Products:**
- Fiddler Trust Service: LLM prompt/response scoring with fine-tuned Trust Models (launched 2024)
- LLM Observability: latency, cost, hallucination, toxicity monitoring
- Agent Observability: monitoring agentic AI behavior
- ML Model Monitoring: drift, bias, fairness, performance
- Explainable AI (XAI): feature attribution for model decisions

**Pricing:** Subscription-based with annual and monthly tiers; product-specific pricing for Trust Service and LLM Observability modules.

**Investor Signal:** Cisco Investments is a noted follower of Fiddler — CiscoInvestments.com profiled Fiddler's observability vision, suggesting Cisco may be a potential acquirer.

**Data Poisoning Coverage:** NONE directly. Fiddler operates in the observability and responsible AI lane, not adversarial security. Their Trust Service scores outputs but does not detect training-stage poisoning.

**Threat Level to Poisoning PaaS:** Low. Complementary product, not competing. Could be a potential partner channel (Fiddler detects model drift; poisoning PaaS detects the cause of that drift).

---

### 14. Wiz AI-SPM
**Status:** Part of Wiz (acquired by Google for $32B, 2025)
**Product:** AI Security Posture Management (AI-SPM) module within Wiz CNAPP

**Capabilities:**
- Agentless discovery of AI services, models, MCP servers, and integrations across clouds
- AI Bill of Materials (AI BOM): inventory of AI software, SDKs, libraries, dependencies
- Runtime Monitoring: detects new AI activity in production
- Threat Correlation: links agent behavior to cloud resources, identities, and sensitive data
- Detection of AI pipeline abuse
- Visual dependency mapping with remediation suggestions
- Sensitive data exposure monitoring for AI training data and model outputs

**Pricing:** Wiz Advanced pricing: approximately $38,000/year for fixed annual contracts (entry-level tier). Full enterprise AI-SPM coverage is additive to core Wiz platform.

**Data Poisoning Coverage:** PARTIAL. AI pipeline abuse detection and training data exposure monitoring approach poisoning from a posture/configuration angle (is training data exposed to unauthorized writes?), but does not perform active poisoning detection or model scanning.

**Threat Level to Poisoning PaaS:** Low-to-Medium. Wiz AI-SPM is infrastructure-level; poisoning PaaS is application and model-level. The buyers overlap (security teams) but the use cases are complementary. Post-Google acquisition, Wiz will be embedded in GCP-heavy enterprises, creating a channel partnership opportunity.

---

### 15. Cranium AI
**Status:** Independent
**Founded:** 2022 (spun out of KPMG)
**Headquarters:** New Jersey

**Funding:**
- Seed: $7M — KPMG LLP, SYN Ventures (spun out with backing)
- Series A (Oct 2023): $25M — Telstra Ventures (lead), KPMG, SYN Ventures
- **Total raised: $32M**

**Product:**
- AI Security & Governance platform for enterprise AI ecosystems
- Maps, monitors, and manages AI/ML environments against adversarial threats
- Governance: regulation and compliance across AI systems
- Visibility: inventory of AI assets and their security posture
- Security: protection against adversarial threats without interrupting training, testing, and deployment workflows

**Notable Recognition:** Fortune/Evolution Equity Partners Top 50 Cybersecurity Companies of 2025.

**KPMG Heritage:** Strong advisory and compliance angle; well-positioned for regulated industries (financial services, healthcare) that need AI governance documentation.

**Data Poisoning Coverage:** PARTIAL. Coverage is framed around adversarial threat monitoring, but specific poisoning detection capabilities are not detailed in public materials.

**Threat Level to Poisoning PaaS:** Low-to-Medium. Cranium occupies the governance/compliance lane more than the active detection lane. Complementary rather than directly competing.

---

## Part II: Market Size and Financial Data

### Total Addressable Market (TAM) — AI in Cybersecurity

| Source | 2024 Market Size | 2030 Projection | CAGR |
|--------|-----------------|-----------------|------|
| Grand View Research | $25.35B | $93.75B | 24.4% |
| Mordor Intelligence | ~$25B | $86.34B | 22.8% |
| Statista | ~$30B | $134B | ~28% |
| NextMSC | $28.24B | $82.45B | 19.2% |

**Working consensus TAM (2024):** ~$27B, growing to $85–$135B by 2030 at 20–28% CAGR.

**Specialized LLM/AI Security Sub-market (2025):**
- Only 13 companies focused specifically on securing AI systems, LLMs, and agentic applications
- Total funding for this sub-category: $414M (less than 5% of the $8.5B total security funding in the period measured)
- This sub-category is significantly underfunded relative to its threat surface

**Note on AI infrastructure spending:** Organizations are projected to spend $250B+ on AI infrastructure through end of 2025, creating the attack surface this market exists to protect.

---

### Funding Trends 2024–2025

| Period | AI Security Funding | Avg. Deal Size |
|--------|---------------------|----------------|
| 2024 | $2.16B | $34M |
| 2025 | $6.34B | $54M |
| Change | +193% | +59% |

**Gartner:** Global information security spending forecast at $213B in 2025, growing 15% YoY.

**Key enterprise budget signal:** ServiceNow's Security and Risk business crossed $1B in annual contract value in Q3 2025, demonstrating that security platforms can reach $1B ARR rapidly.

---

## Part III: Key Strategic Questions Answered

### Q1: What is the average deal size in AI security SaaS?

Based on aggregated data:
- **Median enterprise ACV across SaaS:** $26,265 (all categories); growing to $47K–$890K for larger seat-count contracts
- **AI security specifically:** Entry-level enterprise deals $50K–$150K annually; mid-market platform deals $150K–$500K; large enterprise $500K–$2M+
- **Acquisitions as a proxy for scale:** Prompt Security ($23M raised, acquired for $250M) implies ~$20–25M ARR at exit. CalypsoAI (acquired for $180M) suggests $15–20M ARR. These imply enterprise customers paying $200K–$500K+ per year in aggregate per vendor.
- **Wiz AI-SPM entry point:** $38,000/year fixed, suggesting AI security modules attached to broader platforms start below $50K and scale with usage.

**Recommendation for Poisoning PaaS pricing:** A $25K–$75K/year entry tier per deployment environment (per model, per pipeline, or per organization unit), scaling to $200K–$500K for enterprise-wide contracts. Usage-based API pricing (per scan, per model evaluated) is the preferred developer-adoption model (see Lakera).

---

### Q2: What pricing models are most common?

| Model | Prevalence | Examples |
|-------|-----------|---------|
| Custom enterprise (opaque) | Most common (80%+) | Noma, HiddenLayer, Protect AI, Cranium |
| Usage-based / per-API-call | Developer-first | Lakera (freemium + enterprise) |
| Platform / seat-based | Legacy security | Cisco, Palo Alto bundles |
| Per-model / per-scan | Emerging | Protect AI Guardian (custom), Arthur AI |
| Hybrid (platform fee + usage) | 49% of AI vendors as of 2025 | Industry trend |

**The winning model for a poisoning detection PaaS:** Hybrid. Developer-facing free tier with API call limits (mirroring Lakera's community tier), plus a per-model/per-pipeline scan fee at the mid-market, converting to platform fee with unlimited scans at enterprise.

---

### Q3: Which competitors focus specifically on data poisoning (vs. broader AI security)?

| Competitor | Data Poisoning Focus | Depth |
|-----------|---------------------|-------|
| Cisco AI Defense (Robust Intelligence) | YES | Medium — listed as a protected threat but bundled in a platform |
| HiddenLayer | YES | High — model scanning detects backdoor injection (supply chain poisoning) |
| Protect AI (Guardian) | YES | High — model serialization attack detection, pipeline scanning |
| Lasso Security | YES | Medium — named as one of 6 threat categories |
| Invariant Labs (Snyk) | YES | High — tool poisoning (MCP); narrow scope |
| Wiz AI-SPM | PARTIAL | Low — configuration/posture angle only |
| Noma Security | PARTIAL | Low — runtime only, not training stage |
| All Others | NO | —  |

**Critical finding:** No competitor has a dedicated, standalone data poisoning detection product. The deepest coverage exists within Cisco AI Defense (now bundled with networking), Protect AI/Guardian (now inside Palo Alto's $500M platform), and HiddenLayer (government-focused). A pure-play, standalone poisoning detection PaaS with API-first architecture has no direct equivalent in the market.

---

### Q4: What is the funding gap — how much capital is needed to compete?

**Phase 1 (MVP to Series A credibility):**
- Minimum viable: $2M–$5M pre-seed / seed
- Comparable seed rounds: Invariant Labs ($0 external, acquired); Lasso ($6M); Prompt Security ($5M); Cranium ($7M)
- Target: $5M–$10M seed to build detection engine, publish research (essential for credibility in this category), and reach first 10–20 paying enterprise customers

**Phase 2 (Series A, competing as an independent):**
- Comparable Series A: Lakera ($20M), Prompt Security ($18M), Cranium ($25M), Noma ($32M)
- Target: $20M–$35M Series A at 1,000%+ ARR growth signal
- Use of funds: GTM (North America + Europe), R&D for detection models, regulatory compliance features (EU AI Act, NIST AI RMF)

**Phase 3 (compete or position for acquisition):**
- Comparable: HiddenLayer ($56M total), Lasso ($14.5M total with government traction)
- Acquisition floor: ~$150M–$300M (CalypsoAI $180M with $40M raised; Prompt Security $250M with $23M raised)
- Acquisition ceiling with government contracts and strong ARR: $400M–$700M (Robust Intelligence, Protect AI range)

**Capital efficiency benchmark:** Prompt Security returned ~10.8x on $23M raised at a $250M exit in ~2 years from founding. The market is paying premium multiples for AI security IP.

---

### Q5: Which competitors have government/defense contracts?

| Competitor | Government Presence | Details |
|-----------|---------------------|---------|
| HiddenLayer | DEEP | DoD, Air Force (AFWERX), MDA SHIELD IDIQ ($151B ceiling), USIC ICMP marketplace |
| CalypsoAI (F5) | DEEP | DoD CDAO, Air Force, DHS, Palantir FedStart; FedRAMP + air-gap support |
| Protect AI (Palo Alto) | MODERATE | Leidos partnership for U.S. Government AI security (announced April 2025) |
| Cranium | MODERATE | KPMG heritage enables regulated-sector access; compliance-focused |
| Noma Security | NASCENT | Not publicly disclosed; primarily commercial enterprise focus |
| Lakera | NONE stated | Commercial focus; European company (Swiss) |
| Lasso Security | NONE stated | Israeli startup; early stage |

**Key insight:** HiddenLayer and CalypsoAI have the most entrenched government positions. The SHIELD IDIQ (MDA) multi-award vehicle with a $151B ceiling is a landmark — HiddenLayer can now compete on any task order under that vehicle without recompeting. A poisoning detection PaaS should pursue FedRAMP authorization and CMMC compliance as a strategic asset for this segment.

---

## Part IV: M&A Consolidation Map

The following acquisition wave has restructured the competitive landscape:

| Acquired Company | Acquirer | Price | Date |
|-----------------|----------|-------|------|
| Robust Intelligence | Cisco | ~$400M est. | Oct 2024 |
| Protect AI | Palo Alto Networks | $500M+ | April–July 2025 |
| Prompt Security | SentinelOne | ~$250M | Aug 2025 |
| Pangea | CrowdStrike | ~$260M | Sept 2025 |
| CalypsoAI | F5 | $180M | Sept 2025 |
| Invariant Labs | Snyk | Undisclosed | June 2025 |
| SPLX | Zscaler | Undisclosed | Nov 2025 |

**Total disclosed M&A value (AI security, 2024–2025):** ~$1.59B+ across 7 transactions

**Acquirer landscape:** The five largest enterprise security vendors (Palo Alto, Cisco, CrowdStrike, SentinelOne, Zscaler) and two adjacent platform companies (F5, Snyk) have all made AI security acquisitions. This dramatically narrows the pool of potential future acquirers, making Wiz (now Google), Microsoft (via HiddenLayer's M12 investment), IBM (HiddenLayer investor), and ServiceNow the most likely next acquirers of remaining independents.

**Remaining acquirable independents:**
- Noma Security ($132M raised — may IPO or pursue strategic sale to a non-cybersecurity tech company)
- HiddenLayer ($56M raised — Microsoft strategic relationship; M12 investor; acquisition by Microsoft or government-adjacent buyer plausible)
- Lasso Security ($14.5M raised — next Israeli-press-identified M&A target)
- Arthur AI ($63M raised — Cisco invested/followed; potential Cisco acqui-hire or acquisition)
- Fiddler AI ($98.6M raised — Cisco involvement noted; or standalone IPO candidate)
- Cranium AI ($32M raised — KPMG heritage; Big Four advisory firm or compliance software vendor acquisition plausible)

---

## Part V: Regulatory Drivers

### EU AI Act (Enforcement Timeline)
- **February 2, 2025:** Banned practices prohibited (unacceptable risk AI)
- **August 2, 2025:** GPAI model transparency and governance requirements active
- **August 2, 2026:** High-risk AI system obligations fully enforceable — the single biggest enterprise compliance forcing function
- **August 2, 2027:** Additional high-risk obligations for certain sectors

**Strategic implication:** August 2026 is approximately 4 months away. Enterprises deploying high-risk AI systems (in healthcare, critical infrastructure, employment, education, law enforcement, financial services) are in active procurement cycles for compliance tooling now. A poisoning detection product with EU AI Act audit trail capability is a direct compliance enabler.

### NIST AI Risk Management Framework (AI RMF)
- Voluntary but de facto mandatory for U.S. federal agencies and regulated industries
- Becoming the baseline for enterprise AI governance documentation
- Four pillars: Govern, Map, Measure, Manage
- A poisoning detection PaaS that maps to NIST AI RMF "Measure" and "Manage" functions (specifically, adversarial robustness measurement) is directly aligned with enterprise compliance needs

### SEC AI Disclosure
- SEC has increased scrutiny on AI-related material risks in public company disclosures
- Companies reporting AI in their 10-K must disclose known risks to AI systems — data poisoning qualifies as a material risk for any company whose business logic depends on AI models
- This creates CFO/Legal/Risk-driven demand alongside CISO-driven demand

### OWASP LLM Top 10 (2025 Edition)
- LLM04:2025 is specifically "Data and Model Poisoning" — positioned as a top-tier documented risk
- OWASP classification drives enterprise security checklist requirements; poisoning is now mandatory in AI security assessments
- This is the most direct standards-body tailwind for a poisoning-specific product

---

## Part VI: Competitive Positioning Matrix

```
                    TRAINING-DATA         RUNTIME
                    POISONING DETECTION   PROTECTION
                    ─────────────────     ──────────────
HiddenLayer         HIGH (model files)    Medium
Cisco AI Defense    Medium (stated)       High (inline)
Protect AI/PAN      HIGH (Guardian)       Medium
Lasso Security      Medium (listed)       Medium
POISONING PAAS      HIGH (focused)        In roadmap

Noma Security       None                  HIGH (agents)
Lakera              None                  HIGH (prompts)
Pangea/CrowdStrike  None                  HIGH (prompts)
SentinelOne/Prompt  None                  HIGH (GenAI)
Arthur AI           None (drift proxy)    Medium
Fiddler AI          None                  Medium
Cranium             Partial (posture)     Medium
Wiz AI-SPM          Partial (config)      None
CalypsoAI/F5        None (inference)      High (guardrails)
Invariant/Snyk      MCP/tool layer        Medium
```

**White space confirmed:** No competitor owns the training-data poisoning detection category as a standalone, API-first, developer-accessible product. The closest are HiddenLayer and Protect AI/Guardian, but both are now inside large enterprise platform plays ($56M and $500M+ respectively) that are not API-accessible to smaller teams or government contractors without full platform subscriptions.

---

## Part VII: Strategic Recommendations

### Immediate (0–6 months)
1. **Publish research.** Every acquired company in this space had a research-first credibility foundation (Robust Intelligence pioneered algorithmic red teaming; Invariant Labs coined "tool poisoning" and published MCP vulnerability research). Publishing 2–3 pieces of original data poisoning detection research is not optional — it is the primary GTM motion for enterprise credibility and analyst coverage.
2. **OWASP alignment.** Explicitly map the product to LLM04:2025 in all materials. This makes the product a checkbox item in every enterprise AI security assessment.
3. **Free tier / open-source component.** Lakera, Protect AI (LLM Guard), and Invariant Labs (Guardrails) all launched open-source components first. This is the developer adoption flywheel. Consider open-sourcing the detection rules or a lightweight scanner while keeping the cloud platform proprietary.
4. **Government channel.** HiddenLayer's SHIELD IDIQ win was transformational. Pursue FedRAMP Moderate authorization and identify a prime contractor (Leidos, Booz Allen, Palantir FedStart equivalent) as a distribution partner. CalypsoAI used Palantir FedStart; Protect AI used Leidos.

### Medium-term (6–18 months)
5. **Target the acquisition orphans.** Cisco AI Defense, Palo Alto Prisma AIRS, CrowdStrike AIDR, SentinelOne, and Zscaler all have enterprise customers who now require a poisoning detection module but did not get one in their platform acquisition. Position as the poisoning detection layer that integrates with all these platforms via API.
6. **EU AI Act compliance module.** Build an audit trail and compliance reporting layer explicitly mapped to EU AI Act Article 9 (risk management) and Annex IV requirements for high-risk AI systems. This converts the product from a security tool to a compliance tool, opening a second buyer (General Counsel, Chief Risk Officer, DPO) alongside the CISO.
7. **Series A narrative:** The narrative is "we are the only purpose-built, API-first data poisoning detection platform in a $27B market where every large security vendor has chosen breadth over depth." The $414M total funding across all 13 pure-play AI security companies (less than 5% of total security funding) is the funding gap evidence. Poisoning-specific coverage is the category differentiation.

### Long-term (18–36 months)
8. **Acquisition positioning.** The five large acquirers (Cisco, Palo Alto, CrowdStrike, SentinelOne, Zscaler) have each made their primary AI security acquisition. The next wave of acquirers will be: Microsoft, Google (via Wiz), ServiceNow, IBM, and potentially defense primes (Leidos, Northrop Grumman, L3Harris). Build the product and customer relationships to be the obvious next acquisition target for one of these buyers. Government contracts dramatically increase acquisition appeal (CalypsoAI's defense relationships were cited in F5's acquisition rationale).

---

## Appendix A: Competitor Funding Summary Table

| Company | Status | Total Raised | Acquisition Price | Acquirer |
|---------|--------|-------------|-------------------|----------|
| Noma Security | Independent | $132M | — | — |
| Cisco AI Defense | Acquired | ~$11M pre-acq | ~$400M est. | Cisco |
| HiddenLayer | Independent | $56M | — | — |
| Protect AI | Acquired | $108.5M | $500M+ | Palo Alto Networks |
| Lakera | Independent | ~$24.5M | — | — |
| SPLX | Acquired | Undisclosed | Undisclosed | Zscaler |
| Prompt Security | Acquired | $23M | ~$250M | SentinelOne |
| Lasso Security | Independent | $14.5M | — | — |
| CalypsoAI | Acquired | ~$40M | $180M | F5 |
| Pangea | Acquired | $52M | ~$260M | CrowdStrike |
| Invariant Labs | Acquired | ~$0 | Undisclosed | Snyk |
| Arthur AI | Independent | ~$63M | — | — |
| Fiddler AI | Independent | ~$98.6M | — | — |
| Wiz AI-SPM | Part of Wiz | N/A (module) | $32B (Wiz→Google) | Google |
| Cranium AI | Independent | $32M | — | — |

---

## Appendix B: Sources

### Primary Sources
- [Noma Security $100M Series B Press Release](https://noma.security/blog/noma-security-raises-100m-to-drive-adoption-of-ai-agent-security/)
- [SecurityWeek: Noma Security Raises $100M](https://www.securityweek.com/noma-security-raises-100-million-for-ai-security-platform/)
- [Cisco: Robust Intelligence Acquisition Announcement](https://blogs.cisco.com/news/fortifying-the-future-of-security-for-ai-cisco-announces-intent-to-acquire-robust-intelligence)
- [Ctech: Yaron Singer's $400M Sale to Cisco](https://www.calcalistech.com/ctechnews/article/rjgsb5npa)
- [HiddenLayer AFWERX STTR Phase II Contract](https://www.hiddenlayer.com/news/hiddenlayer-awarded-afwerx-sttr-phase-ii-contract-to-accelerate-usa-department-of-defense-security-adoption)
- [GovConWire: HiddenLayer $50M Series A](https://www.govconwire.com/articles/hiddenlayer-raises-50m-in-series-a-funding-to-advance-ai-security-platform-development)
- [Palo Alto Networks: Protect AI Acquisition Complete](https://www.paloaltonetworks.com/company/press/2025/palo-alto-networks-completes-acquisition-of-protect-ai)
- [Business Wire: Protect AI $60M Series B](https://www.businesswire.com/news/home/20240801066345/en/Protect-AI-Raises-$60M-in-Series-B-Financing-to-Secure-Artificial-Intelligence-and-Machine-Learning-from-Unique-Security-Risks)
- [TechCrunch: Lakera $20M Series A](https://techcrunch.com/2024/07/24/lakera-which-protects-enterprises-from-llm-vulnerabilities-raises-20m/)
- [Lakera Guard Platform Pricing](https://platform.lakera.ai/pricing)
- [Zscaler: SPLX Acquisition Press Release](https://www.zscaler.com/press/zscaler-secures-enterprise-ai-lifecycle-acquisition-innovative-ai-security-pioneer-splx)
- [Prompt Security $18M Series A](https://prompt.security/press/prompt-security-raises-18m-series-a-to-accelerate-its-mission-to-secure-genai-in-enterprises)
- [SentinelOne: Prompt Security Acquisition](https://www.sentinelone.com/press/sentinelone-to-acquire-prompt-security-to-advance-genai-security/)
- [Lasso Security $6M Seed](https://www.lasso.security/resources/lasso-security-funding-announcement-2023)
- [CalypsoAI $23M Raise](https://www.securityweek.com/calypsoai-raises-23-million-for-ai-security-tech/)
- [F5: CalypsoAI Acquisition Announcement](https://www.f5.com/company/news/press-releases/f5-to-acquire-calypsoai-to-bring-advanced-ai-guardrails-to-large-enterprises)
- [GeekWire: F5 Pays $180M for CalypsoAI](https://www.geekwire.com/2025/f5-paying-180m-to-acquire-calypsoai-to-boost-ai-enterprise-security-offerings/)
- [CrowdStrike: Pangea Acquisition Press Release](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-to-acquire-pangea-to-secure-every-layer-of-enterprise-ai/)
- [BankInfoSecurity: CrowdStrike Buys Pangea for $260M](https://www.bankinfosecurity.com/crowdstrike-buys-pangea-for-260m-to-guard-enterprise-ai-use-a-29480)
- [Snyk: Invariant Labs Acquisition](https://snyk.io/news/snyk-acquires-invariant-labs-to-accelerate-agentic-ai-security-innovation/)
- [ETH Zurich: Invariant Labs Acquired by Snyk](https://inf.ethz.ch/news-and-events/spotlights/infk-news-channel/2025/06/eth-spin-off-aquired-by-snyk.html)
- [Arthur AI Series B — TechCrunch](https://techcrunch.com/2022/09/27/arthur-ais-machine-learning-monitoring-gathering-steam-with-42m-investment/)
- [Fiddler AI $18.6M Series B Prime](https://www.fiddler.ai/blog/series-b-prime)
- [Wiz AI-SPM Product Page](https://www.wiz.io/solutions/ai-spm)
- [Cranium $25M Series A](https://cranium.ai/resources/press-release/cranium-series-a-funding-to-secure-ai/)

### Market Research
- [Grand View Research: AI in Cybersecurity Market $93B by 2030](https://www.grandviewresearch.com/industry-analysis/artificial-intelligence-cybersecurity-market-report)
- [PRNewswire: Global AI Cybersecurity $93B by 2030](https://www.prnewswire.com/news-releases/global-ai-in-cybersecurity-market-size-projected-to-reach-93-billion-by-2030-due-to-frequent-high-profile-cyberattacks-302565478.html)
- [Software Strategies Blog: AI Security Market 2025 Funding Data](https://softwarestrategiesblog.com/2025/12/30/ai-security-startups-funding-2025/)
- [Gartner: LLM Observability Investments Prediction](https://www.gartner.com/en/newsroom/press-releases/2026-03-30-gartner-predicts-by-2028-explainable-ai-will-drive-llm-observability-investments-to-50-percent-for-secure-genai-deployment)
- [Gartner: Global InfoSec Spending $213B in 2025](https://www.gartner.com/en/newsroom/press-releases/2025-07-29-gartner-forecasts-worldwide-end-user-spending-on-information-security-to-total-213-billion-us-dollars-in-2025)
- [F5 Blog: AI Security Through the Analyst Lens](https://www.f5.com/company/blog/ai-security-through-the-analyst-lens-insights-from-gartner-forrester-and-kuppingercole)

### Regulatory
- [EU AI Act Implementation Timeline](https://artificialintelligenceact.eu/implementation-timeline/)
- [OWASP LLM04:2025 Data and Model Poisoning](https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/)
- [NIST vs EU AI Act Framework Comparison](https://www.magicmirror.team/blog/nist-vs-eu-ai-act-which-ai-risk-framework-should-you-follow)

### M&A Analysis
- [Infosecurity Magazine: Biggest Cybersecurity M&A of 2025](https://www.infosecurity-magazine.com/news-features/biggest-cybersecurity-mergers/)
- [Latio Pulse: Unpacking the 2025 AI Security Acquisitions](https://pulse.latio.tech/p/unpacking-the-2025-ai-security-acquisitions)
- [Ctech: M&A Spotlight on Lasso, Aim, Pillar After SentinelOne Prompt Deal](https://www.calcalistech.com/ctechnews/article/bjt0500luxl)

---

*Report compiled April 14, 2026. All data sourced from public disclosures, press releases, and verified news reporting. Acquisition prices marked "estimated" or "reported" are from press coverage and analyst estimates, not confirmed by the parties. Confidence level: High for funding data; Medium-to-High for pricing signals (most enterprise pricing is not publicly disclosed); High for M&A transaction details; High for product capability scope.*
