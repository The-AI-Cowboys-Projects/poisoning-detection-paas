# Market Research: AI-SPM LLM Data Poisoning Detection Platform
## Monetization Strategy, Pricing Models, and Customer Targeting

**Research Date:** April 14, 2026
**Analyst:** Market Research Division, AI Cowboys Workforce
**Platform:** Poisoning Detection PaaS (5 detection engines, 19-technique red team generator, self-evolution loop, cryptographic proof chains)

---

## EXECUTIVE SUMMARY

The platform sits at the intersection of three explosive and converging markets: LLM Security Platforms ($2.37B in 2024, 21.4% CAGR), AI Red Teaming Services ($1.3B in 2025, 30.5% CAGR through 2035), and the broader Security Posture Management market ($26.64B in 2025, growing to $53.31B by 2030). The August 2026 EU AI Act enforcement deadline, the NDAA FY2026 AI security mandate for defense contractors, and the 2025 HIPAA Security Rule update have together created an acute and non-discretionary compliance buying cycle that favors a purpose-built poisoning detection product over generalist CNAPP/CSPM platforms attempting to bolt on AI coverage.

The optimal monetization model is a hybrid: product-led growth (PLG) via a generous free tier to capture developer mindshare, with a usage-based Pro tier that expands naturally as RAG deployments scale, and high-ACVenterprise contracts anchored on compliance deliverables (cryptographic proof chains, audit-ready reports) rather than pure feature gating.

---

## SECTION 1: USE CASES BY INDUSTRY

### 1.1 Enterprise AI Teams — RAG Application Owners

**Pain point:** RAG's architectural design allows untrusted content to flow directly into the LLM context window with implicit authority over internal data and systems. Poisoned documents in the knowledge base produce persistent, hard-to-detect manipulation that survives model upgrades.

**Specific scenarios:**
- Knowledge base contamination via poisoned PDF uploads in enterprise document stores
- SharePoint/Confluence RAG pipeline integrity monitoring for internal copilots
- Customer-facing chatbot knowledge base audit (legal liability if poisoned output causes harm)
- Developer assistant pipelines (Cursor IDE, GitHub Copilot Enterprise) with code repository poisoning exposure
- Multi-tenant RAG isolation verification — one tenant's poisoned data must not cross into another tenant's context

**Regulatory driver:** NIST AI RMF March 2025 update explicitly requires model provenance and data integrity controls.

**Buyer:** AI Platform Engineering Lead, VP Engineering, CISO

---

### 1.2 AI/ML Platform Teams — Model Pipeline Operators

**Pain point:** Supply chain attacks on fine-tuning datasets, synthetic data pipelines, and embedded model weights. The "Virus Infection Attack" (2025) demonstrated that poisoned synthetic data propagates recursively across model generations.

**Specific scenarios:**
- Fine-tuning dataset provenance verification before training runs
- Continuous monitoring of vector embeddings for statistical distribution drift indicating injection
- MCP server tool-description integrity checks (tool poisoning attack surface)
- Third-party model ingestion scanning (open-source models from HuggingFace)
- Model registry integrity audit with cryptographic proof chain

**Regulatory driver:** SR 11-7 model risk management requires independent validation and continuous monitoring — the platform's empirical benchmarks against 8 real datasets directly satisfy this.

**Buyer:** ML Engineering Lead, Head of MLOps, Chief AI Officer

---

### 1.3 Security Teams — AppSec and AI Red Teams

**Pain point:** Traditional SAST/DAST tools have zero coverage of LLM-specific attack vectors. AppSec teams lack tooling for the OWASP Top 10 LLM risks (data/model poisoning is #5 in the 2025 list). Internal AI red teams lack automated attack generation.

**Specific scenarios:**
- Pre-production red team automation using the 19-technique poison generator before RAG deployment
- CI/CD pipeline integration — scan every knowledge base update as a security gate
- Adversarial testing of prompt injection + poisoning kill chains (cross-engine correlation is a differentiator here)
- Security regression testing after model or retrieval stack upgrades
- Penetration testing engagements — external red teams running the generator against client environments

**Regulatory driver:** SOC 2 AI controls (2025 additions), ISO 42001 certification requirements.

**Buyer:** CISO, AppSec Lead, Director of Security Engineering

---

### 1.4 Compliance and Audit Teams

**Pain point:** Auditors and GRC teams cannot demonstrate AI system integrity without vendor-neutral, tamper-evident evidence. The platform's cryptographic proof chains directly produce court-admissible and audit-ready artifacts.

**Specific scenarios:**
- SOC 2 Type II evidence collection for AI systems (automated report generation)
- EU AI Act Article 9 risk management system documentation
- NIST AI RMF "Measure" function continuous monitoring evidence
- ISO 27001/42001 control testing for AI-related controls
- Pre-audit readiness assessments with gap analysis
- Board-level AI risk reporting with quantified poisoning exposure scores

**Regulatory driver:** EU AI Act full enforcement August 2026; fines up to EUR 35M or 7% of global revenue. ISO 42001 published as the de facto AI management systems certification standard.

**Buyer:** Chief Compliance Officer, GRC Director, Internal Audit Lead, External Auditors (Big Four)

---

### 1.5 Government and Defense

**Pain point:** The NDAA FY2026 directs DoD to develop and implement an AI/ML cybersecurity framework incorporated into DFARS and CMMC. DoD agencies deploying RAG systems for intelligence analysis, logistics, and contract management have zero current tooling for poisoning detection in classified environments.

**Specific scenarios:**
- CMMC Level 3 AI security controls validation
- FedRAMP-authorized deployment for civilian agency AI systems
- Classified RAG pipeline integrity monitoring (on-prem / air-gap deployment requirement)
- Defense contractor supply chain AI security — third-party AI component vetting
- Intelligence community document ingestion pipeline security

**Regulatory driver:** NDAA FY2026 AI security mandate; FedRAMP's 20x AI prioritization initiative (GSA announcement August 2025); OMB AI governance requirements.

**Buyer:** DoD Program Managers, Federal CISOs, Defense contractor IT Security

**Note:** FedRAMP authorization is a prerequisite for federal sales. This is a 12-18 month investment but unlocks the $151B+ IDIQ vehicle space (HiddenLayer won a Missile Defense Agency SHIELD IDIQ — a direct comparable).

---

### 1.6 Healthcare AI

**Pain point:** 93% of healthcare organizations suffered a cyber attack in the past 12 months (Ponemon 2025). The January 2025 HIPAA Security Rule update removes the "addressable" designation for encryption and expands direct vendor accountability. AI agents processing PHI require tamper-evident audit trails.

**Specific scenarios:**
- Clinical decision support RAG system integrity (poisoned outputs could constitute medical negligence)
- Patient record summarization LLM audit trail with cryptographic proof chains
- Drug discovery RAG pipeline contamination detection
- Medical imaging AI model integrity verification
- Health system AI vendor vetting — proving third-party models are uncontaminated

**Regulatory driver:** HIPAA Security Rule 2025 update (encryption now required, not addressable); FDA AI/ML-based Software as a Medical Device (SaMD) guidance.

**Buyer:** Healthcare CISO, Chief Medical Information Officer (CMIO), Compliance Director

---

### 1.7 Financial Services

**Pain point:** SR 11-7 requires continuous monitoring and independent validation of models. The SEC identified AI governance as a 2025 examination priority. LLMs used in credit decisions, trading, and fraud detection are directly subject to model risk management requirements.

**Specific scenarios:**
- Credit decision RAG model integrity monitoring (SR 11-7 continuous monitoring requirement)
- AML/fraud detection LLM supply chain security
- Algorithmic trading system AI component validation
- Customer service chatbot knowledge base poisoning prevention (FTC/CFPB liability)
- Third-party AI vendor due diligence automation
- Automated model risk management evidence package generation

**Regulatory driver:** SR 11-7 model risk management; SEC AI governance examination priority 2025; DORA (EU Digital Operational Resilience Act) requiring ICT third-party risk management.

**Buyer:** Chief Risk Officer, Model Risk Management team, CISO, Chief Compliance Officer

---

### 1.8 Legal and Professional Services

**Pain point:** Firms using AI for contract review, legal research, and document analysis face liability if poisoned knowledge bases produce incorrect legal conclusions (e.g., citation hallucinations combined with poisoned precedent databases).

**Specific scenarios:**
- Legal research RAG pipeline integrity (Westlaw/LexisNexis alternative RAG systems)
- Contract review AI audit trail for malpractice protection
- Accounting/tax AI system integrity (Big Four internal tool security)
- Consulting firm AI knowledge base contamination prevention

**Buyer:** General Counsel, CTO, Risk Partner

---

### 1.9 Education and Research

**Pain point:** Universities deploying RAG-based academic assistants, research institutions training models on curated datasets, and EdTech companies face reputational and academic integrity risks from poisoned knowledge bases.

**Specific scenarios:**
- University library RAG assistant integrity monitoring
- Research data pipeline contamination detection
- EdTech platform curriculum AI security
- Academic plagiarism/manipulation detection in AI-assisted work

**Buyer:** CTO/CIO, Research Compliance Officer, Provost Office

---

## SECTION 2: MONETIZATION MODELS AND PRICING TIERS

### 2.1 Competitive Pricing Landscape

| Vendor | Model | Pricing Signal |
|--------|-------|---------------|
| Lakera Guard | Free (10K calls/mo) + Enterprise custom | Starts ~$99/mo small teams; enterprise custom |
| Protect AI | Enterprise contracts | Quote-based, six figures |
| HiddenLayer | Enterprise SaaS | Quote-based; won $151B IDIQ |
| Noma Security | Enterprise platform | Quote-based; $100M Series B at 1,300% ARR growth |
| Wiz | Consumption-based | $38,000/yr Advanced plan |
| Orca Security | Workload-based | $84,000-$360,000/yr |
| Legit Security | Developer-instance | $50/mo/developer instance |
| Snyk | Developer-seat | Free / $25/dev/mo Team / $52-98/dev/mo Enterprise |

**Key insight:** The AI security market is bifurcated between developer-seat tools (Snyk model, $25-$98/dev/mo) and platform-level contracts (Wiz/Orca/Noma model, $38K-$360K/yr). A poisoning detection platform is closer to the platform model because it operates at the infrastructure layer, not the developer IDE layer.

---

### 2.2 Recommended Pricing Architecture

**Design principle:** PLG funnel from free to Pro, enterprise ACV anchored on compliance deliverables rather than usage caps. Compliance-gated features (cryptographic proof chains, audit reports, EU AI Act evidence packages) justify premium pricing because they represent avoided regulatory fines, not just security features.

---

#### TIER 1 — Community (Free)

**Target:** Individual developers, researchers, students, open-source projects, proof-of-concept evaluations

**Price:** $0/month

**Included:**
- 500 scans/month (vector + RAG engine only)
- 3 detection engines (vector, RAG, basic telemetry)
- 5 poison technique variants in red team generator (out of 19)
- Single vector store connection (Pinecone or Chroma only)
- Basic scan reports (no cryptographic signing)
- Community documentation and support
- No SLA
- Watermarked reports
- Single user, no team features
- Public dashboard (metrics shared for community benchmarking)

**Gated (upgrade trigger):**
- MCP tool and provenance engines
- All 19 red team techniques
- Kill chain correlation
- Automated remediation
- Cryptographic proof chains
- Multi-tenant support
- CI/CD integration
- Compliance report exports
- Team/org management

**Strategic purpose:** Developer mindshare, viral spread via GitHub integrations, talent pipeline seeding in universities, community data for improving detection models.

---

#### TIER 2 — Pro (Team)

**Target:** AI startups, scale-up engineering teams, SMB security teams, individual security researchers, small RAG deployments (1-5 pipelines)

**Price:** $299/month (billed annually at $2,988/yr) or $399/month (month-to-month)

**Included:**
- 5,000 scans/month
- All 5 detection engines (vector, RAG, MCP tools, provenance, telemetry)
- All 19 red team poison techniques
- Up to 3 vector store connections
- Up to 2 MCP server connections
- Cross-engine kill chain correlation
- Automated remediation (with manual approval gate)
- Basic cryptographic proof chains (SHA-256 signed reports)
- CI/CD webhooks (GitHub Actions, GitLab CI)
- Standard compliance report templates (SOC 2, NIST AI RMF)
- Up to 5 users
- Email support, 48h response SLA
- Monthly benchmark reports vs. industry baseline
- 30-day scan history

**Gated (enterprise upgrade trigger):**
- Rollback automation
- EU AI Act / HIPAA / SR 11-7 specific report templates
- SSO/SAML
- Audit log export
- Custom detection rules
- On-prem/VPC deployment
- Multi-tenant isolation
- Unlimited connections
- Dedicated support
- SLA > 99.9% uptime

**Pricing rationale:** $299/mo is positioned below Snyk Enterprise ($52-98/dev/mo * 5 devs = $260-490/mo) and well below Lakera enterprise contracts, while providing significantly deeper poisoning-specific capabilities than any comparable tool at this price point.

---

#### TIER 3 — Enterprise

**Target:** Fortune 500 AI teams, mid-large financial institutions, healthcare systems, regulated tech companies, multinational corporations with EU AI Act exposure

**Price:** $2,500-$15,000/month (custom ACV: $30K-$180K/year typical range)
- Small enterprise (1-10 RAG pipelines, 500-seat org): ~$30,000-$60,000/yr
- Mid enterprise (10-50 pipelines, 1,000-5,000-seat org): ~$60,000-$120,000/yr
- Large enterprise (50+ pipelines, 10,000+ seat org): ~$120,000-$180,000/yr+

**Included (everything in Pro plus):**
- Unlimited scans (subject to fair use)
- Unlimited vector store and MCP server connections
- Automated remediation with one-click rollback
- Tamper-evident cryptographic proof chains (Merkle tree + timestamped)
- Full compliance report suite: EU AI Act (Articles 9, 13, 17), SOC 2 Type II AI addendum, ISO 42001, NIST AI RMF, HIPAA audit trail, SR 11-7 evidence package
- Custom detection rule authoring (rule marketplace access)
- Multi-tenant isolation with per-tenant reporting
- SSO/SAML, RBAC, audit log export (SIEM integration)
- Dedicated Slack/Teams channel + named CSM
- 99.9% uptime SLA with financial penalties
- Private VPC deployment option
- Annual on-site red team exercise (1 day, included)
- Quarterly executive briefing on threat intelligence
- API rate: 10,000 calls/day via REST API

**Pricing rationale:** Anchored significantly below Orca ($84K-$360K) and Wiz ($38K+) while being purpose-built for the LLM poisoning threat surface those tools do not natively address. The compliance report suite (EU AI Act evidence package alone has a regulatory fine avoidance value of up to EUR 35M) justifies the ACV anchoring.

---

#### TIER 4 — Government / Compliance (FedRAMP/CMMC/HIPAA BAA)

**Target:** Federal agencies, DoD contractors, healthcare systems requiring HIPAA BAA, cleared facility operators

**Price:** Custom contract; typical range $150,000-$500,000/yr
- Requires FedRAMP Moderate or High authorization (roadmap item)
- HIPAA BAA available at this tier
- CMMC Level 3 evidence package

**Included (everything in Enterprise plus):**
- Air-gapped / on-premises deployment option
- FedRAMP-compliant deployment (post-authorization)
- CMMC Level 3 AI security control evidence package
- HIPAA BAA with subcontractor data processing terms
- ITAR-compliant data handling (for defense contractors)
- Classified network deployment roadmap
- Dedicated security engineer (embedded, 20 hrs/month)
- Congressional reporting templates for NDAA FY2026 AI security compliance
- GSA Schedule / SEWP V procurement vehicle (roadmap)

**Pricing rationale:** Comparable to HiddenLayer's Missile Defense Agency SHIELD IDIQ positioning. FedRAMP authorization is the key investment that unlocks this tier at scale.

---

## SECTION 3: REVENUE STREAMS

### 3.1 Core Subscription (Primary)

Estimated contribution: 55-65% of total revenue at scale

The four tiers above form the recurring revenue core. Enterprise and Government tiers will represent the majority of ARR even with low logo counts (10-20 enterprise customers = $600K-$3.6M ARR).

---

### 3.2 API Access / Per-Scan Pricing (CI/CD Integration)

**Model:** Overage and standalone API access billed per scan above tier limits

**Pricing:**
- $0.05 per scan (vector/RAG engine, single technique)
- $0.15 per scan (all 5 engines, full kill chain)
- $0.50 per red team run (full 19-technique generator, single pipeline)
- $2.00 per compliance report generation (EU AI Act / HIPAA / SR 11-7 templates)
- Volume discounts: 20% off at 10K scans/mo, 40% off at 100K scans/mo

**Target buyer:** DevSecOps teams running scans on every PR/merge in large engineering organizations, security vendors embedding the API in their own products.

**Comparable:** Lakera's API model (free tier 10K calls; enterprise custom). This pricing sits in the mid-market gap Lakera does not publicly address.

---

### 3.3 Professional Services

**Model:** Time-and-materials or fixed-fee project engagements

**Services:**
- Implementation and onboarding: $15,000-$45,000 (1-3 weeks; connector setup, custom rule authoring, CI/CD integration)
- Custom detection rule development: $5,000-$20,000 per rule set (domain-specific poisoning patterns for finance, healthcare, legal)
- Custom red team engagement: $25,000-$75,000 (adversarial exercise using the 19-technique generator against the client's specific stack)
- Compliance readiness assessment: $20,000-$50,000 (gap analysis + evidence package preparation for EU AI Act or HIPAA)
- Incident response (AI poisoning confirmed): $10,000-$30,000/incident (forensics via proof chains + remediation guidance)

**Estimated contribution:** 15-20% of total revenue, high margin in early growth phase when professional services subsidize customer success costs.

---

### 3.4 Marketplace — Detection Rule and Evasion Technique Packs

**Model:** Third-party security researchers and detection engineers publish rules to a marketplace; revenue split 70/30 (creator/platform)

**Products:**
- Domain-specific detection rule packs: $500-$2,500/pack (e.g., "Healthcare PHI Exfiltration via RAG" rule set)
- Evasion technique packs: $1,000-$5,000/pack (advanced adversarial variants for red team testing)
- Industry threat intelligence feeds: $500/month subscription (updated monthly by security research community)
- Custom automation recipes (remediation playbooks): $250-$1,500 each

**Strategic value:** Builds community, extends detection coverage at near-zero marginal cost, creates network effects (more rules = better product = more customers = more rule authors). Comparable to Snyk's open-source vulnerability database as a moat.

---

### 3.5 Compliance Report Generation

**Model:** Premium feature within Enterprise tier; also available standalone for audit-prep use cases

**Products:**
- EU AI Act Article 9/13/17 evidence package: $500 per report generation (standalone)
- SOC 2 AI Security Addendum report: $350 per report
- HIPAA AI Audit Trail report: $400 per report
- SR 11-7 Model Risk Evidence Package: $600 per report
- Full compliance bundle (all frameworks): $1,200 per generation

**Volume:** An organization audited quarterly across 3 frameworks = ~$5,000/year in report generation revenue above subscription.

---

### 3.6 Training and Certification

**Model:** Self-paced online courses + instructor-led workshops + professional certification

**Products:**
- "AI Poisoning Detection Fundamentals" (self-paced, 4 hours): $299 per seat
- "Certified AI Red Team Operator" (instructor-led, 2 days): $1,499 per seat
- "Enterprise AI Security Implementation" workshop (team, 1 day on-site): $8,000-$15,000
- Annual certification renewal: $99/year

**Target:** AppSec engineers, AI red teamers, compliance teams at enterprise customers and system integrators

**Strategic value:** Creates a certified practitioner community that advocates for the platform, generates leads, and builds switching costs. Comparable to Offensive Security's OSCP certification model applied to AI security.

---

### 3.7 Managed Detection and Response (MDR for AI)

**Model:** Fully managed service where the platform's team monitors customer environments, triages alerts, and coordinates remediation

**Pricing:** $5,000-$20,000/month depending on pipeline count and SLA
- Basic MDR (business hours, 5 pipelines): $5,000/month
- Standard MDR (24/7, 20 pipelines, 4h response SLA): $10,000/month
- Premium MDR (24/7, unlimited, 1h response SLA, dedicated analyst): $20,000/month

**Market context:** MDR market held 27% of managed security services share in 2025, with CAGR of 12.72%. MDR pricing benchmarks: $36,000-$60,000/year for traditional MDR. AI-specific MDR can command a premium given the nascency of the threat category.

**Strategic value:** Converts platform customers into long-term managed service customers. Particularly relevant for mid-market companies that have RAG deployments but lack dedicated AI security staff.

---

### 3.8 White-Label / OEM Licensing

**Model:** License the detection engines and red team generator to be embedded in third-party security platforms

**Target partners:**
- CNAPP vendors (Wiz, Orca, Prisma Cloud) seeking to add LLM poisoning coverage to their platform without building it
- SIEM/SOAR vendors (Splunk, Microsoft Sentinel, CrowdStrike) adding AI threat detection
- GRC platforms (ServiceNow GRC, OneTrust) embedding compliance report generation
- DevSecOps tools (Snyk, Checkmarx) embedding AI supply chain scanning

**Pricing:** $500K-$5M annual OEM license fee + per-scan royalty ($0.01-0.03/scan)

**Strategic value:** OEM licensing to a single major CNAPP or SIEM vendor could generate revenue at 10x the ARR of direct enterprise sales in years 3-5. This is the highest-leverage exit path for acquisition (Wiz acquiring this capability is a direct comparable to HiddenLayer's defense IDIQ positioning).

---

## SECTION 4: POTENTIAL CUSTOMERS

### 4.1 Fortune 500 Companies Deploying LLMs (Priority Targets, 20+)

| Company | Segment | AI Deployment | Poisoning Risk | Urgency |
|---------|---------|--------------|----------------|---------|
| JPMorgan Chase | Financial Services | RAG for trading analytics, fraud detection (Databricks) | SR 11-7 continuous monitoring gap | HIGH |
| Goldman Sachs | Financial Services | LLM for research, internal copilot | SR 11-7 + SEC AI examination | HIGH |
| Bank of America | Financial Services | Erica chatbot RAG expansion | SR 11-7 + customer liability | HIGH |
| UnitedHealth Group | Healthcare | Clinical AI, claims processing RAG | HIPAA 2025 update, PHI exposure | HIGH |
| CVS Health | Healthcare | Pharmacy AI, Aetna claims RAG | HIPAA BAA requirement | HIGH |
| Johnson & Johnson | Healthcare/Pharma | Drug discovery RAG pipelines | FDA SaMD guidance, data poisoning | HIGH |
| Microsoft | Technology | Copilot Enterprise, Azure OpenAI | EU AI Act, MCP vulnerability surface | HIGH |
| Google/Alphabet | Technology | Gemini Enterprise, Vertex AI RAG | EU AI Act, FTC scrutiny | HIGH |
| Amazon/AWS | Technology | Bedrock RAG, Q Business | EU AI Act, FedRAMP | HIGH |
| Meta | Technology | Llama fine-tuning, enterprise RAG | EU AI Act GPAI model obligations | MEDIUM |
| Salesforce | Technology | Einstein GPT RAG, Agentforce | EU AI Act, customer data liability | HIGH |
| ServiceNow | Technology | Now Assist RAG pipelines | Enterprise customer compliance pass-through | MEDIUM |
| Lockheed Martin | Defense | Internal AI/ML pipelines | CMMC, NDAA FY2026 | HIGH |
| Raytheon/RTX | Defense | Defense AI systems | CMMC, classified RAG | HIGH |
| Northrop Grumman | Defense | AI-enabled ISR systems | CMMC, NDAA FY2026 | HIGH |
| Deloitte | Consulting/SI | 100+ AI agents on Google Cloud | Client liability, ISO 42001 | MEDIUM |
| Accenture | Consulting/SI | Frontier Alliance OpenAI partner | Client liability pass-through | MEDIUM |
| Citigroup | Financial Services | LLM for operations, risk | SR 11-7 + DORA (EU) | HIGH |
| Wells Fargo | Financial Services | AI fraud detection, underwriting | SR 11-7 OCC oversight | HIGH |
| Mayo Clinic | Healthcare | Clinical AI RAG, diagnostic tools | HIPAA, FDA SaMD | HIGH |

---

### 4.2 AI-Native Companies (Priority Targets, 15+)

| Company | Why They Need This | Vector Store Used | Urgency |
|---------|-------------------|------------------|---------|
| Anthropic | Claude Enterprise RAG security, model supply chain | Custom / Weaviate | HIGH |
| OpenAI | ChatGPT Enterprise, GPT-4 RAG, MCP server ecosystem | Custom | HIGH |
| Cohere | Enterprise RAG platform (Command R+) | Pinecone / Weaviate | HIGH |
| Mistral AI | EU-based; EU AI Act GPAI obligations | Custom | HIGH |
| Perplexity AI | Web RAG at scale; poisoned source injection risk | Custom | MEDIUM |
| Glean | Enterprise search RAG; knowledge base contamination | Proprietary | HIGH |
| Notion AI | Document RAG; collaborative poisoning surface | Chroma/Pinecone | MEDIUM |
| UiPath | Agentic AI platform; named Noma customer — competitive displacement | Custom | HIGH |
| Weights & Biases | MLOps platform; model registry integrity | Custom | MEDIUM |
| Hugging Face | Model hub; supply chain poisoning at massive scale | Custom | HIGH |
| Pinecone | Vector DB vendor; platform-level poisoning detection partnership potential | Pinecone | MEDIUM |
| LangChain / LangSmith | LLM framework; ecosystem integration partnership | Weaviate/Chroma | HIGH |
| Databricks | Lakehouse AI; MLflow model registry integrity | Proprietary | MEDIUM |
| Snowflake | Cortex AI, RAG on enterprise data | Custom | MEDIUM |
| Scale AI | Training data pipeline; supply chain poisoning at source | Custom | HIGH |

---

### 4.3 Government Agencies (Priority Targets, 10+)

| Agency | Use Case | Compliance Driver | Procurement Path |
|--------|---------|------------------|-----------------|
| Department of Defense (OUSD R&E) | AI/ML system integrity across services | NDAA FY2026 AI security mandate | DFARS, CMMC, IDIQ |
| Missile Defense Agency | Shield IDIQ (HiddenLayer precedent) — competitive bid | CMMC Level 3 | MDA SHIELD IDIQ |
| National Security Agency | Classified RAG pipeline integrity | ITAR, SAP security | Black contract |
| CIA / Intelligence Community | Intelligence analysis RAG | IC security requirements | Other Transaction Authority |
| Department of Veterans Affairs | Clinical AI for veteran healthcare | HIPAA + FedRAMP | VA T4NG |
| Department of Health and Human Services | HHS AI deployments, NIH research | HIPAA, NIST AI RMF | GSA MAS |
| Social Security Administration | Claims processing AI | FedRAMP Moderate | GSA SEWP V |
| CISA | Critical infrastructure AI security tooling | FedRAMP High | DHS EAGLE |
| Department of Energy | Nuclear complex AI system integrity | DOE security, NNSA | DOE IDIQ |
| DARPA | AI red teaming R&D program alignment | OTA, BAA | DARPA OTA / BAA |

---

### 4.4 System Integrators and Consulting Firms (Channel Partners, 10+)

| Firm | AI Practice Scale | Channel Opportunity |
|------|-----------------|---------------------|
| Accenture | Frontier Alliance OpenAI partner; 100K+ AI practitioners | Embed in client deliverables, OEM resell |
| Deloitte | $3B AI investment; 100+ AI agents on Google Cloud | Include in AI security practice offerings |
| KPMG | Google Cloud agentic AI partner | Compliance practice integration |
| PwC | $1B AI investment | AI risk assurance practice |
| Booz Allen Hamilton | Largest defense contractor AI practice | FedRAMP deployment, classified track |
| SAIC | DoD AI systems integrator | CMMC / NDAA compliance |
| Leidos | Intelligence community AI | Classified RAG integrity |
| ManTech | DoD cyber + AI | CMMC Level 3 delivery |
| IBM Consulting | AI security practice | Enterprise and government |
| Capgemini | European enterprise AI | EU AI Act compliance practice |

**Channel model:** 20-30% reseller margin for SIs who embed the platform in their AI security practice and close enterprise contracts. SIs handle the enterprise relationship; the platform provides the technology. This is how Snyk scaled through DevOps toolchain partnerships.

---

### 4.5 Cloud Providers (Partnership and Marketplace Targets)

| Provider | Partnership Opportunity | Status |
|---------|------------------------|--------|
| AWS | AWS Marketplace listing + Bedrock RAG security integration | Priority Year 1 |
| Microsoft Azure | Azure Marketplace + Copilot Studio / Azure AI Foundry security | Priority Year 1 |
| Google Cloud | GCP Marketplace + Vertex AI RAG security integration | Year 1-2 |
| Databricks | Partner program + MLflow integration | Year 2 |
| Snowflake | Cortex AI security partner | Year 2 |

**AWS Marketplace:** AWS's PLG guide for SaaS specifically recommends free trial + freemium listings as the primary growth motion, with 27% of AI application spend now flowing through PLG channels. AWS Seller Prime provides GTM funding for security ISVs.

---

### 4.6 Cybersecurity Vendors (OEM / Integration Targets)

| Vendor | Integration Opportunity | Strategic Value |
|--------|------------------------|----------------|
| Wiz | AI-SPM module to complement existing CNAPP | Acquisition candidate or OEM licensee |
| CrowdStrike | Falcon platform AI detection module | OEM licensing |
| Microsoft Sentinel | SIEM integration for AI threat detection | Distribution at scale |
| Splunk (Cisco) | SIEM/SOAR AI threat intel feed | Distribution at scale |
| Palo Alto Networks (Prisma) | CNAPP AI security extension | OEM or acquisition |
| Checkmarx | AppSec + AI supply chain scanning | Direct integration |
| Snyk | Developer AI security scanning | Integration partnership |
| Veracode | AppSec AI extension | Integration |

---

### 4.7 Companies by Urgency / Pain Point

**Highest urgency — confirmed AI incidents or active regulatory scrutiny:**
- Microsoft (EchoLeak MCP vulnerability affected M365 Copilot — enterprise customers need proof of remediation)
- Any company using Cursor IDE (2025 prompt injection RCE incident)
- Companies using WordPress AI plugins (100K+ sites affected by MCP privilege escalation)
- Asana (tenant isolation flaw affected up to 1,000 enterprises — supply chain incident)

**Highest urgency — EU AI Act deadline (August 2026):**
- All EU-based enterprises deploying high-risk AI (GDPR infrastructure already in place, EU AI Act compliance is the next wave)
- US multinationals with EU operations: Microsoft, Google, Amazon, Salesforce, JPMorgan, Goldman Sachs
- Mistral AI, SAP, Siemens (EU-headquartered, direct obligation)

**Highest urgency — large RAG deployments:**
- Glean (enterprise search is pure RAG at scale — this is their core product security)
- Perplexity AI (web RAG at billion-query scale)
- Any LLM-based customer support platform (Intercom AI, Zendesk AI, Salesforce Agentforce)

**Highest urgency — MCP tool-use agents:**
- Companies building on Claude with MCP (Anthropic's enterprise customers)
- GitHub Copilot Enterprise users (13,000+ MCP servers launched on GitHub in 2025)
- Any company running multi-agent systems with tool-calling (LangGraph, AutoGen deployments)

---

## SECTION 5: GO-TO-MARKET STRATEGY

### 5.1 Motion Architecture: PLG + Enterprise Sales

**Phase 1 (Months 1-12): PLG-Led Developer Adoption**

The free Community tier is the primary growth vehicle. Target:
- Integration into LangChain, LlamaIndex documentation as a recommended security scanning step
- GitHub Actions marketplace listing (one-click scan on PR merge)
- Hugging Face Spaces demo (interactive poisoning demo using the 19-technique generator)
- Blog content targeting OWASP LLM Top 10 keywords (data/model poisoning, RAG security)
- Developer conference presence: DEF CON AI Village, Black Hat AI Security Summit, NeurIPS Security Workshop

**Conversion trigger:** Free tier users hitting scan limits when deploying to production = natural upgrade to Pro.

**Phase 2 (Months 6-18): Enterprise Sales Motion**

- Outbound to CISO/AppSec leads at Fortune 500 companies with confirmed large RAG deployments
- Account-based marketing targeting companies that mentioned LLM/RAG deployments in earnings calls or press releases
- SI channel partnerships (Deloitte, Accenture) to reach enterprise accounts through trusted advisors
- Compliance-anchored landing pages: "EU AI Act compliance in 30 days" — capture buyers on regulatory deadlines

**Phase 3 (Months 12-24): Government Track**

- Engage FedRAMP authorization process (12-18 months; start early)
- SBIR/STTR Phase I/II applications for AI security R&D (DoD, DARPA, DHS CISA)
- Partner with Booz Allen Hamilton or SAIC for federal distribution
- Respond to DARPA AI red teaming BAAs

---

### 5.2 Cloud Marketplace Strategy

AWS, Azure, and GCP marketplaces are non-negotiable distribution channels for enterprise SaaS in 2026. Key facts:
- 27% of AI application spend flows through PLG/marketplace motions
- AWS Seller Prime provides GTM funding and priority placement for security ISVs
- Enterprise procurement teams increasingly prefer marketplace purchases because they draw down existing cloud commitments (EDP/MACC)

**Action:** List on AWS Marketplace as Year 1 priority. Azure Marketplace as Year 1. GCP Year 2.

---

### 5.3 Conference and Community Strategy

| Conference | Target Audience | Action |
|-----------|----------------|--------|
| DEF CON AI Village (August) | AI red teamers, security researchers | Sponsor, present 19-technique generator research |
| Black Hat USA | Enterprise CISO/AppSec | Booth + briefing theater |
| RSA Conference | Enterprise security buyers | Exhibit hall + compliance-focused session |
| NeurIPS / ICML Security Workshops | ML researchers, AI engineers | Paper + demo presence |
| AWS re:Invent | Cloud AI buyers | Marketplace launch + partner session |
| Microsoft Ignite | Azure AI / Copilot users | Azure Marketplace launch |
| HIMSS | Healthcare AI buyers | HIPAA-focused demo |
| Money20/20 | FinServ AI buyers | SR 11-7 compliance messaging |

---

### 5.4 Content and Thought Leadership

The 19-technique red team generator and empirical benchmarks against 8 real datasets are unique assets that can drive organic inbound:
- Publish annual "State of LLM Data Poisoning" report (primary lead generation)
- Open-source a subset of detection rules (community trust building; comparable to CrowdStrike's threat intelligence sharing)
- OWASP contribution — propose addition of "RAG Pipeline Integrity" as formal OWASP LLM control
- Academic papers: submit benchmark results to IEEE S&P, USENIX Security, ACM CCS

---

## SECTION 6: TAM / SAM / SOM ANALYSIS

### 6.1 Total Addressable Market (TAM)

**Method:** Bottom-up aggregation of addressable spend categories

| Market Segment | Market Size (2025/2026) | CAGR | Addressable Fraction |
|---------------|------------------------|------|---------------------|
| LLM Security Platforms | $2.37B (2024) | 21.4% | 100% (direct) |
| AI Red Teaming Services | $1.3B (2025) | 30.5% | 60% (automated portion) |
| Security Posture Management (AI-SPM component) | ~$2B estimate (60% of $3.3B DSPM component) | 37.4% | 30% (LLM-specific) |
| AI Compliance/GRC tooling | ~$500M (2025 estimate) | 25% | 40% |
| MDR/MSSP (AI-specific) | ~$1B (2025 estimate, AI slice of $39.4B) | 15% | 20% |

**TAM calculation:**
- LLM Security: $2.37B * 1.214 (2025 growth) = ~$2.88B
- AI Red Teaming addressable: $1.3B * 0.60 = $780M
- AI-SPM (LLM-specific): ~$600M
- AI Compliance tooling: $200M
- AI MDR: $200M

**Total TAM: approximately $4.7 billion (2025), growing to approximately $9-12 billion by 2028 at blended 25-30% CAGR**

Note: The broader Security Posture Management market ($26.64B in 2025) and AI in Cybersecurity market ($22.4B) represent adjacent expansion opportunities but are not the primary TAM for this product.

---

### 6.2 Serviceable Addressable Market (SAM)

**Method:** TAM filtered by segments the platform can realistically serve given current capabilities (multi-tenant SaaS, 5 engines, compliance reports, no current FedRAMP authorization)

**SAM constraints:**
- Geographic: English-language markets primarily (US, UK, Canada, Australia, EU with English interface)
- Segment: Excludes classified government (pre-FedRAMP), excludes pure on-prem-only requirements
- Competitive: Must have confirmed LLM/RAG deployments (not just AI aspirations)
- Capability: Platforms connecting to Pinecone, Weaviate, Chroma, Qdrant, Milvus, PGVector, Elasticsearch (all supported) — covers 90%+ of enterprise vector store market

**SAM calculation:**
- Fortune 500 with confirmed LLM deployments: 67 companies * ~$75,000 average ACV = ~$5M (100% penetration scenario)
- Fortune 1000 extension: ~200 companies * $50,000 average ACV = $10M
- Mid-market AI-native companies (1,000-10,000 employees, confirmed RAG): ~5,000 companies * $3,600/yr (Pro tier) = $18M
- Healthcare systems (6,000+ in US, 10% AI-active): 600 systems * $25,000/yr = $15M
- Financial institutions (top 200 US banks): 200 * $50,000/yr = $10M
- EU multinationals (EU AI Act exposure): ~500 companies * $40,000/yr = $20M
- System integrator channel: ~$30M in influenced revenue at 20% margin = $6M

**SAM: approximately $84 million (fully developed, 2026)**

This is conservative. The SAM expands significantly upon FedRAMP authorization (adds ~$150M government addressable market) and OEM licensing (adds potentially $100M+).

---

### 6.3 Serviceable Obtainable Market (SOM)

**Method:** Realistic capture given 12-24 month competitive dynamics, team size, and GTM investment

**Year 1 (2026) SOM targets:**
- 200 Pro tier customers * $3,588/yr average = $717,600
- 15 Enterprise tier customers * $60,000/yr average = $900,000
- Professional services (5 engagements): $125,000
- API/per-scan revenue: $50,000

**Year 1 SOM: approximately $1.8M ARR**

**Year 2 (2027) SOM targets:**
- 800 Pro tier customers * $3,588/yr = $2.9M
- 50 Enterprise customers * $70,000/yr = $3.5M
- 2 Government contracts * $200,000/yr = $400,000
- Professional services (20 engagements): $500,000
- MDR customers (5) * $120,000/yr = $600,000
- Marketplace revenue: $150,000

**Year 2 SOM: approximately $8M ARR**

**Year 3 (2028) SOM targets (assuming FedRAMP + OEM partnership):**
- 2,500 Pro customers: $9M
- 150 Enterprise customers: $12M
- 10 Government contracts: $2M
- 1 OEM licensing deal: $2M
- MDR (20 customers): $2.4M
- Professional services + training + marketplace: $2M

**Year 3 SOM: approximately $29M ARR**

**Confidence levels:**
- Year 1 targets: HIGH confidence (conservative; achievable with founder-led sales + PLG)
- Year 2 targets: MEDIUM-HIGH confidence (requires 2-3 enterprise AEs + channel activation)
- Year 3 targets: MEDIUM confidence (depends on FedRAMP timeline and OEM deal closure)

---

## SECTION 7: KEY RISKS AND MITIGATION

| Risk | Severity | Probability | Mitigation |
|------|---------|-------------|-----------|
| Wiz/CrowdStrike/Palo Alto build native LLM poisoning detection | HIGH | MEDIUM (2-3 year lag) | Speed to market + compliance depth as moat; pursue OEM licensing to become the detection layer |
| FedRAMP authorization delay (>18 months) | MEDIUM | HIGH | Partner with FedRAMP-authorized platform (AWS GovCloud) as interim path; pursue OTA contracts with DoD as bridge |
| Enterprise sales cycle length (9-18 months) | MEDIUM | HIGH | PLG + Pro tier generates revenue while enterprise pipeline matures; SI channel accelerates cycles |
| EU AI Act enforcement delayed or weakened | LOW | LOW | Diversified regulatory drivers (HIPAA, SR 11-7, NIST AI RMF, CMMC) reduce single-regulation dependency |
| Model evolution outpaces detection engines | HIGH | MEDIUM | Self-evolution loop is the core differentiator; invest in continuous adversarial research |
| Customer data privacy concerns (scanning prod data) | MEDIUM | MEDIUM | VPC deployment option, no data retention by default, cryptographic proof chains as trust anchors |

---

## SECTION 8: IMMEDIATE PRIORITIES

Based on the research, the following actions are highest-leverage for the next 90 days:

1. **AWS Marketplace listing:** Free tier + Pro tier self-service. Draw down existing AWS commits for enterprise buyers. No FedRAMP required.

2. **EU AI Act compliance landing page:** August 2026 enforcement is 4 months away. "EU AI Act Article 9/13/17 evidence package in 30 minutes" is a high-converting message right now.

3. **LangChain and LlamaIndex integrations:** These are the two dominant RAG framework ecosystems. Being the recommended security scanner in their documentation is equivalent to Snyk being in the npm/pip flow.

4. **Target Glean, Cohere, and Scale AI as lighthouse customers:** AI-native, confirmed large RAG deployments, no natural incumbent for poisoning detection.

5. **DARPA BAA monitoring:** DARPA regularly issues AI red teaming and AI security BAAs. The 19-technique generator with empirical benchmarks is competitive for Phase I SBIR ($50K-$300K non-dilutive).

6. **Deloitte/Accenture partnership outreach:** Both firms are actively building AI security practices and need technical tooling to put behind their consulting engagements. A channel deal with either generates enterprise ACV without hiring an enterprise sales team.

---

## DATA SOURCES AND CONFIDENCE RATINGS

| Finding | Source | Confidence |
|---------|--------|------------|
| SPM market $53.31B by 2030 | MarketsandMarkets | HIGH |
| LLM Security Platforms $2.37B, 21.4% CAGR | Growth Market Reports | MEDIUM (single source) |
| AI Red Teaming Services $1.3B, 30.5% CAGR | Market.us | MEDIUM (single source) |
| Noma 1,300% ARR growth, $100M Series B | SecurityWeek, BankInfoSecurity | HIGH |
| Lakera free tier 10K calls/mo | Lakera platform, eesel.ai | HIGH |
| Snyk $25/dev/mo Team, $52-98/dev/mo Enterprise | Snyk.io, Vendr | HIGH |
| Wiz $38,000/yr Advanced | CSO Online AI-SPM Buyers Guide | HIGH |
| Orca $84,000-$360,000/yr | CSO Online AI-SPM Buyers Guide | HIGH |
| EU AI Act August 2026 enforcement | EC official, Greenberg Traurig | HIGH |
| NDAA FY2026 AI security mandate | Government Contracts Legal Forum | HIGH |
| 67 Fortune 500 confirmed LLM deployments | Bloomberry analysis | MEDIUM |
| MDR $36K-$60K/yr pricing | PetronellaTech | MEDIUM |
| HIPAA 2025 Security Rule update | HHS OCR, HIPAA Journal | HIGH |
| MCP 13,000+ servers on GitHub in 2025 | eSentire, Checkmarx Zero | HIGH |
| 27% AI spend via PLG channels | UserGuiding / Menlo Ventures | MEDIUM |

---

*Report compiled by Market Research Division, AI Cowboys Workforce v14.0*
*Data current as of April 2026. All market sizing figures are estimates from third-party research firms and should be independently verified for investor or board-level use.*
