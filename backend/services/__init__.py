"""
Detection engine services for the LLM Data Poisoning Detection PaaS.

This package contains the core analysis engines:

- **VectorIntegrityAnalyzer** -- cosine-dispersion anomaly detection on embedding
  vectors to surface RAG poisoning candidates.
- **RAGPoisoningDetector** -- multi-signal document scanner (perplexity, entropy,
  homoglyph, hidden-instruction, semantic-coherence).
- **MCPToolAuditor** -- static analysis of MCP tool schemas for sleeper-agent
  triggers, base64 exfiltration payloads, and structural manipulation.
- **ProvenanceTracker** -- Neo4j-backed lineage graph for synthetic-data provenance
  and contamination propagation detection.
- **ThreatAggregator** -- weighted fusion of all engine outputs into a single
  prioritised threat report per tenant.

All public methods that touch I/O are ``async``.  Pure-math helpers are synchronous
so they can be tested without an event loop.
"""

from backend.services.vector_analyzer import VectorIntegrityAnalyzer
from backend.services.rag_analyzer import RAGPoisoningDetector
from backend.services.mcp_auditor import MCPToolAuditor
from backend.services.provenance_tracker import ProvenanceTracker
from backend.services.threat_aggregator import ThreatAggregator
from backend.services.telemetry_simulator import TelemetrySimulator

__all__ = [
    "VectorIntegrityAnalyzer",
    "RAGPoisoningDetector",
    "MCPToolAuditor",
    "ProvenanceTracker",
    "ThreatAggregator",
    "TelemetrySimulator",
]
