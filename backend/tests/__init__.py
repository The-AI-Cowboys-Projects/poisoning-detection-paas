"""
Test suite for the LLM Data Poisoning Detection PaaS backend.

Structure:
  conftest.py              -- shared fixtures (async client, tenant, vectors, schemas, mocks)
  test_vector_analyzer.py  -- unit tests for VectorIntegrityAnalyzer
  test_rag_analyzer.py     -- unit tests for RAGPoisoningDetector
  test_mcp_auditor.py      -- unit tests for MCPToolAuditor
  test_api_routes.py       -- integration tests against the full FastAPI app
"""
