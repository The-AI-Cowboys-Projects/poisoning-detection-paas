"""
RAG document scanning router.

POST /api/v1/rag/scan      — scan a document for contamination
GET  /api/v1/rag/{scan_id} — retrieve a previous scan result
GET  /api/v1/rag           — list scan results (paginated)
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Annotated

import numpy as np
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.middleware.auth import get_current_tenant, rate_limiter
from backend.models.database import get_db
from backend.models.detection import RAGDocumentScan
from backend.models.schemas import (
    DetectionResponse,
    Finding,
    PaginatedResponse,
    RAGDocumentSubmission,
)
from backend.models.tenant import Tenant

logger = logging.getLogger(__name__)
router = APIRouter()

# Known attack signatures for heuristic pattern matching
_ATTACK_PATTERNS: dict[str, list[str]] = {
    "anchor_poisoning": [
        "ignore previous instructions",
        "you must now",
        "assistant:",
        "[system]",
    ],
    "bad_actor_insert": [
        "exfiltrate",
        "send to",
        "http://",
        "https://",
        "base64",
        "eval(",
    ],
    "gradient_attack": [],  # Detected geometrically, not lexically
}


def _detect_attack_type(content: str, cosine_deviation: float) -> str | None:
    """
    Heuristic attack type classification.

    Returns a named attack type string or None if no signature matched.
    Gradient attacks are identified purely by geometric anomaly.
    """
    content_lower = content.lower()
    for attack_type, patterns in _ATTACK_PATTERNS.items():
        if attack_type == "gradient_attack":
            # Geometric signal: very high deviation with otherwise normal text
            if cosine_deviation > 0.6:
                return "gradient_attack"
            continue
        if any(p in content_lower for p in patterns):
            return attack_type
    return None


def _compute_perplexity_estimate(content: str) -> float:
    """
    Lightweight perplexity proxy based on character n-gram entropy.

    A real implementation would use an LM; this heuristic provides a useful
    signal for obviously crafted text (very repetitive = low entropy = low
    perplexity) without requiring an inference call.

    Returns a value in [0, 1] where lower = more suspicious.
    """
    if not content:
        return 0.0
    # Character bigram entropy
    bigrams: dict[str, int] = {}
    for i in range(len(content) - 1):
        bg = content[i : i + 2]
        bigrams[bg] = bigrams.get(bg, 0) + 1
    total = sum(bigrams.values())
    if total == 0:
        return 0.0
    import math
    entropy = -sum((c / total) * math.log2(c / total) for c in bigrams.values() if c > 0)
    # Normalise to [0, 1]; typical English bigram entropy ~4.5 bits
    return min(1.0, entropy / 6.0)


def _analyze_document(
    submission: RAGDocumentSubmission,
    cosine_threshold: float,
    dispersion_sigma: float,
    reference_centroid: list[float] | None = None,
) -> dict:
    """
    Pure-function document contamination analysis.

    Without a reference centroid (first document for a tenant), the cosine
    deviation is set to 0.0 — the document becomes the reference point.
    """
    emb = np.array(submission.embedding, dtype=np.float32)
    emb_norm = float(np.linalg.norm(emb))

    cosine_deviation = 0.0
    if reference_centroid is not None:
        ref = np.array(reference_centroid, dtype=np.float32)
        ref_norm = float(np.linalg.norm(ref))
        if emb_norm > 1e-9 and ref_norm > 1e-9:
            similarity = float(np.dot(emb / emb_norm, ref / ref_norm))
            cosine_deviation = 1.0 - max(-1.0, min(1.0, similarity))

    perplexity = _compute_perplexity_estimate(submission.content)
    # Semantic coherence proxy: inverse of cosine_deviation
    semantic_coherence = 1.0 - cosine_deviation

    attack_type = _detect_attack_type(submission.content, cosine_deviation)

    # Flagging logic: any signal beyond threshold OR known attack pattern
    is_flagged = (
        cosine_deviation > (1.0 - cosine_threshold)
        or perplexity < 0.15  # suspiciously low entropy
        or attack_type is not None
    )

    return {
        "cosine_deviation": cosine_deviation,
        "perplexity_score": perplexity,
        "semantic_coherence": semantic_coherence,
        "is_flagged": is_flagged,
        "attack_type_detected": attack_type,
    }


@router.post(
    "/scan",
    response_model=DetectionResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan a RAG document for contamination",
)
async def scan_document(
    body: RAGDocumentSubmission,
    request: Annotated[object, Depends(lambda r: r)],
    tenant: Annotated[Tenant, Depends(get_current_tenant)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> DetectionResponse:
    from backend.config import get_settings
    from fastapi import Request

    settings = get_settings()
    if isinstance(request, Request):
        await rate_limiter.check(tenant, request)

    analysis = _analyze_document(
        submission=body,
        cosine_threshold=settings.vector.cosine_similarity_threshold,
        dispersion_sigma=settings.vector.dispersion_sigma,
    )

    record = RAGDocumentScan(
        tenant_id=tenant.id,
        document_id=body.document_id,
        source_uri=body.source_uri,
        timestamp=datetime.now(tz=timezone.utc),
        **analysis,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)

    findings: list[Finding] = []
    if analysis["is_flagged"]:
        findings.append(
            Finding(
                rule="rag_contamination_detected",
                severity="high" if analysis["attack_type_detected"] else "medium",
                excerpt=body.content[:300] if body.content else None,
                details={
                    "cosine_deviation": analysis["cosine_deviation"],
                    "perplexity_score": analysis["perplexity_score"],
                    "attack_type": analysis["attack_type_detected"],
                },
            )
        )

    risk_score = min(
        1.0,
        analysis["cosine_deviation"] * 0.5
        + (1.0 - analysis["perplexity_score"]) * 0.3
        + (0.2 if analysis["attack_type_detected"] else 0.0),
    )
    verdict = "poisoned" if risk_score >= 0.7 else ("suspicious" if risk_score >= 0.3 else "clean")

    return DetectionResponse(
        scan_id=record.id,
        status=verdict,
        risk_score=risk_score,
        findings=findings,
        timestamp=record.timestamp,
        document_id=body.document_id,
    )


@router.get(
    "/{scan_id}",
    response_model=DetectionResponse,
    summary="Retrieve a RAG document scan result",
)
async def get_rag_result(
    scan_id: uuid.UUID,
    tenant: Annotated[Tenant, Depends(get_current_tenant)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> DetectionResponse:
    result = await db.execute(
        select(RAGDocumentScan).where(
            RAGDocumentScan.id == scan_id,
            RAGDocumentScan.tenant_id == tenant.id,
        )
    )
    record = result.scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    risk_score = min(
        1.0,
        record.cosine_deviation * 0.5
        + (1.0 - record.perplexity_score) * 0.3
        + (0.2 if record.attack_type_detected else 0.0),
    )
    verdict = "poisoned" if risk_score >= 0.7 else ("suspicious" if risk_score >= 0.3 else "clean")

    return DetectionResponse(
        scan_id=record.id,
        status=verdict,
        risk_score=risk_score,
        findings=[],
        timestamp=record.timestamp,
        document_id=record.document_id,
    )


@router.get(
    "",
    response_model=PaginatedResponse,
    summary="List RAG document scan results",
)
async def list_rag_results(
    tenant: Annotated[Tenant, Depends(get_current_tenant)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    flagged_only: bool = Query(default=False),
) -> PaginatedResponse:
    offset = (page - 1) * page_size
    base_filter = [RAGDocumentScan.tenant_id == tenant.id]
    if flagged_only:
        base_filter.append(RAGDocumentScan.is_flagged.is_(True))

    count_result = await db.execute(
        select(func.count()).select_from(RAGDocumentScan).where(*base_filter)
    )
    total = count_result.scalar_one()

    rows_result = await db.execute(
        select(RAGDocumentScan)
        .where(*base_filter)
        .order_by(RAGDocumentScan.timestamp.desc())
        .offset(offset)
        .limit(page_size)
    )
    rows = list(rows_result.scalars().all())

    items = [
        DetectionResponse(
            scan_id=r.id,
            status="flagged" if r.is_flagged else "clean",
            risk_score=min(1.0, r.cosine_deviation * 0.5),
            findings=[],
            timestamp=r.timestamp,
            document_id=r.document_id,
        )
        for r in rows
    ]

    return PaginatedResponse(items=items, total=total, page=page, page_size=page_size, total_pages=1)
