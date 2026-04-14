"""
Vector analysis router.

POST /api/v1/vectors/analyze    — submit a vector batch for dispersion analysis
GET  /api/v1/vectors/{scan_id}  — retrieve a previous analysis result
GET  /api/v1/vectors            — list results for the current tenant (paginated)
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
from backend.models.detection import VectorAnalysisResult, VectorStatus
from backend.models.schemas import (
    DetectionResponse,
    Finding,
    PaginatedResponse,
    VectorSubmission,
)
from backend.models.tenant import Tenant

logger = logging.getLogger(__name__)
router = APIRouter()


def _analyze_vectors(
    vectors: list[list[float]],
    cosine_threshold: float,
    dispersion_sigma: float,
    min_baseline: int,
) -> dict:
    """
    Pure-function cosine-dispersion analysis.

    Algorithm:
    1. Compute centroid (mean vector).
    2. Compute cosine similarity of each vector to the centroid.
    3. Convert to dispersion (1 - similarity).
    4. Compute mean and std of dispersion.
    5. Flag vectors whose similarity < threshold OR z-score > dispersion_sigma.
    6. Compute anomaly_score as weighted combination of flag rate and max z-score.

    Returns a dict compatible with VectorAnalysisResult columns.
    """
    arr = np.array(vectors, dtype=np.float32)
    n, dim = arr.shape

    # Centroid
    centroid = arr.mean(axis=0)
    centroid_norm = np.linalg.norm(centroid)

    # Cosine similarities
    norms = np.linalg.norm(arr, axis=1, keepdims=True)
    # Avoid division by zero for zero vectors
    norms = np.where(norms == 0, 1e-9, norms)
    normalised = arr / norms

    if centroid_norm < 1e-9:
        # Degenerate case — all vectors are near-zero
        similarities = np.zeros(n, dtype=np.float32)
    else:
        centroid_unit = centroid / centroid_norm
        similarities = (normalised @ centroid_unit).clip(-1.0, 1.0)

    dispersions = 1.0 - similarities
    mean_disp = float(dispersions.mean())
    std_disp = float(dispersions.std()) if n > 1 else 0.0
    max_disp = float(dispersions.max())

    # Z-scores (avoid div by zero)
    if std_disp > 1e-9:
        z_scores = (dispersions - mean_disp) / std_disp
    else:
        z_scores = np.zeros(n, dtype=np.float32)

    # Flag vectors
    below_threshold = similarities < cosine_threshold
    high_zscore = z_scores > dispersion_sigma
    flagged_mask = below_threshold | high_zscore
    flagged_count = int(flagged_mask.sum())

    # Anomaly score: blend of flag rate and normalised max z-score
    flag_rate = flagged_count / n
    max_z = float(z_scores.max()) if n > 0 else 0.0
    normalised_z = min(max_z / max(dispersion_sigma, 1.0), 1.0)
    anomaly_score = float(0.6 * flag_rate + 0.4 * normalised_z)

    # Verdict
    if n < min_baseline:
        verdict = VectorStatus.INSUFFICIENT_DATA.value
    elif anomaly_score >= 0.7:
        verdict = VectorStatus.POISONED.value
    elif anomaly_score >= 0.3:
        verdict = VectorStatus.SUSPICIOUS.value
    else:
        verdict = VectorStatus.CLEAN.value

    # Top-10 outliers for the details blob
    top_indices = np.argsort(dispersions)[-10:][::-1].tolist()
    top_outliers = [
        {
            "index": int(i),
            "dispersion": float(dispersions[i]),
            "cosine_similarity": float(similarities[i]),
            "z_score": float(z_scores[i]),
        }
        for i in top_indices
    ]

    return {
        "total_vectors": n,
        "flagged_vectors": flagged_count,
        "mean_dispersion": mean_disp,
        "max_dispersion": max_disp,
        "anomaly_score": anomaly_score,
        "status": verdict,
        "details": {
            "std_dispersion": std_disp,
            "centroid_norm": float(centroid_norm),
            "embedding_dimension": dim,
            "cosine_threshold_used": cosine_threshold,
            "sigma_used": dispersion_sigma,
            "top_outliers": top_outliers,
        },
    }


@router.post(
    "/analyze",
    response_model=DetectionResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze a vector batch for poisoning anomalies",
)
async def analyze_vectors(
    body: VectorSubmission,
    request: Annotated[object, Depends(lambda r: r)],
    tenant: Annotated[Tenant, Depends(get_current_tenant)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> DetectionResponse:
    """
    Submit a batch of embedding vectors for cosine-dispersion analysis.

    The service:
    1. Validates dimension consistency.
    2. Computes centroid and per-vector dispersion.
    3. Flags outliers against configured thresholds.
    4. Persists the result and returns a DetectionResponse.
    """
    from backend.config import get_settings
    from fastapi import Request

    settings = get_settings()

    # Rate-limit check
    if isinstance(request, Request):
        await rate_limiter.check(tenant, request)

    # Dimension bounds check
    dim = body.dimension
    if dim < settings.vector.embedding_dimension_min or dim > settings.vector.embedding_dimension_max:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Embedding dimension {dim} out of allowed range "
                f"[{settings.vector.embedding_dimension_min}, "
                f"{settings.vector.embedding_dimension_max}]."
            ),
        )
    if len(body.vectors) > settings.vector.max_vectors_per_submission:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Submission exceeds maximum of {settings.vector.max_vectors_per_submission} vectors.",
        )

    try:
        analysis = _analyze_vectors(
            body.vectors,
            cosine_threshold=settings.vector.cosine_similarity_threshold,
            dispersion_sigma=settings.vector.dispersion_sigma,
            min_baseline=settings.vector.min_baseline_samples,
        )
    except Exception as exc:
        logger.error("Vector analysis failed for tenant %s: %s", tenant.id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis computation failed.",
        ) from exc

    record = VectorAnalysisResult(
        tenant_id=tenant.id,
        dataset_id=body.dataset_id,
        timestamp=datetime.now(tz=timezone.utc),
        **analysis,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)

    # Build findings list for the response
    findings: list[Finding] = []
    if analysis["flagged_vectors"] > 0:
        findings.append(
            Finding(
                rule="cosine_dispersion_threshold",
                severity="high" if analysis["status"] == VectorStatus.POISONED.value else "medium",
                excerpt=f"{analysis['flagged_vectors']} of {analysis['total_vectors']} vectors flagged",
                details={
                    "flagged_count": analysis["flagged_vectors"],
                    "mean_dispersion": analysis["mean_dispersion"],
                    "max_dispersion": analysis["max_dispersion"],
                },
            )
        )

    return DetectionResponse(
        scan_id=record.id,
        status=analysis["status"],
        risk_score=analysis["anomaly_score"],
        findings=findings,
        timestamp=record.timestamp,
        dataset_id=body.dataset_id,
    )


@router.get(
    "/{scan_id}",
    response_model=DetectionResponse,
    summary="Retrieve a vector analysis result",
)
async def get_vector_result(
    scan_id: uuid.UUID,
    tenant: Annotated[Tenant, Depends(get_current_tenant)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> DetectionResponse:
    result = await db.execute(
        select(VectorAnalysisResult).where(
            VectorAnalysisResult.id == scan_id,
            VectorAnalysisResult.tenant_id == tenant.id,
        )
    )
    record = result.scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    return DetectionResponse(
        scan_id=record.id,
        status=record.status,
        risk_score=record.anomaly_score,
        findings=[],
        timestamp=record.timestamp,
        dataset_id=record.dataset_id,
    )


@router.get(
    "",
    response_model=PaginatedResponse,
    summary="List vector analysis results for current tenant",
)
async def list_vector_results(
    tenant: Annotated[Tenant, Depends(get_current_tenant)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> PaginatedResponse:
    offset = (page - 1) * page_size

    count_result = await db.execute(
        select(func.count()).select_from(VectorAnalysisResult).where(
            VectorAnalysisResult.tenant_id == tenant.id
        )
    )
    total = count_result.scalar_one()

    rows_result = await db.execute(
        select(VectorAnalysisResult)
        .where(VectorAnalysisResult.tenant_id == tenant.id)
        .order_by(VectorAnalysisResult.timestamp.desc())
        .offset(offset)
        .limit(page_size)
    )
    rows = list(rows_result.scalars().all())

    items = [
        DetectionResponse(
            scan_id=r.id,
            status=r.status,
            risk_score=r.anomaly_score,
            findings=[],
            timestamp=r.timestamp,
            dataset_id=r.dataset_id,
        )
        for r in rows
    ]

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=1,  # recomputed by model_validator
    )
