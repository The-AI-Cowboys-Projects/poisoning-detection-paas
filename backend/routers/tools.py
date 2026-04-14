"""
MCP tool auditing router.

POST /api/v1/tools/audit    — audit an MCP tool schema and description
GET  /api/v1/tools/{scan_id} — retrieve a previous audit result
GET  /api/v1/tools           — list audit results (paginated)
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.middleware.auth import get_current_tenant, rate_limiter
from backend.models.database import get_db
from backend.models.detection import MCPToolAuditResult, MCPVerdict
from backend.models.schemas import (
    DetectionResponse,
    Finding,
    MCPToolSubmission,
    PaginatedResponse,
)
from backend.models.tenant import Tenant

logger = logging.getLogger(__name__)
router = APIRouter()

# Pre-compiled for performance — compiled once at module load
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")


def _count_base64_tokens(text: str) -> tuple[int, int]:
    """Return (base64_token_count, total_token_count)."""
    tokens = text.split()
    b64_count = sum(1 for t in tokens if _BASE64_RE.match(t))
    return b64_count, len(tokens)


def _schema_depth(obj: Any, current: int = 0) -> int:
    """Recursively compute maximum JSON nesting depth."""
    if isinstance(obj, dict):
        if not obj:
            return current
        return max(_schema_depth(v, current + 1) for v in obj.values())
    if isinstance(obj, list):
        if not obj:
            return current
        return max(_schema_depth(item, current + 1) for item in obj)
    return current


def _count_schema_fields(obj: Any) -> int:
    """Count total number of leaf fields in a JSON schema."""
    if isinstance(obj, dict):
        return sum(_count_schema_fields(v) for v in obj.values()) or 1
    if isinstance(obj, list):
        return sum(_count_schema_fields(item) for item in obj)
    return 1


def _audit_tool(
    submission: MCPToolSubmission,
    patterns: list[str],
    max_desc_len: int,
    base64_threshold: float,
    max_depth: int,
    max_fields: int,
) -> dict:
    """
    Pure-function MCP tool audit.

    Checks performed (each contributes to risk_score):
    1. Description length excess (weight 0.2)
    2. Base64 token ratio (weight 0.3)
    3. Hidden instruction patterns (weight 0.4 per match, capped at 1.0)
    4. Schema depth anomaly (weight 0.15)
    5. Schema field count anomaly (weight 0.1)

    Returns dict compatible with MCPToolAuditResult columns plus 'findings'.
    """
    findings: list[dict] = []
    hidden_instructions: list[str] = []
    schema_anomalies: list[str] = []
    base64_detected = False
    risk_components: list[float] = []

    full_text = submission.description

    # 1. Description length
    if len(full_text) > max_desc_len:
        excess = len(full_text) - max_desc_len
        risk_components.append(min(0.2, 0.2 * excess / max_desc_len))
        findings.append(
            {
                "rule": "excessive_description_length",
                "severity": "medium",
                "excerpt": full_text[:200],
                "position": max_desc_len,
                "details": {"length": len(full_text), "limit": max_desc_len},
            }
        )

    # 2. Base64 token ratio
    b64_count, total_tokens = _count_base64_tokens(full_text)
    if total_tokens > 0:
        b64_ratio = b64_count / total_tokens
        if b64_ratio >= base64_threshold:
            base64_detected = True
            risk_components.append(min(0.35, b64_ratio))
            findings.append(
                {
                    "rule": "base64_payload_detected",
                    "severity": "high",
                    "excerpt": None,
                    "position": None,
                    "details": {"b64_ratio": b64_ratio, "threshold": base64_threshold},
                }
            )

    # 3. Hidden instruction pattern matching
    for raw_pattern in patterns:
        try:
            compiled = re.compile(raw_pattern, re.IGNORECASE | re.DOTALL)
        except re.error:
            continue
        for match in compiled.finditer(full_text):
            hidden_instructions.append(match.group(0)[:300])
            findings.append(
                {
                    "rule": "hidden_instruction_pattern",
                    "severity": "critical",
                    "excerpt": match.group(0)[:200],
                    "position": match.start(),
                    "details": {"pattern": raw_pattern},
                }
            )
            risk_components.append(0.4)

    # 4. Schema depth
    combined_schema = {**submission.schema, **submission.parameters}
    depth = _schema_depth(combined_schema)
    if depth > max_depth:
        schema_anomalies.append(f"schema_depth:{depth}")
        risk_components.append(min(0.15, 0.15 * depth / max_depth))
        findings.append(
            {
                "rule": "schema_depth_anomaly",
                "severity": "low",
                "excerpt": None,
                "position": None,
                "details": {"depth": depth, "limit": max_depth},
            }
        )

    # 5. Schema field count
    field_count = _count_schema_fields(combined_schema)
    if field_count > max_fields:
        schema_anomalies.append(f"schema_fields:{field_count}")
        risk_components.append(min(0.1, 0.1 * field_count / max_fields))
        findings.append(
            {
                "rule": "schema_field_count_anomaly",
                "severity": "low",
                "excerpt": None,
                "position": None,
                "details": {"field_count": field_count, "limit": max_fields},
            }
        )

    # Composite risk score (capped at 1.0)
    risk_score = min(1.0, sum(risk_components))

    # Verdict
    if risk_score >= 0.7 or any(f["severity"] == "critical" for f in findings):
        verdict = MCPVerdict.CRITICAL.value
    elif risk_score >= 0.3:
        verdict = MCPVerdict.WARNING.value
    else:
        verdict = MCPVerdict.SAFE.value

    return {
        "risk_score": risk_score,
        "findings": findings,
        "hidden_instructions": hidden_instructions if hidden_instructions else None,
        "base64_detected": base64_detected,
        "schema_anomalies": schema_anomalies if schema_anomalies else None,
        "verdict": verdict,
    }


@router.post(
    "/audit",
    response_model=DetectionResponse,
    status_code=status.HTTP_200_OK,
    summary="Audit an MCP tool schema for injection and exfiltration risks",
)
async def audit_tool(
    body: MCPToolSubmission,
    request: Annotated[object, Depends(lambda r: r)],
    tenant: Annotated[Tenant, Depends(get_current_tenant)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> DetectionResponse:
    from backend.config import get_settings
    from fastapi import Request

    settings = get_settings()
    if isinstance(request, Request):
        await rate_limiter.check(tenant, request)

    audit = _audit_tool(
        submission=body,
        patterns=settings.mcp.suspicious_instruction_patterns,
        max_desc_len=settings.mcp.max_description_length,
        base64_threshold=settings.mcp.base64_pattern_threshold,
        max_depth=settings.mcp.max_parameter_depth,
        max_fields=settings.mcp.max_schema_fields,
    )

    record = MCPToolAuditResult(
        tenant_id=tenant.id,
        tool_name=body.tool_name,
        tool_uri=body.tool_uri,
        timestamp=datetime.now(tz=timezone.utc),
        risk_score=audit["risk_score"],
        findings=audit["findings"],
        hidden_instructions=audit["hidden_instructions"],
        base64_detected=audit["base64_detected"],
        schema_anomalies=audit["schema_anomalies"],
        verdict=audit["verdict"],
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)

    findings = [
        Finding(
            rule=f["rule"],
            severity=f["severity"],
            excerpt=f.get("excerpt"),
            position=f.get("position"),
            details=f.get("details", {}),
        )
        for f in (audit["findings"] or [])
    ]

    return DetectionResponse(
        scan_id=record.id,
        status=audit["verdict"],
        risk_score=audit["risk_score"],
        findings=findings,
        timestamp=record.timestamp,
        tool_name=body.tool_name,
    )


@router.get(
    "/{scan_id}",
    response_model=DetectionResponse,
    summary="Retrieve a tool audit result",
)
async def get_tool_result(
    scan_id: uuid.UUID,
    tenant: Annotated[Tenant, Depends(get_current_tenant)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> DetectionResponse:
    result = await db.execute(
        select(MCPToolAuditResult).where(
            MCPToolAuditResult.id == scan_id,
            MCPToolAuditResult.tenant_id == tenant.id,
        )
    )
    record = result.scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found.")

    return DetectionResponse(
        scan_id=record.id,
        status=record.verdict,
        risk_score=record.risk_score,
        findings=[],
        timestamp=record.timestamp,
        tool_name=record.tool_name,
    )


@router.get(
    "",
    response_model=PaginatedResponse,
    summary="List MCP tool audit results",
)
async def list_tool_results(
    tenant: Annotated[Tenant, Depends(get_current_tenant)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> PaginatedResponse:
    offset = (page - 1) * page_size

    count_result = await db.execute(
        select(func.count()).select_from(MCPToolAuditResult).where(
            MCPToolAuditResult.tenant_id == tenant.id
        )
    )
    total = count_result.scalar_one()

    rows_result = await db.execute(
        select(MCPToolAuditResult)
        .where(MCPToolAuditResult.tenant_id == tenant.id)
        .order_by(MCPToolAuditResult.timestamp.desc())
        .offset(offset)
        .limit(page_size)
    )
    rows = list(rows_result.scalars().all())

    items = [
        DetectionResponse(
            scan_id=r.id,
            status=r.verdict,
            risk_score=r.risk_score,
            findings=[],
            timestamp=r.timestamp,
            tool_name=r.tool_name,
        )
        for r in rows
    ]

    return PaginatedResponse(items=items, total=total, page=page, page_size=page_size, total_pages=1)
