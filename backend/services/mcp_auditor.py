"""
MCP Tool Schema Auditor
========================

Static analysis of MCP (Model Context Protocol) tool schemas for sleeper-agent
triggers, backdoors, and adversarial manipulation.

Detection capabilities:

1. **Description length anomaly** -- excessively long descriptions are a
   hallmark of prompt-injection-via-tool-description attacks.
2. **Base64 encoded strings** -- hidden payloads embedded in schema fields.
3. **Hidden instruction detection** -- behavioral instructions smuggled
   into description text.
4. **Schema structural validation** -- checks against MCP specification
   for structural manipulation (infinite nesting, type confusion).
5. **Parameter type confusion** -- parameters declared with one type but
   whose default/enum values suggest a different type.
6. **Recursive depth analysis** -- prevents denial-of-service through
   deeply nested schemas.
7. **Unicode / invisible character scanning** -- invisible content in any
   string field.
8. **Behavioral instruction extraction** -- isolates imperative sentences
   that attempt to alter model behavior.
9. **Known malicious patterns** -- cross-references a database of known
   attack signatures.
10. **Rug-pull indicators** -- detects schema features that could allow
    post-approval mutation (e.g., ``$ref`` to external URLs, ``oneOf``
    with wildcard branches).

The composite risk score is a weighted sum of all findings, normalised to
[0.0, 1.0] where 1.0 is critical risk.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(str, Enum):
    """Category for an individual audit finding."""
    DESCRIPTION_ANOMALY = "description_anomaly"
    BASE64_PAYLOAD = "base64_payload"
    HIDDEN_INSTRUCTION = "hidden_instruction"
    SCHEMA_VIOLATION = "schema_violation"
    TYPE_CONFUSION = "type_confusion"
    DEPTH_VIOLATION = "depth_violation"
    INVISIBLE_UNICODE = "invisible_unicode"
    BEHAVIORAL_INSTRUCTION = "behavioral_instruction"
    KNOWN_MALICIOUS_PATTERN = "known_malicious_pattern"
    RUG_PULL_INDICATOR = "rug_pull_indicator"


@dataclass(frozen=True, slots=True)
class MCPAuditConfig:
    """Configuration for the MCP tool auditor.

    Attributes:
        max_description_length: Descriptions longer than this are flagged.
        base64_min_length: Minimum length for a base64 candidate string.
        max_schema_depth: Maximum allowed JSON schema nesting depth.
        max_schema_fields: Maximum number of properties before flagging.
        suspicious_patterns: Regex patterns for hidden instruction detection.
    """
    max_description_length: int = 2000
    base64_min_length: int = 20
    max_schema_depth: int = 5
    max_schema_fields: int = 50
    suspicious_patterns: tuple[str, ...] = (
        r"ignore\s+(previous|all|above|prior)\s+instructions",
        r"system\s*prompt",
        r"you\s+are\s+now",
        r"disregard",
        r"<\|.*?\|>",
        r"\[INST\]",
        r"###\s*(human|assistant|system)\s*:",
        r"do\s+not\s+tell\s+the\s+user",
        r"secretly",
        r"override\s+(all|any|the)\s+(safety|security|rules|restrictions)",
        r"act\s+as\s+(if|though)\s+you\s+(are|were)",
        r"pretend\s+(to\s+be|you\s+are)",
    )


@dataclass(slots=True)
class Base64Finding:
    """A base64-encoded string detected in a schema field.

    Attributes:
        field_path: JSON path to the field containing the base64 string.
        encoded_text: The raw base64 string (truncated for display).
        decoded_content: Decoded UTF-8 content.
        severity: Assessed severity.
    """
    field_path: str
    encoded_text: str
    decoded_content: str
    severity: Severity


@dataclass(slots=True)
class DescriptionAnalysis:
    """Analysis result for a tool description field.

    Attributes:
        length: Character count.
        is_anomalous: Whether the length or content is suspicious.
        hidden_instruction_count: Number of hidden instructions found.
        behavioral_instruction_count: Number of behavioral directives found.
        invisible_char_count: Number of invisible Unicode characters.
        reasons: Human-readable explanation strings.
    """
    length: int
    is_anomalous: bool
    hidden_instruction_count: int
    behavioral_instruction_count: int
    invisible_char_count: int
    reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SchemaViolation:
    """A structural violation in the MCP tool schema.

    Attributes:
        path: JSON path to the violating element.
        violation_type: Type of violation.
        description: Human-readable explanation.
        severity: Assessed severity.
    """
    path: str
    violation_type: str
    description: str
    severity: Severity


@dataclass(slots=True)
class RugPullIndicator:
    """An indicator that a tool schema may mutate after approval.

    Attributes:
        path: JSON path to the suspicious element.
        indicator_type: Category of the indicator.
        description: Human-readable explanation.
        severity: Assessed severity.
    """
    path: str
    indicator_type: str
    description: str
    severity: Severity


@dataclass(slots=True)
class AuditFinding:
    """A single finding from the MCP audit.

    Attributes:
        category: Finding category.
        severity: Assessed severity.
        description: Human-readable explanation.
        field_path: JSON path to the offending field (if applicable).
        evidence: Raw evidence string.
    """
    category: FindingCategory
    severity: Severity
    description: str
    field_path: str = ""
    evidence: str = ""


@dataclass(slots=True)
class MCPAuditReport:
    """Complete report from auditing a single MCP tool definition.

    Attributes:
        tool_name: Name of the audited tool.
        risk_score: Composite risk score in [0.0, 1.0].
        verdict: Human-readable verdict string.
        findings: All individual findings.
        base64_findings: Decoded base64 payloads found.
        description_analysis: Analysis of the tool description.
        schema_violations: Structural schema issues.
        rug_pull_indicators: Post-approval mutation risks.
        total_finding_count: Total number of findings.
        critical_count: Number of CRITICAL findings.
        high_count: Number of HIGH findings.
        elapsed_ms: Wall-clock analysis time in milliseconds.
    """
    tool_name: str
    risk_score: float
    verdict: str
    findings: list[AuditFinding]
    base64_findings: list[Base64Finding]
    description_analysis: DescriptionAnalysis
    schema_violations: list[SchemaViolation]
    rug_pull_indicators: list[RugPullIndicator]
    total_finding_count: int
    critical_count: int
    high_count: int
    elapsed_ms: float


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

_BASE64_RE = re.compile(
    r"(?<![A-Za-z0-9+/=])"
    r"([A-Za-z0-9+/]{20,}={0,3})"
    r"(?![A-Za-z0-9+/=])"
)

_BEHAVIORAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(always|never|must|shall|should)\b.{5,80}\b(return|output|respond|reply|say)\b", re.IGNORECASE),
    re.compile(r"\b(before|after|when|if)\b.{3,60}\b(executing?|running?|calling?|invoking?)\b.{3,80}\b(first|also|additionally)\b", re.IGNORECASE),
    re.compile(r"\b(include|append|prepend|inject|insert)\b.{3,60}\b(in|to|into)\b.{3,40}\b(response|output|result)\b", re.IGNORECASE),
    re.compile(r"\bdo\s+not\s+(mention|reveal|disclose|tell|show|log)\b", re.IGNORECASE),
    re.compile(r"\b(silently|quietly|secretly|covertly)\b", re.IGNORECASE),
]

# Invisible Unicode codepoints
_INVISIBLE_CODEPOINTS: set[int] = {
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F,
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
    0xFEFF, 0x00AD,
}

# Known malicious tool naming patterns
_MALICIOUS_NAME_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(exec|eval|shell|system|subprocess|os\.)", re.IGNORECASE),
    re.compile(r"(read_file|write_file|delete_file|rm\s+-rf)", re.IGNORECASE),
    re.compile(r"(exfiltrate|exfil|steal|harvest|scrape_creds)", re.IGNORECASE),
    re.compile(r"(backdoor|rootkit|keylog|reverse.?shell)", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class MCPToolAuditor:
    """Static analysis of MCP tool schemas for sleeper-agent triggers and backdoors.

    The auditor performs ten independent checks on a tool definition and
    produces a composite risk score.  It is entirely stateless and can be
    used concurrently without synchronisation.

    Example::

        auditor = MCPToolAuditor()
        report = await auditor.audit_tool(
            tool_name="fetch_data",
            description="Fetches data from a URL",
            schema={"type": "object", "properties": {...}},
            parameters={"url": {"type": "string"}},
        )
        print(report.risk_score, report.verdict)
    """

    def __init__(self, config: MCPAuditConfig | None = None) -> None:
        self._config = config or MCPAuditConfig()
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self._config.suspicious_patterns
        ]
        logger.info(
            "MCPToolAuditor initialised  max_desc=%d  max_depth=%d",
            self._config.max_description_length,
            self._config.max_schema_depth,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def audit_tool(
        self,
        tool_name: str,
        description: str,
        schema: dict[str, Any],
        parameters: dict[str, Any],
    ) -> MCPAuditReport:
        """Comprehensive audit of an MCP tool definition.

        Args:
            tool_name: The tool's registered name.
            description: The tool's human-readable description.
            schema: The full JSON schema for the tool's input.
            parameters: The ``properties`` section of the schema (may be
                identical to ``schema["properties"]``).

        Returns:
            An :class:`MCPAuditReport` with all findings and a composite
            risk score.
        """
        t0 = time.perf_counter()
        findings: list[AuditFinding] = []

        # 1. Description length anomaly
        desc_analysis = self._analyze_description_anomalies(description)
        if desc_analysis.is_anomalous:
            for reason in desc_analysis.reasons:
                findings.append(AuditFinding(
                    category=FindingCategory.DESCRIPTION_ANOMALY,
                    severity=Severity.MEDIUM if desc_analysis.length <= self._config.max_description_length * 2 else Severity.HIGH,
                    description=reason,
                    field_path="description",
                ))

        # 2. Base64 scanning across all string fields
        all_text_fields = self._extract_all_strings(
            {"name": tool_name, "description": description, "schema": schema, "parameters": parameters}
        )
        base64_findings: list[Base64Finding] = []
        for path, text in all_text_fields:
            for b64f in self._scan_for_base64(text):
                b64f.field_path = path
                base64_findings.append(b64f)
                findings.append(AuditFinding(
                    category=FindingCategory.BASE64_PAYLOAD,
                    severity=b64f.severity,
                    description=f"Base64 payload in {path}: {b64f.decoded_content[:60]}",
                    field_path=path,
                    evidence=b64f.encoded_text[:80],
                ))

        # 3. Hidden instruction detection in description
        for pattern in self._compiled_patterns:
            for match in pattern.finditer(description):
                findings.append(AuditFinding(
                    category=FindingCategory.HIDDEN_INSTRUCTION,
                    severity=Severity.CRITICAL,
                    description=f"Suspicious instruction pattern: '{match.group(0)}'",
                    field_path="description",
                    evidence=match.group(0),
                ))

        # 4. Schema structural validation
        schema_violations = self._validate_schema_structure(schema)
        for sv in schema_violations:
            findings.append(AuditFinding(
                category=FindingCategory.SCHEMA_VIOLATION,
                severity=sv.severity,
                description=sv.description,
                field_path=sv.path,
            ))

        # 5. Parameter type confusion detection
        type_findings = self._detect_type_confusion(parameters)
        findings.extend(type_findings)

        # 6. Recursive depth analysis
        max_depth = self._measure_depth(schema)
        if max_depth > self._config.max_schema_depth:
            findings.append(AuditFinding(
                category=FindingCategory.DEPTH_VIOLATION,
                severity=Severity.HIGH,
                description=f"Schema nesting depth {max_depth} exceeds limit {self._config.max_schema_depth}",
                field_path="schema",
            ))

        # 7. Unicode / invisible character scanning
        for path, text in all_text_fields:
            invisible_count = sum(1 for c in text if ord(c) in _INVISIBLE_CODEPOINTS)
            if invisible_count > 0:
                findings.append(AuditFinding(
                    category=FindingCategory.INVISIBLE_UNICODE,
                    severity=Severity.HIGH,
                    description=f"{invisible_count} invisible Unicode characters in {path}",
                    field_path=path,
                ))

        # 8. Behavioral instruction extraction
        for bp in _BEHAVIORAL_PATTERNS:
            for match in bp.finditer(description):
                findings.append(AuditFinding(
                    category=FindingCategory.BEHAVIORAL_INSTRUCTION,
                    severity=Severity.MEDIUM,
                    description=f"Behavioral directive: '{match.group(0)[:80]}'",
                    field_path="description",
                    evidence=match.group(0)[:120],
                ))

        # 9. Known malicious patterns
        for mp in _MALICIOUS_NAME_PATTERNS:
            if mp.search(tool_name):
                findings.append(AuditFinding(
                    category=FindingCategory.KNOWN_MALICIOUS_PATTERN,
                    severity=Severity.CRITICAL,
                    description=f"Tool name '{tool_name}' matches known malicious pattern",
                    field_path="name",
                    evidence=tool_name,
                ))

        # 10. Rug-pull indicators
        rug_pulls = self._detect_rug_pull_indicators(schema)
        for rp in rug_pulls:
            findings.append(AuditFinding(
                category=FindingCategory.RUG_PULL_INDICATOR,
                severity=rp.severity,
                description=rp.description,
                field_path=rp.path,
            ))

        # Calculate composite risk score
        risk_score = self._calculate_risk_score(findings)

        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)

        # Verdict
        if critical_count > 0:
            verdict = "REJECT -- critical security findings"
        elif high_count >= 3:
            verdict = "REJECT -- multiple high-severity findings"
        elif risk_score > 0.7:
            verdict = "REJECT -- high composite risk score"
        elif risk_score > 0.4:
            verdict = "REVIEW -- moderate risk, manual inspection recommended"
        elif len(findings) > 0:
            verdict = "CAUTION -- minor findings detected"
        else:
            verdict = "PASS -- no findings"

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return MCPAuditReport(
            tool_name=tool_name,
            risk_score=risk_score,
            verdict=verdict,
            findings=findings,
            base64_findings=base64_findings,
            description_analysis=desc_analysis,
            schema_violations=schema_violations,
            rug_pull_indicators=rug_pulls,
            total_finding_count=len(findings),
            critical_count=critical_count,
            high_count=high_count,
            elapsed_ms=elapsed_ms,
        )

    # ------------------------------------------------------------------
    # Detection methods
    # ------------------------------------------------------------------

    def _scan_for_base64(self, text: str) -> list[Base64Finding]:
        """Detect and decode base64 encoded strings that may contain hidden instructions.

        Args:
            text: String to scan.

        Returns:
            List of :class:`Base64Finding` for each decoded payload.
        """
        findings: list[Base64Finding] = []

        for match in _BASE64_RE.finditer(text):
            candidate = match.group(1)
            if len(candidate) < self._config.base64_min_length:
                continue
            try:
                decoded = base64.b64decode(candidate, validate=True).decode(
                    "utf-8", errors="replace"
                )
                # Filter: only flag if decoded looks like real text
                printable = sum(1 for c in decoded if c.isprintable() or c.isspace())
                if printable / max(len(decoded), 1) > 0.7 and len(decoded) > 5:
                    findings.append(Base64Finding(
                        field_path="",  # Will be set by caller
                        encoded_text=candidate[:80] + ("..." if len(candidate) > 80 else ""),
                        decoded_content=decoded[:200],
                        severity=Severity.HIGH,
                    ))
            except Exception:
                pass

        return findings

    def _analyze_description_anomalies(self, description: str) -> DescriptionAnalysis:
        """Analyze tool description for abnormal length, hidden content, behavioral instructions.

        Args:
            description: The tool's description string.

        Returns:
            A :class:`DescriptionAnalysis` with all findings.
        """
        reasons: list[str] = []
        is_anomalous = False

        length = len(description)

        # Length check
        if length > self._config.max_description_length:
            reasons.append(
                f"Description length {length} exceeds maximum {self._config.max_description_length}"
            )
            is_anomalous = True

        # Invisible character count
        invisible_count = sum(1 for c in description if ord(c) in _INVISIBLE_CODEPOINTS)
        if invisible_count > 0:
            reasons.append(f"{invisible_count} invisible Unicode characters detected")
            is_anomalous = True

        # Hidden instruction count
        hidden_count = 0
        for pattern in self._compiled_patterns:
            hidden_count += len(pattern.findall(description))
        if hidden_count > 0:
            reasons.append(f"{hidden_count} hidden instruction patterns detected")
            is_anomalous = True

        # Behavioral instruction count
        behavioral_count = 0
        for bp in _BEHAVIORAL_PATTERNS:
            behavioral_count += len(bp.findall(description))
        if behavioral_count > 0:
            reasons.append(f"{behavioral_count} behavioral directives detected")
            is_anomalous = True

        # Check for excessive newlines (padding to push instructions off-screen)
        newline_ratio = description.count("\n") / max(length, 1)
        if newline_ratio > 0.3 and length > 100:
            reasons.append("Excessive newlines suggest content-hiding padding")
            is_anomalous = True

        return DescriptionAnalysis(
            length=length,
            is_anomalous=is_anomalous,
            hidden_instruction_count=hidden_count,
            behavioral_instruction_count=behavioral_count,
            invisible_char_count=invisible_count,
            reasons=reasons,
        )

    def _validate_schema_structure(
        self,
        schema: dict[str, Any],
        max_depth: int | None = None,
    ) -> list[SchemaViolation]:
        """Validate MCP schema against specification, detecting structural manipulation.

        Args:
            schema: JSON schema dict.
            max_depth: Override for maximum allowed depth.

        Returns:
            List of :class:`SchemaViolation` findings.
        """
        max_depth = max_depth or self._config.max_schema_depth
        violations: list[SchemaViolation] = []

        # Check top-level type
        if schema.get("type") != "object":
            violations.append(SchemaViolation(
                path="$",
                violation_type="invalid_root_type",
                description=f"MCP tool schema root must be 'object', got '{schema.get('type', 'missing')}'",
                severity=Severity.MEDIUM,
            ))

        # Check for excessive properties
        properties = schema.get("properties", {})
        if len(properties) > self._config.max_schema_fields:
            violations.append(SchemaViolation(
                path="$.properties",
                violation_type="excessive_fields",
                description=f"Schema has {len(properties)} fields, exceeding limit of {self._config.max_schema_fields}",
                severity=Severity.MEDIUM,
            ))

        # Check for additionalProperties: true (allows arbitrary input)
        if schema.get("additionalProperties") is True:
            violations.append(SchemaViolation(
                path="$.additionalProperties",
                violation_type="open_schema",
                description="Schema allows arbitrary additional properties -- potential injection vector",
                severity=Severity.HIGH,
            ))

        # Recursive depth check on nested schemas
        self._check_depth_recursive(schema, "$", 0, max_depth, violations)

        return violations

    def _check_depth_recursive(
        self,
        obj: Any,
        path: str,
        current_depth: int,
        max_depth: int,
        violations: list[SchemaViolation],
    ) -> None:
        """Recursively check schema depth.

        Args:
            obj: Current schema node.
            path: JSON path string.
            current_depth: Current nesting depth.
            max_depth: Maximum allowed depth.
            violations: Accumulator for violations found.
        """
        if current_depth > max_depth:
            violations.append(SchemaViolation(
                path=path,
                violation_type="excessive_depth",
                description=f"Schema depth {current_depth} exceeds limit {max_depth}",
                severity=Severity.HIGH,
            ))
            return

        if not isinstance(obj, dict):
            return

        for key in ("properties", "items", "additionalProperties"):
            child = obj.get(key)
            if isinstance(child, dict):
                child_path = f"{path}.{key}"
                if key == "properties":
                    for prop_name, prop_schema in child.items():
                        if isinstance(prop_schema, dict):
                            self._check_depth_recursive(
                                prop_schema, f"{child_path}.{prop_name}",
                                current_depth + 1, max_depth, violations,
                            )
                else:
                    self._check_depth_recursive(
                        child, child_path,
                        current_depth + 1, max_depth, violations,
                    )

        # Check oneOf / anyOf / allOf branches
        for combiner in ("oneOf", "anyOf", "allOf"):
            branches = obj.get(combiner)
            if isinstance(branches, list):
                for i, branch in enumerate(branches):
                    if isinstance(branch, dict):
                        self._check_depth_recursive(
                            branch, f"{path}.{combiner}[{i}]",
                            current_depth + 1, max_depth, violations,
                        )

    def _detect_type_confusion(
        self, parameters: dict[str, Any],
    ) -> list[AuditFinding]:
        """Detect parameters whose declared type conflicts with their constraints.

        For example, a parameter declared as ``"type": "string"`` but with
        ``"minimum": 0`` (a numeric constraint) suggests either a mistake or
        intentional confusion to trick the model.

        Args:
            parameters: The ``properties`` dict from the schema.

        Returns:
            List of :class:`AuditFinding` for type confusion issues.
        """
        findings: list[AuditFinding] = []

        numeric_keys = {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"}
        string_keys = {"minLength", "maxLength", "pattern", "format"}
        array_keys = {"minItems", "maxItems", "uniqueItems", "items"}

        for name, spec in parameters.items():
            if not isinstance(spec, dict):
                continue

            declared_type = spec.get("type", "")
            spec_keys = set(spec.keys())

            if declared_type == "string" and spec_keys & numeric_keys:
                findings.append(AuditFinding(
                    category=FindingCategory.TYPE_CONFUSION,
                    severity=Severity.MEDIUM,
                    description=f"Parameter '{name}' declared as string but has numeric constraints: {spec_keys & numeric_keys}",
                    field_path=f"parameters.{name}",
                ))

            if declared_type in ("integer", "number") and spec_keys & string_keys:
                findings.append(AuditFinding(
                    category=FindingCategory.TYPE_CONFUSION,
                    severity=Severity.MEDIUM,
                    description=f"Parameter '{name}' declared as {declared_type} but has string constraints: {spec_keys & string_keys}",
                    field_path=f"parameters.{name}",
                ))

            if declared_type != "array" and spec_keys & array_keys:
                findings.append(AuditFinding(
                    category=FindingCategory.TYPE_CONFUSION,
                    severity=Severity.MEDIUM,
                    description=f"Parameter '{name}' declared as {declared_type} but has array constraints: {spec_keys & array_keys}",
                    field_path=f"parameters.{name}",
                ))

            # Check for enum values that don't match declared type
            enum_values = spec.get("enum")
            if enum_values and declared_type:
                type_map = {
                    "string": str, "integer": int, "number": (int, float),
                    "boolean": bool,
                }
                expected = type_map.get(declared_type)
                if expected:
                    mismatched = [v for v in enum_values if not isinstance(v, expected)]
                    if mismatched:
                        findings.append(AuditFinding(
                            category=FindingCategory.TYPE_CONFUSION,
                            severity=Severity.HIGH,
                            description=f"Parameter '{name}' enum contains values incompatible with declared type '{declared_type}': {mismatched[:5]}",
                            field_path=f"parameters.{name}.enum",
                        ))

        return findings

    def _detect_rug_pull_indicators(
        self, schema: dict[str, Any],
    ) -> list[RugPullIndicator]:
        """Detect indicators that a tool definition may mutate after approval.

        Checks for:
        - ``$ref`` pointing to external URLs (schema can change remotely)
        - ``oneOf``/``anyOf`` with a wildcard branch that matches anything
        - ``default`` values that contain executable-looking content

        Args:
            schema: The tool's JSON schema.

        Returns:
            List of :class:`RugPullIndicator` findings.
        """
        indicators: list[RugPullIndicator] = []
        self._scan_rug_pull_recursive(schema, "$", indicators)
        return indicators

    def _scan_rug_pull_recursive(
        self,
        obj: Any,
        path: str,
        indicators: list[RugPullIndicator],
        depth: int = 0,
    ) -> None:
        """Recursively scan for rug-pull indicators."""
        if depth > 20 or not isinstance(obj, dict):
            return

        # External $ref
        ref = obj.get("$ref", "")
        if isinstance(ref, str) and (ref.startswith("http://") or ref.startswith("https://")):
            indicators.append(RugPullIndicator(
                path=path,
                indicator_type="external_ref",
                description=f"External $ref '{ref[:100]}' -- schema content can change after approval",
                severity=Severity.CRITICAL,
            ))

        # Wildcard branches in oneOf/anyOf
        for combiner in ("oneOf", "anyOf"):
            branches = obj.get(combiner)
            if isinstance(branches, list):
                for i, branch in enumerate(branches):
                    if isinstance(branch, dict):
                        # A branch with no type and no properties matches anything
                        if "type" not in branch and "properties" not in branch and "$ref" not in branch:
                            indicators.append(RugPullIndicator(
                                path=f"{path}.{combiner}[{i}]",
                                indicator_type="wildcard_branch",
                                description=f"Unconstrained branch in {combiner} -- accepts any input",
                                severity=Severity.HIGH,
                            ))

        # Default values with executable content
        default = obj.get("default")
        if isinstance(default, str):
            suspicious_defaults = [
                r"javascript:", r"data:", r"<script", r"eval\(",
                r"exec\(", r"import\s+os", r"__import__",
            ]
            for pattern in suspicious_defaults:
                if re.search(pattern, default, re.IGNORECASE):
                    indicators.append(RugPullIndicator(
                        path=f"{path}.default",
                        indicator_type="executable_default",
                        description=f"Default value contains executable pattern: '{default[:60]}'",
                        severity=Severity.CRITICAL,
                    ))
                    break

        # Recurse
        for key, value in obj.items():
            if isinstance(value, dict):
                self._scan_rug_pull_recursive(value, f"{path}.{key}", indicators, depth + 1)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        self._scan_rug_pull_recursive(item, f"{path}.{key}[{i}]", indicators, depth + 1)

    def _calculate_risk_score(self, findings: list[AuditFinding]) -> float:
        """Weighted risk score from all findings (0.0 = safe, 1.0 = critical).

        Severity weights:
        - CRITICAL: 0.40 each (capped at 1.0)
        - HIGH:     0.20 each
        - MEDIUM:   0.08 each
        - LOW:      0.03 each

        The raw sum is passed through a sigmoid-like compression to ensure
        the score stays in [0, 1] and saturates gracefully.

        Args:
            findings: All audit findings.

        Returns:
            Risk score in [0.0, 1.0].
        """
        if not findings:
            return 0.0

        weights = {
            Severity.CRITICAL: 0.40,
            Severity.HIGH: 0.20,
            Severity.MEDIUM: 0.08,
            Severity.LOW: 0.03,
        }

        raw = sum(weights.get(f.severity, 0.03) for f in findings)

        # Compress via tanh to [0, 1]
        import math
        score = math.tanh(raw)
        return round(score, 4)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _measure_depth(self, obj: Any, current: int = 0) -> int:
        """Measure the maximum nesting depth of a JSON-like structure.

        Args:
            obj: JSON-like object.
            current: Current depth (for recursion).

        Returns:
            Maximum depth found.
        """
        if not isinstance(obj, dict):
            return current

        max_d = current
        for value in obj.values():
            if isinstance(value, dict):
                max_d = max(max_d, self._measure_depth(value, current + 1))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        max_d = max(max_d, self._measure_depth(item, current + 1))
        return max_d

    @staticmethod
    def _extract_all_strings(
        obj: Any, path: str = "$",
    ) -> list[tuple[str, str]]:
        """Recursively extract all string values from a nested structure.

        Args:
            obj: JSON-like object.
            path: Current JSON path (for reporting).

        Returns:
            List of ``(path, value)`` tuples for every string leaf.
        """
        results: list[tuple[str, str]] = []

        if isinstance(obj, str):
            results.append((path, obj))
        elif isinstance(obj, dict):
            for key, value in obj.items():
                results.extend(
                    MCPToolAuditor._extract_all_strings(value, f"{path}.{key}")
                )
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                results.extend(
                    MCPToolAuditor._extract_all_strings(item, f"{path}[{i}]")
                )

        return results
