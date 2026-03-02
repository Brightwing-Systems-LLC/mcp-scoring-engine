"""Composite scoring engine for MCP server quality assessment.

Combines data from all three tiers into a single 0-100 score:

  Category                Weight  Source
  ────────────────────    ──────  ──────────────────────────
  Schema & Documentation  25%     Tier 1 static analysis
  Protocol Compliance     20%     Tier 2 deep probe
  Reliability             20%     Tier 3 fast probe history
  Maintenance & Health    15%     Tier 1 static analysis
  Security & Permissions  20%     Tier 1 registry metadata

Score types:
  partial  — Only one data tier (shown on leaderboard, but no letter grade)
  full     — 2+ data tiers (static + probe data) — receives a letter grade
  enhanced — Full + real agent feedback (future)

Grade thresholds (full/enhanced only):
  A+ 95-100 | A 85-94 | B 70-84 | C 55-69 | D 40-54 | F 0-39
"""

from __future__ import annotations

import logging

from .badges import generate_badges
from .classification import classify_server
from .flags import detect_flags
from .types import (
    DeepProbeResult,
    ReliabilityData,
    ScoreResult,
    ServerInfo,
    StaticAnalysis,
)

logger = logging.getLogger(__name__)

# ── Category weights ──────────────────────────────────────────────────
WEIGHT_SCHEMA_DOCS = 0.25
WEIGHT_PROTOCOL = 0.20
WEIGHT_RELIABILITY = 0.20
WEIGHT_MAINTENANCE = 0.15
WEIGHT_SECURITY = 0.20

# ── Grade thresholds ──────────────────────────────────────────────────
GRADE_THRESHOLDS = [
    (95, "A+"),
    (85, "A"),
    (70, "B"),
    (55, "C"),
    (40, "D"),
    (0, "F"),
]

# ── Verified publishers ───────────────────────────────────────────────
VERIFIED_PUBLISHERS = {
    "modelcontextprotocol",
    "anthropics",
    "anthropic",
    "openai",
    "microsoft",
    "google",
    "aws",
    "cloudflare",
    "stripe",
    "supabase",
    "vercel",
    "github",
    "gitlab",
    "docker",
    "hashicorp",
    "datadog",
    "sentry-io",
    "grafana",
    "elastic",
    "mongodb",
    "redis",
}


def score_to_grade(score: int) -> str:
    """Convert a numeric score (0-100) to a letter grade."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def is_verified_publisher(server: ServerInfo) -> bool:
    """Check if server belongs to a verified publisher namespace."""
    rid = server.registry_id or ""
    if rid.startswith("@"):
        namespace = rid.split("/")[0].lstrip("@").lower()
        if namespace in VERIFIED_PUBLISHERS:
            return True

    repo = server.repo_url or ""
    if "github.com/" in repo:
        parts = repo.rstrip("/").split("github.com/")
        if len(parts) > 1:
            org = parts[1].split("/")[0].lower()
            if org in VERIFIED_PUBLISHERS:
                return True

    return False


def extract_publisher(server: ServerInfo) -> str:
    """Extract publisher name from registry namespace, GitHub org, or name prefix."""
    rid = server.registry_id or ""
    if rid.startswith("@"):
        return rid.split("/")[0].lstrip("@")

    repo = server.repo_url or ""
    if "github.com/" in repo:
        parts = repo.rstrip("/").split("github.com/")
        if len(parts) > 1:
            return parts[1].split("/")[0]

    name = server.name or ""
    if "/" in name:
        return name.split("/")[0]

    return ""


def _compute_schema_docs_score(static_result: StaticAnalysis) -> int | None:
    """Compute Schema & Documentation category score.

    Averages schema_completeness, description_quality, documentation_coverage.
    """
    scores = [
        s
        for s in [
            static_result.schema_completeness,
            static_result.description_quality,
            static_result.documentation_coverage,
        ]
        if s is not None
    ]
    if not scores:
        return None
    return int(sum(scores) / len(scores))


def _compute_protocol_score(deep_probe: DeepProbeResult | None) -> int | None:
    """Compute Protocol Compliance category score.

    Components: reachability, schema validity, error handling, fuzz resilience.
    """
    if deep_probe is None:
        return None

    components = []

    components.append(100 if deep_probe.is_reachable else 0)

    if deep_probe.schema_valid is not None:
        components.append(100 if deep_probe.schema_valid else 30)

    if deep_probe.error_handling_score is not None:
        components.append(deep_probe.error_handling_score)

    if deep_probe.fuzz_score is not None:
        components.append(deep_probe.fuzz_score)

    if not components:
        return None
    return int(sum(components) / len(components))


def _compute_reliability_score(reliability: ReliabilityData | None) -> int | None:
    """Compute Reliability category score from pre-computed metrics.

    Uptime contributes 70%, latency 30%.
    If only latency available (CLI single-run), scores latency only.
    """
    if reliability is None:
        return None

    if reliability.uptime_pct is None and reliability.latency_p50_ms is None:
        return None

    # Latency scoring: <200ms=100, <500ms=80, <1000ms=60, <2000ms=40, else=20
    latency_score = None
    if reliability.latency_p50_ms is not None:
        p50 = reliability.latency_p50_ms
        if p50 < 200:
            latency_score = 100
        elif p50 < 500:
            latency_score = 80
        elif p50 < 1000:
            latency_score = 60
        elif p50 < 2000:
            latency_score = 40
        else:
            latency_score = 20

    if reliability.uptime_pct is not None and latency_score is not None:
        return int(reliability.uptime_pct * 0.7 + latency_score * 0.3)
    elif reliability.uptime_pct is not None:
        return int(reliability.uptime_pct)
    else:
        return latency_score


def _compute_maintenance_score(static_result: StaticAnalysis) -> int | None:
    """Compute Maintenance & Health category score.

    Averages maintenance_pulse, dependency_health, license_clarity, version_hygiene.
    """
    scores = [
        s
        for s in [
            static_result.maintenance_pulse,
            static_result.dependency_health,
            static_result.license_clarity,
            static_result.version_hygiene,
        ]
        if s is not None
    ]
    if not scores:
        return None
    return int(sum(scores) / len(scores))


def _compute_security_score(server: ServerInfo) -> int | None:
    """Compute Security & Permissions category score.

    Analyzes registry metadata for security posture:
    - Secret env var count (35pts)
    - Transport risk (25pts)
    - Credential sensitivity (25pts)
    - Package type risk (15pts)
    """
    import re

    meta = server.registry_metadata or {}
    env_vars = meta.get("env_vars", [])

    secret_pattern = re.compile(
        r"(api[_-]?key|secret|token|password|auth|credential|private[_-]?key)",
        re.IGNORECASE,
    )

    # 1. Secret env var count (35 pts)
    sensitive_vars = [v for v in env_vars if secret_pattern.search(v)]
    num_sensitive = len(sensitive_vars)
    if num_sensitive == 0:
        secret_score = 35
    elif num_sensitive == 1:
        secret_score = 28
    elif num_sensitive == 2:
        secret_score = 20
    elif num_sensitive <= 4:
        secret_score = 10
    else:
        secret_score = 0

    # 2. Transport risk (25 pts)
    is_remote = server.is_remote
    transport = meta.get("transport", "")
    if not is_remote and transport != "sse":
        transport_score = 25
    elif transport == "sse":
        transport_score = 15
    else:
        transport_score = 10

    # 3. Credential sensitivity (25 pts)
    high_sensitivity = re.compile(
        r"(private[_-]?key|database|db_|postgres|mysql|redis|aws_secret)",
        re.IGNORECASE,
    )
    high_sens_count = len([v for v in env_vars if high_sensitivity.search(v)])
    if high_sens_count == 0 and num_sensitive == 0:
        cred_score = 25
    elif high_sens_count == 0:
        cred_score = 18
    elif high_sens_count <= 2:
        cred_score = 10
    else:
        cred_score = 3

    # 4. Package type risk (15 pts)
    has_package = bool(server.npm_url or server.pypi_url or server.dockerhub_url)
    has_repo = bool(server.repo_url)
    if has_package:
        package_score = 15
    elif has_repo:
        package_score = 10
    else:
        package_score = 3

    total = secret_score + transport_score + cred_score + package_score
    return max(0, min(100, total))


def compute_score(
    server: ServerInfo,
    static_result: StaticAnalysis | None = None,
    deep_probe: DeepProbeResult | None = None,
    reliability: ReliabilityData | None = None,
) -> ScoreResult:
    """Compute composite MCP server quality score.

    Pure function — no side effects, no DB, no network.
    """
    result = ScoreResult(
        server_info=server,
        deep_probe=deep_probe,
        static_analysis=static_result,
        reliability_data=reliability,
    )

    # ── Compute category scores ───────────────────────────────────────
    schema_docs = _compute_schema_docs_score(static_result) if static_result else None
    protocol = _compute_protocol_score(deep_probe)
    reliability_score = _compute_reliability_score(reliability)
    maintenance = _compute_maintenance_score(static_result) if static_result else None
    security = _compute_security_score(server)

    # ── Classification, publisher, verification ───────────────────────
    category, targets = classify_server(server)
    result.category = category
    result.targets = targets
    result.verified_publisher = is_verified_publisher(server)
    result.publisher = extract_publisher(server)

    # ── Detect flags ──────────────────────────────────────────────────
    detected_flags = detect_flags(server)
    result.flags = detected_flags

    # Apply template description penalty to schema_docs
    has_template_flag = any(f.key == "TEMPLATE_DESCRIPTION" for f in detected_flags)
    if has_template_flag and schema_docs is not None:
        schema_docs = max(0, schema_docs - 15)

    # ── Determine score type ──────────────────────────────────────────
    has_static = schema_docs is not None or maintenance is not None
    has_deep = protocol is not None
    has_reliability = reliability_score is not None

    data_tiers = sum([has_static, has_deep, has_reliability])
    score_type = "full" if data_tiers >= 2 else "partial"

    # ── Compute weighted composite ────────────────────────────────────
    weighted_sum = 0.0
    total_weight = 0.0

    if schema_docs is not None:
        weighted_sum += schema_docs * WEIGHT_SCHEMA_DOCS
        total_weight += WEIGHT_SCHEMA_DOCS

    if protocol is not None:
        weighted_sum += protocol * WEIGHT_PROTOCOL
        total_weight += WEIGHT_PROTOCOL

    if reliability_score is not None:
        weighted_sum += reliability_score * WEIGHT_RELIABILITY
        total_weight += WEIGHT_RELIABILITY

    if maintenance is not None:
        weighted_sum += maintenance * WEIGHT_MAINTENANCE
        total_weight += WEIGHT_MAINTENANCE

    if security is not None:
        weighted_sum += security * WEIGHT_SECURITY
        total_weight += WEIGHT_SECURITY

    if total_weight == 0:
        return result

    raw_score = weighted_sum / total_weight
    composite_score = max(0, min(100, int(round(raw_score))))

    grade = "" if score_type == "partial" else score_to_grade(composite_score)

    # ── Store results ─────────────────────────────────────────────────
    result.composite_score = composite_score
    result.grade = grade
    result.score_type = score_type
    result.schema_docs_score = schema_docs
    result.protocol_score = protocol
    result.reliability_score = reliability_score
    result.maintenance_score = maintenance
    result.security_score = security

    # ── Generate badges ───────────────────────────────────────────────
    flag_dicts = [
        {"key": f.key, "severity": f.severity, "label": f.label, "description": f.description}
        for f in detected_flags
    ]
    result.badges = generate_badges(
        server, static_result, deep_probe, reliability, flag_dicts
    )

    return result
