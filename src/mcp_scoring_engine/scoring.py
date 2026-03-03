"""Composite scoring engine for MCP server quality assessment.

Combines data from multiple tiers into a single 0-100 score.

Standard weights (no agent usability data):

  Category                Weight  Source
  ────────────────────    ──────  ──────────────────────────
  Schema & Documentation  25%     Tier 1 static analysis
  Protocol Compliance     20%     Tier 2 deep probe (remote only)
  Reliability             20%     Tier 3 fast probe history (remote only)
  Maintenance & Health    15%     Tier 1 static analysis
  Security & Permissions  20%     Tier 1 registry metadata

Enhanced weights (with agent usability data):

  Category                Weight  Source
  ────────────────────    ──────  ──────────────────────────
  Schema & Documentation  20%     Tier 1 static analysis
  Protocol Compliance     18%     Tier 2 deep probe (remote only)
  Reliability             18%     Tier 3 fast probe history (remote only)
  Maintenance & Health    12%     Tier 1 static analysis
  Security & Permissions  17%     Tier 1 registry metadata
  Agent Usability         15%     Tier 4 multi-model LLM eval

Local vs Remote scoring:
  Remote servers have 5 applicable dimensions (all of the above).
  Local servers have 3 applicable dimensions (Schema, Maintenance, Security).
  Protocol and Reliability require a remote endpoint and are structurally
  inapplicable to local (stdio-only) servers.

Score types (applicability-aware):
  partial  — Some *applicable* dimensions not yet measured (no letter grade)
  full     — All applicable dimensions scored — receives a letter grade
  enhanced — Full + agent usability evaluation

  A local server with Schema + Maintenance + Security all scored → "full".
  A remote server needs all 5 dimensions scored → "full".

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

# ── Standard category weights (without agent usability) ──────────────
WEIGHT_SCHEMA_QUALITY = 0.25
WEIGHT_PROTOCOL = 0.20
WEIGHT_RELIABILITY = 0.20
WEIGHT_DOCS_MAINTENANCE = 0.15
WEIGHT_SECURITY = 0.20

# Backward-compatible aliases (deprecated)
WEIGHT_SCHEMA_DOCS = WEIGHT_SCHEMA_QUALITY
WEIGHT_MAINTENANCE = WEIGHT_DOCS_MAINTENANCE

# ── Enhanced category weights (with agent usability) ─────────────────
WEIGHT_AGENT_USABILITY = 0.15
_ENHANCED_WEIGHTS = {
    "schema_quality": 0.20,
    "protocol": 0.18,
    "reliability": 0.18,
    "docs_maintenance": 0.12,
    "security": 0.17,
    "agent_usability": WEIGHT_AGENT_USABILITY,
}

# ── Critical flag score caps ──────────────────────────────────────────
# Flags with critical consequences cap the composite score.
# Individual category scores remain unaffected (for diagnostics).
FLAG_SCORE_CAPS = {
    "DEAD_REPO": 0,  # Dead repos get 0 — no exceptions
    "REPO_ARCHIVED": 40,  # Archived = max D grade
    "STAGING_ARTIFACT": 55,  # Staging URLs = max C grade
}

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


def _compute_schema_quality_score(static_result: StaticAnalysis) -> int | None:
    """Compute Schema Quality category score.

    Weighted average of schema_completeness (60%) and description_quality (40%).
    These measure whether tools are well-defined and clearly described.
    """
    components = [
        (static_result.schema_completeness, 0.60),
        (static_result.description_quality, 0.40),
    ]
    scores = [(s, w) for s, w in components if s is not None]
    if not scores:
        return None
    total_weight = sum(w for _, w in scores)
    return int(sum(s * w for s, w in scores) / total_weight)


# Backward-compatible alias
_compute_schema_docs_score = _compute_schema_quality_score


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


from .probes.reliability import (
    compute_reliability_score as _compute_reliability_score,
    MINIMUM_PROBE_COUNT,
)


def _compute_docs_maintenance_score(static_result: StaticAnalysis) -> int | None:
    """Compute Documentation & Maintenance category score.

    Weighted blend of project health signals:
      documentation_coverage: 30%
      maintenance_pulse:      30%
      dependency_health:      15%
      license_clarity:        15%
      version_hygiene:        10%
    """
    components = [
        (static_result.documentation_coverage, 0.30),
        (static_result.maintenance_pulse, 0.30),
        (static_result.dependency_health, 0.15),
        (static_result.license_clarity, 0.15),
        (static_result.version_hygiene, 0.10),
    ]
    scores = [(s, w) for s, w in components if s is not None]
    if not scores:
        return None
    total_weight = sum(w for _, w in scores)
    return int(sum(s * w for s, w in scores) / total_weight)


# Backward-compatible alias
_compute_maintenance_score = _compute_docs_maintenance_score


def _compute_security_score(server: ServerInfo) -> int | None:
    """Compute Security & Permissions category score.

    Analyzes registry metadata for security posture:
    - Secret env var count (35pts)
    - Transport risk (25pts)
    - Credential sensitivity (25pts)
    - Distribution clarity (15pts)
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
        r"(private[_-]?key|database|db_|postgres|mysql|redis|mongo"
        r"|aws_secret|azure[_-]?secret|gcp[_-]?key|gcloud"
        r"|stripe[_-]?secret|twilio|sendgrid"
        r"|mongo[_-]?uri|connection[_-]?string"
        r"|jwt[_-]?secret|encryption[_-]?key|ssh[_-]?key|ssl[_-]?cert)",
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

    # 4. Distribution clarity (15 pts)
    # Can users verify what they're installing?
    has_package = bool(server.npm_url or server.pypi_url or server.dockerhub_url)
    has_repo = bool(server.repo_url)
    if has_package and has_repo:
        dist_score = 15  # Verifiable: published + source available
    elif has_repo:
        dist_score = 12  # Fully auditable from source
    elif has_package:
        dist_score = 8  # Published but can't verify source
    else:
        dist_score = 3

    total = secret_score + transport_score + cred_score + dist_score
    return max(0, min(100, total))


def compute_score(
    server: ServerInfo,
    static_result: StaticAnalysis | None = None,
    deep_probe: DeepProbeResult | None = None,
    reliability: ReliabilityData | None = None,
    agent_usability: int | None = None,
) -> ScoreResult:
    """Compute composite MCP server quality score.

    Pure function — no side effects, no DB, no network.

    When ``agent_usability`` is provided (0-100 int), enhanced weights are
    used and the score type is promoted to "enhanced" (if the server already
    qualifies for "full").  When ``None``, behaviour is identical to the
    pre-agent-usability engine — standard weights, no promotion.
    """
    result = ScoreResult(
        server_info=server,
        deep_probe=deep_probe,
        static_analysis=static_result,
        reliability_data=reliability,
    )

    # ── Compute category scores ───────────────────────────────────────
    schema_quality = _compute_schema_quality_score(static_result) if static_result else None
    protocol = _compute_protocol_score(deep_probe)
    reliability_score = _compute_reliability_score(reliability)
    docs_maintenance = _compute_docs_maintenance_score(static_result) if static_result else None
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

    # Apply template description penalty to schema_quality
    has_template_flag = any(f.key == "TEMPLATE_DESCRIPTION" for f in detected_flags)
    if has_template_flag and schema_quality is not None:
        schema_quality = max(0, schema_quality - 15)

    # ── Determine score type (applicability-aware) ──────────────────
    is_remote = getattr(server, "is_remote", True)
    applicable = {
        "schema_quality": True,
        "protocol": is_remote,
        "reliability": is_remote,
        "docs_maintenance": True,
        "security": True,
    }
    filled = {
        "schema_quality": schema_quality is not None,
        "protocol": protocol is not None,
        "reliability": reliability_score is not None,
        "docs_maintenance": docs_maintenance is not None,
        "security": security is not None,
    }
    all_applicable_filled = all(
        filled[d] for d, applies in applicable.items() if applies
    )

    has_agent_usability = agent_usability is not None
    if all_applicable_filled and has_agent_usability:
        score_type = "enhanced"
    elif all_applicable_filled:
        score_type = "full"
    else:
        score_type = "partial"

    # ── Select weight set ─────────────────────────────────────────────
    use_enhanced = has_agent_usability

    # ── Compute weighted composite ────────────────────────────────────
    weighted_sum = 0.0
    total_weight = 0.0

    if use_enhanced:
        w = _ENHANCED_WEIGHTS
        if schema_quality is not None:
            weighted_sum += schema_quality * w["schema_quality"]
            total_weight += w["schema_quality"]
        if protocol is not None:
            weighted_sum += protocol * w["protocol"]
            total_weight += w["protocol"]
        if reliability_score is not None:
            weighted_sum += reliability_score * w["reliability"]
            total_weight += w["reliability"]
        if docs_maintenance is not None:
            weighted_sum += docs_maintenance * w["docs_maintenance"]
            total_weight += w["docs_maintenance"]
        if security is not None:
            weighted_sum += security * w["security"]
            total_weight += w["security"]
        weighted_sum += agent_usability * w["agent_usability"]
        total_weight += w["agent_usability"]
    else:
        if schema_quality is not None:
            weighted_sum += schema_quality * WEIGHT_SCHEMA_QUALITY
            total_weight += WEIGHT_SCHEMA_QUALITY
        if protocol is not None:
            weighted_sum += protocol * WEIGHT_PROTOCOL
            total_weight += WEIGHT_PROTOCOL
        if reliability_score is not None:
            weighted_sum += reliability_score * WEIGHT_RELIABILITY
            total_weight += WEIGHT_RELIABILITY
        if docs_maintenance is not None:
            weighted_sum += docs_maintenance * WEIGHT_DOCS_MAINTENANCE
            total_weight += WEIGHT_DOCS_MAINTENANCE
        if security is not None:
            weighted_sum += security * WEIGHT_SECURITY
            total_weight += WEIGHT_SECURITY

    if total_weight == 0:
        return result

    raw_score = weighted_sum / total_weight
    composite_score = max(0, min(100, int(round(raw_score))))

    # ── Apply critical flag score caps ─────────────────────────────────
    for flag in detected_flags:
        if flag.key in FLAG_SCORE_CAPS:
            composite_score = min(composite_score, FLAG_SCORE_CAPS[flag.key])

    grade = "" if score_type == "partial" else score_to_grade(composite_score)

    # ── Store results ─────────────────────────────────────────────────
    result.composite_score = composite_score
    result.grade = grade
    result.score_type = score_type
    result.schema_quality_score = schema_quality
    result.protocol_score = protocol
    result.reliability_score = reliability_score
    result.docs_maintenance_score = docs_maintenance
    result.security_score = security
    result.agent_usability_score = agent_usability

    # ── Generate badges ───────────────────────────────────────────────
    flag_dicts = [
        {"key": f.key, "severity": f.severity, "label": f.label, "description": f.description}
        for f in detected_flags
    ]
    result.badges = generate_badges(server, static_result, deep_probe, reliability, flag_dicts)

    return result
