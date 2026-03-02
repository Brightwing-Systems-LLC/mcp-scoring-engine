"""Structured badge generation for MCP server scoring.

Generates badge pills grouped by scoring category. Each badge conveys
a quick status signal: good (green), neutral (gray), warning (orange),
critical (red).
"""

from __future__ import annotations

import re

from .types import Badge, DeepProbeResult, ReliabilityData, ServerInfo, StaticAnalysis


def generate_badges(
    server: ServerInfo,
    static_result: StaticAnalysis | None = None,
    deep_probe: DeepProbeResult | None = None,
    reliability: ReliabilityData | None = None,
    flags: list[dict] | None = None,
) -> dict:
    """Generate badge groups keyed by scoring category.

    Returns {"schema": [...], "protocol": [...], ...} where each value
    is a list of serialized badge dicts.
    """
    badges = {
        "schema": _schema_badges(server, static_result, flags),
        "protocol": _protocol_badges(deep_probe),
        "reliability": _reliability_badges(server, reliability),
        "maintenance": _maintenance_badges(static_result),
        "security": _security_badges(server),
    }
    return {k: [_serialize(b) for b in v] for k, v in badges.items()}


def _serialize(badge: Badge) -> dict:
    return {"key": badge.key, "label": badge.label, "level": badge.level}


def _schema_badges(
    server: ServerInfo,
    static_result: StaticAnalysis | None,
    flags: list[dict] | None,
) -> list[Badge]:
    badges = []

    if static_result:
        details = static_result.details or {}

        doc_checks = details.get("documentation_coverage", {}).get("checks", {})
        if doc_checks.get("has_readme"):
            badges.append(Badge("has_readme", "README", "good"))
        elif doc_checks:
            badges.append(Badge("no_readme", "No README", "critical"))

        if doc_checks.get("has_changelog"):
            badges.append(Badge("has_changelog", "Changelog", "good"))
        if doc_checks.get("has_examples"):
            badges.append(Badge("has_examples", "Examples", "good"))
        if doc_checks.get("has_contributing"):
            badges.append(Badge("has_contributing", "Contributing Guide", "good"))
        if doc_checks.get("has_docs_dir"):
            badges.append(Badge("has_docs_dir", "Docs Dir", "good"))

        prov_checks = details.get("provenance", {}).get("checks", {})
        if prov_checks.get("has_security_policy"):
            badges.append(Badge("security_policy", "SECURITY.md", "good"))
        if prov_checks.get("has_code_of_conduct"):
            badges.append(Badge("code_of_conduct", "Code of Conduct", "good"))
        if prov_checks.get("namespace_owner_match") is True:
            badges.append(Badge("namespace_match", "Namespace Match", "good"))
        elif prov_checks.get("namespace_owner_match") is False:
            badges.append(Badge("namespace_mismatch", "Namespace Mismatch", "warning"))
        if prov_checks.get("has_installable_package"):
            badges.append(Badge("installable", "Installable", "good"))

        desc_checks = details.get("description_quality", {}).get("checks", {})
        if desc_checks.get("has_usage_section"):
            badges.append(Badge("usage_docs", "Usage Docs", "good"))
        if desc_checks.get("has_code_examples"):
            badges.append(Badge("code_examples", "Code Examples", "good"))

    if flags:
        flag_keys = {f["key"] if isinstance(f, dict) else f.key for f in flags}
        if "TEMPLATE_DESCRIPTION" in flag_keys:
            badges.append(Badge("template_desc", "Template Description", "warning"))

    return badges


def _protocol_badges(deep_probe: DeepProbeResult | None) -> list[Badge]:
    badges = []

    if not deep_probe:
        return badges

    if deep_probe.is_reachable:
        badges.append(Badge("reachable", "Reachable", "good"))
    else:
        badges.append(Badge("unreachable", "Unreachable", "critical"))

    if deep_probe.schema_valid is True:
        badges.append(Badge("schema_valid", "Schema Valid", "good"))
    elif deep_probe.schema_valid is False:
        badges.append(Badge("schema_invalid", "Schema Invalid", "warning"))

    if deep_probe.tools_count is not None and deep_probe.tools_count > 0:
        badges.append(Badge("has_tools", f"{deep_probe.tools_count} Tools", "good"))

    if deep_probe.error_handling_score is not None:
        if deep_probe.error_handling_score >= 70:
            badges.append(Badge("good_errors", "Good Error Handling", "good"))
        elif deep_probe.error_handling_score < 40:
            badges.append(Badge("poor_errors", "Poor Error Handling", "warning"))

    if deep_probe.auth_discovery_valid is True:
        badges.append(Badge("auth_discovery", "Auth Discovery", "good"))

    return badges


def _reliability_badges(
    server: ServerInfo, reliability: ReliabilityData | None
) -> list[Badge]:
    badges = []

    if reliability and reliability.uptime_pct is not None:
        if reliability.uptime_pct >= 99.0:
            badges.append(Badge("high_uptime", "99%+ Uptime", "good"))
        elif reliability.uptime_pct >= 95.0:
            badges.append(Badge("good_uptime", "95%+ Uptime", "good"))
        elif reliability.uptime_pct >= 80.0:
            badges.append(Badge("degraded_uptime", "Degraded Uptime", "warning"))
        else:
            badges.append(Badge("low_uptime", "Low Uptime", "critical"))

    if reliability and reliability.latency_p50_ms is not None:
        p50 = reliability.latency_p50_ms
        if p50 < 200:
            badges.append(Badge("low_latency", "Fast (<200ms)", "good"))
        elif p50 < 500:
            badges.append(Badge("med_latency", "Moderate Latency", "neutral"))
        elif p50 < 1000:
            badges.append(Badge("high_latency", "Slow (>500ms)", "warning"))
        else:
            badges.append(Badge("very_high_latency", "Very Slow (>1s)", "critical"))

    if not server.is_remote:
        badges.append(Badge("local_only", "Local Only", "neutral"))

    return badges


def _maintenance_badges(static_result: StaticAnalysis | None) -> list[Badge]:
    badges = []

    if not static_result:
        return badges

    details = static_result.details or {}

    maint = details.get("maintenance_pulse", {})
    days = maint.get("days_since_last_push")
    if days is not None:
        if days <= 30:
            badges.append(Badge("active", "Active Development", "good"))
        elif days <= 180:
            badges.append(Badge("moderate", "Moderate Activity", "neutral"))
        elif days <= 365:
            badges.append(Badge("stale", "Stale", "warning"))
        else:
            badges.append(Badge("abandoned", "Possibly Abandoned", "critical"))

    if maint.get("release_count", 0) >= 3:
        badges.append(Badge("regular_releases", "Regular Releases", "good"))
    elif maint.get("release_count", 0) >= 1:
        badges.append(Badge("has_releases", "Has Releases", "good"))

    dep_checks = details.get("dependency_health", {}).get("checks", {})
    if dep_checks.get("has_ci"):
        badges.append(Badge("has_ci", "CI/CD", "good"))
    if dep_checks.get("has_lock_file"):
        badges.append(Badge("lock_file", "Lock File", "good"))
    if dep_checks.get("has_dependency_automation"):
        badges.append(Badge("dep_automation", "Dep Automation", "good"))

    lic = details.get("license_clarity", {})
    if lic.get("spdx_id") and lic["spdx_id"] != "NOASSERTION":
        badges.append(Badge("licensed", lic["spdx_id"], "good"))
    elif lic.get("issue") == "no_license_detected":
        badges.append(Badge("no_license", "No License", "warning"))

    ver = details.get("version_hygiene", {})
    if ver.get("semver_ratio", 0) >= 0.8:
        badges.append(Badge("semver", "Semver", "good"))

    return badges


def _security_badges(server: ServerInfo) -> list[Badge]:
    badges = []

    meta = server.registry_metadata or {}
    env_vars = meta.get("env_vars", [])

    secret_pattern = re.compile(
        r"(api[_-]?key|secret|token|password|auth|credential|private[_-]?key)",
        re.IGNORECASE,
    )
    sensitive_vars = [v for v in env_vars if secret_pattern.search(v)]

    if len(sensitive_vars) == 0:
        badges.append(Badge("no_secrets", "No Secrets Required", "good"))
    elif len(sensitive_vars) <= 2:
        badges.append(Badge("few_secrets", f"{len(sensitive_vars)} Secret(s)", "neutral"))
    else:
        badges.append(Badge("many_secrets", f"{len(sensitive_vars)} Secrets", "warning"))

    if not server.is_remote:
        badges.append(Badge("stdio", "STDIO Only", "good"))
    else:
        badges.append(Badge("remote", "Remote Endpoint", "neutral"))

    if server.npm_url or server.pypi_url or server.dockerhub_url:
        badges.append(Badge("published", "Published Package", "good"))

    return badges
