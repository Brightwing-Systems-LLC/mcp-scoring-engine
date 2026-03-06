"""Red flag detection for MCP servers.

Detects 11 categories of red flags that indicate quality or security concerns.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .types import Flag, ServerInfo

# ── Sensitive env var patterns ────────────────────────────────────────────
_SECRET_PATTERNS = re.compile(
    r"(api[_-]?key|secret|token|password|auth|credential|private[_-]?key)",
    re.IGNORECASE,
)

# ── Template description patterns ─────────────────────────────────────────
_TEMPLATE_DESCRIPTIONS = [
    "a model context protocol server",
    "an mcp server",
    "mcp server for",
    "a mcp server",
    "description of my mcp server",
    "your mcp server description",
    "todo: add description",
    "add your description here",
]

# ── Staging artifact patterns ─────────────────────────────────────────────
_STAGING_PATTERNS = re.compile(
    r"(localhost|127\.0\.0\.1|example\.com|staging\.|\.local:|test-server)",
    re.IGNORECASE,
)


@dataclass
class FlagContext:
    """Corpus-wide data precomputed for dedup detection.

    Only used by the Django scoreboard for batch processing.
    The CLI does not use this.
    """

    description_counts: Counter = field(default_factory=Counter)
    archived_repos: set = field(default_factory=set)


def detect_flags(server: ServerInfo, context: FlagContext | None = None) -> list[Flag]:
    """Run all flag detectors against a server. Returns list of Flag objects."""
    flags = []

    flags.extend(_check_dead_repo(server))
    flags.extend(_check_no_source(server))
    flags.extend(_check_sensitive_creds(server))
    flags.extend(_check_high_secret_demand(server))
    flags.extend(_check_repo_archived(server, context))
    flags.extend(_check_stale_project(server))
    flags.extend(_check_staging_artifact(server))
    flags.extend(_check_template_description(server))
    flags.extend(_check_description_duplicate(server, context))
    flags.extend(_check_schema_drift(server))
    flags.extend(_check_ambiguous_schema(server))
    flags.extend(_check_outdated_spec(server))
    flags.extend(_check_prompt_injection(server))
    flags.extend(_check_exfiltration_risk(server))
    flags.extend(_check_stale_analysis(server))

    return flags


def _check_dead_repo(server: ServerInfo) -> list[Flag]:
    """Repo URL returns 404 or is missing when expected."""
    meta = server.registry_metadata or {}
    if meta.get("repo_status") == "404" or meta.get("repo_status") == "gone":
        return [
            Flag(
                key="DEAD_REPO",
                severity="critical",
                label="Dead Repository",
                description="The linked GitHub repository returns 404 or has been deleted.",
            )
        ]
    return []


def _check_no_source(server: ServerInfo) -> list[Flag]:
    """No repo URL and no registry source code link."""
    if server.repo_url:
        return []
    meta = server.registry_metadata or {}
    if meta.get("source_url") or meta.get("homepage"):
        return []
    return [
        Flag(
            key="NO_SOURCE",
            severity="warning",
            label="No Source Code",
            description="No repository URL or source code link found.",
        )
    ]


def _check_sensitive_creds(server: ServerInfo) -> list[Flag]:
    """Server requires sensitive environment variables (API keys, tokens)."""
    meta = server.registry_metadata or {}
    env_vars = meta.get("env_vars", [])
    if not env_vars:
        return []

    sensitive = [v for v in env_vars if _SECRET_PATTERNS.search(v)]
    if len(sensitive) >= 3:
        return [
            Flag(
                key="SENSITIVE_CREDS",
                severity="warning",
                label="Many Secrets Required",
                description=(
                    f"Requires {len(sensitive)} sensitive environment variables "
                    f"({', '.join(sensitive[:3])})."
                ),
            )
        ]
    return []


_NON_SENSITIVE_PATTERN = re.compile(
    r"^(port|host|log[_-]?level|debug|workers?|timeout|env|node[_-]?env"
    r"|base[_-]?url|app[_-]?name|version|region|locale|lang(uage)?)$",
    re.IGNORECASE,
)


def _check_high_secret_demand(server: ServerInfo) -> list[Flag]:
    """Requires an unusually high number of potentially-sensitive env vars (5+).

    Filters out non-sensitive config vars (PORT, HOST, LOG_LEVEL, etc.)
    before counting.
    """
    meta = server.registry_metadata or {}
    env_vars = meta.get("env_vars", [])
    # Only count vars that could be sensitive (not PORT, HOST, etc.)
    sensitive_vars = [v for v in env_vars if not _NON_SENSITIVE_PATTERN.match(v)]
    if len(sensitive_vars) >= 5:
        return [
            Flag(
                key="HIGH_SECRET_DEMAND",
                severity="warning",
                label="High Config Demand",
                description=f"Requires {len(sensitive_vars)} potentially-sensitive environment variables.",
            )
        ]
    return []


def _check_repo_archived(server: ServerInfo, context: FlagContext | None) -> list[Flag]:
    """Repository is archived on GitHub."""
    meta = server.registry_metadata or {}
    if meta.get("archived"):
        return [
            Flag(
                key="REPO_ARCHIVED",
                severity="critical",
                label="Archived Repository",
                description="The GitHub repository is archived and no longer maintained.",
            )
        ]

    if context and server.repo_url and server.repo_url in context.archived_repos:
        return [
            Flag(
                key="REPO_ARCHIVED",
                severity="critical",
                label="Archived Repository",
                description="The GitHub repository is archived and no longer maintained.",
            )
        ]
    return []


def _check_stale_project(server: ServerInfo) -> list[Flag]:
    """No commits in over 12 months."""
    if not server.last_commit_at:
        return []
    stale_threshold = datetime.now(timezone.utc) - timedelta(days=365)
    if server.last_commit_at < stale_threshold:
        return [
            Flag(
                key="STALE_PROJECT",
                severity="warning",
                label="Stale Project",
                description="No commits in over 12 months.",
            )
        ]
    return []


def _check_staging_artifact(server: ServerInfo) -> list[Flag]:
    """Endpoint URL contains localhost, staging, or test patterns."""
    url = server.remote_endpoint_url or ""
    if url and _STAGING_PATTERNS.search(url):
        return [
            Flag(
                key="STAGING_ARTIFACT",
                severity="warning",
                label="Staging Endpoint",
                description="Remote endpoint URL contains localhost/staging patterns.",
            )
        ]
    return []


def _check_template_description(server: ServerInfo) -> list[Flag]:
    """Description is a generic template placeholder."""
    desc = (server.description or "").strip().lower()
    if not desc:
        return []
    for template in _TEMPLATE_DESCRIPTIONS:
        if desc.startswith(template) or desc == template:
            return [
                Flag(
                    key="TEMPLATE_DESCRIPTION",
                    severity="warning",
                    label="Template Description",
                    description="Server description appears to be a default template placeholder.",
                )
            ]
    return []


def _check_description_duplicate(
    server: ServerInfo, context: FlagContext | None
) -> list[Flag]:
    """Description is shared by 3+ other servers (copy-paste)."""
    if not context:
        return []
    desc = (server.description or "").strip().lower()[:200]
    if not desc or len(desc) < 20:
        return []
    count = context.description_counts.get(desc, 0)
    if count >= 3:
        return [
            Flag(
                key="DESCRIPTION_DUPLICATE",
                severity="warning",
                label="Duplicate Description",
                description=f"This description is shared by {count} servers — likely copy-pasted.",
            )
        ]
    return []


def _check_schema_drift(server: ServerInfo) -> list[Flag]:
    """Static analysis and runtime probe found different tool sets."""
    meta = server.registry_metadata or {}
    drift = meta.get("schema_drift", {})
    if not isinstance(drift, dict) or not drift.get("has_drift"):
        return []

    missing = drift.get("missing_at_runtime", [])
    extra = drift.get("extra_at_runtime", [])
    parts = []
    if missing:
        parts.append(f"{len(missing)} tool(s) missing at runtime")
    if extra:
        parts.append(f"{len(extra)} tool(s) only found at runtime")
    detail = "; ".join(parts) if parts else "Tool sets differ"

    return [
        Flag(
            key="SCHEMA_DRIFT",
            severity="warning",
            label="Schema Drift",
            description=f"Source code and runtime expose different tools. {detail}.",
        )
    ]


def _check_ambiguous_schema(server: ServerInfo) -> list[Flag]:
    """Multiple AI models interpret tool schemas differently."""
    meta = server.registry_metadata or {}
    ambiguous = meta.get("ambiguous_tools", [])
    if not isinstance(ambiguous, list) or len(ambiguous) < 2:
        return []
    return [
        Flag(
            key="AMBIGUOUS_SCHEMA",
            severity="warning",
            label="Ambiguous Schemas",
            description=(
                f"{len(ambiguous)} tool(s) have ambiguous schemas that AI models "
                f"interpret differently: {', '.join(ambiguous[:5])}."
            ),
        )
    ]


def _check_outdated_spec(server: ServerInfo) -> list[Flag]:
    """Server implements an outdated MCP spec version."""
    meta = server.registry_metadata or {}
    spec = meta.get("spec_version", {})
    if not isinstance(spec, dict):
        return []
    version = spec.get("detected_spec_version", "")
    if version == "2024-11-05":
        return [
            Flag(
                key="OUTDATED_SPEC",
                severity="warning",
                label="Outdated MCP Spec",
                description=(
                    "Implements the original MCP spec (2024-11-05). "
                    "Missing StreamableHTTP, OAuth 2.1, and modern features."
                ),
            )
        ]
    return []


def _check_prompt_injection(server: ServerInfo) -> list[Flag]:
    """Tool descriptions contain prompt injection patterns."""
    meta = server.registry_metadata or {}
    behavioral = meta.get("behavioral_security", {})
    if not isinstance(behavioral, dict):
        return []
    if behavioral.get("prompt_injection_found"):
        return [
            Flag(
                key="PROMPT_INJECTION",
                severity="critical",
                label="Prompt Injection Risk",
                description="Tool descriptions contain patterns that could manipulate AI agents.",
            )
        ]
    return []


def _check_exfiltration_risk(server: ServerInfo) -> list[Flag]:
    """Source code shows data exfiltration patterns."""
    meta = server.registry_metadata or {}
    behavioral = meta.get("behavioral_security", {})
    if not isinstance(behavioral, dict):
        return []
    if behavioral.get("exfiltration_risk"):
        return [
            Flag(
                key="EXFILTRATION_RISK",
                severity="critical",
                label="Exfiltration Risk",
                description="Source code contains patterns that may send data to unexpected destinations.",
            )
        ]
    return []


def _check_stale_analysis(server: ServerInfo) -> list[Flag]:
    """Static analysis data is older than 60 days."""
    meta = server.registry_metadata or {}
    last_analyzed = meta.get("last_analyzed_at")
    if not last_analyzed:
        return []

    if isinstance(last_analyzed, str):
        try:
            last_analyzed = datetime.fromisoformat(last_analyzed.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return []

    if not isinstance(last_analyzed, datetime):
        return []

    if last_analyzed.tzinfo is None:
        last_analyzed = last_analyzed.replace(tzinfo=timezone.utc)

    age = datetime.now(timezone.utc) - last_analyzed
    if age > timedelta(days=60):
        days = age.days
        return [
            Flag(
                key="STALE_ANALYSIS",
                severity="warning",
                label="Stale Analysis",
                description=f"Static analysis data is {days} days old. Results may not reflect current state.",
            )
        ]
    return []
