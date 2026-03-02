"""Central type definitions for the MCP scoring engine.

All scoring functions accept these dataclasses instead of ORM objects,
keeping the engine free of any framework dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ServerInfo:
    """Minimal server metadata needed by scoring functions.

    Both the CLI and Django app construct this from their own data sources.
    """

    name: str = ""
    description: str = ""
    repo_url: str = ""
    registry_id: str = ""
    remote_endpoint_url: str = ""
    is_remote: bool = True
    registry_metadata: dict = field(default_factory=dict)
    npm_url: str = ""
    pypi_url: str = ""
    dockerhub_url: str = ""
    last_commit_at: datetime | None = None


@dataclass
class FastProbeResult:
    """Result of a fast health probe."""

    is_reachable: bool = False
    connection_ms: int | None = None
    initialize_ms: int | None = None
    ping_ms: int | None = None
    error_message: str = ""


@dataclass
class DeepProbeResult:
    """Result of a deep protocol compliance probe."""

    # Fast probe fields (reused)
    is_reachable: bool = False
    connection_ms: int | None = None
    initialize_ms: int | None = None
    ping_ms: int | None = None
    error_message: str = ""

    # Deep probe fields
    tools_list_ms: int | None = None
    tools_count: int | None = None
    tools: list = field(default_factory=list)
    schema_valid: bool | None = None
    schema_issues: list = field(default_factory=list)
    error_handling_score: int | None = None
    error_handling_details: dict = field(default_factory=dict)
    fuzz_score: int | None = None
    fuzz_details: dict = field(default_factory=dict)
    auth_discovery_valid: bool | None = None


@dataclass
class StaticAnalysis:
    """Complete static analysis result for a single server."""

    # Individual metric scores (0-100)
    schema_completeness: int = 0
    description_quality: int = 0
    documentation_coverage: int = 0
    maintenance_pulse: int = 0
    dependency_health: int = 0
    license_clarity: int = 0
    version_hygiene: int = 0

    # Raw data
    details: dict = field(default_factory=dict)

    # GitHub metadata snapshot
    last_commit_at: datetime | None = None
    open_issues_count: int | None = None
    stars_count: int | None = None
    latest_version: str = ""


@dataclass
class ReliabilityData:
    """Pre-computed reliability metrics.

    CLI: computed from single probe run (latency only, no uptime).
    Scoreboard: computed from 7-day rolling window of probes.
    """

    uptime_pct: float | None = None  # 0-100, None if not available
    latency_p50_ms: int | None = None
    latency_p95_ms: int | None = None
    probe_count: int = 0


@dataclass
class Flag:
    """A quality or security red flag detected on a server."""

    key: str
    severity: str  # "critical" or "warning"
    label: str
    description: str


@dataclass
class Badge:
    """A status badge for display in scoring UI."""

    key: str
    label: str
    level: str  # "good", "neutral", "warning", "critical"


@dataclass
class ScoreResult:
    """Complete scoring output."""

    composite_score: int | None = None
    grade: str = ""
    score_type: str = ""  # "partial", "full", "enhanced"

    # Category scores
    schema_docs_score: int | None = None
    protocol_score: int | None = None
    reliability_score: int | None = None
    maintenance_score: int | None = None
    security_score: int | None = None

    # Metadata
    flags: list[Flag] = field(default_factory=list)
    badges: dict = field(default_factory=dict)
    category: str = ""
    targets: list[str] = field(default_factory=list)
    publisher: str = ""
    verified_publisher: bool = False

    # Source data (for report generation)
    deep_probe: DeepProbeResult | None = None
    static_analysis: StaticAnalysis | None = None
    reliability_data: ReliabilityData | None = None
    server_info: ServerInfo | None = None
