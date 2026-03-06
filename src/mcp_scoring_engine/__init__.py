"""MCP Scoring Engine — standalone quality assessment for MCP servers.

Public API for scoring, probing, and classifying MCP servers.
No Django, no database — pure Python.
"""

from .badges import generate_badges
from .classification import classify_server
from .flags import detect_flags, FlagContext
from .probes.health import probe_server, probe_server_stdio
from .probes.protocol import deep_probe_server, deep_probe_server_stdio
from .probes.reliability import compute_reliability_score
from .probes.entry_point import detect_entry_point, make_github_file_reader
from .probes.static import analyze_repo
from .probes.reliability import MINIMUM_PROBE_COUNT
from .probes.spec_version import (
    SpecVersionResult,
    detect_spec_from_sdk,
    detect_spec_from_source_markers,
)
from .security import scan_tool_descriptions
from .scoring import (
    compute_score,
    extract_publisher,
    FLAG_SCORE_CAPS,
    GRADE_THRESHOLDS,
    is_verified_publisher,
    score_to_grade,
    VERIFIED_PUBLISHERS,
    WEIGHT_AGENT_USABILITY,
    WEIGHT_DOCS_MAINTENANCE,
    WEIGHT_MAINTENANCE,
    WEIGHT_PROTOCOL,
    WEIGHT_RELIABILITY,
    WEIGHT_SCHEMA_DOCS,
    WEIGHT_SCHEMA_QUALITY,
    WEIGHT_SECURITY,
)
from .types import (
    Badge,
    DeepProbeResult,
    FastProbeResult,
    Flag,
    ReliabilityData,
    ScoreResult,
    ServerInfo,
    StaticAnalysis,
)

__all__ = [
    # Types
    "Badge",
    "DeepProbeResult",
    "FastProbeResult",
    "Flag",
    "FlagContext",
    "ReliabilityData",
    "ScoreResult",
    "ServerInfo",
    "StaticAnalysis",
    # Scoring
    "compute_score",
    "score_to_grade",
    "is_verified_publisher",
    "extract_publisher",
    "FLAG_SCORE_CAPS",
    "GRADE_THRESHOLDS",
    "MINIMUM_PROBE_COUNT",
    "VERIFIED_PUBLISHERS",
    "WEIGHT_AGENT_USABILITY",
    "WEIGHT_DOCS_MAINTENANCE",
    "WEIGHT_MAINTENANCE",
    "WEIGHT_PROTOCOL",
    "WEIGHT_RELIABILITY",
    "WEIGHT_SCHEMA_DOCS",
    "WEIGHT_SCHEMA_QUALITY",
    "WEIGHT_SECURITY",
    # Probes
    "probe_server",
    "probe_server_stdio",
    "deep_probe_server",
    "deep_probe_server_stdio",
    "analyze_repo",
    "detect_entry_point",
    "make_github_file_reader",
    "compute_reliability_score",
    # Classification & Flags & Badges
    "classify_server",
    "detect_flags",
    "generate_badges",
    # Spec version detection
    "SpecVersionResult",
    "detect_spec_from_sdk",
    "detect_spec_from_source_markers",
    # Security scanning
    "scan_tool_descriptions",
]
