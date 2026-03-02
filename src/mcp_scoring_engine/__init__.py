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
from .probes.static import analyze_repo
from .scoring import (
    compute_score,
    extract_publisher,
    GRADE_THRESHOLDS,
    is_verified_publisher,
    score_to_grade,
    VERIFIED_PUBLISHERS,
    WEIGHT_MAINTENANCE,
    WEIGHT_PROTOCOL,
    WEIGHT_RELIABILITY,
    WEIGHT_SCHEMA_DOCS,
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
    "GRADE_THRESHOLDS",
    "VERIFIED_PUBLISHERS",
    "WEIGHT_SCHEMA_DOCS",
    "WEIGHT_PROTOCOL",
    "WEIGHT_RELIABILITY",
    "WEIGHT_MAINTENANCE",
    "WEIGHT_SECURITY",
    # Probes
    "probe_server",
    "probe_server_stdio",
    "deep_probe_server",
    "deep_probe_server_stdio",
    "analyze_repo",
    "compute_reliability_score",
    # Classification & Flags & Badges
    "classify_server",
    "detect_flags",
    "generate_badges",
]
