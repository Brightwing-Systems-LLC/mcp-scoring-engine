"""MCP spec version detection from SDK dependencies and source markers.

Maps SDK versions to protocol spec versions:
  < 1.1.0        → "2024-11-05" (initial spec)
  1.1.x – 1.5.x  → "2025-06-18" (StreamableHTTP, OAuth)
  ≥ 1.6.0        → "2025-11-25" (tasks, structured outputs, elicitation)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


@dataclass
class SpecVersionResult:
    """Result of spec version detection."""

    detected_spec_version: str = "unknown"  # "2024-11-05", "2025-06-18", "2025-11-25", "unknown"
    protocol_version: str | None = None  # From initialize response
    sdk_name: str = ""  # e.g., "@modelcontextprotocol/sdk"
    sdk_version: str = ""  # e.g., "1.6.2"
    features_detected: list[str] = field(default_factory=list)
    detection_source: str = ""  # "sdk_version", "source_markers", "protocol_probe", "inferred"
    confidence: str = "low"  # "high", "medium", "low"


# ── SDK version → spec version mapping ────────────────────────────────────

# Node SDK: @modelcontextprotocol/sdk
# Python SDK: mcp
_SDK_PACKAGES = {
    "@modelcontextprotocol/sdk": "node",
    "mcp": "python",
}

# Version boundaries
_SPEC_2025_11_25_MIN = (1, 6, 0)
_SPEC_2025_06_18_MIN = (1, 1, 0)


def _parse_semver(version_str: str) -> tuple[int, ...] | None:
    """Parse a semver string into a tuple of ints, ignoring pre-release."""
    version_str = version_str.strip().lstrip("^~>=<! ")
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version_str)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    m = re.match(r"(\d+)\.(\d+)", version_str)
    if m:
        return (int(m.group(1)), int(m.group(2)), 0)
    m = re.match(r"(\d+)", version_str)
    if m:
        return (int(m.group(1)), 0, 0)
    return None


def _version_to_spec(version_tuple: tuple[int, ...]) -> str:
    """Map an SDK version tuple to a spec version string."""
    if version_tuple >= _SPEC_2025_11_25_MIN:
        return "2025-11-25"
    if version_tuple >= _SPEC_2025_06_18_MIN:
        return "2025-06-18"
    return "2024-11-05"


# ── Source code feature markers ──────────────────────────────────────────

_FEATURE_MARKERS = {
    # 2025-06-18 features
    "streamable_http": re.compile(r"streamable[_\-]?http|StreamableHTTP", re.IGNORECASE),
    "oauth": re.compile(r"oauth[_\-]?protected[_\-]?resource|OAuthProvider", re.IGNORECASE),
    # 2025-11-25 features
    "elicitation": re.compile(r"elicitation|createElicitation|ElicitationRequest", re.IGNORECASE),
    "tasks": re.compile(r"tasks/list|TaskRequest|server\.task\(", re.IGNORECASE),
    "structured_output": re.compile(r"structuredOutput|structured_output|StructuredContent", re.IGNORECASE),
}

_FEATURES_2025_11_25 = {"elicitation", "tasks", "structured_output"}
_FEATURES_2025_06_18 = {"streamable_http", "oauth"}


def detect_spec_from_sdk(manifest_content: str, manifest_type: str) -> SpecVersionResult:
    """Detect spec version from package.json or pyproject.toml content.

    Args:
        manifest_content: Raw file content of the manifest.
        manifest_type: "package.json" or "pyproject.toml".
    """
    result = SpecVersionResult(detection_source="sdk_version")

    if manifest_type == "package.json":
        return _detect_from_package_json(manifest_content, result)
    elif manifest_type == "pyproject.toml":
        return _detect_from_pyproject_toml(manifest_content, result)
    return result


def _detect_from_package_json(content: str, result: SpecVersionResult) -> SpecVersionResult:
    """Parse package.json for @modelcontextprotocol/sdk version."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return result

    deps = {}
    deps.update(data.get("dependencies", {}))
    deps.update(data.get("devDependencies", {}))

    sdk_key = "@modelcontextprotocol/sdk"
    if sdk_key in deps:
        version_str = deps[sdk_key]
        result.sdk_name = sdk_key
        result.sdk_version = version_str
        parsed = _parse_semver(version_str)
        if parsed:
            result.detected_spec_version = _version_to_spec(parsed)
            result.confidence = "high"
    return result


def _detect_from_pyproject_toml(content: str, result: SpecVersionResult) -> SpecVersionResult:
    """Parse pyproject.toml for mcp SDK version."""
    # Simple regex parsing to avoid toml dependency
    for line in content.splitlines():
        line = line.strip()
        # Match patterns like: "mcp>=1.6.0", "mcp~=1.2.0", "mcp==1.5.0", 'mcp>=1.1.0,<2.0'
        m = re.match(r'["\']?mcp\s*([><=~!]+\s*[\d.]+)', line)
        if m:
            result.sdk_name = "mcp"
            version_part = m.group(1)
            result.sdk_version = version_part.strip()
            parsed = _parse_semver(version_part)
            if parsed:
                result.detected_spec_version = _version_to_spec(parsed)
                result.confidence = "high"
            break
    return result


def detect_spec_from_source_markers(source_files: list[dict]) -> SpecVersionResult:
    """Detect spec version from feature markers in source code.

    Args:
        source_files: List of dicts with "path" and "content" keys.
    """
    result = SpecVersionResult(detection_source="source_markers")
    features_found: set[str] = set()

    for sf in source_files:
        content = sf.get("content", "")
        for feature_name, pattern in _FEATURE_MARKERS.items():
            if pattern.search(content):
                features_found.add(feature_name)

    result.features_detected = sorted(features_found)

    if features_found & _FEATURES_2025_11_25:
        result.detected_spec_version = "2025-11-25"
        result.confidence = "medium"
    elif features_found & _FEATURES_2025_06_18:
        result.detected_spec_version = "2025-06-18"
        result.confidence = "medium"

    return result
