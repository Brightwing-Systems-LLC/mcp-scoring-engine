"""Shared test fixtures for mcp-scoring-engine tests."""

from datetime import datetime, timezone

import pytest

from mcp_scoring_engine import (
    DeepProbeResult,
    ReliabilityData,
    ServerInfo,
    StaticAnalysis,
)


@pytest.fixture
def clean_server() -> ServerInfo:
    """A well-configured server with no issues."""
    return ServerInfo(
        name="acme/awesome-mcp-server",
        description="An MCP server that connects to the Acme API for widget management.",
        repo_url="https://github.com/acme-corp/awesome-mcp-server",
        registry_id="@acme-corp/awesome-mcp-server",
        remote_endpoint_url="https://mcp.acme.dev/mcp",
        is_remote=True,
        registry_metadata={
            "env_vars": ["ACME_API_KEY"],
            "transport": "streamable-http",
        },
        npm_url="https://www.npmjs.com/package/@acme-corp/awesome-mcp-server",
        pypi_url="",
        dockerhub_url="",
        last_commit_at=datetime(2026, 2, 15, tzinfo=timezone.utc),
    )


@pytest.fixture
def full_static() -> StaticAnalysis:
    """Complete static analysis with good scores across the board."""
    return StaticAnalysis(
        schema_completeness=85,
        description_quality=78,
        documentation_coverage=72,
        maintenance_pulse=80,
        dependency_health=75,
        license_clarity=100,
        version_hygiene=65,
        details={
            "documentation_coverage": {
                "checks": {
                    "has_readme": True,
                    "has_changelog": True,
                    "has_examples": True,
                    "has_contributing": False,
                    "has_license_file": True,
                    "has_docs_dir": False,
                }
            },
            "provenance": {
                "checks": {
                    "has_security_policy": True,
                    "has_code_of_conduct": False,
                    "namespace_owner_match": True,
                    "has_installable_package": True,
                }
            },
            "description_quality": {
                "checks": {
                    "has_usage_section": True,
                    "has_code_examples": True,
                }
            },
            "maintenance_pulse": {
                "days_since_last_push": 12,
                "release_count": 5,
            },
            "dependency_health": {
                "checks": {
                    "has_ci": True,
                    "has_lock_file": True,
                    "has_dependency_automation": True,
                }
            },
            "license_clarity": {
                "spdx_id": "MIT",
                "name": "MIT License",
            },
            "version_hygiene": {
                "semver_ratio": 0.9,
            },
        },
        last_commit_at=datetime(2026, 2, 15, tzinfo=timezone.utc),
        open_issues_count=3,
        stars_count=150,
        latest_version="v2.1.0",
    )


@pytest.fixture
def full_deep_probe() -> DeepProbeResult:
    """Successful deep probe with good results."""
    return DeepProbeResult(
        is_reachable=True,
        connection_ms=45,
        initialize_ms=120,
        ping_ms=30,
        error_message="",
        tools_list_ms=80,
        tools_count=5,
        schema_valid=True,
        schema_issues=[],
        error_handling_score=87,
        error_handling_details={"tests_passed": 3, "tests_total": 3},
        fuzz_score=75,
        fuzz_details={"tests_passed": 6, "tests_total": 8},
        auth_discovery_valid=None,
    )


@pytest.fixture
def full_reliability() -> ReliabilityData:
    """Good reliability data from a 7-day window."""
    return ReliabilityData(
        uptime_pct=98.5,
        latency_p50_ms=145,
        latency_p95_ms=380,
        probe_count=2016,
    )
