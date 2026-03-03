"""End-to-end integration tests for the scoring engine."""

from datetime import datetime, timezone

from mcp_scoring_engine import (
    DeepProbeResult,
    ReliabilityData,
    ScoreResult,
    ServerInfo,
    StaticAnalysis,
    compute_score,
    score_to_grade,
)


def test_full_scoring_pipeline():
    """Build a complete server profile and verify scoring output."""
    server = ServerInfo(
        name="@modelcontextprotocol/server-github",
        description="MCP server for GitHub API integration — search repos, manage issues, and more",
        repo_url="https://github.com/modelcontextprotocol/servers",
        registry_id="@modelcontextprotocol/server-github",
        remote_endpoint_url="https://mcp-github.example.com/mcp",
        is_remote=True,
        registry_metadata={
            "env_vars": ["GITHUB_TOKEN"],
            "transport": "streamable-http",
        },
        npm_url="https://www.npmjs.com/package/@modelcontextprotocol/server-github",
        last_commit_at=datetime(2026, 2, 20, tzinfo=timezone.utc),
    )

    static = StaticAnalysis(
        schema_completeness=90,
        description_quality=85,
        documentation_coverage=80,
        maintenance_pulse=95,
        dependency_health=85,
        license_clarity=100,
        version_hygiene=80,
        details={
            "documentation_coverage": {"checks": {"has_readme": True}},
            "provenance": {"checks": {}},
            "description_quality": {"checks": {}},
            "maintenance_pulse": {"days_since_last_push": 5, "release_count": 8},
            "dependency_health": {"checks": {"has_ci": True, "has_lock_file": True}},
            "license_clarity": {"spdx_id": "MIT"},
            "version_hygiene": {"semver_ratio": 1.0},
        },
    )

    deep = DeepProbeResult(
        is_reachable=True,
        connection_ms=30,
        initialize_ms=80,
        ping_ms=20,
        tools_count=8,
        schema_valid=True,
        error_handling_score=90,
        fuzz_score=85,
    )

    reliability = ReliabilityData(
        uptime_pct=99.5,
        latency_p50_ms=100,
        probe_count=2000,
    )

    result = compute_score(server, static, deep, reliability)

    assert isinstance(result, ScoreResult)
    assert result.composite_score is not None
    assert result.score_type == "full"
    assert result.grade in ("A+", "A", "B", "C", "D", "F")
    assert result.verified_publisher is True
    assert result.publisher == "modelcontextprotocol"
    assert result.category != "other"

    # Verify all category scores are set
    assert result.schema_docs_score is not None
    assert result.protocol_score is not None
    assert result.reliability_score is not None
    assert result.maintenance_score is not None
    assert result.security_score is not None

    # Verify grade is consistent with score
    assert result.grade == score_to_grade(result.composite_score)

    # Verify badges are generated
    assert len(result.badges) == 5
    for category in ("schema", "protocol", "reliability", "maintenance", "security"):
        assert category in result.badges

    # Source data preserved
    assert result.server_info is server
    assert result.deep_probe is deep
    assert result.static_analysis is static
    assert result.reliability_data is reliability


def test_cli_mode_latency_only():
    """Simulate CLI mode: single probe, no uptime history."""
    server = ServerInfo(
        name="my-local-server",
        description="A local MCP server for testing",
        is_remote=False,
        registry_metadata={"env_vars": [], "transport": "stdio"},
    )

    deep = DeepProbeResult(
        is_reachable=True,
        connection_ms=50,
        initialize_ms=100,
        ping_ms=25,
        tools_count=3,
        schema_valid=True,
        error_handling_score=75,
        fuzz_score=70,
    )

    # CLI mode: latency only, no uptime (probe_count=0 is CLI default)
    reliability = ReliabilityData(latency_p50_ms=50)

    result = compute_score(server, deep_probe=deep, reliability=reliability)

    assert result.composite_score is None  # No composite for partials
    # Local server: protocol & reliability are N/A, so deep+reliability don't count.
    # Only security is filled (from metadata), schema_docs and maintenance are missing → partial.
    assert result.score_type == "partial"
    assert result.reliability_score == 100  # 50ms latency


def test_github_only_mode():
    """Simulate GitHub-only mode: static analysis only, no probes."""
    server = ServerInfo(
        name="some-tool",
        description="A useful MCP tool for data analysis",
        repo_url="https://github.com/user/some-tool",
        registry_metadata={"env_vars": ["API_KEY"]},
    )

    static = StaticAnalysis(
        schema_completeness=60,
        description_quality=50,
        documentation_coverage=40,
        maintenance_pulse=45,
        dependency_health=50,
        license_clarity=100,
        version_hygiene=30,
    )

    result = compute_score(server, static_result=static)

    assert result.composite_score is None  # No composite for partials
    assert result.score_type == "partial"
    assert result.grade == ""  # Partial scores don't get grades
    assert result.protocol_score is None
    assert result.reliability_score is None
    assert result.schema_docs_score is not None
    assert result.maintenance_score is not None


def test_no_data_returns_partial_score():
    """Server with no data still gets a security-only partial score."""
    server = ServerInfo()
    result = compute_score(server)
    assert result.composite_score is None  # No composite for partials
    assert result.grade == ""
    assert result.score_type == "partial"
    assert result.security_score is not None  # Security always computed
