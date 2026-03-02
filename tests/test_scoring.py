"""Tests for the composite scoring engine."""

from mcp_scoring_engine import (
    DeepProbeResult,
    ReliabilityData,
    ScoreResult,
    ServerInfo,
    StaticAnalysis,
    compute_score,
    score_to_grade,
    GRADE_THRESHOLDS,
    WEIGHT_AGENT_USABILITY,
    WEIGHT_SCHEMA_DOCS,
    WEIGHT_PROTOCOL,
    WEIGHT_RELIABILITY,
    WEIGHT_MAINTENANCE,
    WEIGHT_SECURITY,
)
from mcp_scoring_engine.scoring import (
    _compute_schema_docs_score,
    _compute_protocol_score,
    _compute_reliability_score,
    _compute_maintenance_score,
    _compute_security_score,
    _ENHANCED_WEIGHTS,
    is_verified_publisher,
    extract_publisher,
)


class TestScoreToGrade:
    def test_a_plus(self):
        assert score_to_grade(95) == "A+"
        assert score_to_grade(100) == "A+"

    def test_a(self):
        assert score_to_grade(85) == "A"
        assert score_to_grade(94) == "A"

    def test_b(self):
        assert score_to_grade(70) == "B"
        assert score_to_grade(84) == "B"

    def test_c(self):
        assert score_to_grade(55) == "C"
        assert score_to_grade(69) == "C"

    def test_d(self):
        assert score_to_grade(40) == "D"
        assert score_to_grade(54) == "D"

    def test_f(self):
        assert score_to_grade(0) == "F"
        assert score_to_grade(39) == "F"


class TestComputeSchemaDocs:
    def test_basic(self, full_static):
        score = _compute_schema_docs_score(full_static)
        expected = int((85 + 78 + 72) / 3)
        assert score == expected

    def test_all_zero(self):
        static = StaticAnalysis(
            schema_completeness=0,
            description_quality=0,
            documentation_coverage=0,
        )
        assert _compute_schema_docs_score(static) == 0


class TestComputeProtocol:
    def test_full_probe(self, full_deep_probe):
        score = _compute_protocol_score(full_deep_probe)
        # (100 + 100 + 87 + 75) / 4 = 90.5 → 90
        assert score == 90

    def test_none_probe(self):
        assert _compute_protocol_score(None) is None

    def test_unreachable(self):
        probe = DeepProbeResult(is_reachable=False)
        score = _compute_protocol_score(probe)
        assert score == 0

    def test_partial_data(self):
        probe = DeepProbeResult(
            is_reachable=True,
            schema_valid=False,
            error_handling_score=60,
        )
        # (100 + 30 + 60) / 3 = 63
        score = _compute_protocol_score(probe)
        assert score == 63


class TestComputeReliability:
    def test_full_data(self, full_reliability):
        score = _compute_reliability_score(full_reliability)
        # 98.5 * 0.7 + 100 * 0.3 = 68.95 + 30 = 98.95 → 98
        assert score == 98

    def test_latency_only(self):
        data = ReliabilityData(latency_p50_ms=150)
        assert _compute_reliability_score(data) == 100

    def test_uptime_only(self):
        data = ReliabilityData(uptime_pct=95.0)
        assert _compute_reliability_score(data) == 95

    def test_no_data(self):
        assert _compute_reliability_score(None) is None
        assert _compute_reliability_score(ReliabilityData()) is None

    def test_slow_latency(self):
        data = ReliabilityData(latency_p50_ms=2500)
        assert _compute_reliability_score(data) == 20

    def test_latency_tiers(self):
        assert _compute_reliability_score(ReliabilityData(latency_p50_ms=100)) == 100
        assert _compute_reliability_score(ReliabilityData(latency_p50_ms=300)) == 80
        assert _compute_reliability_score(ReliabilityData(latency_p50_ms=700)) == 60
        assert _compute_reliability_score(ReliabilityData(latency_p50_ms=1500)) == 40


class TestComputeMaintenance:
    def test_full_static(self, full_static):
        score = _compute_maintenance_score(full_static)
        expected = int((80 + 75 + 100 + 65) / 4)
        assert score == expected


class TestComputeSecurity:
    def test_clean_server(self, clean_server):
        score = _compute_security_score(clean_server)
        assert score is not None
        assert 0 <= score <= 100

    def test_no_metadata(self):
        server = ServerInfo()
        score = _compute_security_score(server)
        assert score is not None
        assert 0 <= score <= 100

    def test_stdio_server(self):
        server = ServerInfo(
            is_remote=False,
            registry_metadata={"env_vars": [], "transport": "stdio"},
            repo_url="https://github.com/test/test",
        )
        score = _compute_security_score(server)
        # 35 + 25 + 25 + 10 = 95
        assert score == 95

    def test_many_secrets(self):
        server = ServerInfo(
            registry_metadata={
                "env_vars": [
                    "API_KEY",
                    "SECRET_TOKEN",
                    "AUTH_PASS",
                    "PRIVATE_KEY",
                    "DB_PASSWORD",
                    "REDIS_AUTH",
                ],
            },
        )
        score = _compute_security_score(server)
        # 0 + 10 + 3 + 3 = 16
        assert score == 16


class TestComputeScore:
    def test_full_score(self, clean_server, full_static, full_deep_probe, full_reliability):
        result = compute_score(clean_server, full_static, full_deep_probe, full_reliability)
        assert isinstance(result, ScoreResult)
        assert result.composite_score is not None
        assert 0 <= result.composite_score <= 100
        assert result.grade != ""
        assert result.score_type == "full"
        assert result.schema_docs_score is not None
        assert result.protocol_score is not None
        assert result.reliability_score is not None
        assert result.maintenance_score is not None
        assert result.security_score is not None

    def test_partial_score_static_only(self, clean_server, full_static):
        result = compute_score(clean_server, static_result=full_static)
        assert result.composite_score is not None
        assert result.score_type == "partial"
        assert result.grade == ""

    def test_full_score_two_tiers(self, clean_server, full_static, full_deep_probe):
        result = compute_score(clean_server, full_static, full_deep_probe)
        assert result.score_type == "full"
        assert result.grade != ""

    def test_no_data(self):
        server = ServerInfo()
        result = compute_score(server)
        assert result.composite_score is not None
        assert result.score_type == "partial"

    def test_score_clamped(self, clean_server, full_static, full_deep_probe, full_reliability):
        result = compute_score(clean_server, full_static, full_deep_probe, full_reliability)
        assert 0 <= result.composite_score <= 100

    def test_template_description_penalty(self, full_static, full_deep_probe):
        server = ServerInfo(
            name="test",
            description="A model context protocol server",
            registry_metadata={"env_vars": []},
        )
        result = compute_score(server, full_static, full_deep_probe)
        # Should have TEMPLATE_DESCRIPTION flag and schema_docs gets -15 penalty
        assert any(f.key == "TEMPLATE_DESCRIPTION" for f in result.flags)

    def test_result_has_source_data(self, clean_server, full_static, full_deep_probe):
        result = compute_score(clean_server, full_static, full_deep_probe)
        assert result.server_info is clean_server
        assert result.deep_probe is full_deep_probe
        assert result.static_analysis is full_static

    def test_badges_generated(self, clean_server, full_static, full_deep_probe, full_reliability):
        result = compute_score(clean_server, full_static, full_deep_probe, full_reliability)
        assert isinstance(result.badges, dict)
        assert "schema" in result.badges
        assert "protocol" in result.badges
        assert "reliability" in result.badges
        assert "maintenance" in result.badges
        assert "security" in result.badges

    def test_classification_set(self, clean_server, full_static):
        result = compute_score(clean_server, full_static)
        assert result.category != ""
        assert isinstance(result.targets, list)


class TestVerifiedPublisher:
    def test_registry_namespace(self):
        server = ServerInfo(registry_id="@anthropic/mcp-server")
        assert is_verified_publisher(server) is True

    def test_github_org(self):
        server = ServerInfo(repo_url="https://github.com/openai/some-server")
        assert is_verified_publisher(server) is True

    def test_unknown(self):
        server = ServerInfo(registry_id="@random-user/server", repo_url="")
        assert is_verified_publisher(server) is False


class TestExtractPublisher:
    def test_from_registry(self):
        server = ServerInfo(registry_id="@acme-corp/my-server")
        assert extract_publisher(server) == "acme-corp"

    def test_from_github(self):
        server = ServerInfo(repo_url="https://github.com/myorg/my-server")
        assert extract_publisher(server) == "myorg"

    def test_from_name(self):
        server = ServerInfo(name="myorg/my-server")
        assert extract_publisher(server) == "myorg"

    def test_empty(self):
        assert extract_publisher(ServerInfo()) == ""


class TestAgentUsability:
    """Tests for the agent_usability parameter on compute_score()."""

    def test_none_agent_usability_unchanged(
        self, clean_server, full_static, full_deep_probe, full_reliability
    ):
        """Passing agent_usability=None produces identical results to omitting it."""
        result_without = compute_score(clean_server, full_static, full_deep_probe, full_reliability)
        result_with_none = compute_score(
            clean_server,
            full_static,
            full_deep_probe,
            full_reliability,
            agent_usability=None,
        )
        assert result_without.composite_score == result_with_none.composite_score
        assert result_without.grade == result_with_none.grade
        assert result_without.score_type == result_with_none.score_type
        assert result_with_none.agent_usability_score is None

    def test_full_becomes_enhanced(
        self, clean_server, full_static, full_deep_probe, full_reliability
    ):
        """Full score + agent_usability → enhanced score type."""
        result = compute_score(
            clean_server,
            full_static,
            full_deep_probe,
            full_reliability,
            agent_usability=80,
        )
        assert result.score_type == "enhanced"
        assert result.grade != ""
        assert result.agent_usability_score == 80

    def test_partial_never_becomes_enhanced(self, clean_server, full_static):
        """Partial (1 tier) + agent_usability stays partial."""
        result = compute_score(
            clean_server,
            full_static,
            agent_usability=90,
        )
        assert result.score_type == "partial"
        assert result.grade == ""
        assert result.agent_usability_score == 90

    def test_no_agent_stays_full(
        self, clean_server, full_static, full_deep_probe, full_reliability
    ):
        """Without agent_usability, score stays full."""
        result = compute_score(
            clean_server,
            full_static,
            full_deep_probe,
            full_reliability,
        )
        assert result.score_type == "full"
        assert result.agent_usability_score is None

    def test_enhanced_weights_sum_to_one(self):
        """Enhanced weight allocation must sum to 1.0."""
        total = sum(_ENHANCED_WEIGHTS.values())
        assert abs(total - 1.0) < 0.001

    def test_standard_weights_sum_to_one(self):
        """Standard weight allocation must sum to 1.0."""
        total = (
            WEIGHT_SCHEMA_DOCS
            + WEIGHT_PROTOCOL
            + WEIGHT_RELIABILITY
            + WEIGHT_MAINTENANCE
            + WEIGHT_SECURITY
        )
        assert abs(total - 1.0) < 0.001

    def test_agent_usability_affects_composite(
        self, clean_server, full_static, full_deep_probe, full_reliability
    ):
        """High agent_usability pushes composite up vs low agent_usability."""
        result_high = compute_score(
            clean_server,
            full_static,
            full_deep_probe,
            full_reliability,
            agent_usability=100,
        )
        result_low = compute_score(
            clean_server,
            full_static,
            full_deep_probe,
            full_reliability,
            agent_usability=0,
        )
        assert result_high.composite_score > result_low.composite_score

    def test_agent_usability_weight_constant(self):
        """WEIGHT_AGENT_USABILITY matches the enhanced weights dict."""
        assert WEIGHT_AGENT_USABILITY == _ENHANCED_WEIGHTS["agent_usability"]
        assert WEIGHT_AGENT_USABILITY == 0.15

    def test_enhanced_score_with_missing_categories(self, clean_server, full_static):
        """Enhanced scoring works even when some standard categories are missing."""
        result = compute_score(
            clean_server,
            full_static,
            deep_probe=None,
            reliability=None,
            agent_usability=75,
        )
        # Only 1 standard tier (static), so stays partial even with agent_usability
        assert result.score_type == "partial"
        assert result.composite_score is not None
        assert result.agent_usability_score == 75

    def test_enhanced_two_tiers_plus_agent(self, clean_server, full_static, full_deep_probe):
        """Two standard tiers + agent_usability = enhanced."""
        result = compute_score(
            clean_server,
            full_static,
            full_deep_probe,
            agent_usability=70,
        )
        assert result.score_type == "enhanced"
        assert result.grade != ""
