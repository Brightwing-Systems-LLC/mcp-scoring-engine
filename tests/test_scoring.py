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
    WEIGHT_SCHEMA_QUALITY,
    WEIGHT_DOCS_MAINTENANCE,
    WEIGHT_SCHEMA_DOCS,
    WEIGHT_PROTOCOL,
    WEIGHT_RELIABILITY,
    WEIGHT_MAINTENANCE,
    WEIGHT_SECURITY,
)
from mcp_scoring_engine.scoring import (
    _compute_schema_quality_score,
    _compute_docs_maintenance_score,
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


class TestComputeSchemaQuality:
    def test_weighted_average(self, full_static):
        """Schema quality = 60% schema_completeness + 40% description_quality."""
        score = _compute_schema_quality_score(full_static)
        # 85 * 0.60 + 78 * 0.40 = 51.0 + 31.2 = 82.2 → 82
        expected = int(85 * 0.60 + 78 * 0.40)
        assert score == expected

    def test_all_zero(self):
        static = StaticAnalysis(schema_completeness=0, description_quality=0)
        assert _compute_schema_quality_score(static) == 0

    def test_documentation_coverage_excluded(self, full_static):
        """documentation_coverage no longer affects schema quality."""
        # Changing documentation_coverage should not change schema_quality
        high_docs = StaticAnalysis(
            schema_completeness=85, description_quality=78, documentation_coverage=100
        )
        low_docs = StaticAnalysis(
            schema_completeness=85, description_quality=78, documentation_coverage=0
        )
        assert _compute_schema_quality_score(high_docs) == _compute_schema_quality_score(low_docs)

    def test_backward_compat_alias(self, full_static):
        """_compute_schema_docs_score alias still works."""
        assert _compute_schema_docs_score(full_static) == _compute_schema_quality_score(full_static)


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

    def test_auth_discovery_bonus(self):
        """auth_discovery_valid=True adds +10 to protocol score."""
        probe = DeepProbeResult(
            is_reachable=True,
            schema_valid=True,
            error_handling_score=60,
            auth_discovery_valid=True,
        )
        # base: (100 + 100 + 60) / 3 = 86.67 → 86, +10 = 96
        score = _compute_protocol_score(probe)
        assert score == 96

    def test_auth_discovery_none_no_penalty(self):
        """auth_discovery_valid=None does not affect protocol score."""
        probe = DeepProbeResult(
            is_reachable=True,
            schema_valid=True,
            error_handling_score=60,
            auth_discovery_valid=None,
        )
        # base: (100 + 100 + 60) / 3 = 86.67 → 86, no bonus
        score = _compute_protocol_score(probe)
        assert score == 86

    def test_auth_discovery_false_no_bonus(self):
        """auth_discovery_valid=False (tried and failed) gets no bonus."""
        probe = DeepProbeResult(
            is_reachable=True,
            schema_valid=True,
            error_handling_score=60,
            auth_discovery_valid=False,
        )
        # base: (100 + 100 + 60) / 3 = 86.67 → 86, no bonus
        score = _compute_protocol_score(probe)
        assert score == 86

    def test_auth_discovery_capped_at_100(self):
        """Auth bonus doesn't push score above 100."""
        probe = DeepProbeResult(
            is_reachable=True,
            schema_valid=True,
            error_handling_score=95,
            fuzz_score=95,
            auth_discovery_valid=True,
        )
        # base: (100 + 100 + 95 + 95) / 4 = 97.5 → 97, +10 = 107 → capped at 100
        score = _compute_protocol_score(probe)
        assert score == 100


class TestComputeReliability:
    def test_full_data(self, full_reliability):
        score = _compute_reliability_score(full_reliability)
        # p50=145→95, p95=380→78, uptime=98.5
        # 98.5*0.60 + 95*0.25 + 78*0.15 = 59.1 + 23.75 + 11.7 = 94.55 → 94
        assert score == 94

    def test_latency_only(self):
        """CLI mode (probe_count=0): continuous latency scoring."""
        data = ReliabilityData(latency_p50_ms=150)
        # 150ms → 95 (continuous interpolation)
        assert _compute_reliability_score(data) == 95

    def test_uptime_only(self):
        data = ReliabilityData(uptime_pct=95.0, probe_count=20)
        assert _compute_reliability_score(data) == 95

    def test_no_data(self):
        assert _compute_reliability_score(None) is None
        assert _compute_reliability_score(ReliabilityData()) is None

    def test_slow_latency(self):
        data = ReliabilityData(latency_p50_ms=2500)
        # 2500ms → 22 (continuous)
        assert _compute_reliability_score(data) == 22

    def test_continuous_latency(self):
        """Continuous scoring — no 20-point cliffs at boundaries."""
        assert _compute_reliability_score(ReliabilityData(latency_p50_ms=100)) == 100
        # 300ms → ~83 (between 90@200ms and 70@500ms)
        assert 82 <= _compute_reliability_score(ReliabilityData(latency_p50_ms=300)) <= 84
        # 700ms → ~62 (between 70@500ms and 50@1000ms)
        assert 60 <= _compute_reliability_score(ReliabilityData(latency_p50_ms=700)) <= 64
        # 1500ms → ~37 (between 50@1000ms and 25@2000ms)
        assert 35 <= _compute_reliability_score(ReliabilityData(latency_p50_ms=1500)) <= 40


class TestComputeDocsMaintenance:
    def test_weighted_blend(self, full_static):
        """docs_maintenance = 30% doc_coverage + 30% maint_pulse + 15% dep_health + 15% license + 10% version."""
        score = _compute_docs_maintenance_score(full_static)
        # 72*0.30 + 80*0.30 + 75*0.15 + 100*0.15 + 65*0.10
        # = 21.6 + 24.0 + 11.25 + 15.0 + 6.5 = 78.35 → 78
        expected = int(72 * 0.30 + 80 * 0.30 + 75 * 0.15 + 100 * 0.15 + 65 * 0.10)
        assert score == expected

    def test_includes_documentation_coverage(self, full_static):
        """documentation_coverage is now part of docs_maintenance, not schema."""
        high = StaticAnalysis(
            documentation_coverage=100,
            maintenance_pulse=80,
            dependency_health=75,
            license_clarity=100,
            version_hygiene=65,
        )
        low = StaticAnalysis(
            documentation_coverage=0,
            maintenance_pulse=80,
            dependency_health=75,
            license_clarity=100,
            version_hygiene=65,
        )
        assert _compute_docs_maintenance_score(high) > _compute_docs_maintenance_score(low)

    def test_backward_compat_alias(self, full_static):
        """_compute_maintenance_score alias still works."""
        assert _compute_maintenance_score(full_static) == _compute_docs_maintenance_score(full_static)


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
        # 20 + 15 + 15 + 12 (repo only) + 18 (behavioral default) = 80
        assert score == 80

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
        # 0 + 6 + 2 + 3 + 18 = 29
        assert score == 29

    def test_distribution_clarity_repo_and_package(self):
        """Source repo + published package → 15 pts (fully verifiable)."""
        server = ServerInfo(
            repo_url="https://github.com/test/test",
            npm_url="https://www.npmjs.com/package/test",
            registry_metadata={"env_vars": []},
        )
        score = _compute_security_score(server)
        # 20 + 6 + 15 + 15 + 18 = 74
        assert score == 74

    def test_distribution_clarity_repo_only(self):
        """Source repo only → 12 pts (auditable from source)."""
        server = ServerInfo(
            repo_url="https://github.com/test/test",
            registry_metadata={"env_vars": []},
        )
        score = _compute_security_score(server)
        # 20 + 6 + 15 + 12 + 18 = 71
        assert score == 71

    def test_distribution_clarity_package_only(self):
        """Published package without source → 8 pts (can't verify)."""
        server = ServerInfo(
            npm_url="https://www.npmjs.com/package/test",
            registry_metadata={"env_vars": []},
        )
        score = _compute_security_score(server)
        # 20 + 6 + 15 + 8 + 18 = 67
        assert score == 67

    def test_mongo_uri_detected_as_high_sensitivity(self):
        """MONGO_URI should be detected as high-sensitivity credential."""
        server = ServerInfo(
            registry_metadata={"env_vars": ["MONGO_URI", "PORT"]},
        )
        score = _compute_security_score(server)
        # secret: 0 sensitive → 20, transport: remote → 6
        # cred: 1 high_sens (MONGO_URI) → 6, dist: 3, behavioral: 18
        # So: 20 + 6 + 6 + 3 + 18 = 53
        assert score == 53


class TestComputeScore:
    def test_full_score(self, clean_server, full_static, full_deep_probe, full_reliability):
        result = compute_score(clean_server, full_static, full_deep_probe, full_reliability)
        assert isinstance(result, ScoreResult)
        assert result.composite_score is not None
        assert 0 <= result.composite_score <= 100
        assert result.grade != ""
        assert result.visibility_level == "verified"  # all applicable + live probe
        assert result.score_type == "full"  # backward compat
        assert result.dimensions_scored == 5
        assert result.dimensions_applicable == 5
        assert result.schema_quality_score is not None
        assert result.protocol_score is not None
        assert result.reliability_score is not None
        assert result.docs_maintenance_score is not None
        assert result.security_score is not None
        # Backward-compat aliases still work
        assert result.schema_docs_score == result.schema_quality_score
        assert result.maintenance_score == result.docs_maintenance_score

    def test_limited_score_static_only(self, clean_server, full_static):
        """Remote server with static only → limited visibility, gets composite."""
        result = compute_score(clean_server, static_result=full_static)
        assert result.visibility_level == "limited"
        assert result.score_type == "partial"  # backward compat
        assert result.composite_score is not None  # limited servers now get composites
        assert result.grade != ""
        assert result.dimensions_scored == 3  # schema, docs, security
        # Category scores are still computed
        assert result.schema_quality_score is not None
        assert result.security_score is not None

    def test_remote_without_reliability_is_verified(self, clean_server, full_static, full_deep_probe):
        """Remote server with static + probe but no reliability → verified.

        Reliability is only applicable when probe history data is provided.
        Without it, all applicable dims are filled + live probe → verified.
        """
        result = compute_score(clean_server, full_static, full_deep_probe)
        assert result.visibility_level == "verified"
        assert result.score_type == "full"  # backward compat
        assert result.grade != ""
        assert result.dimensions_scored == 4  # schema, protocol, docs, security
        assert result.dimensions_applicable == 4  # reliability not applicable

    def test_no_data(self):
        server = ServerInfo()
        result = compute_score(server)
        assert result.visibility_level == "unscored"
        assert result.composite_score is None  # Unscored: only 1 dim (security)
        assert result.score_type == "partial"
        assert result.grade == ""
        assert result.dimensions_scored == 1
        # Security score still computed (always available from metadata)
        assert result.security_score is not None

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

    def test_full_becomes_complete(
        self, clean_server, full_static, full_deep_probe, full_reliability
    ):
        """Full score + agent_usability → complete visibility (enhanced score_type)."""
        result = compute_score(
            clean_server,
            full_static,
            full_deep_probe,
            full_reliability,
            agent_usability=80,
        )
        assert result.visibility_level == "complete"
        assert result.score_type == "enhanced"  # backward compat
        assert result.grade != ""
        assert result.agent_usability_score == 80
        assert result.dimensions_scored == 6

    def test_limited_with_agent_stays_limited(self, clean_server, full_static):
        """Missing applicable dims + agent_usability → limited (not enhanced)."""
        result = compute_score(
            clean_server,
            full_static,
            agent_usability=90,
        )
        assert result.visibility_level == "limited"
        assert result.score_type == "partial"  # backward compat
        assert result.composite_score is not None  # limited gets composite
        assert result.grade != ""
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
            WEIGHT_SCHEMA_QUALITY
            + WEIGHT_PROTOCOL
            + WEIGHT_RELIABILITY
            + WEIGHT_DOCS_MAINTENANCE
            + WEIGHT_SECURITY
        )
        assert abs(total - 1.0) < 0.001
        # Backward-compat aliases match
        assert WEIGHT_SCHEMA_DOCS == WEIGHT_SCHEMA_QUALITY
        assert WEIGHT_MAINTENANCE == WEIGHT_DOCS_MAINTENANCE

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

    def test_limited_with_agent_and_missing_categories(self, clean_server, full_static):
        """Limited visibility: has agent_usability but missing applicable dims."""
        result = compute_score(
            clean_server,
            full_static,
            deep_probe=None,
            reliability=None,
            agent_usability=75,
        )
        assert result.visibility_level == "limited"
        assert result.score_type == "partial"  # backward compat
        assert result.composite_score is not None  # limited gets composite
        assert result.agent_usability_score == 75

    def test_remote_two_tiers_plus_agent_is_complete(self, clean_server, full_static, full_deep_probe):
        """Remote server with static + probe + agent_usability → complete.

        Reliability is not applicable without probe history data, so
        all applicable dimensions are filled + agent_usability → complete.
        """
        result = compute_score(
            clean_server,
            full_static,
            full_deep_probe,
            agent_usability=70,
        )
        assert result.visibility_level == "complete"
        assert result.score_type == "enhanced"  # backward compat
        assert result.grade != ""


class TestLocalServerScoring:
    """Tests for applicability-aware scoring of local (stdio-only) servers."""

    def test_local_with_all_applicable_is_assessed(self, full_static):
        """Local server with schema + docs_maintenance + security → assessed (no live probe)."""
        server = ServerInfo(
            name="local/mcp-server",
            description="A local MCP server",
            repo_url="https://github.com/test/local-mcp",
            is_remote=False,
            registry_metadata={"env_vars": ["API_KEY"]},
        )
        result = compute_score(server, static_result=full_static)
        assert result.visibility_level == "assessed"  # all applicable, no live probe
        assert result.score_type == "full"  # backward compat
        assert result.grade != ""
        assert result.dimensions_scored == 3
        assert result.dimensions_applicable == 3  # schema, docs, security
        assert result.schema_quality_score is not None
        assert result.docs_maintenance_score is not None
        assert result.security_score is not None
        assert result.protocol_score is None
        assert result.reliability_score is None

    def test_local_with_only_security_is_unscored(self):
        """Local server with only security data → unscored (1 dim)."""
        server = ServerInfo(
            name="local/bare-server",
            is_remote=False,
            registry_metadata={"env_vars": []},
        )
        result = compute_score(server)
        assert result.visibility_level == "unscored"
        assert result.score_type == "partial"  # backward compat
        assert result.composite_score is None
        assert result.grade == ""
        assert result.dimensions_scored == 1
        assert result.security_score is not None

    def test_remote_without_probe_is_limited(self, full_static):
        """Remote server with only static analysis → limited (missing protocol)."""
        server = ServerInfo(
            name="remote/test",
            is_remote=True,
            registry_metadata={"env_vars": []},
        )
        result = compute_score(server, static_result=full_static)
        assert result.visibility_level == "limited"
        assert result.score_type == "partial"  # backward compat
        assert result.composite_score is not None  # limited gets composite
        assert result.grade != ""

    def test_remote_with_all_five_is_full(
        self, clean_server, full_static, full_deep_probe, full_reliability
    ):
        """Remote server with all 5 dimensions → full."""
        result = compute_score(
            clean_server, full_static, full_deep_probe, full_reliability
        )
        assert result.score_type == "full"
        assert result.grade != ""

    def test_local_full_plus_agent_is_complete(self, full_static):
        """Local server with all applicable + agent_usability → complete."""
        server = ServerInfo(
            name="local/enhanced-server",
            is_remote=False,
            registry_metadata={"env_vars": []},
            repo_url="https://github.com/test/local",
        )
        result = compute_score(
            server, static_result=full_static, agent_usability=80
        )
        assert result.visibility_level == "complete"
        assert result.score_type == "enhanced"  # backward compat
        assert result.grade != ""
        assert result.agent_usability_score == 80
        assert result.dimensions_scored == 4  # schema, docs, security, agent

    def test_local_score_reaches_100(self, full_static):
        """Local servers can reach 100/100 on their applicable dimensions."""
        server = ServerInfo(
            name="local/perfect-server",
            is_remote=False,
            registry_metadata={
                "env_vars": [],
                "transport": "stdio",
                "behavioral_security": {"behavioral_security_score": 100},
            },
            repo_url="https://github.com/test/perfect",
            npm_url="https://npmjs.com/package/perfect-mcp",
        )
        # Create static analysis with perfect scores
        perfect_static = StaticAnalysis(
            schema_completeness=100,
            description_quality=100,
            documentation_coverage=100,
            maintenance_pulse=100,
            dependency_health=100,
            license_clarity=100,
            version_hygiene=100,
        )
        result = compute_score(server, static_result=perfect_static)
        assert result.score_type == "full"
        assert result.composite_score == 100


class TestSandboxProbedScoring:
    """Tests for local servers probed via Docker sandbox."""

    def test_local_probed_with_protocol_is_verified(self, full_static):
        """Local probed server with schema + protocol + docs + security → verified."""
        server = ServerInfo(
            name="local/probed",
            is_remote=False,
            has_sandbox_probe=True,
            registry_metadata={"env_vars": []},
            repo_url="https://github.com/test/probed",
        )
        deep = DeepProbeResult(
            is_reachable=True,
            schema_valid=True,
            error_handling_score=80,
            fuzz_score=70,
        )
        result = compute_score(server, static_result=full_static, deep_probe=deep)
        assert result.visibility_level == "verified"  # all applicable + live probe
        assert result.score_type == "full"  # backward compat
        assert result.grade != ""
        assert result.protocol_score is not None

    def test_local_probed_missing_protocol_is_limited(self, full_static):
        """Local probed server without protocol data → limited (protocol applicable but missing)."""
        server = ServerInfo(
            name="local/probed-no-protocol",
            is_remote=False,
            has_sandbox_probe=True,
            registry_metadata={"env_vars": []},
            repo_url="https://github.com/test/probed-no-proto",
        )
        result = compute_score(server, static_result=full_static)
        assert result.visibility_level == "limited"
        assert result.score_type == "partial"  # backward compat
        assert result.composite_score is not None  # limited gets composite
        assert result.protocol_score is None

    def test_unprobed_local_without_protocol_is_assessed(self, full_static):
        """Unprobed local server without protocol → assessed (all applicable, no live probe)."""
        server = ServerInfo(
            name="local/unprobed",
            is_remote=False,
            has_sandbox_probe=False,
            registry_metadata={"env_vars": []},
            repo_url="https://github.com/test/unprobed",
        )
        result = compute_score(server, static_result=full_static)
        assert result.visibility_level == "assessed"
        assert result.score_type == "full"  # backward compat
        assert result.grade != ""


class TestFlagScoreCaps:
    """Critical flags must cap the composite score."""

    def test_dead_repo_caps_at_zero(self, full_static, full_deep_probe, full_reliability):
        """A dead repo gets composite=0 regardless of other scores."""
        server = ServerInfo(
            name="dead/server",
            description="Good description for a dead server",
            repo_url="https://github.com/dead/repo",
            is_remote=True,
            registry_metadata={"env_vars": [], "repo_status": "404"},
            npm_url="https://npmjs.com/package/dead-server",
        )
        result = compute_score(server, full_static, full_deep_probe, full_reliability)
        assert result.composite_score == 0
        assert any(f.key == "DEAD_REPO" for f in result.flags)
        # Category scores should still be populated (for diagnostics)
        assert result.schema_docs_score is not None
        assert result.protocol_score is not None

    def test_dead_repo_grade_is_f(self, full_static, full_deep_probe, full_reliability):
        """Dead repo with full data gets F grade."""
        server = ServerInfo(
            name="dead/graded",
            description="Good description",
            repo_url="https://github.com/dead/graded",
            is_remote=True,
            registry_metadata={"env_vars": [], "repo_status": "gone"},
            npm_url="https://npmjs.com/package/dead",
        )
        result = compute_score(server, full_static, full_deep_probe, full_reliability)
        assert result.grade == "F"

    def test_archived_caps_at_40(self, full_static, full_deep_probe, full_reliability):
        """Archived repo caps composite at 40 (max D grade)."""
        server = ServerInfo(
            name="archived/server",
            description="Good description for archived server",
            repo_url="https://github.com/archived/repo",
            is_remote=True,
            registry_metadata={"env_vars": [], "archived": True},
            npm_url="https://npmjs.com/package/archived",
        )
        result = compute_score(server, full_static, full_deep_probe, full_reliability)
        assert result.composite_score <= 40
        assert result.grade in ("D", "F")
        assert any(f.key == "REPO_ARCHIVED" for f in result.flags)

    def test_staging_caps_at_55(self, full_static, full_deep_probe, full_reliability):
        """Staging endpoint caps composite at 55 (max C grade)."""
        server = ServerInfo(
            name="staging/server",
            description="Good description",
            repo_url="https://github.com/test/staging",
            remote_endpoint_url="https://localhost:8080/mcp",
            is_remote=True,
            registry_metadata={"env_vars": []},
            npm_url="https://npmjs.com/package/staging",
        )
        result = compute_score(server, full_static, full_deep_probe, full_reliability)
        assert result.composite_score <= 55
        assert result.grade in ("C", "D", "F")
        assert any(f.key == "STAGING_ARTIFACT" for f in result.flags)

    def test_category_scores_unaffected_by_cap(self, full_static, full_deep_probe, full_reliability):
        """Flag caps only affect composite — individual categories stay accurate."""
        # Normal server
        normal_server = ServerInfo(
            name="normal/server",
            description="Good description",
            repo_url="https://github.com/normal/repo",
            is_remote=True,
            registry_metadata={"env_vars": []},
            npm_url="https://npmjs.com/package/normal",
        )
        normal_result = compute_score(normal_server, full_static, full_deep_probe, full_reliability)

        # Dead version of same server
        dead_server = ServerInfo(
            name="normal/server",
            description="Good description",
            repo_url="https://github.com/normal/repo",
            is_remote=True,
            registry_metadata={"env_vars": [], "repo_status": "404"},
            npm_url="https://npmjs.com/package/normal",
        )
        dead_result = compute_score(dead_server, full_static, full_deep_probe, full_reliability)

        # Composite is capped to 0, but category scores match
        assert dead_result.composite_score == 0
        assert dead_result.schema_docs_score == normal_result.schema_docs_score
        assert dead_result.protocol_score == normal_result.protocol_score
        assert dead_result.reliability_score == normal_result.reliability_score
        assert dead_result.maintenance_score == normal_result.maintenance_score

    def test_multiple_flags_use_lowest_cap(self, full_static, full_deep_probe, full_reliability):
        """Server with both DEAD_REPO and STAGING_ARTIFACT uses the lowest cap (0)."""
        server = ServerInfo(
            name="double-flagged/server",
            description="Bad server",
            repo_url="https://github.com/dead/server",
            remote_endpoint_url="https://localhost:3000/mcp",
            is_remote=True,
            registry_metadata={"env_vars": [], "repo_status": "404"},
        )
        result = compute_score(server, full_static, full_deep_probe, full_reliability)
        assert result.composite_score == 0


class TestVisibilityLevels:
    """Dedicated tests for the 5-tier visibility model."""

    def test_complete_requires_all_plus_agent(
        self, clean_server, full_static, full_deep_probe, full_reliability
    ):
        """Complete = all applicable dims + agent_usability."""
        result = compute_score(
            clean_server, full_static, full_deep_probe, full_reliability,
            agent_usability=85,
        )
        assert result.visibility_level == "complete"
        assert result.dimensions_scored == 6
        assert result.composite_score is not None

    def test_verified_requires_all_plus_live_probe(
        self, clean_server, full_static, full_deep_probe, full_reliability
    ):
        """Verified = all applicable dims + live probe, no agent."""
        result = compute_score(clean_server, full_static, full_deep_probe, full_reliability)
        assert result.visibility_level == "verified"
        assert result.dimensions_scored == 5
        assert result.composite_score is not None

    def test_assessed_all_applicable_no_probe(self, full_static):
        """Assessed = all applicable dims filled, but no live probe data."""
        server = ServerInfo(
            name="local/no-probe",
            is_remote=False,
            has_sandbox_probe=False,
            registry_metadata={"env_vars": []},
            repo_url="https://github.com/test/no-probe",
        )
        result = compute_score(server, static_result=full_static)
        # Local, unprobed: applicable = schema, docs, security (3)
        # All 3 filled, no live probe → assessed
        assert result.visibility_level == "assessed"
        assert result.dimensions_scored == 3
        assert result.composite_score is not None

    def test_limited_missing_applicable_dims(self, clean_server, full_static):
        """Limited = ≥2 dims scored but missing some applicable dims."""
        # Remote server with static only: protocol applicable but missing
        result = compute_score(clean_server, static_result=full_static)
        assert result.visibility_level == "limited"
        assert result.dimensions_scored == 3  # schema, docs, security
        assert result.composite_score is not None
        assert result.grade != ""

    def test_unscored_only_one_dim(self):
        """Unscored = 0-1 dimensions scored."""
        server = ServerInfo(
            name="bare/server",
            is_remote=True,
            registry_metadata={"env_vars": []},
        )
        result = compute_score(server)
        assert result.visibility_level == "unscored"
        assert result.dimensions_scored == 1  # security only
        assert result.composite_score is None
        assert result.grade == ""

    def test_visibility_to_score_type_mapping(
        self, clean_server, full_static, full_deep_probe, full_reliability
    ):
        """Verify backward-compatible score_type mapping from visibility."""
        # Complete → enhanced
        r = compute_score(
            clean_server, full_static, full_deep_probe, full_reliability,
            agent_usability=80,
        )
        assert r.visibility_level == "complete"
        assert r.score_type == "enhanced"

        # Verified → full
        r = compute_score(clean_server, full_static, full_deep_probe, full_reliability)
        assert r.visibility_level == "verified"
        assert r.score_type == "full"

        # Assessed → full
        local = ServerInfo(
            name="local/test", is_remote=False,
            registry_metadata={"env_vars": []},
            repo_url="https://github.com/test/local",
        )
        r = compute_score(local, static_result=full_static)
        assert r.visibility_level == "assessed"
        assert r.score_type == "full"

        # Limited → partial
        r = compute_score(clean_server, static_result=full_static)
        assert r.visibility_level == "limited"
        assert r.score_type == "partial"

        # Unscored → partial
        r = compute_score(ServerInfo())
        assert r.visibility_level == "unscored"
        assert r.score_type == "partial"

    def test_dimensions_applicable_remote_with_reliability(
        self, clean_server, full_static, full_deep_probe, full_reliability
    ):
        """Remote with reliability data → 5 applicable dims."""
        result = compute_score(clean_server, full_static, full_deep_probe, full_reliability)
        assert result.dimensions_applicable == 5

    def test_dimensions_applicable_remote_no_reliability(
        self, clean_server, full_static, full_deep_probe
    ):
        """Remote without reliability data → 4 applicable dims."""
        result = compute_score(clean_server, full_static, full_deep_probe)
        assert result.dimensions_applicable == 4

    def test_dimensions_applicable_local_unprobed(self, full_static):
        """Local unprobed → 3 applicable dims."""
        server = ServerInfo(
            name="local/test", is_remote=False,
            registry_metadata={"env_vars": []},
            repo_url="https://github.com/test/local",
        )
        result = compute_score(server, static_result=full_static)
        assert result.dimensions_applicable == 3

    def test_dimensions_applicable_local_probed(self, full_static):
        """Local probed → 4 applicable dims (protocol via sandbox)."""
        server = ServerInfo(
            name="local/probed", is_remote=False, has_sandbox_probe=True,
            registry_metadata={"env_vars": []},
            repo_url="https://github.com/test/probed",
        )
        deep = DeepProbeResult(
            is_reachable=True, schema_valid=True, error_handling_score=80,
        )
        result = compute_score(server, static_result=full_static, deep_probe=deep)
        assert result.dimensions_applicable == 4  # schema, protocol, docs, security

    def test_dimensions_applicable_with_agent(
        self, clean_server, full_static, full_deep_probe, full_reliability
    ):
        """Agent_usability adds 1 to applicable count."""
        result = compute_score(
            clean_server, full_static, full_deep_probe, full_reliability,
            agent_usability=80,
        )
        assert result.dimensions_applicable == 6  # 5 standard + agent
