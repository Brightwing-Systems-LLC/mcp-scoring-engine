"""Tests for badge generation."""

from mcp_scoring_engine import (
    DeepProbeResult,
    ReliabilityData,
    ServerInfo,
    StaticAnalysis,
    generate_badges,
)


class TestGenerateBadges:
    def test_returns_all_categories(self, clean_server):
        badges = generate_badges(clean_server)
        assert "schema" in badges
        assert "protocol" in badges
        assert "reliability" in badges
        assert "maintenance" in badges
        assert "security" in badges

    def test_badge_format(self, clean_server):
        badges = generate_badges(clean_server)
        for category_badges in badges.values():
            for badge in category_badges:
                assert "key" in badge
                assert "label" in badge
                assert "level" in badge
                assert badge["level"] in ("good", "neutral", "warning", "critical")


class TestSchemaBadges:
    def test_with_static_result(self, clean_server, full_static):
        badges = generate_badges(clean_server, static_result=full_static)
        schema_keys = {b["key"] for b in badges["schema"]}
        assert "has_readme" in schema_keys
        assert "has_changelog" in schema_keys
        assert "security_policy" in schema_keys
        assert "namespace_match" in schema_keys
        assert "installable" in schema_keys
        assert "usage_docs" in schema_keys
        assert "code_examples" in schema_keys

    def test_template_flag(self, clean_server):
        flags = [{"key": "TEMPLATE_DESCRIPTION", "severity": "warning"}]
        badges = generate_badges(clean_server, flags=flags)
        schema_keys = {b["key"] for b in badges["schema"]}
        assert "template_desc" in schema_keys

    def test_without_static(self, clean_server):
        badges = generate_badges(clean_server)
        assert badges["schema"] == []


class TestProtocolBadges:
    def test_reachable(self, clean_server, full_deep_probe):
        badges = generate_badges(clean_server, deep_probe=full_deep_probe)
        protocol_keys = {b["key"] for b in badges["protocol"]}
        assert "reachable" in protocol_keys
        assert "schema_valid" in protocol_keys
        assert "has_tools" in protocol_keys
        assert "good_errors" in protocol_keys

    def test_unreachable(self, clean_server):
        probe = DeepProbeResult(is_reachable=False)
        badges = generate_badges(clean_server, deep_probe=probe)
        protocol_keys = {b["key"] for b in badges["protocol"]}
        assert "unreachable" in protocol_keys

    def test_no_probe(self, clean_server):
        badges = generate_badges(clean_server)
        assert badges["protocol"] == []


class TestReliabilityBadges:
    def test_high_uptime(self, clean_server, full_reliability):
        badges = generate_badges(clean_server, reliability=full_reliability)
        keys = {b["key"] for b in badges["reliability"]}
        assert "good_uptime" in keys  # 98.5% → 95%+
        assert "low_latency" in keys  # 145ms

    def test_low_uptime(self, clean_server):
        data = ReliabilityData(uptime_pct=70.0)
        badges = generate_badges(clean_server, reliability=data)
        keys = {b["key"] for b in badges["reliability"]}
        assert "low_uptime" in keys

    def test_local_only(self):
        server = ServerInfo(is_remote=False)
        badges = generate_badges(server)
        keys = {b["key"] for b in badges["reliability"]}
        assert "local_only" in keys


class TestMaintenanceBadges:
    def test_with_static(self, clean_server, full_static):
        badges = generate_badges(clean_server, static_result=full_static)
        keys = {b["key"] for b in badges["maintenance"]}
        assert "active" in keys  # 12 days since push
        assert "regular_releases" in keys  # 5 releases
        assert "has_ci" in keys
        assert "lock_file" in keys
        assert "licensed" in keys


class TestSecurityBadges:
    def test_with_one_secret(self, clean_server):
        badges = generate_badges(clean_server)
        keys = {b["key"] for b in badges["security"]}
        assert "few_secrets" in keys
        assert "remote" in keys
        assert "published" in keys

    def test_no_secrets(self):
        server = ServerInfo(
            registry_metadata={"env_vars": []},
            is_remote=False,
        )
        badges = generate_badges(server)
        keys = {b["key"] for b in badges["security"]}
        assert "no_secrets" in keys
        assert "stdio" in keys
