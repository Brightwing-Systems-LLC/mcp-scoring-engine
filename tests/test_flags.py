"""Tests for red flag detection."""

from datetime import datetime, timedelta, timezone

from mcp_scoring_engine import ServerInfo, detect_flags
from mcp_scoring_engine.flags import (
    FlagContext,
    _check_ambiguous_schema,
    _check_dead_repo,
    _check_description_duplicate,
    _check_high_secret_demand,
    _check_no_source,
    _check_repo_archived,
    _check_schema_drift,
    _check_sensitive_creds,
    _check_staging_artifact,
    _check_stale_project,
    _check_template_description,
)


class TestDeadRepo:
    def test_dead_404(self):
        server = ServerInfo(registry_metadata={"repo_status": "404"})
        flags = _check_dead_repo(server)
        assert len(flags) == 1
        assert flags[0].key == "DEAD_REPO"
        assert flags[0].severity == "critical"

    def test_dead_gone(self):
        server = ServerInfo(registry_metadata={"repo_status": "gone"})
        assert len(_check_dead_repo(server)) == 1

    def test_clean(self):
        server = ServerInfo(registry_metadata={"repo_status": "ok"})
        assert len(_check_dead_repo(server)) == 0


class TestNoSource:
    def test_no_source(self):
        server = ServerInfo(repo_url="", registry_metadata={})
        flags = _check_no_source(server)
        assert len(flags) == 1
        assert flags[0].key == "NO_SOURCE"

    def test_has_repo(self):
        server = ServerInfo(repo_url="https://github.com/test/test")
        assert len(_check_no_source(server)) == 0

    def test_has_homepage(self):
        server = ServerInfo(repo_url="", registry_metadata={"homepage": "https://example.com"})
        assert len(_check_no_source(server)) == 0


class TestSensitiveCreds:
    def test_many_sensitive(self):
        server = ServerInfo(
            registry_metadata={
                "env_vars": ["API_KEY", "SECRET_TOKEN", "AUTH_PASSWORD"]
            }
        )
        flags = _check_sensitive_creds(server)
        assert len(flags) == 1
        assert flags[0].key == "SENSITIVE_CREDS"

    def test_few_sensitive(self):
        server = ServerInfo(registry_metadata={"env_vars": ["API_KEY"]})
        assert len(_check_sensitive_creds(server)) == 0

    def test_no_env_vars(self):
        server = ServerInfo(registry_metadata={"env_vars": []})
        assert len(_check_sensitive_creds(server)) == 0


class TestHighSecretDemand:
    def test_high_demand(self):
        server = ServerInfo(
            registry_metadata={
                "env_vars": ["API_KEY", "SECRET_TOKEN", "DB_HOST", "REDIS_URL", "STRIPE_KEY"]
            }
        )
        flags = _check_high_secret_demand(server)
        assert len(flags) == 1
        assert flags[0].key == "HIGH_SECRET_DEMAND"

    def test_normal(self):
        server = ServerInfo(registry_metadata={"env_vars": ["A", "B"]})
        assert len(_check_high_secret_demand(server)) == 0

    def test_non_sensitive_vars_filtered(self):
        """PORT, HOST, LOG_LEVEL don't count toward HIGH_SECRET_DEMAND."""
        server = ServerInfo(
            registry_metadata={
                "env_vars": [
                    "PORT", "HOST", "LOG_LEVEL", "DEBUG", "NODE_ENV",
                    "WORKERS", "TIMEOUT", "API_KEY",
                ]
            }
        )
        # Only API_KEY is potentially sensitive (7 non-sensitive filtered out)
        flags = _check_high_secret_demand(server)
        assert len(flags) == 0

    def test_mixed_sensitive_and_config(self):
        """Mix of sensitive and config vars — only sensitive ones counted."""
        server = ServerInfo(
            registry_metadata={
                "env_vars": [
                    "PORT", "HOST", "API_KEY", "SECRET_TOKEN",
                    "DB_PASSWORD", "AUTH_CREDENTIAL", "STRIPE_KEY",
                ]
            }
        )
        # 5 sensitive vars (API_KEY, SECRET_TOKEN, DB_PASSWORD, AUTH_CREDENTIAL, STRIPE_KEY)
        flags = _check_high_secret_demand(server)
        assert len(flags) == 1


class TestRepoArchived:
    def test_archived_from_metadata(self):
        server = ServerInfo(registry_metadata={"archived": True})
        flags = _check_repo_archived(server, None)
        assert len(flags) == 1
        assert flags[0].key == "REPO_ARCHIVED"
        assert flags[0].severity == "critical"

    def test_archived_from_context(self):
        ctx = FlagContext(archived_repos={"https://github.com/test/test"})
        server = ServerInfo(repo_url="https://github.com/test/test")
        flags = _check_repo_archived(server, ctx)
        assert len(flags) == 1

    def test_not_archived(self):
        server = ServerInfo(registry_metadata={})
        assert len(_check_repo_archived(server, None)) == 0


class TestStaleProject:
    def test_stale(self):
        old_date = datetime.now(timezone.utc) - timedelta(days=400)
        server = ServerInfo(last_commit_at=old_date)
        flags = _check_stale_project(server)
        assert len(flags) == 1
        assert flags[0].key == "STALE_PROJECT"

    def test_recent(self):
        recent = datetime.now(timezone.utc) - timedelta(days=30)
        server = ServerInfo(last_commit_at=recent)
        assert len(_check_stale_project(server)) == 0

    def test_no_commit_date(self):
        server = ServerInfo()
        assert len(_check_stale_project(server)) == 0


class TestStagingArtifact:
    def test_localhost(self):
        server = ServerInfo(remote_endpoint_url="http://localhost:3000/mcp")
        flags = _check_staging_artifact(server)
        assert len(flags) == 1
        assert flags[0].key == "STAGING_ARTIFACT"

    def test_production_url(self):
        server = ServerInfo(remote_endpoint_url="https://api.acme.com/mcp")
        assert len(_check_staging_artifact(server)) == 0

    def test_no_url(self):
        server = ServerInfo(remote_endpoint_url="")
        assert len(_check_staging_artifact(server)) == 0


class TestTemplateDescription:
    def test_template(self):
        server = ServerInfo(description="A model context protocol server")
        flags = _check_template_description(server)
        assert len(flags) == 1
        assert flags[0].key == "TEMPLATE_DESCRIPTION"

    def test_normal_description(self):
        server = ServerInfo(description="Connects to the Acme API for widget management")
        assert len(_check_template_description(server)) == 0

    def test_empty(self):
        server = ServerInfo(description="")
        assert len(_check_template_description(server)) == 0


class TestDescriptionDuplicate:
    def test_duplicate(self):
        from collections import Counter

        ctx = FlagContext(
            description_counts=Counter({"this is a duplicated description that is fairly long": 5})
        )
        server = ServerInfo(description="This is a duplicated description that is fairly long")
        flags = _check_description_duplicate(server, ctx)
        assert len(flags) == 1
        assert flags[0].key == "DESCRIPTION_DUPLICATE"

    def test_unique(self):
        from collections import Counter

        ctx = FlagContext(description_counts=Counter({"some description text for testing": 1}))
        server = ServerInfo(description="Some description text for testing")
        assert len(_check_description_duplicate(server, ctx)) == 0

    def test_no_context(self):
        server = ServerInfo(description="Any description")
        assert len(_check_description_duplicate(server, None)) == 0


class TestSchemaDrift:
    def test_drift_detected(self):
        server = ServerInfo(
            registry_metadata={
                "schema_drift": {
                    "has_drift": True,
                    "missing_at_runtime": ["tool_a"],
                    "extra_at_runtime": ["tool_b", "tool_c"],
                }
            }
        )
        flags = _check_schema_drift(server)
        assert len(flags) == 1
        assert flags[0].key == "SCHEMA_DRIFT"
        assert flags[0].severity == "warning"
        assert "1 tool(s) missing at runtime" in flags[0].description
        assert "2 tool(s) only found at runtime" in flags[0].description

    def test_no_drift(self):
        server = ServerInfo(
            registry_metadata={
                "schema_drift": {
                    "has_drift": False,
                    "missing_at_runtime": [],
                    "extra_at_runtime": [],
                }
            }
        )
        assert len(_check_schema_drift(server)) == 0

    def test_no_drift_data(self):
        server = ServerInfo(registry_metadata={})
        assert len(_check_schema_drift(server)) == 0

    def test_missing_only(self):
        server = ServerInfo(
            registry_metadata={
                "schema_drift": {
                    "has_drift": True,
                    "missing_at_runtime": ["tool_x", "tool_y"],
                    "extra_at_runtime": [],
                }
            }
        )
        flags = _check_schema_drift(server)
        assert len(flags) == 1
        assert "2 tool(s) missing at runtime" in flags[0].description


class TestAmbiguousSchema:
    def test_ambiguous_multiple(self):
        server = ServerInfo(
            registry_metadata={"ambiguous_tools": ["search", "create_item"]}
        )
        flags = _check_ambiguous_schema(server)
        assert len(flags) == 1
        assert flags[0].key == "AMBIGUOUS_SCHEMA"
        assert flags[0].severity == "warning"
        assert "2 tool(s)" in flags[0].description
        assert "search" in flags[0].description

    def test_single_tool_not_flagged(self):
        """Need 2+ ambiguous tools to trigger the flag."""
        server = ServerInfo(registry_metadata={"ambiguous_tools": ["search"]})
        assert len(_check_ambiguous_schema(server)) == 0

    def test_no_ambiguous(self):
        server = ServerInfo(registry_metadata={"ambiguous_tools": []})
        assert len(_check_ambiguous_schema(server)) == 0

    def test_no_metadata(self):
        server = ServerInfo(registry_metadata={})
        assert len(_check_ambiguous_schema(server)) == 0


class TestDetectFlags:
    def test_clean_server(self, clean_server):
        flags = detect_flags(clean_server)
        assert isinstance(flags, list)

    def test_multiple_flags(self):
        server = ServerInfo(
            description="A model context protocol server",
            registry_metadata={
                "repo_status": "404",
                "env_vars": ["API_KEY", "SECRET", "TOKEN"],
            },
        )
        flags = detect_flags(server)
        keys = {f.key for f in flags}
        assert "DEAD_REPO" in keys
        assert "SENSITIVE_CREDS" in keys
        assert "TEMPLATE_DESCRIPTION" in keys
        assert "NO_SOURCE" in keys
