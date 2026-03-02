"""Tests for server categorization and classification."""

from mcp_scoring_engine import ServerInfo, classify_server


class TestClassifyServer:
    def test_ai_ml_by_name(self):
        server = ServerInfo(name="openai-mcp-server")
        category, targets = classify_server(server)
        assert category == "ai_ml"
        assert "OpenAI" in targets

    def test_database_by_description(self):
        server = ServerInfo(
            name="db-tools",
            description="Connect to PostgreSQL databases for query execution",
        )
        category, targets = classify_server(server)
        assert category == "database"
        assert "PostgreSQL" in targets

    def test_devtools_by_registry(self):
        server = ServerInfo(registry_id="@modelcontextprotocol/server-github")
        category, targets = classify_server(server)
        assert category == "devtools"
        assert "GitHub" in targets

    def test_cloud_by_repo(self):
        server = ServerInfo(
            name="some-tool",
            repo_url="https://github.com/user/aws-mcp-server",
        )
        category, targets = classify_server(server)
        assert category == "cloud"
        assert "AWS" in targets

    def test_communication(self):
        server = ServerInfo(name="slack-mcp-server")
        category, targets = classify_server(server)
        assert category == "communication"
        assert "Slack" in targets

    def test_productivity(self):
        server = ServerInfo(name="notion-mcp")
        category, targets = classify_server(server)
        assert category == "productivity"
        assert "Notion" in targets

    def test_search(self):
        server = ServerInfo(name="brave-search-mcp")
        category, targets = classify_server(server)
        assert category == "search"
        assert "Brave Search" in targets

    def test_monitoring(self):
        server = ServerInfo(description="Datadog metrics and monitoring")
        category, targets = classify_server(server)
        assert category == "monitoring"
        assert "Datadog" in targets

    def test_browser(self):
        server = ServerInfo(name="puppeteer-mcp-server")
        category, targets = classify_server(server)
        assert category == "browser"
        assert "Puppeteer" in targets

    def test_ecommerce(self):
        server = ServerInfo(name="shopify-mcp")
        category, targets = classify_server(server)
        assert category == "ecommerce"
        assert "Shopify" in targets

    def test_other_category(self):
        server = ServerInfo(name="my-custom-tool", description="Does custom stuff")
        category, targets = classify_server(server)
        assert category == "other"
        assert targets == []

    def test_multiple_targets(self):
        server = ServerInfo(
            name="multi-tool",
            description="Connects to GitHub and Slack for notifications",
        )
        _, targets = classify_server(server)
        assert "GitHub" in targets
        assert "Slack" in targets

    def test_name_has_highest_weight(self):
        server = ServerInfo(
            name="openai-server",
            description="Uses Slack to send notifications about AWS resources",
        )
        category, _ = classify_server(server)
        assert category == "ai_ml"
