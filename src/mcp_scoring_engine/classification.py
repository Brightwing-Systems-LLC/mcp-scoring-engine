"""Server categorization engine.

Classifies servers into categories based on name, description, namespace,
and repo URL analysis. Also identifies target platforms.
"""

from __future__ import annotations

import re

from .types import ServerInfo

# Target platforms: keyword → (platform_label, category)
TARGET_PLATFORMS = {
    # AI/ML
    "openai": ("OpenAI", "ai_ml"),
    "gpt": ("OpenAI", "ai_ml"),
    "chatgpt": ("OpenAI", "ai_ml"),
    "anthropic": ("Anthropic", "ai_ml"),
    "claude": ("Anthropic", "ai_ml"),
    "huggingface": ("Hugging Face", "ai_ml"),
    "hugging-face": ("Hugging Face", "ai_ml"),
    "ollama": ("Ollama", "ai_ml"),
    "langchain": ("LangChain", "ai_ml"),
    "cohere": ("Cohere", "ai_ml"),
    "replicate": ("Replicate", "ai_ml"),
    "stable-diffusion": ("Stable Diffusion", "ai_ml"),
    "midjourney": ("Midjourney", "ai_ml"),
    "vertex-ai": ("Google Vertex AI", "ai_ml"),
    "bedrock": ("AWS Bedrock", "ai_ml"),
    "gemini": ("Google Gemini", "ai_ml"),
    # Database
    "postgres": ("PostgreSQL", "database"),
    "postgresql": ("PostgreSQL", "database"),
    "mysql": ("MySQL", "database"),
    "mongodb": ("MongoDB", "database"),
    "redis": ("Redis", "database"),
    "sqlite": ("SQLite", "database"),
    "supabase": ("Supabase", "database"),
    "firebase": ("Firebase", "database"),
    "dynamodb": ("DynamoDB", "database"),
    "elasticsearch": ("Elasticsearch", "database"),
    "pinecone": ("Pinecone", "database"),
    "qdrant": ("Qdrant", "database"),
    "chromadb": ("ChromaDB", "database"),
    "weaviate": ("Weaviate", "database"),
    "neon": ("Neon", "database"),
    "turso": ("Turso", "database"),
    # DevTools
    "github": ("GitHub", "devtools"),
    "gitlab": ("GitLab", "devtools"),
    "bitbucket": ("Bitbucket", "devtools"),
    "docker": ("Docker", "devtools"),
    "kubernetes": ("Kubernetes", "devtools"),
    "terraform": ("Terraform", "devtools"),
    "npm": ("npm", "devtools"),
    "jira": ("Jira", "devtools"),
    "linear": ("Linear", "devtools"),
    "sentry": ("Sentry", "devtools"),
    "jest": ("Jest", "devtools"),
    "eslint": ("ESLint", "devtools"),
    "prettier": ("Prettier", "devtools"),
    # Cloud
    "aws": ("AWS", "cloud"),
    "gcp": ("Google Cloud", "cloud"),
    "azure": ("Azure", "cloud"),
    "cloudflare": ("Cloudflare", "cloud"),
    "vercel": ("Vercel", "cloud"),
    "netlify": ("Netlify", "cloud"),
    "heroku": ("Heroku", "cloud"),
    "digitalocean": ("DigitalOcean", "cloud"),
    "fly.io": ("Fly.io", "cloud"),
    "railway": ("Railway", "cloud"),
    # Communication
    "slack": ("Slack", "communication"),
    "discord": ("Discord", "communication"),
    "telegram": ("Telegram", "communication"),
    "email": ("Email", "communication"),
    "twilio": ("Twilio", "communication"),
    "sendgrid": ("SendGrid", "communication"),
    "whatsapp": ("WhatsApp", "communication"),
    # Productivity
    "notion": ("Notion", "productivity"),
    "obsidian": ("Obsidian", "productivity"),
    "google-docs": ("Google Docs", "productivity"),
    "google-drive": ("Google Drive", "productivity"),
    "google-sheets": ("Google Sheets", "productivity"),
    "airtable": ("Airtable", "productivity"),
    "todoist": ("Todoist", "productivity"),
    "trello": ("Trello", "productivity"),
    "asana": ("Asana", "productivity"),
    "calendar": ("Calendar", "productivity"),
    # Search
    "brave-search": ("Brave Search", "search"),
    "google-search": ("Google Search", "search"),
    "tavily": ("Tavily", "search"),
    "exa": ("Exa", "search"),
    "perplexity": ("Perplexity", "search"),
    "wikipedia": ("Wikipedia", "search"),
    "arxiv": ("arXiv", "search"),
    # Monitoring
    "datadog": ("Datadog", "monitoring"),
    "grafana": ("Grafana", "monitoring"),
    "prometheus": ("Prometheus", "monitoring"),
    "pagerduty": ("PagerDuty", "monitoring"),
    "newrelic": ("New Relic", "monitoring"),
    # Data
    "snowflake": ("Snowflake", "data"),
    "bigquery": ("BigQuery", "data"),
    "dbt": ("dbt", "data"),
    "pandas": ("pandas", "data"),
    "jupyter": ("Jupyter", "data"),
    # Finance
    "stripe": ("Stripe", "finance"),
    "plaid": ("Plaid", "finance"),
    "coinbase": ("Coinbase", "finance"),
    # Media
    "youtube": ("YouTube", "media"),
    "spotify": ("Spotify", "media"),
    "figma": ("Figma", "media"),
    "canva": ("Canva", "media"),
    # E-Commerce
    "shopify": ("Shopify", "ecommerce"),
    "woocommerce": ("WooCommerce", "ecommerce"),
    # Browser
    "puppeteer": ("Puppeteer", "browser"),
    "playwright": ("Playwright", "browser"),
    "selenium": ("Selenium", "browser"),
    "browserbase": ("Browserbase", "browser"),
    "fetch": ("Web Fetch", "browser"),
    "scraper": ("Web Scraper", "browser"),
    "scraping": ("Web Scraping", "browser"),
    "crawl": ("Web Crawler", "browser"),
}


def classify_server(server: ServerInfo) -> tuple[str, list[str]]:
    """Classify a server into a category and identify target platforms.

    Uses 4-tier matching: name, description, registry namespace, repo URL.
    Returns (category, list_of_target_labels).
    """
    targets_found: set[str] = set()
    category_votes: dict[str, int] = {}

    name_lower = (server.name or "").lower()
    desc_lower = (server.description or "").lower()

    namespace = ""
    rid = server.registry_id or ""
    if "/" in rid:
        namespace = rid.rsplit("/", 1)[-1].lower()

    repo_path = ""
    if server.repo_url:
        repo_path = (
            server.repo_url.lower().rstrip("/").rsplit("/", 1)[-1]
            if "/" in server.repo_url
            else ""
        )

    search_fields = [
        (name_lower, 3),
        (desc_lower, 1),
        (namespace, 2),
        (repo_path, 2),
    ]

    for keyword, (platform_label, category) in TARGET_PLATFORMS.items():
        kw_pattern = re.compile(
            r"(?:^|[\s\-_/])(" + re.escape(keyword) + r")(?:[\s\-_/.]|$)", re.IGNORECASE
        )
        for text, weight in search_fields:
            if not text:
                continue
            if keyword in text or kw_pattern.search(text):
                targets_found.add(platform_label)
                category_votes[category] = category_votes.get(category, 0) + weight
                break

    if category_votes:
        best_category = max(category_votes, key=category_votes.get)
    else:
        best_category = "other"

    return best_category, sorted(targets_found)
