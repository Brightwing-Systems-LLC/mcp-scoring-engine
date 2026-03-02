"""Lightweight GitHub API client for public repository analysis.

Uses GITHUB_PUBLIC_TOKEN env var for 5,000 req/hr,
or falls back to unauthenticated access (60 req/hr).
"""

from __future__ import annotations

import logging
import os

import httpx

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
TIMEOUT = 20


class GitHubRateLimitExhausted(Exception):
    """Raised when the GitHub API rate limit is exhausted."""

    pass


def _get_headers() -> dict:
    token = os.environ.get("GITHUB_PUBLIC_TOKEN", "")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "MCPScoringEngine/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _parse_owner_repo(repo_url: str) -> tuple[str, str] | None:
    """Extract owner/repo from a GitHub URL."""
    if not repo_url or "github.com" not in repo_url:
        return None
    parts = repo_url.rstrip("/").split("github.com/")[-1].split("/")
    if len(parts) < 2:
        return None
    return parts[0], parts[1].removesuffix(".git")


class GitHubPublicClient:
    """Client for fetching public repo metadata from GitHub API."""

    def __init__(self, repo_url: str):
        parsed = _parse_owner_repo(repo_url)
        if not parsed:
            raise ValueError(f"Invalid GitHub URL: {repo_url}")
        self.owner, self.repo = parsed
        self._client = httpx.Client(
            base_url=GITHUB_API, headers=_get_headers(), timeout=TIMEOUT
        )

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _get(self, path: str, **params) -> dict | list | None:
        """Make a GET request, returning parsed JSON or None on error."""
        try:
            resp = self._client.get(path, params=params)
            if resp.status_code == 404:
                return None
            if resp.status_code == 403:
                remaining = resp.headers.get("x-ratelimit-remaining", "?")
                logger.warning(
                    "GitHub API rate limited (remaining: %s) for %s/%s",
                    remaining,
                    self.owner,
                    self.repo,
                )
                if str(remaining) == "0":
                    raise GitHubRateLimitExhausted(
                        f"GitHub API rate limit exhausted for {self.owner}/{self.repo}"
                    )
                return None
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            logger.warning("GitHub API error for %s/%s: %s", self.owner, self.repo, e)
            return None

    def get_repo(self) -> dict | None:
        return self._get(f"/repos/{self.owner}/{self.repo}")

    def get_commits(self, per_page: int = 30) -> list | None:
        return self._get(f"/repos/{self.owner}/{self.repo}/commits", per_page=per_page)

    def get_releases(self, per_page: int = 10) -> list | None:
        return self._get(f"/repos/{self.owner}/{self.repo}/releases", per_page=per_page)

    def get_tags(self, per_page: int = 10) -> list | None:
        return self._get(f"/repos/{self.owner}/{self.repo}/tags", per_page=per_page)

    def get_contents(self, path: str = "") -> dict | list | None:
        return self._get(f"/repos/{self.owner}/{self.repo}/contents/{path}")

    def file_exists(self, path: str) -> bool:
        result = self.get_contents(path)
        return result is not None and not isinstance(result, list)

    def get_tree(self, default_branch: str = "") -> list | None:
        branch = default_branch
        if not branch:
            repo = self.get_repo()
            if not repo:
                return None
            branch = repo.get("default_branch", "main")
        result = self._get(
            f"/repos/{self.owner}/{self.repo}/git/trees/{branch}",
            recursive="1",
        )
        if result and "tree" in result:
            return result["tree"]
        return None
