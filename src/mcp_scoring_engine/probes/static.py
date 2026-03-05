"""Static analysis probes for GitHub repositories.

Implements all Tier 1 metrics — no network calls to MCP servers,
only GitHub API and source code analysis.

Each probe function returns a score (0-100) plus a details dict.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from ..types import StaticAnalysis
from .entry_point import detect_entry_point, make_github_file_reader
from .github_client import GitHubPublicClient

logger = logging.getLogger(__name__)


def analyze_repo(
    repo_url: str, *, registry_id: str | None = None
) -> StaticAnalysis | None:
    """Run all static analysis probes against a GitHub repository.

    Returns a StaticAnalysis with all 7 metric scores, or None if
    the repo is unreachable.
    """
    try:
        client = GitHubPublicClient(repo_url)
    except ValueError:
        logger.warning("Cannot analyze non-GitHub URL: %s", repo_url)
        return None

    with client:
        repo = client.get_repo()
        if not repo:
            logger.warning("Repo not found or inaccessible: %s", repo_url)
            return None

        tree = client.get_tree(default_branch=repo.get("default_branch", "main"))
        commits = client.get_commits(per_page=30)
        releases = client.get_releases(per_page=10)
        tags = client.get_tags(per_page=10)

        file_names = {item["path"] for item in (tree or [])}
        root_files = {item["path"] for item in (tree or []) if "/" not in item["path"]}

        result = StaticAnalysis()

        # GitHub metadata snapshot
        result.stars_count = repo.get("stargazers_count", 0)
        result.open_issues_count = repo.get("open_issues_count", 0)
        pushed_at = repo.get("pushed_at")
        if pushed_at:
            result.last_commit_at = datetime.fromisoformat(
                pushed_at.replace("Z", "+00:00")
            )

        if releases:
            result.latest_version = releases[0].get("tag_name", "")
        elif tags:
            result.latest_version = tags[0].get("name", "")

        # Run each probe
        schema_score, schema_details = _probe_schema_completeness(tree, file_names, client)
        result.schema_completeness = schema_score
        result.details["schema_completeness"] = schema_details

        desc_score, desc_details = _probe_description_quality(repo, tree, client)
        result.description_quality = desc_score
        result.details["description_quality"] = desc_details

        doc_score, doc_details = _probe_documentation_coverage(repo, file_names, root_files)

        prov_score, prov_details = _probe_provenance_signals(
            file_names, root_files, repo, registry_id=registry_id
        )
        result.details["provenance"] = prov_details
        result.documentation_coverage = min(doc_score + prov_score, 100)
        result.details["documentation_coverage"] = doc_details

        maint_score, maint_details = _probe_maintenance_pulse(repo, commits, releases)
        result.maintenance_pulse = maint_score
        result.details["maintenance_pulse"] = maint_details

        dep_score, dep_details = _probe_dependency_health(file_names, tree, client)
        result.dependency_health = dep_score
        result.details["dependency_health"] = dep_details

        lic_score, lic_details = _probe_license_clarity(repo)
        result.license_clarity = lic_score
        result.details["license_clarity"] = lic_details

        ver_score, ver_details = _probe_version_hygiene(releases, tags)
        result.version_hygiene = ver_score
        result.details["version_hygiene"] = ver_details

        # Entry point detection — piggybacks on already-fetched tree + client
        entry_point = detect_entry_point(tree or [], make_github_file_reader(client))
        if entry_point:
            result.details["entry_point"] = entry_point

        return result


# ---------------------------------------------------------------------------
# Probe 1: Schema Completeness
# ---------------------------------------------------------------------------

TOOL_DEF_PATTERNS = [
    re.compile(r"@(?:mcp\.)?tool", re.IGNORECASE),
    re.compile(r"server\.tool\s*\(", re.IGNORECASE),
    re.compile(r"addTool\s*\(", re.IGNORECASE),
    re.compile(r"tools?\s*[=:]\s*\[", re.IGNORECASE),
    re.compile(r"inputSchema", re.IGNORECASE),
]

SCHEMA_MARKERS = [
    "inputSchema",
    "parameters",
    "properties",
    "description",
    "type",
    "required",
]


def _probe_schema_completeness(
    tree: list | None, file_names: set, client: GitHubPublicClient
) -> tuple[int, dict]:
    """Check if tools have typed parameters with descriptions."""
    details = {"tool_files_found": 0, "schema_markers_found": [], "issues": []}

    if not tree:
        return 0, {**details, "issues": ["no_tree"]}

    source_exts = {".py", ".ts", ".js", ".mjs", ".go", ".rs"}
    candidate_files = []
    for item in tree:
        if item.get("type") != "blob":
            continue
        path = item["path"]
        ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
        if ext in source_exts and any(
            kw in path.lower()
            for kw in ["tool", "server", "mcp", "handler", "index", "main", "app"]
        ):
            candidate_files.append(path)

    if not candidate_files:
        for item in tree:
            if item.get("type") != "blob":
                continue
            path = item["path"]
            ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
            if ext in source_exts and (
                path.startswith("src/") or path.startswith("lib/")
            ):
                candidate_files.append(path)
            if len(candidate_files) >= 10:
                break

    if not candidate_files:
        return 30, {**details, "issues": ["no_candidate_source_files"]}

    markers_found = set()
    tool_defs_found = 0
    files_checked = 0
    tool_source_files = []

    MAX_SOURCE_BYTES = 12_000  # Cap per file to control token budget

    for path in candidate_files[:5]:
        content_data = client.get_contents(path)
        if not content_data or isinstance(content_data, list):
            continue

        files_checked += 1
        import base64

        try:
            content = base64.b64decode(content_data.get("content", "")).decode(
                "utf-8", errors="replace"
            )
        except Exception:
            continue

        has_tool_pattern = False
        for pattern in TOOL_DEF_PATTERNS:
            if pattern.search(content):
                tool_defs_found += 1
                has_tool_pattern = True
                break

        for marker in SCHEMA_MARKERS:
            if marker in content:
                markers_found.add(marker)

        # Retain source for files with tool patterns (for LLM extraction)
        if has_tool_pattern:
            tool_source_files.append({
                "path": path,
                "content": content[:MAX_SOURCE_BYTES],
            })

    details["tool_files_found"] = tool_defs_found
    details["schema_markers_found"] = sorted(markers_found)
    details["files_checked"] = files_checked
    if tool_source_files:
        details["tool_source_files"] = tool_source_files

    if tool_defs_found == 0:
        return 40, {**details, "issues": ["no_tool_definitions_found"]}

    marker_ratio = len(markers_found) / len(SCHEMA_MARKERS)
    score = int(40 + marker_ratio * 60)

    if "inputSchema" not in markers_found and "parameters" not in markers_found:
        details["issues"].append("no_input_schema")
        score = min(score, 60)

    if "description" not in markers_found:
        details["issues"].append("no_descriptions")
        score = min(score, 70)

    return min(score, 100), details


# ---------------------------------------------------------------------------
# Probe 2: Description Quality
# ---------------------------------------------------------------------------


def _probe_description_quality(
    repo: dict, tree: list | None, client: GitHubPublicClient
) -> tuple[int, dict]:
    """Evaluate quality of the repo's description and tool descriptions."""
    score = 0
    details = {"checks": {}}

    desc = repo.get("description", "") or ""
    if desc:
        details["repo_description_length"] = len(desc)
        if len(desc) >= 20:
            score += 20
            details["checks"]["has_description"] = True
        if len(desc) >= 50:
            score += 10
            details["checks"]["description_detailed"] = True
        action_words = [
            "connect", "query", "search", "manage", "monitor",
            "generate", "analyze", "create", "retrieve", "access",
        ]
        if any(w in desc.lower() for w in action_words):
            score += 10
            details["checks"]["description_actionable"] = True
    else:
        details["checks"]["has_description"] = False

    readme_content = _read_readme(tree, client)
    if readme_content:
        readme_len = len(readme_content)
        details["readme_length"] = readme_len
        if readme_len >= 200:
            score += 15
            details["checks"]["readme_substantive"] = True
        if readme_len >= 1000:
            score += 10
            details["checks"]["readme_detailed"] = True

        headings = re.findall(r"^#+\s+.+", readme_content, re.MULTILINE)
        details["readme_heading_count"] = len(headings)
        if len(headings) >= 3:
            score += 10
            details["checks"]["readme_structured"] = True

        code_blocks = readme_content.count("```")
        if code_blocks >= 2:
            score += 10
            details["checks"]["has_code_examples"] = True

        lower = readme_content.lower()
        if any(
            s in lower
            for s in [
                "## usage", "## install", "## getting started",
                "## setup", "## quick start",
            ]
        ):
            score += 15
            details["checks"]["has_usage_section"] = True
    else:
        details["checks"]["has_readme"] = False

    return min(score, 100), details


def _read_readme(tree: list | None, client: GitHubPublicClient) -> str | None:
    """Find and read the README file."""
    if not tree:
        return None
    readme_names = {"readme.md", "readme.rst", "readme.txt", "readme"}
    for item in tree:
        if item["path"].lower() in readme_names and item.get("type") == "blob":
            content_data = client.get_contents(item["path"])
            if content_data and not isinstance(content_data, list):
                import base64

                try:
                    return base64.b64decode(content_data.get("content", "")).decode(
                        "utf-8", errors="replace"
                    )
                except Exception:
                    return None
    return None


# ---------------------------------------------------------------------------
# Probe 3: Documentation Coverage
# ---------------------------------------------------------------------------


def _probe_documentation_coverage(
    repo: dict, file_names: set, root_files: set
) -> tuple[int, dict]:
    """Check for README, changelog, examples, contributing guide, etc."""
    score = 0
    checks = {}

    has_readme = any(
        f.lower() in {"readme.md", "readme.rst", "readme.txt", "readme"}
        for f in root_files
    )
    checks["has_readme"] = has_readme
    if has_readme:
        score += 25

    changelog_names = {
        "changelog.md", "changelog.txt", "changelog",
        "changes.md", "history.md", "releases.md",
    }
    has_changelog = any(f.lower() in changelog_names for f in root_files)
    checks["has_changelog"] = has_changelog
    if has_changelog:
        score += 15

    has_examples = any(
        f.startswith("examples/") or f.startswith("example/") for f in file_names
    )
    checks["has_examples"] = has_examples
    if has_examples:
        score += 15

    contributing_names = {"contributing.md", "contributing.txt", "contributing"}
    has_contributing = any(f.lower() in contributing_names for f in root_files)
    checks["has_contributing"] = has_contributing
    if has_contributing:
        score += 10

    license_names = {
        "license", "license.md", "license.txt",
        "licence", "licence.md", "copying",
    }
    has_license = any(f.lower() in license_names for f in root_files)
    checks["has_license_file"] = has_license
    if has_license:
        score += 10

    has_docs = any(f.startswith("docs/") or f.startswith("doc/") for f in file_names)
    checks["has_docs_dir"] = has_docs
    if has_docs:
        score += 7

    return min(score, 82), {"checks": checks}


# ---------------------------------------------------------------------------
# Probe 3b: Provenance Signals
# ---------------------------------------------------------------------------


def _probe_provenance_signals(
    file_names: set,
    root_files: set,
    repo: dict,
    *,
    registry_id: str | None = None,
) -> tuple[int, dict]:
    """Check provenance signals that feed into the documentation coverage score."""
    score = 0
    checks: dict = {}

    security_names = {"security.md", "security.txt", ".github/security.md"}
    has_security = any(f.lower() in security_names for f in file_names)
    checks["has_security_policy"] = has_security
    if has_security:
        score += 3

    conduct_names = {"code_of_conduct.md", ".github/code_of_conduct.md"}
    has_conduct = any(f.lower() in conduct_names for f in file_names)
    checks["has_code_of_conduct"] = has_conduct
    if has_conduct:
        score += 3

    repo_owner = ""
    full_name = repo.get("full_name", "")
    if "/" in full_name:
        repo_owner = full_name.split("/")[0].lower()

    namespace = ""
    if registry_id and "/" in registry_id:
        ns_part = registry_id.split("/")[0]
        namespace = ns_part.lstrip("@").lower()

    if repo_owner and namespace:
        match = (
            repo_owner == namespace
            or namespace in repo_owner
            or repo_owner in namespace
        )
        checks["namespace_owner_match"] = match
        checks["repo_owner"] = repo_owner
        checks["registry_namespace"] = namespace
        if match:
            score += 7
    else:
        checks["namespace_owner_match"] = None

    installable_indicators = {
        "package.json", "setup.py", "setup.cfg",
        "pyproject.toml", "Cargo.toml", "go.mod",
    }
    has_installable = bool(file_names & installable_indicators)
    checks["has_installable_package"] = has_installable
    if has_installable:
        score += 5

    return min(score, 18), {"checks": checks}


# ---------------------------------------------------------------------------
# Probe 4: Maintenance Pulse
# ---------------------------------------------------------------------------


def _probe_maintenance_pulse(
    repo: dict, commits: list | None, releases: list | None
) -> tuple[int, dict]:
    """Assess project maintenance using a three-signal model.

    Signals:
      1. Vitality (40 pts) — ongoing development activity, with a stability
         floor so mature healthy projects aren't penalized for inactivity.
      2. Release Discipline (30 pts) — tagged releases with semver.
      3. Community Health (30 pts) — stars, forks, issue responsiveness.

    Total: 100 pts max.
    """
    details: dict = {}
    now = datetime.now(timezone.utc)

    stars = repo.get("stargazers_count", 0)
    forks = repo.get("forks_count", 0)
    open_issues = repo.get("open_issues_count", 0)
    has_any_release = bool(releases)

    details["stars"] = stars
    details["forks"] = forks
    details["open_issues"] = open_issues

    # ── Signal 1: Vitality (40 pts max) ──────────────────────────────

    vitality = 0

    # Push recency (base points)
    pushed_at = repo.get("pushed_at")
    days_since_push = None
    if pushed_at:
        last_push = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
        days_since_push = (now - last_push).days
        details["days_since_last_push"] = days_since_push

        if days_since_push <= 30:
            vitality = 40
        elif days_since_push <= 90:
            vitality = 30
        elif days_since_push <= 180:
            vitality = 20
        elif days_since_push <= 365:
            vitality = 10
        # >365 days: vitality = 0

    # Stability floor: mature projects with evidence of health
    # get minimum vitality even if inactive.
    open_issues_ratio = open_issues / max(stars, 1) if stars > 0 else 0
    is_stable = stars >= 50 and has_any_release and open_issues_ratio < 0.3
    if is_stable and vitality < 20:
        vitality = 20
        details["stability_floor_applied"] = True

    # Recent commits bonus (additive, up to cap of 40)
    recent_commits = len(commits) if commits else 0
    details["recent_commits"] = recent_commits
    if recent_commits >= 10:
        vitality = min(40, vitality + 10)
    elif recent_commits >= 5:
        vitality = min(40, vitality + 5)

    details["vitality"] = vitality

    # ── Signal 2: Release Discipline (30 pts max) ────────────────────

    release_pts = 0

    if releases:
        details["release_count"] = len(releases)
        if len(releases) >= 3:
            release_pts += 15
        elif len(releases) >= 1:
            release_pts += 10

        # Recent release bonus
        latest_date = releases[0].get("published_at", "")
        if latest_date:
            try:
                release_dt = datetime.fromisoformat(
                    latest_date.replace("Z", "+00:00")
                )
                days_since = (now - release_dt).days
                details["days_since_latest_release"] = days_since
                if days_since <= 90:
                    release_pts += 10
                elif days_since <= 180:
                    release_pts += 5
            except ValueError:
                pass

        # Release notes bonus
        has_notes = any(
            bool((r.get("body") or "").strip()) for r in releases[:3]
        )
        if has_notes:
            release_pts += 5
            details["has_release_notes"] = True

    release_pts = min(release_pts, 30)
    details["release_discipline"] = release_pts

    # ── Signal 3: Community Health (30 pts max) ──────────────────────

    # Stars (15 pts max)
    if stars >= 1000:
        star_pts = 15
    elif stars >= 100:
        star_pts = 12
    elif stars >= 50:
        star_pts = 10
    elif stars >= 10:
        star_pts = 5
    else:
        star_pts = 0

    # Issue responsiveness (10 pts max)
    # 0 issues = neutral (5 pts), not maximum — could mean unused
    if open_issues == 0:
        issue_pts = 5
    elif open_issues_ratio < 0.05:
        issue_pts = 10  # very responsive
    elif open_issues_ratio < 0.1:
        issue_pts = 7
    elif open_issues_ratio < 0.3:
        issue_pts = 3
    else:
        issue_pts = 0  # overwhelmed

    # Forks (5 pts max)
    if forks >= 50:
        fork_pts = 5
    elif forks >= 10:
        fork_pts = 3
    elif forks >= 1:
        fork_pts = 1
    else:
        fork_pts = 0

    community = star_pts + issue_pts + fork_pts
    community = min(community, 30)
    details["community_health"] = community
    details["star_pts"] = star_pts
    details["issue_pts"] = issue_pts
    details["fork_pts"] = fork_pts

    total = vitality + release_pts + community
    return min(total, 100), details


# ---------------------------------------------------------------------------
# Probe 5: Dependency Health
# ---------------------------------------------------------------------------


def _probe_dependency_health(
    file_names: set, tree: list | None, client: GitHubPublicClient
) -> tuple[int, dict]:
    """Check dependency management practices."""
    score = 0
    checks = {}

    has_package_json = "package.json" in file_names
    has_pyproject = "pyproject.toml" in file_names
    has_requirements = any(
        f.endswith("requirements.txt") or f == "requirements.in" for f in file_names
    )
    has_cargo = "Cargo.toml" in file_names
    has_go_mod = "go.mod" in file_names

    has_manifest = (
        has_package_json or has_pyproject or has_requirements or has_cargo or has_go_mod
    )
    checks["has_dependency_manifest"] = has_manifest
    if has_manifest:
        score += 30

    lock_files = {
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb",
        "poetry.lock", "uv.lock", "Pipfile.lock", "Cargo.lock", "go.sum",
    }
    has_lock = bool(file_names & lock_files)
    checks["has_lock_file"] = has_lock
    if has_lock:
        score += 25

    ci_paths = [
        ".github/workflows/", ".gitlab-ci.yml",
        ".circleci/", "Jenkinsfile", ".travis.yml",
    ]
    has_ci = any(
        any(f.startswith(ci) or f == ci for f in file_names) for ci in ci_paths
    )
    checks["has_ci"] = has_ci
    if has_ci:
        score += 20

    tool_configs = {
        "renovate.json", "renovate.json5", ".renovaterc",
        ".github/dependabot.yml", ".github/dependabot.yaml",
    }
    has_dep_automation = bool(file_names & tool_configs)
    checks["has_dependency_automation"] = has_dep_automation
    if has_dep_automation:
        score += 25

    return min(score, 100), {"checks": checks}


# ---------------------------------------------------------------------------
# Probe 6: License Clarity
# ---------------------------------------------------------------------------

KNOWN_LICENSES = {
    "MIT", "Apache-2.0", "GPL-2.0", "GPL-3.0", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "MPL-2.0", "LGPL-2.1", "LGPL-3.0", "AGPL-3.0", "Unlicense",
    "0BSD", "Artistic-2.0", "Zlib",
}


def _probe_license_clarity(repo: dict) -> tuple[int, dict]:
    """Check for a clear, standard license."""
    details = {}

    license_info = repo.get("license")
    if not license_info or license_info.get("spdx_id") == "NOASSERTION":
        details["license"] = None
        details["issue"] = "no_license_detected"
        return 0, details

    spdx = license_info.get("spdx_id", "")
    name = license_info.get("name", "")
    details["spdx_id"] = spdx
    details["name"] = name

    if spdx in KNOWN_LICENSES:
        return 100, details

    if spdx and spdx != "NOASSERTION":
        return 70, {**details, "note": "non_standard_but_identified"}

    if name:
        return 40, {**details, "note": "custom_license"}

    return 0, details


# ---------------------------------------------------------------------------
# Probe 7: Version Hygiene
# ---------------------------------------------------------------------------

SEMVER_PATTERN = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")


def _probe_version_hygiene(
    releases: list | None, tags: list | None
) -> tuple[int, dict]:
    """Check for semantic versioning and proper release practices."""
    score = 0
    details = {}

    all_versions = []
    if releases:
        all_versions.extend(r.get("tag_name", "") for r in releases)
    if tags:
        all_versions.extend(t.get("name", "") for t in tags)

    all_versions = list(dict.fromkeys(all_versions))
    details["version_count"] = len(all_versions)

    if not all_versions:
        details["issue"] = "no_versions_or_tags"
        return 0, details

    has_releases = bool(releases)
    details["has_releases"] = has_releases
    if has_releases:
        score += 30

    semver_count = sum(1 for v in all_versions if SEMVER_PATTERN.match(v))
    details["semver_count"] = semver_count
    details["total_versions"] = len(all_versions)

    if len(all_versions) > 0:
        semver_ratio = semver_count / len(all_versions)
        details["semver_ratio"] = round(semver_ratio, 2)
        if semver_ratio >= 0.8:
            score += 35
        elif semver_ratio >= 0.5:
            score += 20
        elif semver_count >= 1:
            score += 10

    if releases:
        with_body = sum(1 for r in releases if r.get("body", "").strip())
        details["releases_with_notes"] = with_body
        if with_body >= 1:
            score += 15
        if len(releases) > 1 and with_body / len(releases) >= 0.5:
            score += 10

    if releases:
        has_prerelease = any(r.get("prerelease", False) for r in releases)
        details["uses_prereleases"] = has_prerelease
        if has_prerelease:
            score += 10

    return min(score, 100), details
