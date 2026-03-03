"""Tests for the three-signal maintenance pulse scoring model."""

from datetime import datetime, timedelta, timezone

import pytest

from mcp_scoring_engine.probes.static import _probe_maintenance_pulse


def _make_repo(
    pushed_days_ago=None,
    stars=0,
    forks=0,
    open_issues=0,
):
    """Build a minimal GitHub repo dict."""
    repo = {
        "stargazers_count": stars,
        "forks_count": forks,
        "open_issues_count": open_issues,
    }
    if pushed_days_ago is not None:
        dt = datetime.now(timezone.utc) - timedelta(days=pushed_days_ago)
        repo["pushed_at"] = dt.isoformat()
    return repo


def _make_commits(count, span_days=60):
    """Build a list of commit dicts spread over `span_days`."""
    now = datetime.now(timezone.utc)
    commits = []
    for i in range(count):
        dt = now - timedelta(days=int(i * span_days / max(count - 1, 1)))
        commits.append(
            {"commit": {"committer": {"date": dt.isoformat()}}}
        )
    return commits


def _make_releases(count, latest_days_ago=30, with_notes=False):
    """Build a list of release dicts."""
    now = datetime.now(timezone.utc)
    releases = []
    for i in range(count):
        dt = now - timedelta(days=latest_days_ago + i * 60)
        body = "Release notes here" if with_notes else ""
        releases.append({"published_at": dt.isoformat(), "body": body})
    return releases


class TestStableMatureProject:
    """Stable mature project: 200 stars, last push 8 months ago, 3 releases.

    Should score >= 60 (stability floor kicks in).
    """

    def test_scores_at_least_60(self):
        repo = _make_repo(pushed_days_ago=240, stars=200, forks=30, open_issues=5)
        commits = _make_commits(3, span_days=90)
        releases = _make_releases(3, latest_days_ago=180, with_notes=True)

        score, details = _probe_maintenance_pulse(repo, commits, releases)

        # Vitality: stability floor = 20 (stars>=50, has releases, ratio<0.3)
        # Release: 3 releases = 15, not recent = 0, has notes = +5 → 20
        # Community: stars≥100 → 12, issues ratio=5/200=0.025 → 10, forks≥10 → 3 → 25
        # Total: 20 + 20 + 25 = 65
        assert score >= 60
        assert details.get("stability_floor_applied") is True

    def test_stability_floor_prevents_low_vitality(self):
        """Even with no recent commits and old push, vitality floors at 20."""
        repo = _make_repo(pushed_days_ago=400, stars=100, forks=20, open_issues=2)
        releases = _make_releases(1, latest_days_ago=300)

        score, details = _probe_maintenance_pulse(repo, None, releases)

        assert details["vitality"] >= 20
        assert details.get("stability_floor_applied") is True


class TestBrandNewActiveProject:
    """Brand new active project: 0 stars, 5 recent commits, burst pattern.

    Should score >= 30 (not penalized for being new).
    """

    def test_scores_at_least_30(self):
        repo = _make_repo(pushed_days_ago=5, stars=0, forks=0, open_issues=0)
        commits = _make_commits(5, span_days=10)

        score, details = _probe_maintenance_pulse(repo, commits, None)

        # Vitality: push<=30 → 40, commits>=5 → min(40, 40+5)=40 → 40
        # Release: no releases → 0
        # Community: 0 stars → 0, 0 issues → 5, 0 forks → 0 → 5
        # Total: 40 + 0 + 5 = 45
        assert score >= 30

    def test_burst_pattern_not_penalized(self):
        """New projects with burst commits shouldn't be penalized."""
        repo = _make_repo(pushed_days_ago=3, stars=2, forks=0, open_issues=0)
        commits = _make_commits(10, span_days=7)  # all within a week

        score, details = _probe_maintenance_pulse(repo, commits, None)

        # Vitality should be max (40) even with burst pattern
        assert details["vitality"] == 40


class TestTrulyAbandonedProject:
    """Abandoned project: 0 stars, no commits in 2 years, no releases.

    Should score < 20.
    """

    def test_scores_below_20(self):
        repo = _make_repo(pushed_days_ago=730, stars=0, forks=0, open_issues=3)

        score, details = _probe_maintenance_pulse(repo, None, None)

        # Vitality: >365 days, no stability floor → 0
        # Release: none → 0
        # Community: 0 stars → 0, issues → 0 (no stars for ratio), forks → 0 → 0
        assert score < 20
        assert details.get("stability_floor_applied") is not True

    def test_no_stability_floor_without_stars(self):
        """Stability floor requires stars >= 50."""
        repo = _make_repo(pushed_days_ago=500, stars=10, forks=0, open_issues=0)
        releases = _make_releases(1, latest_days_ago=400)

        score, details = _probe_maintenance_pulse(repo, None, releases)

        assert details.get("stability_floor_applied") is not True


class TestZeroOpenIssuesNeutral:
    """0 open issues should score 5/10 (neutral), not maximum."""

    def test_zero_issues_scores_5(self):
        repo = _make_repo(pushed_days_ago=10, stars=100, forks=5, open_issues=0)

        _, details = _probe_maintenance_pulse(repo, None, None)

        assert details["issue_pts"] == 5  # neutral, not maximum

    def test_low_ratio_scores_higher_than_zero_issues(self):
        """A responsive project (ratio < 0.05) scores 10 — higher than 0 issues."""
        repo = _make_repo(pushed_days_ago=10, stars=200, forks=10, open_issues=3)

        _, details = _probe_maintenance_pulse(repo, None, None)

        # ratio = 3/200 = 0.015 < 0.05 → 10 pts
        assert details["issue_pts"] == 10


class TestCommunityHealth:
    """Test individual community health signals."""

    @pytest.mark.parametrize(
        "stars,expected",
        [(0, 0), (5, 0), (10, 5), (50, 10), (100, 12), (1000, 15), (5000, 15)],
    )
    def test_star_tiers(self, stars, expected):
        repo = _make_repo(pushed_days_ago=10, stars=stars)
        _, details = _probe_maintenance_pulse(repo, None, None)
        assert details["star_pts"] == expected

    @pytest.mark.parametrize(
        "forks,expected",
        [(0, 0), (1, 1), (10, 3), (50, 5), (200, 5)],
    )
    def test_fork_tiers(self, forks, expected):
        repo = _make_repo(pushed_days_ago=10, forks=forks)
        _, details = _probe_maintenance_pulse(repo, None, None)
        assert details["fork_pts"] == expected


class TestReleaseDiscipline:
    """Test release scoring signals."""

    def test_three_releases_with_notes_and_recent(self):
        repo = _make_repo(pushed_days_ago=10)
        releases = _make_releases(3, latest_days_ago=30, with_notes=True)

        _, details = _probe_maintenance_pulse(repo, None, releases)

        # 3 releases = 15, recent ≤90d = +10, notes = +5 → 30 (capped)
        assert details["release_discipline"] == 30

    def test_one_old_release_no_notes(self):
        repo = _make_repo(pushed_days_ago=10)
        releases = _make_releases(1, latest_days_ago=200, with_notes=False)

        _, details = _probe_maintenance_pulse(repo, None, releases)

        # 1 release = 10, not recent = 0, no notes = 0 → 10
        assert details["release_discipline"] == 10

    def test_no_releases(self):
        repo = _make_repo(pushed_days_ago=10)

        _, details = _probe_maintenance_pulse(repo, None, None)

        assert details["release_discipline"] == 0


class TestVitality:
    """Test vitality signal details."""

    def test_very_recent_push(self):
        repo = _make_repo(pushed_days_ago=5, stars=0)
        commits = _make_commits(15, span_days=30)

        _, details = _probe_maintenance_pulse(repo, commits, None)

        # push ≤30d = 40, commits≥10 = min(40, 40+10) = 40
        assert details["vitality"] == 40

    def test_push_90_days_with_commits(self):
        repo = _make_repo(pushed_days_ago=60, stars=0)
        commits = _make_commits(8, span_days=45)

        _, details = _probe_maintenance_pulse(repo, commits, None)

        # push ≤90d = 30, commits≥5 = min(40, 30+5) = 35
        assert details["vitality"] == 35

    def test_no_push_data(self):
        repo = _make_repo(pushed_days_ago=None, stars=0)

        _, details = _probe_maintenance_pulse(repo, None, None)

        assert details["vitality"] == 0


class TestMaxScore:
    """Perfect project should hit 100."""

    def test_perfect_project(self):
        repo = _make_repo(pushed_days_ago=5, stars=2000, forks=100, open_issues=5)
        commits = _make_commits(25, span_days=60)
        releases = _make_releases(5, latest_days_ago=20, with_notes=True)

        score, details = _probe_maintenance_pulse(repo, commits, releases)

        assert score == 100
        assert details["vitality"] == 40
        assert details["release_discipline"] == 30
        assert details["community_health"] == 30
