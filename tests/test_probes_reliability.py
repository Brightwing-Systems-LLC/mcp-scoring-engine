"""Tests for reliability scoring from pre-computed metrics."""

from mcp_scoring_engine import ReliabilityData, compute_reliability_score
from mcp_scoring_engine.probes.reliability import _score_latency


class TestScoreLatency:
    """Test continuous latency scoring curve."""

    def test_at_100ms(self):
        assert _score_latency(100) == 100

    def test_below_100ms(self):
        assert _score_latency(50) == 100

    def test_at_200ms(self):
        assert _score_latency(200) == 90

    def test_at_500ms(self):
        assert _score_latency(500) == 70

    def test_at_1000ms(self):
        assert _score_latency(1000) == 50

    def test_at_2000ms(self):
        assert _score_latency(2000) == 25

    def test_at_5000ms(self):
        assert _score_latency(5000) == 10

    def test_above_5000ms(self):
        assert _score_latency(10000) == 10

    def test_boundary_smoothness(self):
        """199ms and 201ms should be close — no 20-point cliff."""
        score_199 = _score_latency(199)
        score_201 = _score_latency(201)
        assert abs(score_199 - score_201) <= 2

    def test_midpoint_interpolation(self):
        """150ms → midpoint between 100@100ms and 90@200ms → 95."""
        assert _score_latency(150) == 95

    def test_300ms_interpolation(self):
        """300ms → 1/3 between 90@200ms and 70@500ms → 83."""
        score = _score_latency(300)
        assert 82 <= score <= 84  # ~83


class TestComputeReliabilityScore:
    """Test the reliability score computation."""

    def test_uptime_and_latency_no_p95(self):
        """Without p95, uses 70/30 blend."""
        data = ReliabilityData(uptime_pct=99.0, latency_p50_ms=150)
        score = compute_reliability_score(data)
        # p50=150ms → 95, 99.0 * 0.7 + 95 * 0.3 = 69.3 + 28.5 = 97.8 → 97
        assert score == 97

    def test_full_blend_with_p95(self):
        """With p95, uses 60/25/15 blend."""
        data = ReliabilityData(
            uptime_pct=99.0, latency_p50_ms=150, latency_p95_ms=500, probe_count=20
        )
        score = compute_reliability_score(data)
        # p50=150→95, p95=500→70
        # 99*0.60 + 95*0.25 + 70*0.15 = 59.4 + 23.75 + 10.5 = 93.65 → 93
        assert score == 93

    def test_p95_tail_latency_penalty(self):
        """Server with good p50 but terrible p95 scores lower."""
        good_tail = ReliabilityData(
            uptime_pct=99.0, latency_p50_ms=100, latency_p95_ms=200, probe_count=20
        )
        bad_tail = ReliabilityData(
            uptime_pct=99.0, latency_p50_ms=100, latency_p95_ms=5000, probe_count=20
        )
        good_score = compute_reliability_score(good_tail)
        bad_score = compute_reliability_score(bad_tail)
        assert good_score > bad_score
        # good: 99*0.6 + 100*0.25 + 90*0.15 = 59.4 + 25 + 13.5 = 97.9 → 97
        # bad:  99*0.6 + 100*0.25 + 10*0.15 = 59.4 + 25 + 1.5 = 85.9 → 85
        assert good_score == 97
        assert bad_score == 85

    def test_latency_only_cli_mode(self):
        """CLI mode: latency only, probe_count=0."""
        data = ReliabilityData(latency_p50_ms=100)
        assert compute_reliability_score(data) == 100

    def test_latency_only_moderate(self):
        data = ReliabilityData(latency_p50_ms=300)
        score = compute_reliability_score(data)
        # 300ms → ~83 (continuous)
        assert 82 <= score <= 84

    def test_latency_only_slow(self):
        data = ReliabilityData(latency_p50_ms=700)
        score = compute_reliability_score(data)
        # 700ms → ~62 (continuous)
        assert 60 <= score <= 64

    def test_latency_only_very_slow(self):
        data = ReliabilityData(latency_p50_ms=1500)
        score = compute_reliability_score(data)
        # 1500ms → ~37 (continuous)
        assert 35 <= score <= 40

    def test_uptime_only(self):
        data = ReliabilityData(uptime_pct=85.0, probe_count=20)
        assert compute_reliability_score(data) == 85

    def test_no_data(self):
        data = ReliabilityData()
        assert compute_reliability_score(data) is None

    def test_none(self):
        assert compute_reliability_score(None) is None

    def test_perfect_scores(self):
        data = ReliabilityData(uptime_pct=100.0, latency_p50_ms=50)
        # 100 * 0.7 + 100 * 0.3 = 100
        assert compute_reliability_score(data) == 100

    def test_low_uptime_fast_latency(self):
        data = ReliabilityData(uptime_pct=50.0, latency_p50_ms=100)
        # 50 * 0.7 + 100 * 0.3 = 35 + 30 = 65
        assert compute_reliability_score(data) == 65


class TestMinimumProbeCount:
    """Test the data quality gate."""

    def test_insufficient_probes_returns_none(self):
        """5 probes → not enough data for reliability score."""
        data = ReliabilityData(
            uptime_pct=99.0, latency_p50_ms=150, probe_count=5
        )
        assert compute_reliability_score(data) is None

    def test_exactly_10_probes_returns_score(self):
        """10 probes → just enough data."""
        data = ReliabilityData(
            uptime_pct=99.0, latency_p50_ms=150, probe_count=10
        )
        assert compute_reliability_score(data) is not None

    def test_cli_mode_skips_gate(self):
        """CLI mode (probe_count=0) skips the data quality gate."""
        data = ReliabilityData(latency_p50_ms=150, probe_count=0)
        assert compute_reliability_score(data) is not None

    def test_1_probe_returns_none(self):
        data = ReliabilityData(
            uptime_pct=100.0, latency_p50_ms=50, probe_count=1
        )
        assert compute_reliability_score(data) is None

    def test_9_probes_returns_none(self):
        data = ReliabilityData(
            uptime_pct=100.0, latency_p50_ms=50, probe_count=9
        )
        assert compute_reliability_score(data) is None
