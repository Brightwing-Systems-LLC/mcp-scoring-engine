"""Tests for reliability scoring from pre-computed metrics."""

from mcp_scoring_engine import ReliabilityData, compute_reliability_score


class TestComputeReliabilityScore:
    def test_uptime_and_latency(self):
        data = ReliabilityData(uptime_pct=99.0, latency_p50_ms=150)
        score = compute_reliability_score(data)
        # 99.0 * 0.7 + 100 * 0.3 = 69.3 + 30 = 99.3 → 99
        assert score == 99

    def test_latency_only_fast(self):
        data = ReliabilityData(latency_p50_ms=100)
        assert compute_reliability_score(data) == 100

    def test_latency_only_moderate(self):
        data = ReliabilityData(latency_p50_ms=300)
        assert compute_reliability_score(data) == 80

    def test_latency_only_slow(self):
        data = ReliabilityData(latency_p50_ms=700)
        assert compute_reliability_score(data) == 60

    def test_latency_only_very_slow(self):
        data = ReliabilityData(latency_p50_ms=1500)
        assert compute_reliability_score(data) == 40

    def test_latency_only_extremely_slow(self):
        data = ReliabilityData(latency_p50_ms=3000)
        assert compute_reliability_score(data) == 20

    def test_uptime_only(self):
        data = ReliabilityData(uptime_pct=85.0)
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
