"""Reliability scoring from pre-computed metrics.

Pure functions that accept ReliabilityData — no DB, no ORM.
The caller (Django or CLI) provides the pre-computed data.
"""

from __future__ import annotations

from ..types import ReliabilityData

MINIMUM_PROBE_COUNT = 10  # Need at least 10 probes for a reliability score


def _score_latency(ms: float) -> int:
    """Continuous latency scoring via linear interpolation between anchors.

    100ms → 100, 200ms → 90, 500ms → 70, 1000ms → 50, 2000ms → 25, 5000ms → 10.
    """
    if ms <= 100:
        return 100
    if ms >= 5000:
        return 10
    anchors = [(100, 100), (200, 90), (500, 70), (1000, 50), (2000, 25), (5000, 10)]
    for i in range(len(anchors) - 1):
        ms_lo, score_lo = anchors[i]
        ms_hi, score_hi = anchors[i + 1]
        if ms <= ms_hi:
            ratio = (ms - ms_lo) / (ms_hi - ms_lo)
            return int(score_lo + ratio * (score_hi - score_lo))
    return 10


def compute_reliability_score(data: ReliabilityData) -> int | None:
    """Compute reliability category score from pre-computed metrics.

    Requires at least MINIMUM_PROBE_COUNT probes for a score (data quality gate).
    Exception: CLI mode (probe_count=0, no uptime) skips the gate.

    Blend: uptime 75% + p50 latency 15% + p95 latency 10%.
    Uptime-dominant because latency is geography-dependent (single probe region)
    while uptime is geography-independent.
    Falls back to uptime 80% + p50 20% when p95 is unavailable.
    If only latency available (CLI single-run), scores latency only.
    """
    if data is None:
        return None

    if data.uptime_pct is None and data.latency_p50_ms is None:
        return None

    # Data quality gate: need enough probes for a meaningful reliability score.
    # Exception: CLI mode (probe_count=0, no uptime) skips the gate.
    if data.probe_count > 0 and data.probe_count < MINIMUM_PROBE_COUNT:
        return None

    p50_score = _score_latency(data.latency_p50_ms) if data.latency_p50_ms is not None else None
    p95_score = _score_latency(data.latency_p95_ms) if data.latency_p95_ms is not None else None

    if data.uptime_pct is not None and p50_score is not None:
        # Full blend: uptime 75% + p50 15% + p95 10%
        if p95_score is not None:
            return int(data.uptime_pct * 0.75 + p50_score * 0.15 + p95_score * 0.10)
        # No p95: uptime 80% + p50 20%
        return int(data.uptime_pct * 0.80 + p50_score * 0.20)
    elif data.uptime_pct is not None:
        return int(data.uptime_pct)
    else:
        # CLI mode: latency only
        return p50_score
