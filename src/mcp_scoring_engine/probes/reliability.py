"""Reliability scoring from pre-computed metrics.

Pure functions that accept ReliabilityData — no DB, no ORM.
The caller (Django or CLI) provides the pre-computed data.
"""

from __future__ import annotations

from ..types import ReliabilityData


def compute_reliability_score(data: ReliabilityData) -> int | None:
    """Compute reliability category score from pre-computed metrics.

    Uptime contributes 70%, latency 30%.
    If only latency available (CLI single-run), scores latency only.
    """
    if data is None:
        return None

    if data.uptime_pct is None and data.latency_p50_ms is None:
        return None

    # Latency scoring: <200ms=100, <500ms=80, <1000ms=60, <2000ms=40, else=20
    latency_score = None
    if data.latency_p50_ms is not None:
        p50 = data.latency_p50_ms
        if p50 < 200:
            latency_score = 100
        elif p50 < 500:
            latency_score = 80
        elif p50 < 1000:
            latency_score = 60
        elif p50 < 2000:
            latency_score = 40
        else:
            latency_score = 20

    if data.uptime_pct is not None and latency_score is not None:
        return int(data.uptime_pct * 0.7 + latency_score * 0.3)
    elif data.uptime_pct is not None:
        return int(data.uptime_pct)
    else:
        return latency_score
