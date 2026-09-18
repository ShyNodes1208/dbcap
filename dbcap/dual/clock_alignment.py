"""Simple cross-capture clock alignment from matched segments."""

from __future__ import annotations

import statistics

from dbcap.dual.models import STATUS_BOTH, ClockAlignment, DualSegment


def estimate_clock_alignment(segments: list[DualSegment]) -> ClockAlignment:
    """
    Use matched-both segments with both timestamps.

    estimated_offset_sec ≈ median(app_ts - db_ts).
    This is Observed timestamp delta aggregation — NOT network latency.
    """
    deltas = [
        s.observed_delta
        for s in segments
        if s.match_status == STATUS_BOTH
        and s.observed_delta is not None
        and s.app_timestamp is not None
        and s.db_timestamp is not None
    ]
    if len(deltas) < 3:
        return ClockAlignment(
            status="INSUFFICIENT",
            sample_count=len(deltas),
            note="Need >=3 MATCHED_BOTH_SIDES segments with timestamps.",
        )

    med = statistics.median(deltas)
    mn, mx = min(deltas), max(deltas)
    spread = mx - mn
    # Unreliable if spread > 2s (or > 10x |median| when median large)
    unreliable = spread > 2.0 or (abs(med) > 0.05 and spread > max(1.0, 10 * abs(med)))
    if unreliable:
        return ClockAlignment(
            status="UNRELIABLE",
            estimated_offset_sec=None,
            median_delta=med,
            min_delta=mn,
            max_delta=mx,
            sample_count=len(deltas),
            note=(
                f"Observed timestamp deltas vary widely (spread={spread:.3f}s). "
                "Do not treat raw App-Db timestamp difference as network latency."
            ),
        )

    return ClockAlignment(
        status="OK",
        estimated_offset_sec=med,
        median_delta=med,
        min_delta=mn,
        max_delta=mx,
        sample_count=len(deltas),
        note=(
            f"Estimated App−Db clock offset ≈ {med:+.6f}s "
            f"(median of {len(deltas)} matched segments). "
            "This is Observed timestamp delta, not proven one-way delay."
        ),
    )
