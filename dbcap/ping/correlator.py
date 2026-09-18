"""Correlate ping samples to JDBC events (supporting evidence only)."""

from __future__ import annotations

from typing import Optional

from dbcap.jdbc.models import JdbcEvent
from dbcap.ping.models import (
    STATUS_ERROR,
    STATUS_REPLY,
    STATUS_TIMEOUT,
    STATUS_UNREACHABLE,
    PingAnalysisResult,
    PingCorrelation,
    PingEvent,
    PingTimelineMarker,
)


def correlate_ping_to_jdbc(
    events: list[PingEvent],
    jdbc_event: JdbcEvent,
    *,
    window_seconds: float = 30.0,
) -> PingCorrelation:
    t0 = jdbc_event.timestamp
    in_win: list[PingEvent] = []
    if t0 is not None:
        for e in events:
            if e.timestamp is None:
                continue
            if abs(e.timestamp - t0) <= window_seconds:
                in_win.append(e)

    replies = [e for e in in_win if e.status == STATUS_REPLY]
    timeouts = [e for e in in_win if e.status == STATUS_TIMEOUT]
    unreach = [e for e in in_win if e.status == STATUS_UNREACHABLE]
    errors = [e for e in in_win if e.status == STATUS_ERROR]
    rtts = [e.rtt_ms for e in replies if e.rtt_ms is not None]

    last_before = None
    first_after = None
    nearest_to_before = None
    nearest_to_after = None
    if t0 is not None:
        for e in events:
            if e.timestamp is None:
                continue
            if e.status == STATUS_REPLY:
                if e.timestamp <= t0:
                    if last_before is None or e.timestamp > last_before:
                        last_before = e.timestamp
                if e.timestamp >= t0:
                    if first_after is None or e.timestamp < first_after:
                        first_after = e.timestamp
            if e.status == STATUS_TIMEOUT:
                if e.timestamp <= t0:
                    if nearest_to_before is None or e.timestamp > nearest_to_before:
                        nearest_to_before = e.timestamp
                if e.timestamp >= t0:
                    if nearest_to_after is None or e.timestamp < nearest_to_after:
                        nearest_to_after = e.timestamp

    host = next((e.target_host for e in in_win if e.target_host), None)
    if host is None and events:
        host = next((e.target_host for e in events if e.target_host), None)

    if timeouts and replies:
        summary = (
            f"Around JDBC time, ICMP to {host or 'target'} shows mixed REPLY and TIMEOUT "
            f"({len(replies)} replies, {len(timeouts)} timeouts in ±{window_seconds}s). "
            "ICMP reachability degradation was observed near the JDBC event."
        )
    elif timeouts and not replies:
        summary = (
            f"Around JDBC time, ICMP samples were TIMEOUT/unreachable-dominant "
            f"({len(timeouts)} timeouts in ±{window_seconds}s)."
        )
    elif replies and not timeouts:
        summary = (
            f"ICMP echo replies were observed around the JDBC error time "
            f"({len(replies)} replies in ±{window_seconds}s"
            + (f", RTT {min(rtts):.3f}–{max(rtts):.3f} ms" if rtts else "")
            + ")."
        )
    elif not in_win:
        summary = "No ping samples found inside the configured window around the JDBC event."
    else:
        summary = f"Ping samples in window: {len(in_win)} (see counts)."

    return PingCorrelation(
        event_id=jdbc_event.event_id,
        jdbc_timestamp=t0,
        jdbc_timestamp_raw=jdbc_event.timestamp_raw,
        target_host=host,
        window_seconds=window_seconds,
        samples=len(in_win),
        replies=len(replies),
        timeouts=len(timeouts),
        unreachable=len(unreach),
        errors=len(errors),
        min_rtt_ms=min(rtts) if rtts else None,
        avg_rtt_ms=(sum(rtts) / len(rtts)) if rtts else None,
        max_rtt_ms=max(rtts) if rtts else None,
        last_reply_before=last_before,
        first_reply_after=first_after,
        nearest_timeout_before=nearest_to_before,
        nearest_timeout_after=nearest_to_after,
        summary=summary,
    )


def build_ping_timeline_markers(
    events: list[PingEvent],
    jdbc_ts: Optional[float],
    *,
    window_seconds: float = 30.0,
) -> list[PingTimelineMarker]:
    """Emit condensed markers (not every reply)."""
    markers: list[PingTimelineMarker] = []
    if jdbc_ts is None:
        return markers

    # Restrict to expanded window for markers
    scoped = [
        e
        for e in events
        if e.timestamp is not None and abs(e.timestamp - jdbc_ts) <= window_seconds
    ]
    scoped.sort(key=lambda e: e.timestamp or 0.0)

    # Timeout runs
    run_start = None
    run_count = 0
    last_to = None
    for e in scoped:
        if e.status == STATUS_TIMEOUT:
            if run_start is None:
                run_start = e.timestamp
            run_count += 1
            last_to = e.timestamp
        else:
            if run_start is not None and run_count > 0:
                markers.append(
                    PingTimelineMarker(
                        timestamp=run_start,
                        event_type="PING_TIMEOUT",
                        description=f"{run_count} consecutive ICMP timeout(s) starting",
                        target_host=e.target_host,
                    )
                )
                run_start = None
                run_count = 0
            if e.status == STATUS_REPLY and last_to is not None and e.timestamp is not None:
                if e.timestamp - last_to <= 5.0:
                    markers.append(
                        PingTimelineMarker(
                            timestamp=e.timestamp,
                            event_type="PING_RECOVERY",
                            description="ICMP replies resumed after timeout(s)",
                            target_host=e.target_host,
                        )
                    )
                    last_to = None
    if run_start is not None and run_count > 0:
        markers.append(
            PingTimelineMarker(
                timestamp=run_start,
                event_type="PING_TIMEOUT",
                description=f"{run_count} consecutive ICMP timeout(s) starting",
                target_host=scoped[0].target_host if scoped else None,
            )
        )

    # Stable reply note if replies dominate and few/no timeouts
    replies = [e for e in scoped if e.status == STATUS_REPLY]
    timeouts = [e for e in scoped if e.status == STATUS_TIMEOUT]
    if replies and len(timeouts) == 0:
        markers.append(
            PingTimelineMarker(
                timestamp=replies[0].timestamp,
                event_type="PING_REPLY_STABLE",
                description=f"{len(replies)} ICMP replies in window (no timeouts)",
                target_host=replies[0].target_host,
            )
        )
    elif replies and timeouts:
        # already have timeout/recovery; add one stable-after note if many replies after last timeout
        pass

    return markers


def analyze_ping_for_jdbc_events(
    ping_log: Optional[str],
    jdbc_events: list[JdbcEvent],
    *,
    window_seconds: float = 30.0,
) -> PingAnalysisResult:
    if not ping_log:
        return PingAnalysisResult(ping_log=None, provided=False)

    from dbcap.ping.parser import parse_ping_log

    events = parse_ping_log(ping_log)
    corrs = [
        correlate_ping_to_jdbc(events, je, window_seconds=window_seconds)
        for je in jdbc_events
    ]
    markers: list[PingTimelineMarker] = []
    for je, corr in zip(jdbc_events, corrs):
        markers.extend(
            build_ping_timeline_markers(
                events, je.timestamp, window_seconds=window_seconds
            )
        )
    # de-dup markers by (ts, type, desc)
    seen = set()
    uniq = []
    for m in markers:
        key = (m.timestamp, m.event_type, m.description)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(m)

    return PingAnalysisResult(
        ping_log=ping_log,
        events=events,
        correlations=corrs,
        timeline_markers=uniq,
        provided=True,
    )
