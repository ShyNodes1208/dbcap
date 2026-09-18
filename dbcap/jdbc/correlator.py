"""Correlate JDBC events to Dual-PCAP flows (V2.5 candidate precision).

Ranking is primarily identity-based. TCP anomaly severity is not treated as
connection identity. Ping never participates.
"""

from __future__ import annotations

from typing import Optional

from dbcap.dual.models import DualAnalysisResult
from dbcap.jdbc.models import (
    EV_AMBIGUOUS,
    EV_NO_MATCH,
    EV_STRONG,
    FILTER_ELIGIBLE,
    FILTER_ENDPOINT,
    FILTER_TIME,
    STATUS_AMBIGUOUS,
    STATUS_MATCHED,
    STATUS_NO_MATCH,
    FlowCandidate,
    JdbcEvent,
    JdbcTcpCorrelation,
)
from dbcap.models import AnalysisReport, TcpSession

DEFAULT_LIFETIME_GRACE_SECONDS = 5.0


def _activity_near(
    session: Optional[TcpSession],
    t0: float,
    window: float,
) -> tuple[int, Optional[float], Optional[float]]:
    """Return (count_in_window, nearest_ts, distance_to_nearest)."""
    if session is None or not session.packets:
        return 0, None, None
    count = 0
    nearest = None
    best = None
    for pkt in session.packets:
        d = abs(pkt.timestamp - t0)
        if d <= window:
            count += 1
        if best is None or d < best:
            best = d
            nearest = pkt.timestamp
    return count, nearest, best


def _anomaly_types(
    report: Optional[AnalysisReport],
    stream: int,
) -> list[str]:
    if report is None:
        return []
    hits = []
    for a in report.anomalies:
        if a.tcp_stream != stream:
            continue
        hits.append(a.type)
    return hits


def _lifetime_covers(
    flow,
    t0: Optional[float],
    grace: float,
) -> bool:
    if t0 is None or flow.app_start is None or flow.app_end is None:
        return False
    return (flow.app_start - grace) <= t0 <= (flow.app_end + grace)


def score_candidate(
    *,
    event: JdbcEvent,
    flow,
    app_session: Optional[TcpSession],
    app_report: Optional[AnalysisReport],
    window: float,
    expect_host: Optional[str],
    expect_port: Optional[int],
    lifetime_grace: float = DEFAULT_LIFETIME_GRACE_SECONDS,
) -> FlowCandidate:
    """Score identity primarily; health is informational / tiny secondary."""
    id_reasons: list[str] = []
    health_reasons: list[str] = []
    identity = 0.0
    health = 0.0
    host = event.database_host or expect_host
    port = event.database_port or expect_port
    fk = flow.flow_key
    t0 = event.timestamp

    if host and fk.server_ip == host:
        identity += 30
        id_reasons.append("server_ip match")
    if port and fk.server_port == int(port):
        identity += 30
        id_reasons.append("server_port match")

    # Optional client identity from JDBC (rare)
    if event.connection_hint and ":" in (event.connection_hint or ""):
        # do not invent client IP from hint; reserved for future structured fields
        pass

    covers = _lifetime_covers(flow, t0, lifetime_grace)
    if covers:
        identity += 40
        id_reasons.append(
            f"app flow lifetime covers JDBC time (grace={lifetime_grace:g}s)"
        )
    elif t0 is not None and flow.app_start is not None and flow.app_end is not None:
        # Distance to nearest lifetime edge (not mid) for explanation only
        if t0 < flow.app_start:
            gap = flow.app_start - t0
        elif t0 > flow.app_end:
            gap = t0 - flow.app_end
        else:
            gap = 0.0
        identity += max(0.0, 10.0 - gap / 60.0)
        id_reasons.append(f"lifetime does not cover event (gap_to_edge={gap:.1f}s)")

    act_n, nearest, dist = _activity_near(app_session, t0 or 0.0, window) if t0 else (0, None, None)
    if act_n > 0 and dist is not None:
        # Differentiate near activity: up to 15 proximity + up to 5 packet density
        prox_pts = max(0.0, 15.0 * (1.0 - min(dist, window) / window))
        pkt_pts = min(5.0, act_n * 0.1)
        identity += prox_pts + pkt_pts
        id_reasons.append(
            f"TCP activity near event ({act_n} packets in ±{window:g}s, "
            f"nearest={dist:.3f}s)"
        )
    else:
        id_reasons.append("no TCP packets in correlation window")

    # Health evidence — NOT identity. Tiny values only for secondary display/tie.
    anoms = _anomaly_types(app_report, flow.app_stream)
    if anoms:
        # Cap health low so it cannot overturn identity ranking
        health = min(5.0, 1.0 + 0.25 * len(set(anoms)))
        health_reasons.append(
            f"TCP health signals (not identity): {','.join(sorted(set(anoms))[:4])}"
        )

    reasons = id_reasons + health_reasons
    # Total used for sorting: identity dominates; health only breaks exact ties
    total = identity + health * 0.01

    return FlowCandidate(
        dual_correlation_id=flow.correlation_id,
        app_stream=flow.app_stream,
        db_stream=flow.db_stream,
        client_ip=fk.client_ip,
        client_port=fk.client_port,
        server_ip=fk.server_ip,
        server_port=fk.server_port,
        app_start=flow.app_start,
        app_end=flow.app_end,
        score=total,
        identity_score=identity,
        health_score=health,
        filter_status=FILTER_ELIGIBLE,
        filter_reason="",
        distance_to_event=dist,
        reasons=reasons,
    )


def _filter_endpoint(flow, expect_host: Optional[str], expect_port: Optional[int]) -> Optional[str]:
    fk = flow.flow_key
    if expect_host and fk.server_ip != expect_host:
        return f"server_ip {fk.server_ip} != {expect_host}"
    if expect_port is not None and fk.server_port != int(expect_port):
        return f"server_port {fk.server_port} != {expect_port}"
    return None


def _filter_time(flow, t0: Optional[float], grace: float) -> Optional[str]:
    if t0 is None:
        return None  # cannot time-filter without event time
    if flow.app_start is None or flow.app_end is None:
        return "missing flow lifetime"
    if _lifetime_covers(flow, t0, grace):
        return None
    if t0 < flow.app_start - grace:
        return (
            f"event {t0:.3f} before flow start {flow.app_start:.3f} "
            f"(grace={grace:g}s)"
        )
    return (
        f"event {t0:.3f} after flow end {flow.app_end:.3f} "
        f"(grace={grace:g}s)"
    )


def correlate_event(
    event: JdbcEvent,
    dual: DualAnalysisResult,
    *,
    window_seconds: float = 10.0,
    lifetime_grace_seconds: float = DEFAULT_LIFETIME_GRACE_SECONDS,
) -> JdbcTcpCorrelation:
    expect_host = event.database_host or dual.server_ip
    expect_port = event.database_port or dual.db_port
    grace = lifetime_grace_seconds

    considered = 0
    n_endpoint = 0
    n_time = 0
    eligible: list[FlowCandidate] = []

    for flow in dual.correlated_flows:
        considered += 1
        ep = _filter_endpoint(flow, expect_host, expect_port)
        if ep:
            n_endpoint += 1
            continue
        tm = _filter_time(flow, event.timestamp, grace)
        if tm:
            n_time += 1
            continue

        app_sess = dual.app_sessions.get(flow.app_stream)
        cand = score_candidate(
            event=event,
            flow=flow,
            app_session=app_sess,
            app_report=dual.app_report,  # type: ignore[arg-type]
            window=window_seconds,
            expect_host=expect_host,
            expect_port=expect_port,
            lifetime_grace=grace,
        )
        eligible.append(cand)

    eligible.sort(
        key=lambda c: (
            -c.identity_score,
            # Prefer nearer activity when identity ties (identity-first tie-break)
            c.distance_to_event is None,
            c.distance_to_event if c.distance_to_event is not None else 1e18,
            -c.health_score,
            c.app_stream,
            c.db_stream,
        )
    )

    filter_note = (
        f"considered={considered} filtered_endpoint={n_endpoint} "
        f"filtered_time={n_time} eligible={len(eligible)} "
        f"(grace={grace:g}s). Candidate ranking is primarily identity-based; "
        f"TCP anomaly severity is not treated as connection identity."
    )

    if not eligible:
        return JdbcTcpCorrelation(
            event_id=event.event_id,
            correlation_status=STATUS_NO_MATCH,
            evidence_level=EV_NO_MATCH,
            dual_correlation_id=None,
            client_ip=None,
            client_port=None,
            server_ip=expect_host,
            server_port=expect_port,
            app_stream=None,
            db_stream=None,
            event_timestamp=event.timestamp,
            flow_start=None,
            flow_end=None,
            nearest_tcp_event=None,
            nearest_tcp_event_time=None,
            delta_seconds=None,
            candidate_count=0,
            reason="No ELIGIBLE DualFlow after endpoint/time filters. " + filter_note,
            candidates=[],
            flows_considered=considered,
            filtered_endpoint=n_endpoint,
            filtered_time=n_time,
            eligible_count=0,
            lifetime_grace_seconds=grace,
        )

    top = eligible[0]
    ambiguous = False
    if len(eligible) > 1:
        second = eligible[1]
        if top.identity_score < 70:
            ambiguous = True
        elif (
            second.identity_score >= top.identity_score - 8
            and second.identity_score >= 60
        ):
            ambiguous = True
        covers = [
            c
            for c in eligible
            if event.timestamp is not None
            and c.app_start is not None
            and c.app_end is not None
            and (c.app_start - grace) <= event.timestamp <= (c.app_end + grace)
            and c.identity_score >= 60
        ]
        if len(covers) > 1:
            ambiguous = True

    if ambiguous:
        status, evidence = STATUS_AMBIGUOUS, EV_AMBIGUOUS
        reason = (
            f"Multiple TCP flow candidates near JDBC time "
            f"(top={top.dual_correlation_id} identity={top.identity_score:.1f} "
            f"health={top.health_score:.1f}; eligible={len(eligible)}). "
            + "; ".join(top.reasons[:4])
            + " | "
            + filter_note
        )
        chosen = top
    else:
        status, evidence = STATUS_MATCHED, EV_STRONG
        reason = (
            f"Selected {top.dual_correlation_id} by identity "
            f"(identity={top.identity_score:.1f} health={top.health_score:.1f}). "
            f"JDBC log has no client source port — evidence capped at STRONG. "
            + "; ".join(top.reasons[:5])
            + " | "
            + filter_note
        )
        chosen = top

    app_sess = dual.app_sessions.get(chosen.app_stream)
    nearest_name = None
    nearest_ts = None
    delta = None
    if event.timestamp is not None and app_sess:
        best_d = None
        for pkt in app_sess.packets:
            d = abs(pkt.timestamp - event.timestamp)
            if best_d is None or d < best_d:
                best_d = d
                nearest_ts = pkt.timestamp
                nearest_name = f"packet frame={pkt.frame_number}"
        if nearest_ts is not None:
            delta = nearest_ts - event.timestamp

    return JdbcTcpCorrelation(
        event_id=event.event_id,
        correlation_status=status,
        evidence_level=evidence,
        dual_correlation_id=chosen.dual_correlation_id,
        client_ip=chosen.client_ip,
        client_port=chosen.client_port,
        server_ip=chosen.server_ip,
        server_port=chosen.server_port,
        app_stream=chosen.app_stream,
        db_stream=chosen.db_stream,
        event_timestamp=event.timestamp,
        flow_start=chosen.app_start,
        flow_end=chosen.app_end,
        nearest_tcp_event=nearest_name,
        nearest_tcp_event_time=nearest_ts,
        delta_seconds=delta,
        candidate_count=len(eligible),
        reason=reason,
        candidates=eligible[:10],
        flows_considered=considered,
        filtered_endpoint=n_endpoint,
        filtered_time=n_time,
        eligible_count=len(eligible),
        lifetime_grace_seconds=grace,
    )


def correlate_all(
    events: list[JdbcEvent],
    dual: DualAnalysisResult,
    *,
    window_seconds: float = 10.0,
    lifetime_grace_seconds: float = DEFAULT_LIFETIME_GRACE_SECONDS,
) -> list[JdbcTcpCorrelation]:
    return [
        correlate_event(
            e,
            dual,
            window_seconds=window_seconds,
            lifetime_grace_seconds=lifetime_grace_seconds,
        )
        for e in events
    ]
