"""Orchestrate JDBC timeline analysis on top of V2.1 dual correlation."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from dbcap.dual import analyze_dual_pcaps, export_all_dual
from dbcap.jdbc.correlator import correlate_all
from dbcap.jdbc.models import JdbcTimelineResult
from dbcap.jdbc.parser import parse_jdbc_log
from dbcap.jdbc.report import export_all_jdbc
from dbcap.jdbc.timeline import build_timeline_for_event
from dbcap.models import ThresholdConfig
from dbcap.thresholds import DEFAULT_THRESHOLDS


def analyze_jdbc_timeline(
    jdbc_log: str,
    app_pcap: str,
    db_pcap: str,
    db_port: int,
    *,
    server_ip: Optional[str] = None,
    window_seconds: float = 10.0,
    timeline_window_seconds: float = 30.0,
    lifetime_grace_seconds: float = 5.0,
    thresholds: Optional[ThresholdConfig] = None,
    max_packets: Optional[int] = None,
    also_export_dual: Optional[str] = None,
) -> JdbcTimelineResult:
    th = thresholds or DEFAULT_THRESHOLDS
    events = parse_jdbc_log(jdbc_log, default_host=server_ip, default_port=db_port)
    dual = analyze_dual_pcaps(
        app_pcap,
        db_pcap,
        db_port,
        server_ip=server_ip,
        thresholds=th,
        max_packets=max_packets,
    )
    if also_export_dual:
        export_all_dual(dual, also_export_dual)

    correlations = correlate_all(
        events,
        dual,
        window_seconds=window_seconds,
        lifetime_grace_seconds=lifetime_grace_seconds,
    )
    timeline = []
    for ev, corr in zip(events, correlations):
        # Primary (top) flow timeline
        timeline.extend(
            build_timeline_for_event(
                ev, corr, dual, window_seconds=timeline_window_seconds
            )
        )
        # When AMBIGUOUS, also include near-tie candidates so Dual evidence
        # on secondary ranked flows is not dropped solely because another
        # pool connection had slightly more packets in the window.
        if corr.correlation_status == "AMBIGUOUS" and corr.candidates:
            top_id = corr.candidates[0].identity_score
            extras = [
                c
                for c in corr.candidates[1:4]
                if c.identity_score >= top_id - 10
                and c.dual_correlation_id != corr.dual_correlation_id
            ]
            for cand in extras:
                from dbcap.jdbc.models import JdbcTcpCorrelation as _JTC

                faux = _JTC(
                    event_id=ev.event_id,
                    correlation_status=corr.correlation_status,
                    evidence_level=corr.evidence_level,
                    dual_correlation_id=cand.dual_correlation_id,
                    client_ip=cand.client_ip,
                    client_port=cand.client_port,
                    server_ip=cand.server_ip,
                    server_port=cand.server_port,
                    app_stream=cand.app_stream,
                    db_stream=cand.db_stream,
                    event_timestamp=ev.timestamp,
                    flow_start=cand.app_start,
                    flow_end=cand.app_end,
                    nearest_tcp_event=None,
                    nearest_tcp_event_time=None,
                    delta_seconds=None,
                    candidate_count=corr.candidate_count,
                    reason=f"AMBIGUOUS near-tie candidate {cand.dual_correlation_id}",
                    candidates=[],
                )
                extra_tl = build_timeline_for_event(
                    ev, faux, dual, window_seconds=timeline_window_seconds
                )
                for row in extra_tl:
                    if row.source == "JDBC":
                        continue  # already have one JDBC marker
                    row.description = (
                        f"[candidate {cand.dual_correlation_id}] " + row.description
                    )
                    timeline.append(row)

    timeline.sort(
        key=lambda e: (
            e.event_id,
            e.timeline_timestamp is None,
            e.timeline_timestamp or 0.0,
            e.source,
            e.event_type,
        )
    )

    limitations = [
        "V2.2+ JDBC timeline; V2.5 candidate filtering is identity-based.",
        "JDBC timestamps use application-host wall clock (second precision).",
        "Correlation uses app-side capture time; clocks may differ.",
        "Without JDBC client source port, evidence is capped at STRONG (never forced CONFIRMED).",
        "Temporal correlation ≠ causation.",
        "TCP anomaly severity is not treated as connection identity.",
        "V2.1 Dual-PCAP matchers remain frozen.",
    ]

    return JdbcTimelineResult(
        jdbc_log=str(Path(jdbc_log)),
        app_pcap=str(Path(app_pcap)),
        db_pcap=str(Path(db_pcap)),
        server_ip=server_ip,
        db_port=db_port,
        window_seconds=window_seconds,
        events=events,
        correlations=correlations,
        timeline=timeline,
        clock_status=dual.clock.status,
        clock_note=dual.clock.note,
        limitations=limitations,
        lifetime_grace_seconds=lifetime_grace_seconds,
    )
