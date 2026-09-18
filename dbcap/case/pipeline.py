"""V2.4 unified case pipeline — JDBC + Dual + Ping → evidence report."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from dbcap.case.models import (
    EV_CONFIRMED,
    EV_CORRELATED,
    EV_SUPPORTING,
    EV_UNKNOWN,
    CaseAnalysisResult,
    EvidenceItem,
    UnifiedTimelineRow,
)
from dbcap.dual import analyze_dual_pcaps, export_all_dual
from dbcap.jdbc.correlator import correlate_all
from dbcap.jdbc.models import JdbcTimelineResult
from dbcap.jdbc.parser import parse_jdbc_log
from dbcap.jdbc.report import export_all_jdbc
from dbcap.jdbc.timeline import build_timeline_for_event
from dbcap.models import ThresholdConfig
from dbcap.ping import analyze_ping_for_jdbc_events, export_all_ping
from dbcap.thresholds import DEFAULT_THRESHOLDS


def _pick_key_jdbc(jdbc: JdbcTimelineResult) -> Optional[str]:
    for e in jdbc.events:
        if e.event_type == "CONNECTION_RESET":
            # prefer latest CONNECTION_RESET if multiple
            pass
    resets = [e for e in jdbc.events if e.event_type == "CONNECTION_RESET"]
    if resets:
        return resets[-1].event_id
    return jdbc.events[-1].event_id if jdbc.events else None


def _aggregate_retrans_rows(rows: list[UnifiedTimelineRow]) -> list[UnifiedTimelineRow]:
    """Collapse repeated DATA_RETRANSMISSION of same seq/len into one summary row."""
    out: list[UnifiedTimelineRow] = []
    i = 0
    while i < len(rows):
        r = rows[i]
        if r.event_type != "DATA_RETRANSMISSION" or r.seq is None:
            out.append(r)
            i += 1
            continue
        j = i + 1
        count = 1
        t_end = r.timestamp
        while (
            j < len(rows)
            and rows[j].event_type == "DATA_RETRANSMISSION"
            and rows[j].seq == r.seq
            and rows[j].tcp_len == r.tcp_len
            and rows[j].correlation_id == r.correlation_id
            and rows[j].source == r.source
        ):
            count += 1
            t_end = rows[j].timestamp or t_end
            j += 1
        if count == 1:
            out.append(r)
        else:
            out.append(
                UnifiedTimelineRow(
                    case_id=r.case_id,
                    timestamp=r.timestamp,
                    relative_to_jdbc_seconds=r.relative_to_jdbc_seconds,
                    source=r.source,
                    event_type="DATA_RETRANSMISSION",
                    correlation_id=r.correlation_id,
                    app_stream=r.app_stream,
                    db_stream=r.db_stream,
                    frame=r.frame,
                    direction=r.direction,
                    seq=r.seq,
                    ack=r.ack,
                    tcp_len=r.tcp_len,
                    description=(
                        f"Segment Seq={r.seq} Len={r.tcp_len}: "
                        f"retransmitted {count} times (aggregated)"
                    ),
                    evidence_class=r.evidence_class,
                    confidence=r.confidence,
                )
            )
        i = j
    return out


def _build_unified_timeline(
    case_id: str,
    jdbc: JdbcTimelineResult,
    ping,
    key_event_id: Optional[str],
) -> list[UnifiedTimelineRow]:
    rows: list[UnifiedTimelineRow] = []
    key_ts = None
    if key_event_id:
        for e in jdbc.events:
            if e.event_id == key_event_id:
                key_ts = e.timestamp
                break

    for t in jdbc.timeline:
        if key_event_id and t.event_id != key_event_id:
            continue
        # Skip noisy ordinary packets — timeline builder already filters
        ev_class = EV_CORRELATED
        conf = t.evidence_level
        if t.source == "JDBC":
            ev_class = EV_CONFIRMED
            conf = "CONFIRMED"
        elif t.event_type == "CAPTURE_QUALITY":
            ev_class = EV_CONFIRMED
        elif t.event_type == "MATCHED_SEGMENT":
            ev_class = EV_CORRELATED
        # Prefer explicit DualFlow identity stamped by timeline builder (H-01).
        app_stream = t.app_stream
        db_stream = t.db_stream
        if app_stream is None and t.side in ("APP", "BOTH") and t.stream is not None:
            app_stream = t.stream
        if db_stream is None and t.side == "DB" and t.stream is not None:
            db_stream = t.stream
        rows.append(
            UnifiedTimelineRow(
                case_id=case_id,
                timestamp=t.timeline_timestamp,
                relative_to_jdbc_seconds=t.relative_seconds,
                source=t.source,
                event_type=t.event_type,
                correlation_id=t.correlation_id,
                app_stream=app_stream,
                db_stream=db_stream,
                frame=t.frame,
                direction=t.direction,
                seq=t.seq,
                ack=t.ack,
                tcp_len=t.tcp_len,
                description=t.description,
                evidence_class=ev_class,
                confidence=conf,
            )
        )

    if ping.provided and key_ts is not None:
        for m in ping.timeline_markers:
            rel = None if m.timestamp is None else m.timestamp - key_ts
            rows.append(
                UnifiedTimelineRow(
                    case_id=case_id,
                    timestamp=m.timestamp,
                    relative_to_jdbc_seconds=rel,
                    source="PING",
                    event_type=m.event_type,
                    correlation_id=None,
                    app_stream=None,
                    db_stream=None,
                    frame=None,
                    direction=None,
                    seq=None,
                    ack=None,
                    tcp_len=None,
                    description=m.description,
                    evidence_class=EV_SUPPORTING,
                    confidence="SUPPORTING",
                )
            )

    rows.sort(
        key=lambda r: (
            r.timestamp is None,
            r.timestamp or 0.0,
            r.source,
            r.event_type,
        )
    )
    return _aggregate_retrans_rows(rows)


def _classify_evidence(
    jdbc: JdbcTimelineResult,
    dual,
    ping,
    key_event_id: Optional[str],
) -> tuple[list[EvidenceItem], list[EvidenceItem], list[EvidenceItem], list[EvidenceItem]]:
    confirmed: list[EvidenceItem] = []
    correlated: list[EvidenceItem] = []
    supporting: list[EvidenceItem] = []
    unknown: list[EvidenceItem] = []

    key = next((e for e in jdbc.events if e.event_id == key_event_id), None)
    corr = next((c for c in jdbc.correlations if c.event_id == key_event_id), None)

    if key:
        confirmed.append(
            EvidenceItem(
                EV_CONFIRMED,
                f"JDBC log recorded {key.event_type} at {key.timestamp_raw} "
                f"({key.caused_by_class or key.exception_class}: "
                f"{key.caused_by_message or key.message}). "
                f"Source lines {key.start_line}-{key.end_line}.",
                "CONFIRMED",
            )
        )

    # Capture quality
    qa = dual.capture_quality_app
    qb = dual.capture_quality_db
    confirmed.append(
        EvidenceItem(
            EV_CONFIRMED,
            f"App-side capture quality: credibility={qa.get('credibility')}, "
            f"file_cut_short={qa.get('file_cut_short')}, "
            f"truncated={qa.get('truncated_packets')}.",
            "CONFIRMED",
        )
    )
    confirmed.append(
        EvidenceItem(
            EV_CONFIRMED,
            f"DB-side capture quality: credibility={qb.get('credibility')}, "
            f"file_cut_short={qb.get('file_cut_short')}, "
            f"truncated={qb.get('truncated_packets')}.",
            "CONFIRMED",
        )
    )

    if corr:
        if corr.correlation_status == "AMBIGUOUS":
            unknown.append(
                EvidenceItem(
                    EV_UNKNOWN,
                    "JDBC log has no client source port; multiple DualFlows match "
                    f"server host/port near the event (candidates={corr.candidate_count}). "
                    "The JDBC error cannot be uniquely bound to a single TCP connection.",
                )
            )
            correlated.append(
                EvidenceItem(
                    EV_CORRELATED,
                    f"Top-scoring DualFlow candidate is {corr.dual_correlation_id} "
                    f"(app_stream={corr.app_stream}, db_stream={corr.db_stream}, "
                    f"{corr.client_ip}:{corr.client_port} ↔ "
                    f"{corr.server_ip}:{corr.server_port}). "
                    "This is a ranked suggestion, not a confirmed identity.",
                    corr.evidence_level,
                )
            )
            # near-tie candidates
            if corr.candidates:
                top = corr.candidates[0].score
                near = [c for c in corr.candidates[1:5] if c.score >= top - 10]
                for c in near:
                    correlated.append(
                        EvidenceItem(
                            EV_CORRELATED,
                            f"Near-tie candidate {c.dual_correlation_id}: "
                            f"app_stream={c.app_stream}, db_stream={c.db_stream}, "
                            f"{c.client_ip}:{c.client_port}, score={c.score:.1f}. "
                            "TCP evidence on this flow is candidate-scoped.",
                            "AMBIGUOUS",
                        )
                    )
        elif corr.dual_correlation_id:
            confirmed.append(
                EvidenceItem(
                    EV_CONFIRMED,
                    f"Selected DualFlow {corr.dual_correlation_id}: "
                    f"app_stream={corr.app_stream}, db_stream={corr.db_stream}.",
                    corr.evidence_level,
                )
            )

        # Dual matched segments near JDBC on timeline
        for t in jdbc.timeline:
            if key_event_id and t.event_id != key_event_id:
                continue
            if t.event_type == "MATCHED_SEGMENT" and t.relative_seconds is not None:
                correlated.append(
                    EvidenceItem(
                        EV_CORRELATED,
                        f"{t.description} (relative_to_jdbc={t.relative_seconds:+.3f}s). "
                        "Temporally correlated; not proven causal. "
                        + (
                            "Belongs to an AMBIGUOUS candidate flow."
                            if corr.correlation_status == "AMBIGUOUS"
                            else ""
                        ),
                        t.evidence_level,
                    )
                )
            if t.event_type in ("ACK_STALLED", "DATA_RETRANSMISSION", "RST", "FIN"):
                correlated.append(
                    EvidenceItem(
                        EV_CORRELATED,
                        f"TCP {t.event_type} on {t.side}: {t.description} "
                        f"(relative_to_jdbc="
                        f"{t.relative_seconds:+.3f}s)."
                        if t.relative_seconds is not None
                        else f"TCP {t.event_type}: {t.description}",
                        t.evidence_level,
                    )
                )

    # Ping supporting
    if not ping.provided:
        unknown.append(
            EvidenceItem(EV_UNKNOWN, "Ping evidence was NOT PROVIDED for this case.")
        )
    else:
        pc = next((c for c in ping.correlations if c.event_id == key_event_id), None)
        if pc:
            supporting.append(
                EvidenceItem(EV_SUPPORTING, pc.summary, "SUPPORTING")
            )
            supporting.append(
                EvidenceItem(EV_SUPPORTING, pc.caution, "SUPPORTING")
            )
            confirmed.append(
                EvidenceItem(
                    EV_CONFIRMED,
                    f"Ping window stats for {pc.event_id}: samples={pc.samples}, "
                    f"replies={pc.replies}, timeouts={pc.timeouts}, "
                    f"unreachable={pc.unreachable}, target={pc.target_host}.",
                    "CONFIRMED",
                )
            )

    unknown.append(
        EvidenceItem(
            EV_UNKNOWN,
            "Cannot determine a specific network device (firewall/switch/NIC) drop "
            "from PCAP + JDBC + Ping alone.",
        )
    )
    unknown.append(
        EvidenceItem(
            EV_UNKNOWN,
            "Cannot treat ICMP reply presence as proof that the TCP session was healthy.",
        )
    )
    unknown.append(
        EvidenceItem(
            EV_UNKNOWN,
            "Application-host / capture-host / ping-host clocks are correlated by "
            "wall time only; absolute synchronization is not proven.",
        )
    )

    # Deduplicate correlated MATCHED_SEGMENT spam — keep first 12 correlated
    if len(correlated) > 40:
        correlated = correlated[:40]

    return confirmed, correlated, supporting, unknown


def analyze_case(
    jdbc_log: str,
    app_pcap: str,
    db_pcap: str,
    db_port: int,
    *,
    server_ip: Optional[str] = None,
    ping_log: Optional[str] = None,
    case_id: str = "case",
    jdbc_window_seconds: float = 10.0,
    timeline_window_seconds: float = 30.0,
    ping_window_seconds: float = 30.0,
    lifetime_grace_seconds: float = 5.0,
    thresholds: Optional[ThresholdConfig] = None,
    max_packets: Optional[int] = None,
) -> CaseAnalysisResult:
    """
    Full case analysis. Ping never feeds JDBC flow ranking.
    """
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
    correlations = correlate_all(
        events,
        dual,
        window_seconds=jdbc_window_seconds,
        lifetime_grace_seconds=lifetime_grace_seconds,
    )
    timeline = []
    for ev, corr in zip(events, correlations):
        timeline.extend(
            build_timeline_for_event(
                ev, corr, dual, window_seconds=timeline_window_seconds
            )
        )
        if corr.correlation_status == "AMBIGUOUS" and corr.candidates:
            top_id = corr.candidates[0].identity_score
            extras = [
                c
                for c in corr.candidates[1:4]
                if c.identity_score >= top_id - 10
                and c.dual_correlation_id != corr.dual_correlation_id
            ]
            from dbcap.jdbc.models import JdbcTcpCorrelation as _JTC

            for cand in extras:
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
                for row in build_timeline_for_event(
                    ev, faux, dual, window_seconds=timeline_window_seconds
                ):
                    if row.source == "JDBC":
                        continue
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

    jdbc = JdbcTimelineResult(
        jdbc_log=str(Path(jdbc_log)),
        app_pcap=str(Path(app_pcap)),
        db_pcap=str(Path(db_pcap)),
        server_ip=server_ip,
        db_port=db_port,
        window_seconds=jdbc_window_seconds,
        events=events,
        correlations=correlations,
        timeline=timeline,
        clock_status=dual.clock.status,
        clock_note=dual.clock.note,
        limitations=[
            "Unified case: Ping is supporting evidence only and does not alter JDBC ranking.",
            "V2.5: Candidate ranking is primarily identity-based; TCP anomaly severity is not identity.",
            "V2.1 Dual matchers frozen; V1 TCP Core frozen.",
        ],
        lifetime_grace_seconds=lifetime_grace_seconds,
    )

    ping = analyze_ping_for_jdbc_events(
        ping_log, events, window_seconds=ping_window_seconds
    )

    key_id = _pick_key_jdbc(jdbc)
    unified = _build_unified_timeline(case_id, jdbc, ping, key_id)
    confirmed, correlated, supporting, unknown = _classify_evidence(
        jdbc, dual, ping, key_id
    )

    return CaseAnalysisResult(
        case_id=case_id,
        jdbc=jdbc,
        dual=dual,
        ping=ping,
        unified_timeline=unified,
        confirmed=confirmed,
        correlated=correlated,
        supporting=supporting,
        unknown=unknown,
        key_jdbc_event_id=key_id,
    )
