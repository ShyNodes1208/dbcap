"""Build JDBC↔TCP timelines from important events only."""

from __future__ import annotations

from typing import Optional

from dbcap.dual.models import DualAnalysisResult, DualSegment
from dbcap.jdbc.models import JdbcEvent, JdbcTcpCorrelation, TimelineEntry
from dbcap.models import AnalysisReport, TcpSession

_IMPORTANT_ANOMALY = {
    "DATA_RETRANSMISSION",
    "CONTROL_PLANE_RETRANSMISSION",
    "ACK_STALLED",
    "ZERO_WINDOW",
    "PACKET_TRUNCATED",
    "RST",
    "RST_AFTER_SYN",
    "RST_DURING_DATA",
    "RST_AFTER_FIN",
    "ACK_TO_RST",
}


def _rel(ts: Optional[float], jdbc_ts: Optional[float]) -> Optional[float]:
    if ts is None or jdbc_ts is None:
        return None
    return ts - jdbc_ts


def _anomaly_time(report: AnalysisReport, anomaly, session: Optional[TcpSession]) -> Optional[float]:
    if session is None:
        return None
    frames = set(anomaly.frames or [])
    if frames:
        for pkt in session.packets:
            if pkt.frame_number in frames:
                return pkt.timestamp
    # fall back: session mid
    if session.start_time is not None and session.end_time is not None:
        return (session.start_time + session.end_time) / 2
    return session.start_time


def _flow_identity(
    corr: JdbcTcpCorrelation,
    *,
    direction: Optional[str] = None,
    segment: Optional[DualSegment] = None,
) -> dict:
    """Stamp DualFlow identity onto TCP/Dual timeline rows (H-01)."""
    if segment is not None:
        return {
            "correlation_id": corr.dual_correlation_id,
            "direction": segment.direction,
            "app_stream": segment.app_stream,
            "db_stream": segment.db_stream,
        }
    return {
        "correlation_id": corr.dual_correlation_id,
        "direction": direction,
        "app_stream": corr.app_stream,
        "db_stream": corr.db_stream,
    }


def build_timeline_for_event(
    event: JdbcEvent,
    corr: JdbcTcpCorrelation,
    dual: DualAnalysisResult,
    *,
    window_seconds: float = 30.0,
) -> list[TimelineEntry]:
    entries: list[TimelineEntry] = []
    jdbc_ts = event.timestamp

    entries.append(
        TimelineEntry(
            event_id=event.event_id,
            timeline_timestamp=jdbc_ts,
            relative_seconds=0.0 if jdbc_ts is not None else None,
            source="JDBC",
            event_type=event.event_type,
            side="APP_LOG",
            frame=None,
            stream=None,
            seq=None,
            ack=None,
            tcp_len=None,
            description=(
                f"{event.event_type}: {event.caused_by_class or event.exception_class or ''} "
                f"{event.caused_by_message or event.message or ''}".strip()
            ),
            evidence_level=corr.evidence_level,
        )
    )

    if not corr.app_stream:
        return entries

    app_sess: Optional[TcpSession] = dual.app_sessions.get(corr.app_stream)
    db_sess: Optional[TcpSession] = dual.db_sessions.get(corr.db_stream) if corr.db_stream else None
    ident = _flow_identity(corr)

    # Handshake / FIN / RST markers from packets
    for side, sess, source in (
        ("APP", app_sess, "APP_PCAP"),
        ("DB", db_sess, "DB_PCAP"),
    ):
        if sess is None:
            continue
        for pkt in sess.packets:
            if jdbc_ts is not None and abs(pkt.timestamp - jdbc_ts) > window_seconds:
                # still allow SYN/FIN/RST anywhere on flow if within expanded 120s? keep window
                if not (pkt.syn or pkt.fin or pkt.rst):
                    continue
                if abs(pkt.timestamp - jdbc_ts) > max(window_seconds, 120):
                    continue
            label = None
            if pkt.syn and not pkt.ack_flag:
                label = "SYN"
            elif pkt.syn and pkt.ack_flag:
                label = "SYN_ACK"
            elif pkt.fin:
                label = "FIN"
            elif pkt.rst:
                label = "RST"
            if not label:
                continue
            if jdbc_ts is not None and abs(pkt.timestamp - jdbc_ts) > window_seconds and label not in (
                "SYN",
                "SYN_ACK",
            ):
                # keep FIN/RST only inside window; SYN always if on flow and within 120s handled above
                if abs(pkt.timestamp - jdbc_ts) > window_seconds:
                    continue
            entries.append(
                TimelineEntry(
                    event_id=event.event_id,
                    timeline_timestamp=pkt.timestamp,
                    relative_seconds=_rel(pkt.timestamp, jdbc_ts),
                    source=source,
                    event_type=label,
                    side=side,
                    frame=pkt.frame_number,
                    stream=sess.tcp_stream,
                    seq=pkt.tcp_seq,
                    ack=pkt.tcp_ack,
                    tcp_len=pkt.tcp_len,
                    description=f"{label} observed at {side} capture",
                    evidence_level="CONFIRMED",
                    **ident,
                )
            )

    # Anomalies from V1 reports
    for side, report, sess, source in (
        ("APP", dual.app_report, app_sess, "APP_PCAP"),
        ("DB", dual.db_report, db_sess, "DB_PCAP"),
    ):
        if report is None:
            continue
        stream = corr.app_stream if side == "APP" else corr.db_stream
        for a in report.anomalies:
            if a.tcp_stream != stream:
                continue
            if a.type not in _IMPORTANT_ANOMALY and not a.type.startswith("RST"):
                continue
            ts = _anomaly_time(report, a, sess)
            if jdbc_ts is not None and ts is not None and abs(ts - jdbc_ts) > window_seconds * 3:
                continue
            entries.append(
                TimelineEntry(
                    event_id=event.event_id,
                    timeline_timestamp=ts,
                    relative_seconds=_rel(ts, jdbc_ts),
                    source=source,
                    event_type=a.type,
                    side=side,
                    frame=a.frames[0] if a.frames else None,
                    stream=stream,
                    seq=None,
                    ack=None,
                    tcp_len=None,
                    description=a.summary,
                    evidence_level=getattr(a.evidence_level, "value", str(a.evidence_level)),
                    **ident,
                )
            )

    # Dual matched segments near window (important payloads)
    segs: list[DualSegment] = [
        s
        for s in dual.segments
        if s.correlation_id == corr.dual_correlation_id
        and s.match_status == "MATCHED_BOTH_SIDES"
    ]
    for s in segs:
        ts = s.app_timestamp
        if jdbc_ts is not None and ts is not None and abs(ts - jdbc_ts) > window_seconds:
            continue
        if ts is None:
            continue
        entries.append(
            TimelineEntry(
                event_id=event.event_id,
                timeline_timestamp=ts,
                relative_seconds=_rel(ts, jdbc_ts),
                source="DUAL",
                event_type="MATCHED_SEGMENT",
                side="BOTH",
                frame=s.app_frame,
                stream=s.app_stream,
                seq=s.seq,
                ack=s.ack,
                tcp_len=s.tcp_len,
                description=(
                    f"{s.direction} Seq={s.seq} Len={s.tcp_len} "
                    f"ExpectedACK={s.expected_ack} hash_match={s.payload_hash_match} "
                    f"app_frame={s.app_frame} db_frame={s.db_frame}"
                ),
                evidence_level=s.evidence_level,
                **_flow_identity(corr, segment=s),
            )
        )

    # Capture quality note once (capture-wide, not flow identity)
    for label, q in (("APP", dual.capture_quality_app), ("DB", dual.capture_quality_db)):
        if q.get("file_cut_short") or (q.get("truncated_packets") or 0) > 0:
            entries.append(
                TimelineEntry(
                    event_id=event.event_id,
                    timeline_timestamp=jdbc_ts,
                    relative_seconds=0.0 if jdbc_ts is not None else None,
                    source=f"{label}_PCAP",
                    event_type="CAPTURE_QUALITY",
                    side=label,
                    frame=None,
                    stream=None,
                    seq=None,
                    ack=None,
                    tcp_len=None,
                    description=(
                        f"{label} capture quality: credibility={q.get('credibility')} "
                        f"truncated={q.get('truncated_packets')} "
                        f"file_cut_short={q.get('file_cut_short')}"
                    ),
                    evidence_level="STRONG",
                )
            )

    entries.sort(
        key=lambda e: (
            e.timeline_timestamp is None,
            e.timeline_timestamp or 0.0,
            e.source,
            e.event_type,
        )
    )
    return entries
