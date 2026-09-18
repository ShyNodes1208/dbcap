"""Orchestrate dual-PCAP analysis on top of frozen V1 analyzers."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from dbcap.analyzer import build_analysis_report
from dbcap.capture import load_pcap_file
from dbcap.dual.clock_alignment import estimate_clock_alignment
from dbcap.dual.flow_matcher import match_flows
from dbcap.dual.models import DualAnalysisResult
from dbcap.dual.segment_matcher import match_segments_for_flow
from dbcap.models import AnalysisReport, TcpSession, ThresholdConfig
from dbcap.session import group_into_sessions
from dbcap.thresholds import DEFAULT_THRESHOLDS


def _analyze_side(
    pcap_path: str,
    db_port: int,
    thresholds: ThresholdConfig,
    max_packets: Optional[int],
    server_ip: Optional[str],
) -> tuple[AnalysisReport, dict[int, TcpSession]]:
    display_filter = f"tcp.port == {db_port}"
    loaded = load_pcap_file(
        pcap_path,
        display_filter=display_filter,
        max_packets=max_packets,
    )
    sessions = group_into_sessions(loaded.packets, db_port)
    # Optional soft role check: warn via report metadata only
    report = build_analysis_report(
        sessions,
        thresholds,
        db_port,
        pcap_path,
        all_packets=loaded.packets,
        file_cut_short=loaded.file_cut_short,
        file_warning=loaded.file_warning,
    )
    if server_ip:
        mismatch = 0
        for s in sessions.values():
            if s.key.server_ip != server_ip:
                mismatch += 1
        if mismatch:
            report.metadata["dual_server_ip_mismatch_sessions"] = mismatch
    return report, sessions


def _quality_dict(report: AnalysisReport) -> dict:
    q = report.capture_quality
    return {
        "total_packets": q.total_packets,
        "truncated_packets": q.truncated_packets,
        "credibility": q.credibility,
        "file_cut_short": bool(getattr(q, "file_cut_short", False)),
        "tcp_health": report.summary.get("tcp_health", report.summary.get("overall")),
        "analysis_confidence": report.summary.get("analysis_confidence"),
    }


def analyze_dual_pcaps(
    app_pcap: str,
    db_pcap: str,
    db_port: int,
    *,
    server_ip: Optional[str] = None,
    thresholds: Optional[ThresholdConfig] = None,
    max_packets: Optional[int] = None,
) -> DualAnalysisResult:
    """
    App PCAP + Db PCAP → V1 analyze each → flow/segment correlation.
    """
    th = thresholds or DEFAULT_THRESHOLDS
    report_app, sessions_app = _analyze_side(app_pcap, db_port, th, max_packets, server_ip)
    report_db, sessions_db = _analyze_side(db_pcap, db_port, th, max_packets, server_ip)

    # First pass without clock hint
    flows, unmatched_app, unmatched_db = match_flows(sessions_app, sessions_db)

    all_segments = []
    for flow in flows:
        sa = sessions_app.get(flow.app_stream)
        sb = sessions_db.get(flow.db_stream)
        if sa is None or sb is None:
            continue
        all_segments.extend(match_segments_for_flow(flow, sa, sb))

    clock = estimate_clock_alignment(all_segments)

    # Optional second pass if we got a stable offset and had weak matches — skip for MVP
    # to keep behavior simple; offset is reported only.

    limitations = [
        "V2 Milestone 1: dual-PCAP correlation only; no JDBC/Ping parsers.",
        "Never match sessions by tcp.stream id across PCAPs.",
        "Missing segment on one side is an observation, not a device-level drop verdict.",
        "Observed timestamp delta ≠ network latency unless clock alignment is reliable.",
        "Port reuse disambiguation uses SYN ISN / time overlap; remaining cases may be SUSPECTED.",
        "V1 TCP Core modules are frozen and reused as single source of truth.",
    ]

    return DualAnalysisResult(
        app_pcap=str(Path(app_pcap)),
        db_pcap=str(Path(db_pcap)),
        server_ip=server_ip,
        db_port=db_port,
        capture_quality_app=_quality_dict(report_app),
        capture_quality_db=_quality_dict(report_db),
        correlated_flows=flows,
        unmatched_app_streams=unmatched_app,
        unmatched_db_streams=unmatched_db,
        segments=all_segments,
        clock=clock,
        limitations=limitations,
        app_report=report_app,
        db_report=report_db,
        app_sessions=sessions_app,
        db_sessions=sessions_db,
    )
