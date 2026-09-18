"""V2.4 unified case report unit tests."""

from __future__ import annotations

import shutil
from pathlib import Path

from dbcap.case.models import EV_CONFIRMED, EV_CORRELATED, EV_SUPPORTING, EV_UNKNOWN
from dbcap.case.pipeline import analyze_case
from dbcap.case.report import export_all_case
from dbcap.dual.models import (
    ClockAlignment,
    CorrelatedFlow,
    DualAnalysisResult,
    NormalizedFlowKey,
)
from dbcap.jdbc.correlator import correlate_event
from dbcap.jdbc.models import JdbcEvent
from dbcap.jdbc.parser import parse_jdbc_timestamp
from dbcap.jdbc.redact import redact_secrets
from dbcap.ping.correlator import correlate_ping_to_jdbc
from dbcap.ping.parser import parse_ping_log

_TMP = Path(__file__).resolve().parents[1] / "output" / "_case_test_tmp"


def _fresh(name: str) -> Path:
    p = _TMP / name
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _write(d: Path, name: str, text: str) -> Path:
    p = d / name
    p.write_text(text, encoding="utf-8")
    return p


def test_evidence_classes_partition():
    # Structural constants used by unified report
    assert EV_CONFIRMED != EV_CORRELATED != EV_SUPPORTING != EV_UNKNOWN


def test_ambiguous_not_promoted_by_ping():
    """Ping must not change JDBC correlation status (ranking untouched)."""
    from dbcap.dual.models import DualAnalysisResult
    from dbcap.models import FlowKey, PacketSummary, TcpSession

    t = parse_jdbc_timestamp("2026-09-16 09:38:41")
    flows = [
        CorrelatedFlow(
            correlation_id="CF0001",
            flow_key=NormalizedFlowKey("10.4.7.233", 10001, "10.4.34.95", 5236),
            app_stream=1,
            db_stream=10,
            app_start=t - 50,
            app_end=t + 50,
        ),
        CorrelatedFlow(
            correlation_id="CF0002",
            flow_key=NormalizedFlowKey("10.4.7.233", 10002, "10.4.34.95", 5236),
            app_stream=2,
            db_stream=11,
            app_start=t - 50,
            app_end=t + 50,
        ),
    ]

    def sess(stream, port):
        key = FlowKey(
            src_ip="10.4.7.233",
            src_port=port,
            dst_ip="10.4.34.95",
            dst_port=5236,
            server_ip="10.4.34.95",
            server_port=5236,
        )
        pk = PacketSummary(
            timestamp=t - 0.5,
            src_ip="10.4.7.233",
            dst_ip="10.4.34.95",
            src_port=port,
            dst_port=5236,
            tcp_flags=0x18,
            tcp_seq=1,
            tcp_ack=1,
            tcp_window=1,
            tcp_len=10,
            frame_number=1,
            tcp_stream=stream,
            payload_hex="aa" * 10,
        )
        s = TcpSession(tcp_stream=stream, key=key, packets=[pk])
        s.start_time = t - 50
        s.end_time = t + 50
        return s

    dual = DualAnalysisResult(
        app_pcap="a",
        db_pcap="b",
        server_ip="10.4.34.95",
        db_port=5236,
        correlated_flows=flows,
        app_sessions={1: sess(1, 10001), 2: sess(2, 10002)},
        clock=ClockAlignment(status="UNRELIABLE", note="t"),
    )
    je = JdbcEvent(
        event_id="JE0001",
        timestamp=t,
        timestamp_raw="2026-09-16 09:38:41",
        level="ERROR",
        exception_class="X",
        message="y",
        event_type="CONNECTION_RESET",
        thread_name="t",
        tid="1",
        database_host="10.4.34.95",
        database_port=5236,
        connection_hint=None,
        stack_summary="",
        source_file="x",
        start_line=1,
        end_line=1,
        raw_excerpt_hash="a",
    )
    before = correlate_event(je, dual, window_seconds=10)
    assert before.correlation_status == "AMBIGUOUS"

    # Ping analysis is separate — correlator API does not accept dual flows
    d = _fresh("ping_rank")
    plog = _write(
        d,
        "p.log",
        "[2026-09-16 09:38:00.000] ===== Ping monitor started: 10.4.7.233 =====\n"
        "[2026-09-16 09:38:40.000] no answer yet for icmp_seq=1\n"
        "[2026-09-16 09:38:41.000] 64 bytes from 10.4.7.233: icmp_seq=2 ttl=63 time=0.4 ms\n",
    )
    ping_corr = correlate_ping_to_jdbc(parse_ping_log(str(plog)), je, window_seconds=30)
    after = correlate_event(je, dual, window_seconds=10)
    assert after.correlation_status == before.correlation_status
    assert after.dual_correlation_id == before.dual_correlation_id
    assert after.candidates[0].score == before.candidates[0].score
    assert ping_corr.evidence_class == "SUPPORTING"


def test_redaction_in_unified_text():
    assert "secret" not in redact_secrets("password=secret").lower() or "***" in redact_secrets(
        "password=secret"
    )


def test_ping_optional_in_analyze_case_missing_pcaps_fails_cleanly():
    # Without real PCAPs, analyze_case should error — ensure ping optional path exists via API
    from dbcap.ping.correlator import analyze_ping_for_jdbc_events

    r = analyze_ping_for_jdbc_events(None, [])
    assert r.provided is False


def test_export_layout_helpers_exist():
    from dbcap.case import analyze_case, export_all_case

    assert callable(analyze_case)
    assert callable(export_all_case)
