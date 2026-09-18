"""V2.7 offline HTML report tests."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from dbcap.case.html_report import export_case_html
from dbcap.case.models import (
    EV_CONFIRMED,
    EV_CORRELATED,
    EV_SUPPORTING,
    EV_UNKNOWN,
    CaseAnalysisResult,
    EvidenceItem,
    UnifiedTimelineRow,
)
from dbcap.case.report import export_all_case
from dbcap.dual.models import ClockAlignment, DualAnalysisResult
from dbcap.jdbc.models import (
    JdbcEvent,
    JdbcTcpCorrelation,
    JdbcTimelineResult,
    FlowCandidate,
)
from dbcap.jdbc.redact import redact_secrets
from dbcap.ping.models import PingAnalysisResult


_TMP = Path(__file__).resolve().parents[1] / "output" / "_html_v27_tmp"


def _fresh(name: str) -> Path:
    p = _TMP / name
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _minimal_result(*, with_secret: bool = False, inject_script: bool = False) -> CaseAnalysisResult:
    msg = "Connection reset"
    if with_secret:
        msg = "password=sekrit access_token=tok123 Authorization: Bearer BEARERVAL"
    if inject_script:
        msg = "<script>alert(1)</script> Connection reset"

    ev = JdbcEvent(
        event_id="JE0001",
        timestamp=100.0,
        timestamp_raw="2026-09-16 09:38:41",
        level="ERROR",
        exception_class="java.net.SocketException",
        message=redact_secrets(msg),
        event_type="CONNECTION_RESET",
        thread_name="pool",
        tid="1",
        database_host="10.0.0.1",
        database_port=5236,
        connection_hint="conn-1",
        stack_summary=redact_secrets(msg),
        source_file="x.log",
        start_line=1,
        end_line=5,
        raw_excerpt_hash="abc",
        caused_by_message=redact_secrets(msg),
        occurrence_count=1,
        group_id="JG0001",
    )
    cand = FlowCandidate(
        dual_correlation_id="CF0001",
        app_stream=26,
        db_stream=20,
        client_ip="10.0.0.2",
        client_port=1234,
        server_ip="10.0.0.1",
        server_port=5236,
        app_start=90.0,
        app_end=110.0,
        score=100.0,
        identity_score=100.0,
        health_score=1.0,
        reasons=["server_ip match", "server_port match"],
    )
    corr = JdbcTcpCorrelation(
        event_id="JE0001",
        correlation_status="AMBIGUOUS",
        evidence_level="AMBIGUOUS",
        dual_correlation_id="CF0001",
        client_ip="10.0.0.2",
        client_port=1234,
        server_ip="10.0.0.1",
        server_port=5236,
        app_stream=26,
        db_stream=20,
        event_timestamp=100.0,
        flow_start=90.0,
        flow_end=110.0,
        nearest_tcp_event=None,
        nearest_tcp_event_time=None,
        delta_seconds=None,
        candidate_count=2,
        reason="ambiguous test",
        candidates=[
            cand,
            FlowCandidate(
                dual_correlation_id="CF0002",
                app_stream=44,
                db_stream=38,
                client_ip="10.0.0.2",
                client_port=5678,
                server_ip="10.0.0.1",
                server_port=5236,
                app_start=90.0,
                app_end=110.0,
                score=98.0,
                identity_score=98.0,
                health_score=2.0,
                reasons=["server_ip match"],
            ),
        ],
        flows_considered=10,
        filtered_endpoint=2,
        filtered_time=3,
        eligible_count=2,
    )
    jdbc = JdbcTimelineResult(
        jdbc_log="x.log",
        app_pcap="a.pcap",
        db_pcap="b.pcap",
        server_ip="10.0.0.1",
        db_port=5236,
        window_seconds=10,
        events=[ev],
        correlations=[corr],
        limitations=["test limitation"],
    )
    dual = DualAnalysisResult(
        app_pcap="a.pcap",
        db_pcap="b.pcap",
        server_ip="10.0.0.1",
        db_port=5236,
        clock=ClockAlignment(status="UNRELIABLE", note="t"),
        capture_quality_app={"credibility": "DEGRADED", "file_cut_short": True, "truncated_packets": 1},
        capture_quality_db={"credibility": "HIGH", "file_cut_short": False, "truncated_packets": 0},
    )
    row = UnifiedTimelineRow(
        case_id="case",
        timestamp=95.0,
        relative_to_jdbc_seconds=-5.0,
        source="DUAL",
        event_type="MATCHED_SEGMENT",
        correlation_id="CF0001",
        app_stream=26,
        db_stream=20,
        frame=10,
        direction="APP_TO_DB",
        seq=100,
        ack=1,
        tcp_len=10,
        description=redact_secrets(msg),
        evidence_class=EV_CORRELATED,
        confidence="CONFIRMED",
    )
    return CaseAnalysisResult(
        case_id="case_html",
        jdbc=jdbc,
        dual=dual,
        ping=PingAnalysisResult(ping_log=None, provided=False),
        unified_timeline=[row],
        confirmed=[EvidenceItem(EV_CONFIRMED, "JDBC CONNECTION_RESET at 09:38:41", "CONFIRMED")],
        correlated=[EvidenceItem(EV_CORRELATED, "CF0001 candidate evidence", "AMBIGUOUS")],
        supporting=[EvidenceItem(EV_SUPPORTING, "Ping supporting only", "SUPPORTING")],
        unknown=[EvidenceItem(EV_UNKNOWN, "Unique JDBC connection identity unknown")],
        key_jdbc_event_id="JE0001",
    )


def test_v27_html_generated_self_contained():
    d = _fresh("gen")
    path = export_case_html(_minimal_result(), str(d / "report.html"))
    text = Path(path).read_text(encoding="utf-8")
    assert Path(path).exists()
    assert "DBCAP Case Report" in text
    assert "Executive Summary" in text
    assert "JDBC Events" in text
    assert "Identity Score" in text
    assert "AMBIGUOUS" in text
    assert "不足以唯一确定" in text
    assert "CF0001" in text
    assert "tcp.stream eq 26" in text
    assert "DEGRADED" in text
    assert "supporting evidence only" in text.lower() or "SUPPORTING" in text
    assert "http://" not in text.lower()
    assert "https://" not in text.lower()
    assert "cdn." not in text.lower()
    assert "<style>" in text
    assert "googleapis" not in text.lower()


def test_v27_html_redaction_and_escape():
    d = _fresh("sec")
    path = export_case_html(
        _minimal_result(with_secret=True, inject_script=True),
        str(d / "report.html"),
    )
    text = Path(path).read_text(encoding="utf-8")
    assert "sekrit" not in text
    assert "tok123" not in text
    assert "BEARERVAL" not in text
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text
    # our own inline script block is allowed; injected payload must be escaped text
    assert re.search(r"&lt;script&gt;alert\(1\)&lt;/script&gt;", text)


def test_v27_export_all_writes_html():
    d = _fresh("all")
    paths = export_all_case(_minimal_result(), str(d))
    assert "report_html" in paths
    assert Path(paths["report_html"]).exists()
