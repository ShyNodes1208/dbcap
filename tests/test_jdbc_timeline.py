"""V2.2 JDBC timeline unit tests."""

from __future__ import annotations

import shutil
from pathlib import Path

from dbcap.dual.models import (
    ClockAlignment,
    CorrelatedFlow,
    DualAnalysisResult,
    NormalizedFlowKey,
)
from dbcap.jdbc.classifier import classify_exception
from dbcap.jdbc.correlator import correlate_event
from dbcap.jdbc.models import STATUS_AMBIGUOUS, STATUS_MATCHED, STATUS_NO_MATCH, JdbcEvent
from dbcap.jdbc.parser import parse_jdbc_log, parse_jdbc_timestamp
from dbcap.jdbc.redact import redact_secrets
from dbcap.jdbc.timeline import build_timeline_for_event
from dbcap.models import FlowKey, PacketSummary, TcpSession

_TMP = Path(__file__).resolve().parents[1] / "output" / "_jdbc_test_tmp"


def _fresh(name: str) -> Path:
    p = _TMP / name
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _write(dirpath: Path, name: str, text: str) -> Path:
    p = dirpath / name
    p.write_text(text, encoding="utf-8")
    return p


def test_parse_connection_reset_single_block():
    d = _fresh("reset")
    log = _write(
        d,
        "a.log",
        """[ERROR - 2026-09-16 09:38:41] tid:1 - [pool-1] { conn-1 } execute();  [USED TIME]: 10ms;
dm.jdbc.driver.DMException: network error
\tat dm.jdbc.driver.DBError.throwException(SourceFile:1)
Caused by: java.net.SocketException: Connection reset
\tat java.net.SocketInputStream.read(SocketInputStream.java:1)
[INFO  - 2026-09-16 09:38:42] tid:1 - [pool-1] { conn-1 } isClosed(): true;
""",
    )
    events = parse_jdbc_log(str(log), default_host="10.4.34.95", default_port=5236)
    assert len(events) == 1
    assert events[0].event_type == "CONNECTION_RESET"
    assert events[0].timestamp_raw == "2026-09-16 09:38:41"
    assert events[0].caused_by_class == "java.net.SocketException"
    assert "Connection reset" in (events[0].caused_by_message or "")
    assert events[0].start_line == 1
    assert events[0].end_line >= 5


def test_multiline_exception_block_aggregation():
    d = _fresh("multi")
    lines = ["[ERROR - 2026-09-16 09:00:00] tid:1 - [t] { conn-1 } execute();"]
    lines.append("dm.jdbc.driver.DMException: network")
    for i in range(20):
        lines.append(f"\tat pkg.Class.method(File.java:{i})")
    lines.append("Caused by: java.net.SocketException: Connection reset")
    lines.append("\tat java.net.SocketInputStream.read(SocketInputStream.java:210)")
    lines.append("[INFO  - 2026-09-16 09:00:01] tid:1 - [t] done")
    log = _write(d, "b.log", "\n".join(lines) + "\n")
    events = parse_jdbc_log(str(log))
    assert len(events) == 1
    assert events[0].end_line - events[0].start_line >= 20


def test_caused_by_connection_reset():
    assert (
        classify_exception(
            "dm.jdbc.driver.DMException",
            "network",
            "java.net.SocketException",
            "Connection reset",
        )
        == "CONNECTION_RESET"
    )


def test_connect_timeout_classification():
    assert (
        classify_exception(
            "dm.jdbc.driver.DMException",
            "network",
            "java.net.SocketTimeoutException",
            "connect timed out",
        )
        == "CONNECT_TIMEOUT"
    )


def test_read_socket_timeout_classification():
    assert (
        classify_exception(None, None, "java.net.SocketTimeoutException", "Read timed out")
        == "READ_TIMEOUT"
    )
    assert (
        classify_exception("java.net.SocketTimeoutException", "timeout waiting", None, None)
        == "SOCKET_TIMEOUT"
    )


def test_unknown_network_exception():
    assert (
        classify_exception("java.sql.SQLException", "I/O error writing request", None, None)
        == "UNKNOWN_NETWORK_ERROR"
    )


def test_multiple_jdbc_events():
    d = _fresh("multi_ev")
    log = _write(
        d,
        "c.log",
        """[ERROR - 2026-09-16 08:17:07] tid:1 - [Druid] { DmDriver } connect(); host=10.4.34.95 port=5236
dm.jdbc.driver.DMException: fail
Caused by: java.net.SocketTimeoutException: connect timed out
[INFO  - 2026-09-16 08:17:08] tid:1 - [Druid] ok
[ERROR - 2026-09-16 09:38:41] tid:2 - [pool] { conn-9 } execute();
dm.jdbc.driver.DMException: network
Caused by: java.net.SocketException: Connection reset
[INFO  - 2026-09-16 09:38:42] tid:2 - [pool] closed
""",
    )
    events = parse_jdbc_log(str(log))
    assert len(events) == 2
    assert events[0].event_type == "CONNECT_TIMEOUT"
    assert events[1].event_type == "CONNECTION_RESET"


def test_bad_timestamp_format():
    assert parse_jdbc_timestamp("not-a-time") is None
    assert parse_jdbc_timestamp("2026-09-16 09:38:41") is not None


def test_server_host_port_extraction():
    d = _fresh("hostport")
    log = _write(
        d,
        "d.log",
        """[DEBUG - 2026-09-16 08:00:00] tid:1 - [Druid] try connect success [10.4.34.95:5236]
[ERROR - 2026-09-16 08:00:01] tid:1 - [Druid] { DmDriver } connect(DmProperties): null;  [PARAMS]: {host=10.4.34.95, port=5236};
dm.jdbc.driver.DMException: x
Caused by: java.net.SocketTimeoutException: connect timed out
[INFO  - 2026-09-16 08:00:02] tid:1 - [Druid] next
""",
    )
    events = parse_jdbc_log(str(log))
    assert events[0].database_host == "10.4.34.95"
    assert events[0].database_port == 5236


def _dual_with_flows(flows, sessions=None):
    return DualAnalysisResult(
        app_pcap="a.pcap",
        db_pcap="b.pcap",
        server_ip="10.4.34.95",
        db_port=5236,
        correlated_flows=flows,
        app_sessions=sessions or {},
        db_sessions={},
        clock=ClockAlignment(status="UNRELIABLE", note="test"),
    )


def _flow(cid, app_s, db_s, cport, t0, t1):
    return CorrelatedFlow(
        correlation_id=cid,
        flow_key=NormalizedFlowKey("10.4.7.233", cport, "10.4.34.95", 5236),
        app_stream=app_s,
        db_stream=db_s,
        app_start=t0,
        app_end=t1,
        db_start=t0,
        db_end=t1,
    )


def _sess(stream, cport, packets):
    key = FlowKey(
        src_ip="10.4.7.233",
        src_port=cport,
        dst_ip="10.4.34.95",
        dst_port=5236,
        server_ip="10.4.34.95",
        server_port=5236,
    )
    s = TcpSession(tcp_stream=stream, key=key, packets=packets)
    if packets:
        s.start_time = min(p.timestamp for p in packets)
        s.end_time = max(p.timestamp for p in packets)
    return s


def _pkt(ts, frame, stream, cport=48134, flags=0x18, seq=1, tcp_len=10):
    return PacketSummary(
        timestamp=ts,
        src_ip="10.4.7.233",
        dst_ip="10.4.34.95",
        src_port=cport,
        dst_port=5236,
        tcp_flags=flags,
        tcp_seq=seq,
        tcp_ack=1,
        tcp_window=65535,
        tcp_len=tcp_len,
        frame_number=frame,
        tcp_stream=stream,
        payload_hex="aa" * max(tcp_len, 0),
    )


def test_unique_tcp_candidate_matched():
    t = parse_jdbc_timestamp("2026-09-16 09:38:41")
    assert t is not None
    flow = _flow("CF0001", 26, 20, 48134, t - 100, t + 100)
    sess = _sess(26, 48134, [_pkt(t - 1, 1, 26), _pkt(t + 0.5, 2, 26)])
    dual = _dual_with_flows([flow], {26: sess})
    ev = JdbcEvent(
        event_id="JE0001",
        timestamp=t,
        timestamp_raw="2026-09-16 09:38:41",
        level="ERROR",
        exception_class="dm.jdbc.driver.DMException",
        message="network",
        event_type="CONNECTION_RESET",
        thread_name="pool",
        tid="1",
        database_host="10.4.34.95",
        database_port=5236,
        connection_hint="conn-1",
        stack_summary="",
        source_file="x",
        start_line=1,
        end_line=2,
        raw_excerpt_hash="abc",
        caused_by_class="java.net.SocketException",
        caused_by_message="Connection reset",
    )
    corr = correlate_event(ev, dual, window_seconds=10)
    assert corr.correlation_status == STATUS_MATCHED
    assert corr.evidence_level == "STRONG"
    assert corr.app_stream == 26
    assert corr.db_stream == 20


def test_multiple_tcp_candidates_ambiguous():
    t = parse_jdbc_timestamp("2026-09-16 09:38:41")
    assert t is not None
    flows = [
        _flow("CF0001", 1, 10, 10001, t - 50, t + 50),
        _flow("CF0002", 2, 11, 10002, t - 50, t + 50),
    ]
    sessions = {
        1: _sess(1, 10001, [_pkt(t - 0.5, 1, 1, cport=10001)]),
        2: _sess(2, 10002, [_pkt(t - 0.4, 2, 2, cport=10002)]),
    }
    dual = _dual_with_flows(flows, sessions)
    ev = JdbcEvent(
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
    corr = correlate_event(ev, dual, window_seconds=10)
    assert corr.correlation_status == STATUS_AMBIGUOUS
    assert corr.candidate_count >= 2


def test_no_tcp_candidate():
    t = parse_jdbc_timestamp("2026-09-16 09:38:41")
    dual = _dual_with_flows([])
    ev = JdbcEvent(
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
    corr = correlate_event(ev, dual)
    assert corr.correlation_status == STATUS_NO_MATCH


def test_event_outside_flow_lifetime_no_strong_cover():
    t = parse_jdbc_timestamp("2026-09-16 09:38:41")
    flow = _flow("CF0001", 26, 20, 48134, t - 10000, t - 9000)
    dual = _dual_with_flows([flow], {26: _sess(26, 48134, [_pkt(t - 9500, 1, 26)])})
    ev = JdbcEvent(
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
    corr = correlate_event(ev, dual, window_seconds=10)
    assert corr.evidence_level != "CONFIRMED"
    if corr.candidates:
        assert any("does not cover" in r for r in corr.candidates[0].reasons)


def test_timeline_before_after_and_delta_sign():
    t = parse_jdbc_timestamp("2026-09-16 09:38:41")
    flow = _flow("CF0001", 26, 20, 48134, t - 100, t + 100)
    sess = _sess(
        26,
        48134,
        [
            _pkt(t - 2.0, 10, 26, flags=0x02, tcp_len=0),
            _pkt(t - 1.0, 11, 26),
            _pkt(t + 1.5, 12, 26, flags=0x01, tcp_len=0),
        ],
    )
    dual = _dual_with_flows([flow], {26: sess})
    ev = JdbcEvent(
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
    corr = correlate_event(ev, dual)
    tl = build_timeline_for_event(ev, corr, dual, window_seconds=30)
    jdbc_rows = [x for x in tl if x.source == "JDBC"]
    assert jdbc_rows and jdbc_rows[0].relative_seconds == 0.0
    before = [x for x in tl if x.relative_seconds is not None and x.relative_seconds < 0]
    after = [x for x in tl if x.relative_seconds is not None and x.relative_seconds > 0]
    assert before and after
    assert any(x.event_type == "SYN" for x in before)
    assert any(x.event_type == "FIN" for x in after)


def test_clock_alignment_unreliable_surfaced():
    dual = _dual_with_flows([])
    assert dual.clock.status == "UNRELIABLE"


def test_password_redaction():
    s = redact_secrets("host=10.1.1.1, password=SuperSecret, user=u1")
    assert "SuperSecret" not in s
    assert "password=***" in s
    assert "token=abc" not in redact_secrets("token=abc")
