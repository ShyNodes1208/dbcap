"""V2.5 Candidate Precision regression tests."""

from __future__ import annotations

from dbcap.dual.models import (
    ClockAlignment,
    CorrelatedFlow,
    DualAnalysisResult,
    NormalizedFlowKey,
)
from dbcap.jdbc.correlator import correlate_event
from dbcap.jdbc.models import STATUS_AMBIGUOUS, STATUS_MATCHED, STATUS_NO_MATCH, JdbcEvent
from dbcap.jdbc.parser import parse_jdbc_timestamp
from dbcap.models import (
    AnalysisReport,
    Anomaly,
    EvidenceLevel,
    FlowKey,
    PacketSummary,
    Severity,
    TcpSession,
)


def _dual(flows, sessions=None, app_report=None, server_ip="10.4.34.95", db_port=5236):
    return DualAnalysisResult(
        app_pcap="a.pcap",
        db_pcap="b.pcap",
        server_ip=server_ip,
        db_port=db_port,
        correlated_flows=flows,
        app_sessions=sessions or {},
        db_sessions={},
        app_report=app_report,
        clock=ClockAlignment(status="UNRELIABLE", note="test"),
    )


def _flow(cid, app_s, db_s, cport, t0, t1, sip="10.4.34.95", sport=5236, cip="10.4.7.233"):
    return CorrelatedFlow(
        correlation_id=cid,
        flow_key=NormalizedFlowKey(cip, cport, sip, sport),
        app_stream=app_s,
        db_stream=db_s,
        app_start=t0,
        app_end=t1,
        db_start=t0,
        db_end=t1,
    )


def _sess(stream, cport, packets, sip="10.4.34.95", sport=5236):
    key = FlowKey(
        src_ip="10.4.7.233",
        src_port=cport,
        dst_ip=sip,
        dst_port=sport,
        server_ip=sip,
        server_port=sport,
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


def _ev(t, host="10.4.34.95", port=5236):
    return JdbcEvent(
        event_id="JE0001",
        timestamp=t,
        timestamp_raw="2026-09-16 09:38:41",
        level="ERROR",
        exception_class="X",
        message="y",
        event_type="CONNECTION_RESET",
        thread_name="t",
        tid="1",
        database_host=host,
        database_port=port,
        connection_hint=None,
        stack_summary="",
        source_file="x",
        start_line=1,
        end_line=1,
        raw_excerpt_hash="a",
    )


def test_v25_different_server_ip_filtered():
    t = parse_jdbc_timestamp("2026-09-16 09:38:41")
    flow = _flow("CF1", 1, 2, 10001, t - 10, t + 10, sip="10.9.9.9")
    dual = _dual([flow], {1: _sess(1, 10001, [_pkt(t, 1, 1, cport=10001)])})
    corr = correlate_event(_ev(t), dual)
    assert corr.correlation_status == STATUS_NO_MATCH
    assert corr.filtered_endpoint >= 1
    assert corr.eligible_count == 0


def test_v25_different_server_port_filtered():
    t = parse_jdbc_timestamp("2026-09-16 09:38:41")
    flow = _flow("CF1", 1, 2, 10001, t - 10, t + 10, sport=9999)
    dual = _dual([flow], {1: _sess(1, 10001, [_pkt(t, 1, 1, cport=10001)])})
    corr = correlate_event(_ev(t), dual)
    assert corr.filtered_endpoint >= 1
    assert corr.eligible_count == 0


def test_v25_event_far_from_lifetime_filtered():
    t = parse_jdbc_timestamp("2026-09-16 09:38:41")
    flow = _flow("CF1", 1, 2, 10001, t - 10000, t - 9000)
    dual = _dual([flow], {1: _sess(1, 10001, [_pkt(t - 9500, 1, 1, cport=10001)])})
    corr = correlate_event(_ev(t), dual, lifetime_grace_seconds=5.0)
    assert corr.filtered_time >= 1
    assert corr.eligible_count == 0
    assert corr.correlation_status == STATUS_NO_MATCH


def test_v25_flow_ended_shortly_before_retained_by_grace():
    t = parse_jdbc_timestamp("2026-09-16 09:38:41")
    # ended 3s before event — within default 5s grace
    flow = _flow("CF1", 1, 2, 10001, t - 100, t - 3)
    dual = _dual([flow], {1: _sess(1, 10001, [_pkt(t - 4, 1, 1, cport=10001)])})
    corr = correlate_event(_ev(t), dual, lifetime_grace_seconds=5.0)
    assert corr.eligible_count == 1
    assert corr.candidates[0].dual_correlation_id == "CF1"


def test_v25_long_lived_with_nearby_activity_retained():
    t = parse_jdbc_timestamp("2026-09-16 09:38:41")
    flow = _flow("CF1", 1, 2, 10001, t - 3600, t + 3600)
    dual = _dual([flow], {1: _sess(1, 10001, [_pkt(t - 0.5, 1, 1, cport=10001)])})
    corr = correlate_event(_ev(t), dual)
    assert corr.eligible_count == 1
    assert corr.candidates[0].identity_score >= 70


def test_v25_multiple_pool_connections_ambiguous():
    t = parse_jdbc_timestamp("2026-09-16 09:38:41")
    flows = [
        _flow("CF1", 1, 10, 10001, t - 50, t + 50),
        _flow("CF2", 2, 11, 10002, t - 50, t + 50),
    ]
    sessions = {
        1: _sess(1, 10001, [_pkt(t - 0.5, 1, 1, cport=10001)]),
        2: _sess(2, 10002, [_pkt(t - 0.4, 2, 2, cport=10002)]),
    }
    corr = correlate_event(_ev(t), _dual(flows, sessions))
    assert corr.correlation_status == STATUS_AMBIGUOUS
    assert corr.eligible_count >= 2


def test_v25_anomaly_severity_does_not_outrank_better_identity():
    """Worse identity + heavy anomalies must not beat better identity."""
    t = parse_jdbc_timestamp("2026-09-16 09:38:41")
    # CF_GOOD: covers event, nearby activity, no anomalies
    good = _flow("CF_GOOD", 1, 10, 10001, t - 50, t + 50)
    # CF_BAD: ended long ago but... wait, that would be filtered.
    # Instead: same cover, but GOOD has nearer activity; BAD has many anomalies
    # and slightly worse activity distance.
    bad = _flow("CF_BAD", 2, 11, 10002, t - 50, t + 50)
    sessions = {
        1: _sess(1, 10001, [_pkt(t - 0.2, 1, 1, cport=10001)]),
        2: _sess(2, 10002, [_pkt(t - 5.0, 2, 2, cport=10002)]),
    }
    report = AnalysisReport(
        anomalies=[
            Anomaly(
                type="ACK_STALLED",
                severity=Severity.HIGH,
                evidence_level=EvidenceLevel.CONFIRMED,
                tcp_stream=2,
                summary="stalled",
                detail="stalled",
                frames=[2],
            ),
            Anomaly(
                type="DATA_RETRANSMISSION",
                severity=Severity.WARNING,
                evidence_level=EvidenceLevel.CONFIRMED,
                tcp_stream=2,
                summary="retrans",
                detail="retrans",
                frames=[3],
            ),
            Anomaly(
                type="RST",
                severity=Severity.HIGH,
                evidence_level=EvidenceLevel.CONFIRMED,
                tcp_stream=2,
                summary="rst",
                detail="rst",
                frames=[4],
            ),
        ],
    )
    corr = correlate_event(_ev(t), _dual([good, bad], sessions, app_report=report))
    assert corr.candidates[0].dual_correlation_id == "CF_GOOD"
    assert corr.candidates[0].identity_score >= corr.candidates[1].identity_score
    # Health may be higher on BAD but must not flip rank
    bad_c = next(c for c in corr.candidates if c.dual_correlation_id == "CF_BAD")
    assert bad_c.health_score >= 0


def test_v25_closer_activity_wins_when_anomalies_equal():
    t = parse_jdbc_timestamp("2026-09-16 09:38:41")
    near = _flow("CF_NEAR", 1, 10, 10001, t - 50, t + 50)
    far = _flow("CF_FAR", 2, 11, 10002, t - 50, t + 50)
    sessions = {
        1: _sess(1, 10001, [_pkt(t - 0.1, 1, 1, cport=10001)]),
        2: _sess(2, 10002, [_pkt(t - 8.0, 2, 2, cport=10002)]),
    }
    corr = correlate_event(_ev(t), _dual([far, near], sessions))
    assert corr.candidates[0].dual_correlation_id == "CF_NEAR"


def test_v25_no_eligible_is_no_match():
    t = parse_jdbc_timestamp("2026-09-16 09:38:41")
    corr = correlate_event(_ev(t), _dual([]))
    assert corr.correlation_status == STATUS_NO_MATCH


def test_v25_single_reliable_candidate_matched():
    t = parse_jdbc_timestamp("2026-09-16 09:38:41")
    flow = _flow("CF1", 26, 20, 48134, t - 100, t + 100)
    dual = _dual([flow], {26: _sess(26, 48134, [_pkt(t - 1, 1, 26), _pkt(t + 0.5, 2, 26)])})
    corr = correlate_event(_ev(t), dual)
    assert corr.correlation_status == STATUS_MATCHED
    assert corr.evidence_level == "STRONG"
    assert corr.candidates[0].identity_score > corr.candidates[0].health_score
