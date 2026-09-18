"""HIGH regression tests for V2.2–V2.4 combined review (H-01, H-02)."""

from __future__ import annotations

from dbcap.case.models import EV_CORRELATED
from dbcap.case.pipeline import _build_unified_timeline
from dbcap.jdbc.models import JdbcTimelineResult, TimelineEntry
from dbcap.jdbc.redact import redact_secrets
from dbcap.ping.models import PingAnalysisResult


def _jdbc_result_with_mixed_candidates() -> JdbcTimelineResult:
    """Simulate AMBIGUOUS timeline: primary CF0031 unlabeled + near-tie CF0026 prefixed."""
    entries = [
        TimelineEntry(
            event_id="JE0003",
            timeline_timestamp=100.0,
            relative_seconds=0.0,
            source="JDBC",
            event_type="CONNECTION_RESET",
            side="APP_LOG",
            frame=None,
            stream=None,
            seq=None,
            ack=None,
            tcp_len=None,
            description="CONNECTION_RESET",
            evidence_level="AMBIGUOUS",
            correlation_id=None,
            direction=None,
            app_stream=None,
            db_stream=None,
        ),
        TimelineEntry(
            event_id="JE0003",
            timeline_timestamp=95.0,
            relative_seconds=-5.0,
            source="DUAL",
            event_type="MATCHED_SEGMENT",
            side="BOTH",
            frame=16472,
            stream=44,
            seq=100,
            ack=1,
            tcp_len=10,
            description="APP_TO_DB Seq=100 Len=10 ExpectedACK=110 hash_match=True app_frame=1 db_frame=2",
            evidence_level="CONFIRMED",
            # Intentionally missing identity — reproduces H-01 primary-row bug when builder forgets
            correlation_id=None,
            direction=None,
            app_stream=None,
            db_stream=None,
        ),
        TimelineEntry(
            event_id="JE0003",
            timeline_timestamp=96.0,
            relative_seconds=-4.0,
            source="DUAL",
            event_type="MATCHED_SEGMENT",
            side="BOTH",
            frame=16490,
            stream=26,
            seq=200,
            ack=1,
            tcp_len=20,
            description=(
                "[candidate CF0026] DB_TO_APP Seq=200 Len=20 ExpectedACK=220 "
                "hash_match=True app_frame=3 db_frame=4"
            ),
            evidence_level="CONFIRMED",
            correlation_id="CF0026",
            direction="DB_TO_APP",
            app_stream=26,
            db_stream=20,
        ),
    ]
    return JdbcTimelineResult(
        jdbc_log="x",
        app_pcap="a",
        db_pcap="b",
        server_ip="10.4.34.95",
        db_port=5236,
        window_seconds=10,
        timeline=entries,
    )


def test_high_h01_unified_timeline_preserves_candidate_identity():
    """
    Codex H-01: every Dual/TCP unified row must carry correlation_id;
    BOTH rows must expose app_stream and db_stream; direction must be set;
    primary and near-tie candidates must remain separable.
    """
    jdbc = _jdbc_result_with_mixed_candidates()
    # Fix path: timeline entries for TCP must be filled by builder; for this test we
    # assert the unified converter requires/propagates identity. First ensure primary
    # Dual row is repaired the way production builder should emit.
    primary = jdbc.timeline[1]
    # Production builder must set these; if still None, unified layer must not export blanks.
    # Simulate post-fix builder output for primary:
    primary.correlation_id = "CF0031"
    primary.direction = "APP_TO_DB"
    primary.app_stream = 44
    primary.db_stream = 38

    rows = _build_unified_timeline(
        "case",
        jdbc,
        PingAnalysisResult(ping_log=None, provided=False),
        "JE0003",
    )
    dual_rows = [r for r in rows if r.source == "DUAL"]
    assert dual_rows, "expected Dual rows"
    assert all(r.correlation_id for r in dual_rows), (
        "H-01: correlation_id must not be empty on Dual/TCP evidence rows"
    )
    ids = {r.correlation_id for r in dual_rows}
    assert "CF0031" in ids and "CF0026" in ids
    both = [r for r in dual_rows if r.event_type == "MATCHED_SEGMENT"]
    for r in both:
        assert r.app_stream is not None, "BOTH/matched segment must keep app_stream"
        assert r.db_stream is not None, "BOTH/matched segment must keep db_stream"
        assert r.direction, "direction must be preserved"
    # Must not collapse into unlabeled single connection story
    assert any(r.correlation_id == "CF0031" for r in both)
    assert any(r.correlation_id == "CF0026" for r in both)


def test_high_h01_builder_fills_primary_candidate_fields():
    """Timeline builder must stamp correlation_id/streams/direction on primary flow rows."""
    from dbcap.dual.models import (
        ClockAlignment,
        DualAnalysisResult,
        DualSegment,
        NormalizedFlowKey,
    )
    from dbcap.jdbc.models import JdbcEvent, JdbcTcpCorrelation
    from dbcap.jdbc.parser import parse_jdbc_timestamp
    from dbcap.jdbc.timeline import build_timeline_for_event
    from dbcap.models import FlowKey, PacketSummary, TcpSession

    t = parse_jdbc_timestamp("2026-09-16 09:38:41")
    assert t is not None
    key = FlowKey(
        src_ip="10.4.7.233",
        src_port=51834,
        dst_ip="10.4.34.95",
        dst_port=5236,
        server_ip="10.4.34.95",
        server_port=5236,
    )
    pkt = PacketSummary(
        timestamp=t - 1,
        src_ip="10.4.7.233",
        dst_ip="10.4.34.95",
        src_port=51834,
        dst_port=5236,
        tcp_flags=0x18,
        tcp_seq=1,
        tcp_ack=1,
        tcp_window=1,
        tcp_len=10,
        frame_number=10,
        tcp_stream=44,
        payload_hex="aa" * 10,
    )
    app = TcpSession(tcp_stream=44, key=key, packets=[pkt])
    app.start_time = t - 10
    app.end_time = t + 10
    dual = DualAnalysisResult(
        app_pcap="a",
        db_pcap="b",
        server_ip="10.4.34.95",
        db_port=5236,
        app_sessions={44: app},
        db_sessions={},
        segments=[
            DualSegment(
                correlation_id="CF0031",
                direction="APP_TO_DB",
                seq=100,
                tcp_len=10,
                expected_ack=110,
                ack=1,
                app_frame=10,
                app_timestamp=t - 1,
                app_stream=44,
                db_frame=20,
                db_timestamp=t - 1,
                db_stream=38,
                payload_hash_app="a",
                payload_hash_db="a",
                payload_hash_match=True,
                observed_delta=0.0,
                match_status="MATCHED_BOTH_SIDES",
                evidence_level="CONFIRMED",
            )
        ],
        clock=ClockAlignment(status="UNRELIABLE", note="t"),
    )
    ev = JdbcEvent(
        event_id="JE0003",
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
    corr = JdbcTcpCorrelation(
        event_id="JE0003",
        correlation_status="AMBIGUOUS",
        evidence_level="AMBIGUOUS",
        dual_correlation_id="CF0031",
        client_ip="10.4.7.233",
        client_port=51834,
        server_ip="10.4.34.95",
        server_port=5236,
        app_stream=44,
        db_stream=38,
        event_timestamp=t,
        flow_start=t - 10,
        flow_end=t + 10,
        nearest_tcp_event=None,
        nearest_tcp_event_time=None,
        delta_seconds=None,
        candidate_count=2,
        reason="test",
    )
    entries = build_timeline_for_event(ev, corr, dual, window_seconds=30)
    dual_rows = [e for e in entries if e.source == "DUAL"]
    assert dual_rows
    for e in dual_rows:
        assert e.correlation_id == "CF0031"
        assert e.direction == "APP_TO_DB"
        assert e.app_stream == 44
        assert e.db_stream == 38


def test_high_h02_redact_access_token_and_authorization():
    """Codex H-02: access_token and Authorization must not survive redaction."""
    probe = (
        "password=abc pwd=def token=ghi access_token=xyz789 "
        "Authorization: Bearer TOPSECRET Authorization: Basic QWxhZGRpbjpvcGVu"
    )
    out = redact_secrets(probe)
    assert "xyz789" not in out
    assert "TOPSECRET" not in out
    assert "QWxhZGRpbjpvcGVu" not in out
    assert "abc" not in out
    assert "access_token=***" in out.lower() or "access_token:***" in out.lower() or "***" in out
    assert "bearer ***" in out.lower() or "authorization:***" in out.lower() or "authorization: ***" in out.lower()
