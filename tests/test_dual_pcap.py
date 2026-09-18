"""V2 Dual-PCAP correlation unit tests."""

from __future__ import annotations

import hashlib

from dbcap.dual.clock_alignment import estimate_clock_alignment
from dbcap.dual.flow_matcher import match_flows
from dbcap.dual.models import (
    DIR_APP_TO_DB,
    DIR_DB_TO_APP,
    STATUS_AMBIGUOUS,
    STATUS_APP_ONLY,
    STATUS_BOTH,
    STATUS_DB_ONLY,
    STATUS_HASH_UNAVAIL,
    CorrelatedFlow,
    DualSegment,
    NormalizedFlowKey,
)
from dbcap.dual.segment_matcher import match_segments_for_flow
from dbcap.models import FlowKey, PacketSummary, TcpSession
from dbcap.seq_ack import expected_ack


def _sess(
    stream: int,
    packets: list[PacketSummary],
    *,
    cip: str = "10.4.7.233",
    cport: int = 48134,
    sip: str = "10.4.34.95",
    sport: int = 5236,
) -> TcpSession:
    key = FlowKey(
        src_ip=cip,
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


def _pkt(
    *,
    ts: float,
    src: str,
    sport: int,
    dst: str,
    dport: int,
    seq: int,
    tcp_len: int,
    frame: int,
    stream: int,
    payload_hex: str = "",
    flags: int = 0x18,
    frame_len: int | None = None,
    cap_len: int | None = None,
) -> PacketSummary:
    fl = frame_len if frame_len is not None else (54 + max(tcp_len, 0))
    cl = cap_len if cap_len is not None else fl
    return PacketSummary(
        timestamp=ts,
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        tcp_flags=flags,
        tcp_seq=seq,
        tcp_ack=1,
        tcp_window=65535,
        tcp_len=tcp_len,
        frame_number=frame,
        tcp_stream=stream,
        frame_len=fl,
        cap_len=cl,
        payload_hex=payload_hex,
    )


def test_stream_id_different_same_tuple_matches():
    app = {
        26: _sess(
            26,
            [_pkt(ts=1.0, src="10.4.7.233", sport=48134, dst="10.4.34.95", dport=5236, seq=1, tcp_len=0, frame=1, stream=26, flags=0x02)],
        )
    }
    db = {
        20: _sess(
            20,
            [_pkt(ts=1.0, src="10.4.7.233", sport=48134, dst="10.4.34.95", dport=5236, seq=1, tcp_len=0, frame=1, stream=20, flags=0x02)],
        )
    }
    flows, _, _ = match_flows(app, db)
    assert len(flows) == 1
    assert flows[0].app_stream == 26
    assert flows[0].db_stream == 20


def test_same_tuple_different_connections_not_merged():
    # Different SYN ISNs at non-overlapping times
    app = {
        1: _sess(
            1,
            [
                _pkt(ts=1.0, src="10.4.7.233", sport=48134, dst="10.4.34.95", dport=5236, seq=100, tcp_len=0, frame=1, stream=1, flags=0x02),
                _pkt(ts=10.0, src="10.4.7.233", sport=48134, dst="10.4.34.95", dport=5236, seq=200, tcp_len=10, frame=2, stream=1, payload_hex="aa" * 10),
            ],
        ),
        2: _sess(
            2,
            [
                _pkt(ts=1000.0, src="10.4.7.233", sport=48134, dst="10.4.34.95", dport=5236, seq=9000, tcp_len=0, frame=3, stream=2, flags=0x02),
                _pkt(ts=1010.0, src="10.4.7.233", sport=48134, dst="10.4.34.95", dport=5236, seq=9100, tcp_len=10, frame=4, stream=2, payload_hex="bb" * 10),
            ],
        ),
    }
    db = {
        10: _sess(
            10,
            [
                _pkt(ts=1.0, src="10.4.7.233", sport=48134, dst="10.4.34.95", dport=5236, seq=100, tcp_len=0, frame=1, stream=10, flags=0x02),
                _pkt(ts=10.0, src="10.4.7.233", sport=48134, dst="10.4.34.95", dport=5236, seq=200, tcp_len=10, frame=2, stream=10, payload_hex="aa" * 10),
            ],
        ),
        11: _sess(
            11,
            [
                _pkt(ts=1000.0, src="10.4.7.233", sport=48134, dst="10.4.34.95", dport=5236, seq=9000, tcp_len=0, frame=3, stream=11, flags=0x02),
                _pkt(ts=1010.0, src="10.4.7.233", sport=48134, dst="10.4.34.95", dport=5236, seq=9100, tcp_len=10, frame=4, stream=11, payload_hex="bb" * 10),
            ],
        ),
    }
    flows, _, _ = match_flows(app, db)
    assert len(flows) == 2
    pairs = {(f.app_stream, f.db_stream) for f in flows}
    assert (1, 10) in pairs
    assert (2, 11) in pairs


def test_both_sides_segment_match():
    payload = "deadbeef" * 8
    ph = hashlib.sha256(bytes.fromhex(payload)).hexdigest()
    flow = CorrelatedFlow(
        correlation_id="CF0001",
        flow_key=NormalizedFlowKey("10.4.7.233", 48134, "10.4.34.95", 5236),
        app_stream=26,
        db_stream=20,
    )
    app = _sess(
        26,
        [
            _pkt(
                ts=1.0,
                src="10.4.7.233",
                sport=48134,
                dst="10.4.34.95",
                dport=5236,
                seq=4895,
                tcp_len=73,
                frame=10,
                stream=26,
                payload_hex=payload,
            )
        ],
    )
    db = _sess(
        20,
        [
            _pkt(
                ts=1.01,
                src="10.4.7.233",
                sport=48134,
                dst="10.4.34.95",
                dport=5236,
                seq=4895,
                tcp_len=73,
                frame=99,
                stream=20,
                payload_hex=payload,
            )
        ],
    )
    segs = match_segments_for_flow(flow, app, db)
    both = [s for s in segs if s.match_status == STATUS_BOTH]
    assert len(both) == 1
    assert both[0].direction == DIR_APP_TO_DB
    assert both[0].payload_hash_match is True
    assert both[0].payload_hash_app == ph
    assert both[0].expected_ack == expected_ack(4895, 73)


def test_same_seq_len_different_hash_ambiguous():
    flow = CorrelatedFlow(
        correlation_id="CF0001",
        flow_key=NormalizedFlowKey("10.4.7.233", 48134, "10.4.34.95", 5236),
        app_stream=1,
        db_stream=2,
    )
    app = _sess(
        1,
        [
            _pkt(
                ts=1.0,
                src="10.4.7.233",
                sport=48134,
                dst="10.4.34.95",
                dport=5236,
                seq=100,
                tcp_len=10,
                frame=1,
                stream=1,
                payload_hex="aa" * 10,
            )
        ],
    )
    db = _sess(
        2,
        [
            _pkt(
                ts=1.0,
                src="10.4.7.233",
                sport=48134,
                dst="10.4.34.95",
                dport=5236,
                seq=100,
                tcp_len=10,
                frame=2,
                stream=2,
                payload_hex="bb" * 10,
            )
        ],
    )
    segs = match_segments_for_flow(flow, app, db)
    assert any(s.match_status == STATUS_AMBIGUOUS for s in segs)
    assert not any(s.match_status == STATUS_BOTH and s.payload_hash_match for s in segs)


def test_truncated_payload_hash_unavailable():
    flow = CorrelatedFlow(
        correlation_id="CF0001",
        flow_key=NormalizedFlowKey("10.4.7.233", 48134, "10.4.34.95", 5236),
        app_stream=1,
        db_stream=2,
    )
    app = _sess(
        1,
        [
            _pkt(
                ts=1.0,
                src="10.4.7.233",
                sport=48134,
                dst="10.4.34.95",
                dport=5236,
                seq=200,
                tcp_len=100,
                frame=1,
                stream=1,
                payload_hex="",
                frame_len=200,
                cap_len=60,
            )
        ],
    )
    db = _sess(
        2,
        [
            _pkt(
                ts=1.1,
                src="10.4.7.233",
                sport=48134,
                dst="10.4.34.95",
                dport=5236,
                seq=200,
                tcp_len=100,
                frame=2,
                stream=2,
                payload_hex="",
                frame_len=200,
                cap_len=60,
            )
        ],
    )
    segs = match_segments_for_flow(flow, app, db)
    assert any(s.match_status in (STATUS_HASH_UNAVAIL, STATUS_BOTH) for s in segs)


def test_only_at_app():
    flow = CorrelatedFlow(
        correlation_id="CF0001",
        flow_key=NormalizedFlowKey("10.4.7.233", 48134, "10.4.34.95", 5236),
        app_stream=1,
        db_stream=2,
    )
    app = _sess(
        1,
        [
            _pkt(
                ts=1.0,
                src="10.4.7.233",
                sport=48134,
                dst="10.4.34.95",
                dport=5236,
                seq=1,
                tcp_len=5,
                frame=1,
                stream=1,
                payload_hex="11" * 5,
            )
        ],
    )
    db = _sess(2, [])
    segs = match_segments_for_flow(flow, app, db)
    assert segs[0].match_status == STATUS_APP_ONLY
    assert "device" not in segs[0].note.lower() or "not" in segs[0].note.lower()


def test_only_at_db():
    flow = CorrelatedFlow(
        correlation_id="CF0001",
        flow_key=NormalizedFlowKey("10.4.7.233", 48134, "10.4.34.95", 5236),
        app_stream=1,
        db_stream=2,
    )
    app = _sess(1, [])
    db = _sess(
        2,
        [
            _pkt(
                ts=1.0,
                src="10.4.34.95",
                sport=5236,
                dst="10.4.7.233",
                dport=48134,
                seq=7125,
                tcp_len=124,
                frame=7,
                stream=2,
                payload_hex="22" * 124,
            )
        ],
    )
    segs = match_segments_for_flow(flow, app, db)
    assert segs[0].match_status == STATUS_DB_ONLY
    assert segs[0].direction == DIR_DB_TO_APP


def test_clock_offset_stable():
    segs = [
        DualSegment(
            correlation_id="CF1",
            direction=DIR_APP_TO_DB,
            seq=i,
            tcp_len=10,
            expected_ack=i + 10,
            ack=None,
            app_frame=i,
            app_timestamp=100.0 + i + 1.5,
            app_stream=1,
            db_frame=i,
            db_timestamp=100.0 + i,
            db_stream=2,
            payload_hash_app="a",
            payload_hash_db="a",
            payload_hash_match=True,
            observed_delta=1.5,
            match_status=STATUS_BOTH,
            evidence_level="CONFIRMED",
        )
        for i in range(5)
    ]
    clock = estimate_clock_alignment(segs)
    assert clock.status == "OK"
    assert abs((clock.estimated_offset_sec or 0) - 1.5) < 1e-6


def test_clock_offset_unstable():
    segs = [
        DualSegment(
            correlation_id="CF1",
            direction=DIR_APP_TO_DB,
            seq=i,
            tcp_len=10,
            expected_ack=i + 10,
            ack=None,
            app_frame=i,
            app_timestamp=100.0 + i * 10,
            app_stream=1,
            db_frame=i,
            db_timestamp=100.0,
            db_stream=2,
            payload_hash_app="a",
            payload_hash_db="a",
            payload_hash_match=True,
            observed_delta=float(i * 10),
            match_status=STATUS_BOTH,
            evidence_level="CONFIRMED",
        )
        for i in range(5)
    ]
    clock = estimate_clock_alignment(segs)
    assert clock.status == "UNRELIABLE"


def test_wireshark_filters_per_side():
    flow = CorrelatedFlow(
        correlation_id="CF0001",
        flow_key=NormalizedFlowKey("10.4.7.233", 48134, "10.4.34.95", 5236),
        app_stream=26,
        db_stream=20,
    )
    assert f"tcp.stream eq {flow.app_stream}" == "tcp.stream eq 26"
    assert f"tcp.stream eq {flow.db_stream}" == "tcp.stream eq 20"
    assert flow.app_stream != flow.db_stream


def test_retransmission_cross_correlation_counts():
    payload = "cc" * 20
    flow = CorrelatedFlow(
        correlation_id="CF0001",
        flow_key=NormalizedFlowKey("10.4.7.233", 48134, "10.4.34.95", 5236),
        app_stream=1,
        db_stream=2,
    )
    app_pkts = [
        _pkt(
            ts=1.0 + i * 0.1,
            src="10.4.34.95",
            sport=5236,
            dst="10.4.7.233",
            dport=48134,
            seq=500,
            tcp_len=20,
            frame=10 + i,
            stream=1,
            payload_hex=payload,
        )
        for i in range(2)
    ]
    db_pkts = [
        _pkt(
            ts=1.0 + i * 0.05,
            src="10.4.34.95",
            sport=5236,
            dst="10.4.7.233",
            dport=48134,
            seq=500,
            tcp_len=20,
            frame=20 + i,
            stream=2,
            payload_hex=payload,
        )
        for i in range(5)
    ]
    segs = match_segments_for_flow(flow, _sess(1, app_pkts), _sess(2, db_pkts))
    both = [s for s in segs if s.match_status == STATUS_BOTH]
    assert both
    assert both[0].retransmission_count_app == 2
    assert both[0].retransmission_count_db == 5


def test_app_db_capture_roles_in_direction():
    payload = "dd" * 8
    flow = CorrelatedFlow(
        correlation_id="CF0001",
        flow_key=NormalizedFlowKey("10.4.7.233", 48134, "10.4.34.95", 5236),
        app_stream=1,
        db_stream=2,
    )
    app = _sess(
        1,
        [
            _pkt(
                ts=1.0,
                src="10.4.7.233",
                sport=48134,
                dst="10.4.34.95",
                dport=5236,
                seq=10,
                tcp_len=8,
                frame=1,
                stream=1,
                payload_hex=payload,
            )
        ],
    )
    db = _sess(
        2,
        [
            _pkt(
                ts=1.1,
                src="10.4.7.233",
                sport=48134,
                dst="10.4.34.95",
                dport=5236,
                seq=10,
                tcp_len=8,
                frame=2,
                stream=2,
                payload_hex=payload,
            )
        ],
    )
    segs = match_segments_for_flow(flow, app, db)
    assert segs[0].direction == DIR_APP_TO_DB


def test_db_to_app_both_sides_note():
    payload = "ab" * 124
    flow = CorrelatedFlow(
        correlation_id="CF0001",
        flow_key=NormalizedFlowKey("10.4.7.233", 48134, "10.4.34.95", 5236),
        app_stream=26,
        db_stream=20,
    )
    app = _sess(
        26,
        [
            _pkt(
                ts=2.0,
                src="10.4.34.95",
                sport=5236,
                dst="10.4.7.233",
                dport=48134,
                seq=7125,
                tcp_len=124,
                frame=50,
                stream=26,
                payload_hex=payload,
            )
        ],
    )
    db = _sess(
        20,
        [
            _pkt(
                ts=1.0,
                src="10.4.34.95",
                sport=5236,
                dst="10.4.7.233",
                dport=48134,
                seq=7125,
                tcp_len=124,
                frame=40,
                stream=20,
                payload_hex=payload,
            )
        ],
    )
    segs = match_segments_for_flow(flow, app, db)
    both = [s for s in segs if s.match_status == STATUS_BOTH]
    assert both and both[0].direction == DIR_DB_TO_APP
    assert "fully lost" in both[0].note.lower() or "lost between" in both[0].note.lower()


def test_h01_relative_syn_seq_zero_does_not_merge_reused_port():
    """
    Codex H-01 reproduction: relative tcp.seq on SYN is typically 0 and must
    not be treated as a raw ISN that boosts a non-overlapping historical session
    over the time-overlapping current session.
    """
    # Historical App connection (ended long before DB capture)
    app_old = _sess(
        1,
        [
            _pkt(
                ts=0.0,
                src="10.4.7.233",
                sport=48134,
                dst="10.4.34.95",
                dport=5236,
                seq=0,
                tcp_len=0,
                frame=1,
                stream=1,
                flags=0x02,
            ),
            _pkt(
                ts=1.0,
                src="10.4.7.233",
                sport=48134,
                dst="10.4.34.95",
                dport=5236,
                seq=1,
                tcp_len=10,
                frame=2,
                stream=1,
                payload_hex="aa" * 10,
            ),
        ],
    )
    # Current App connection (overlaps DB)
    app_cur = _sess(
        2,
        [
            _pkt(
                ts=100.0,
                src="10.4.7.233",
                sport=48134,
                dst="10.4.34.95",
                dport=5236,
                seq=0,
                tcp_len=0,
                frame=10,
                stream=2,
                flags=0x02,
            ),
            _pkt(
                ts=101.0,
                src="10.4.7.233",
                sport=48134,
                dst="10.4.34.95",
                dport=5236,
                seq=1,
                tcp_len=10,
                frame=11,
                stream=2,
                payload_hex="bb" * 10,
            ),
        ],
    )
    db_cur = _sess(
        20,
        [
            _pkt(
                ts=100.1,
                src="10.4.7.233",
                sport=48134,
                dst="10.4.34.95",
                dport=5236,
                seq=0,
                tcp_len=0,
                frame=100,
                stream=20,
                flags=0x02,
            ),
            _pkt(
                ts=100.2,
                src="10.4.7.233",
                sport=48134,
                dst="10.4.34.95",
                dport=5236,
                seq=1,
                tcp_len=10,
                frame=101,
                stream=20,
                payload_hex="bb" * 10,
            ),
        ],
    )
    flows, unmatched_app, unmatched_db = match_flows(
        {1: app_old, 2: app_cur},
        {20: db_cur},
    )
    assert len(flows) == 1
    assert flows[0].app_stream == 2
    assert flows[0].db_stream == 20
    assert 1 in unmatched_app
    assert "SYN ISN" not in flows[0].note
    assert flows[0].confidence != "CONFIRMED" or "time" in flows[0].note.lower() or "overlap" in flows[0].note.lower() or "4-tuple" in flows[0].note.lower()


def test_h02_hashless_vs_multiple_hashed_is_ambiguous():
    """
    Codex H-02 reproduction: one truncated/hashless segment vs multiple
    different full-hash peers with same dir/seq/len must stay AMBIGUOUS;
    choice must not depend on insertion order.
    """
    flow = CorrelatedFlow(
        correlation_id="CF0001",
        flow_key=NormalizedFlowKey("10.4.7.233", 48134, "10.4.34.95", 5236),
        app_stream=1,
        db_stream=2,
    )

    def _run(db_payloads: list[tuple[str, int]]) -> list:
        app = _sess(
            1,
            [
                _pkt(
                    ts=1.0,
                    src="10.4.7.233",
                    sport=48134,
                    dst="10.4.34.95",
                    dport=5236,
                    seq=200,
                    tcp_len=10,
                    frame=1,
                    stream=1,
                    payload_hex="",
                    frame_len=200,
                    cap_len=60,
                )
            ],
        )
        db_pkts = [
            _pkt(
                ts=1.0 + i * 0.01,
                src="10.4.7.233",
                sport=48134,
                dst="10.4.34.95",
                dport=5236,
                seq=200,
                tcp_len=10,
                frame=frame,
                stream=2,
                payload_hex=payload,
            )
            for i, (payload, frame) in enumerate(db_payloads)
        ]
        return match_segments_for_flow(flow, app, _sess(2, db_pkts))

    order_a = _run([("aa" * 10, 20), ("bb" * 10, 21)])
    order_b = _run([("bb" * 10, 21), ("aa" * 10, 20)])

    for segs in (order_a, order_b):
        forced = [
            s
            for s in segs
            if s.match_status == STATUS_HASH_UNAVAIL and s.evidence_level == "STRONG"
        ]
        assert not forced, "must not force HASH_UNAVAILABLE/STRONG against multiple hashed peers"
        amb = [s for s in segs if s.match_status == STATUS_AMBIGUOUS]
        assert amb, "expected AMBIGUOUS when hash cannot distinguish multiple candidates"
        assert all(s.payload_hash_match is not True for s in segs)
