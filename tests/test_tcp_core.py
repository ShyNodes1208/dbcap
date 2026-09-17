"""Unit tests for DBCAP TCP evidence core."""

from __future__ import annotations

import hashlib

import pytest

from dbcap.ack_analysis import detect_ack_stalled
from dbcap.analyzer import build_analysis_report
from dbcap.capture_quality import analyze_capture_quality
from dbcap.handshake import extract_handshake
from dbcap.models import PacketSummary, Severity, ThresholdConfig
from dbcap.retransmission import detect_persistent_retransmissions, payload_sha256
from dbcap.rst_analysis import classify_rst
from dbcap.seq_ack import expected_ack, expected_ack_from_packet
from dbcap.session import group_into_sessions
from dbcap.thresholds import DEFAULT_THRESHOLDS
from dbcap.window_analysis import extract_zero_window_events


def _pkt(
    *,
    ts: float,
    src: str = "10.0.0.1",
    sport: int = 40000,
    dst: str = "10.0.0.2",
    dport: int = 5236,
    flags: int = 0x10,
    seq: int = 1,
    ack: int = 1,
    window: int = 65535,
    tcp_len: int = 0,
    frame: int = 1,
    stream: int = 0,
    payload_hex: str = "",
    frame_len: int | None = None,
    cap_len: int | None = None,
) -> PacketSummary:
    fl = frame_len if frame_len is not None else (54 + tcp_len)
    cl = cap_len if cap_len is not None else fl
    return PacketSummary(
        timestamp=ts,
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        tcp_flags=flags,
        tcp_seq=seq,
        tcp_ack=ack,
        tcp_window=window,
        tcp_len=tcp_len,
        frame_number=frame,
        tcp_stream=stream,
        frame_len=fl,
        cap_len=cl,
        payload_hex=payload_hex,
    )


# --- seq/ack ---


def test_expected_ack_normal_data():
    # Seq=4453 Len=73 → Expected ACK=4526
    assert expected_ack(4453, 73) == 4526


def test_expected_ack_syn():
    assert expected_ack(1000, 0, syn=True) == 1001


def test_expected_ack_fin():
    assert expected_ack(2000, 0, fin=True) == 2001


def test_expected_ack_syn_plus_payload():
    assert expected_ack(1000, 20, syn=True) == 1021


def test_expected_ack_fin_plus_payload():
    assert expected_ack(2000, 10, fin=True) == 2011


def test_expected_ack_from_packet_flags():
    syn = _pkt(ts=1.0, flags=0x02, seq=100, tcp_len=0)
    fin = _pkt(ts=2.0, flags=0x11, seq=200, tcp_len=5)  # FIN+ACK
    assert expected_ack_from_packet(syn) == 101
    assert expected_ack_from_packet(fin) == 206


# --- handshake ---


def test_normal_three_way_handshake_latency():
    pkts = [
        _pkt(ts=1.000, flags=0x02, seq=100, ack=0, frame=1),  # SYN
        _pkt(  # SYN+ACK
            ts=1.050,
            src="10.0.0.2",
            sport=5236,
            dst="10.0.0.1",
            dport=40000,
            flags=0x12,
            seq=500,
            ack=101,
            frame=2,
        ),
        _pkt(ts=1.060, flags=0x10, seq=101, ack=501, frame=3),  # ACK
    ]
    hs = extract_handshake(pkts)
    assert hs.complete is True
    assert hs.latency_ms == pytest.approx(50.0, abs=0.01)
    assert hs.latency_ms < 1000  # never Epoch-scale


def test_missing_syn_handshake_is_na():
    pkts = [
        _pkt(  # SYN+ACK only
            ts=100.0,
            src="10.0.0.2",
            sport=5236,
            dst="10.0.0.1",
            dport=40000,
            flags=0x12,
            seq=500,
            ack=101,
            frame=1,
        ),
        _pkt(ts=100.01, flags=0x10, seq=101, ack=501, frame=2),
    ]
    hs = extract_handshake(pkts)
    assert hs.syn_ts is None
    assert hs.latency_ms is None  # N/A — must NOT be timestamp - 0


def test_handshake_never_uses_timestamp_minus_zero():
    hs = extract_handshake([])
    assert hs.latency_ms is None


# --- session / tcp.stream ---


def test_sessions_keyed_by_tcp_stream():
    pkts = [
        _pkt(ts=1.0, stream=7, frame=1, flags=0x02, seq=1),
        _pkt(
            ts=1.1,
            src="10.0.0.2",
            sport=5236,
            dst="10.0.0.1",
            dport=40000,
            stream=7,
            frame=2,
            flags=0x12,
            seq=100,
            ack=2,
        ),
        _pkt(ts=2.0, stream=8, sport=40001, frame=3, flags=0x02, seq=1),
    ]
    sessions = group_into_sessions(pkts, db_port=5236)
    assert 7 in sessions
    assert 8 in sessions
    assert sessions[7].packet_count == 2
    assert sessions[7].key.server_port == 5236


# --- retransmission ---


def test_same_segment_persistent_retransmission():
    payload = "aabbcc"
    phash = payload_sha256(payload)
    pkts = [
        _pkt(ts=1.0, flags=0x18, seq=4453, tcp_len=73, payload_hex=payload, frame=10, stream=1),
        _pkt(ts=1.5, flags=0x18, seq=4453, tcp_len=73, payload_hex=payload, frame=11, stream=1),
        _pkt(ts=2.0, flags=0x18, seq=4453, tcp_len=73, payload_hex=payload, frame=12, stream=1),
        _pkt(ts=2.5, flags=0x18, seq=4453, tcp_len=73, payload_hex=payload, frame=13, stream=1),
    ]
    sessions = group_into_sessions(pkts, 5236)
    retx = detect_persistent_retransmissions(sessions[1], DEFAULT_THRESHOLDS)
    assert len(retx) == 1
    assert retx[0].count == 4
    assert retx[0].seq == 4453
    assert retx[0].tcp_len == 73
    assert retx[0].payload_sha256 == phash
    assert retx[0].expected_ack == 4526
    assert retx[0].frames == [10, 11, 12, 13]
    assert retx[0].duration_ms == pytest.approx(1500.0, abs=0.1)


def test_same_seq_len_different_payload_not_same_segment():
    pkts = [
        _pkt(ts=1.0, flags=0x18, seq=100, tcp_len=4, payload_hex="aaaa", frame=1, stream=2),
        _pkt(ts=1.1, flags=0x18, seq=100, tcp_len=4, payload_hex="bbbb", frame=2, stream=2),
    ]
    sessions = group_into_sessions(pkts, 5236)
    retx = detect_persistent_retransmissions(sessions[2], DEFAULT_THRESHOLDS)
    assert retx == []


# --- ACK stalled ---


def test_ack_stalled_detected():
    th = ThresholdConfig(ack_stall_ms=500, retx_high_count=3, retx_high_duration_ms=500)
    payload = "deadbeef"
    # Server sends Seq=5810 Len=124 repeatedly; client ACK stuck at 5810
    pkts = [
        _pkt(  # server → client data
            ts=10.0,
            src="10.0.0.2",
            sport=5236,
            dst="10.0.0.1",
            dport=40000,
            flags=0x18,
            seq=5810,
            ack=100,
            tcp_len=124,
            payload_hex=payload,
            frame=100,
            stream=3,
        ),
        _pkt(  # client ACK stuck
            ts=10.1,
            flags=0x10,
            seq=100,
            ack=5810,
            frame=101,
            stream=3,
        ),
        _pkt(
            ts=11.0,
            src="10.0.0.2",
            sport=5236,
            dst="10.0.0.1",
            dport=40000,
            flags=0x18,
            seq=5810,
            ack=100,
            tcp_len=124,
            payload_hex=payload,
            frame=102,
            stream=3,
        ),
        _pkt(ts=11.1, flags=0x10, seq=100, ack=5810, frame=103, stream=3),
        _pkt(
            ts=12.0,
            src="10.0.0.2",
            sport=5236,
            dst="10.0.0.1",
            dport=40000,
            flags=0x18,
            seq=5810,
            ack=100,
            tcp_len=124,
            payload_hex=payload,
            frame=104,
            stream=3,
        ),
        _pkt(ts=12.1, flags=0x10, seq=100, ack=5810, frame=105, stream=3),
    ]
    sessions = group_into_sessions(pkts, 5236)
    retx = detect_persistent_retransmissions(sessions[3], th)
    stalled = detect_ack_stalled(sessions[3], retx, th)
    assert stalled
    assert stalled[0].expected_ack == 5934
    assert stalled[0].observed_ack == 5810
    assert stalled[0].seq == 5810
    assert stalled[0].tcp_len == 124


def test_ack_normal_advance_not_stalled():
    th = ThresholdConfig(ack_stall_ms=500)
    payload = "cafebabe"
    pkts = [
        _pkt(
            ts=1.0,
            src="10.0.0.2",
            sport=5236,
            dst="10.0.0.1",
            dport=40000,
            flags=0x18,
            seq=5810,
            tcp_len=124,
            payload_hex=payload,
            frame=1,
            stream=4,
        ),
        _pkt(ts=1.05, flags=0x10, seq=1, ack=5934, frame=2, stream=4),  # ACK advanced
    ]
    sessions = group_into_sessions(pkts, 5236)
    retx = detect_persistent_retransmissions(sessions[4], th)
    stalled = detect_ack_stalled(sessions[4], retx, th)
    assert stalled == []


# --- RST classification ---


def test_rst_after_syn():
    pkts = [
        _pkt(ts=1.0, flags=0x02, seq=1, frame=1, stream=5),
        _pkt(
            ts=1.01,
            src="10.0.0.2",
            sport=5236,
            dst="10.0.0.1",
            dport=40000,
            flags=0x14,  # RST+ACK
            seq=0,
            ack=2,
            frame=2,
            stream=5,
        ),
    ]
    sessions = group_into_sessions(pkts, 5236)
    events = classify_rst(sessions[5], DEFAULT_THRESHOLDS)
    assert events[0].classification.value == "RST_AFTER_SYN"


def test_rst_during_data():
    pkts = [
        _pkt(ts=1.0, flags=0x02, seq=1, frame=1, stream=6),
        _pkt(
            ts=1.01,
            src="10.0.0.2",
            sport=5236,
            dst="10.0.0.1",
            dport=40000,
            flags=0x12,
            seq=100,
            ack=2,
            frame=2,
            stream=6,
        ),
        _pkt(ts=1.02, flags=0x10, seq=2, ack=101, frame=3, stream=6),
        _pkt(ts=1.10, flags=0x18, seq=2, ack=101, tcp_len=50, payload_hex="aa" * 50, frame=4, stream=6),
        _pkt(
            ts=1.20,
            src="10.0.0.2",
            sport=5236,
            dst="10.0.0.1",
            dport=40000,
            flags=0x04,
            seq=101,
            frame=5,
            stream=6,
        ),
    ]
    sessions = group_into_sessions(pkts, 5236)
    events = classify_rst(sessions[6], DEFAULT_THRESHOLDS)
    assert events[0].classification.value == "RST_DURING_DATA"


def test_ack_to_rst():
    pkts = [
        _pkt(ts=1.0, flags=0x02, seq=1, frame=1, stream=7),
        _pkt(
            ts=1.01,
            src="10.0.0.2",
            sport=5236,
            dst="10.0.0.1",
            dport=40000,
            flags=0x12,
            seq=100,
            ack=2,
            frame=2,
            stream=7,
        ),
        _pkt(ts=1.02, flags=0x10, seq=2, ack=101, frame=3, stream=7),
        _pkt(ts=1.10, flags=0x18, seq=2, tcp_len=10, payload_hex="aabbccddee", frame=4, stream=7),
        _pkt(
            ts=1.11,
            src="10.0.0.2",
            sport=5236,
            dst="10.0.0.1",
            dport=40000,
            flags=0x10,
            seq=101,
            ack=12,
            tcp_len=0,
            frame=5,
            stream=7,
        ),  # pure ACK
        _pkt(
            ts=1.12,
            src="10.0.0.2",
            sport=5236,
            dst="10.0.0.1",
            dport=40000,
            flags=0x04,
            seq=101,
            frame=6,
            stream=7,
        ),  # RST after ACK
    ]
    sessions = group_into_sessions(pkts, 5236)
    events = classify_rst(sessions[7], DEFAULT_THRESHOLDS)
    assert events[0].classification.value == "ACK_TO_RST"


def test_rst_after_fin():
    pkts = [
        _pkt(ts=1.0, flags=0x02, seq=1, frame=1, stream=8),
        _pkt(
            ts=1.01,
            src="10.0.0.2",
            sport=5236,
            dst="10.0.0.1",
            dport=40000,
            flags=0x12,
            seq=100,
            ack=2,
            frame=2,
            stream=8,
        ),
        _pkt(ts=1.02, flags=0x10, seq=2, ack=101, frame=3, stream=8),
        _pkt(ts=2.0, flags=0x11, seq=2, ack=101, frame=4, stream=8),  # FIN+ACK
        _pkt(
            ts=2.1,
            src="10.0.0.2",
            sport=5236,
            dst="10.0.0.1",
            dport=40000,
            flags=0x14,
            seq=101,
            ack=3,
            frame=5,
            stream=8,
        ),  # RST after FIN
    ]
    sessions = group_into_sessions(pkts, 5236)
    events = classify_rst(sessions[8], DEFAULT_THRESHOLDS)
    assert events[0].classification.value == "RST_AFTER_FIN"
    assert events[0].severity.value == "INFO"


# --- zero window / truncation / payload hash ---


def test_zero_window_detection():
    pkts = [
        _pkt(ts=1.0, flags=0x10, window=0, frame=1, stream=9),
        _pkt(ts=1.5, flags=0x10, window=0, frame=2, stream=9),
        _pkt(ts=2.0, flags=0x10, window=1000, frame=3, stream=9),
    ]
    sessions = group_into_sessions(pkts, 5236)
    events = extract_zero_window_events(sessions[9])
    assert len(events) == 1
    assert events[0].duration_ms == pytest.approx(1000.0, abs=0.1)


def test_packet_truncated():
    pkts = [
        _pkt(ts=1.0, frame=1, frame_len=1500, cap_len=128, tcp_len=0),
        _pkt(ts=1.1, frame=2, frame_len=1500, cap_len=128, tcp_len=0),
        _pkt(ts=1.2, frame=3, frame_len=100, cap_len=100, tcp_len=0),
    ]
    q = analyze_capture_quality(pkts, DEFAULT_THRESHOLDS)
    assert q.truncated_packets == 2
    assert q.snaplen_hint is not None
    assert "128" in q.snaplen_hint
    assert q.credibility in ("DEGRADED", "LOW")


def test_payload_sha256():
    raw = bytes.fromhex("01020304")
    assert payload_sha256("01020304") == hashlib.sha256(raw).hexdigest()


def test_end_to_end_report_builds():
    pkts = [
        _pkt(ts=1.0, flags=0x02, seq=1, frame=1, stream=0),
        _pkt(
            ts=1.02,
            src="10.0.0.2",
            sport=5236,
            dst="10.0.0.1",
            dport=40000,
            flags=0x12,
            seq=100,
            ack=2,
            frame=2,
            stream=0,
        ),
        _pkt(ts=1.03, flags=0x10, seq=2, ack=101, frame=3, stream=0),
    ]
    sessions = group_into_sessions(pkts, 5236)
    report = build_analysis_report(sessions, DEFAULT_THRESHOLDS, 5236, "synthetic.pcap", pkts)
    assert report.summary["total_sessions"] == 1
    assert report.sessions[0].handshake_latency_ms == pytest.approx(20.0, abs=0.01)


def test_control_plane_retransmission_not_ack_stalled_and_not_high():
    """Pure SYN retransmissions are CONTROL_PLANE and never ACK_STALLED."""
    pkts = [
        _pkt(ts=1.0, flags=0x02, seq=0, tcp_len=0, frame=1, stream=20),
        _pkt(ts=2.0, flags=0x02, seq=0, tcp_len=0, frame=2, stream=20),
        _pkt(ts=3.0, flags=0x02, seq=0, tcp_len=0, frame=3, stream=20),
        _pkt(ts=4.5, flags=0x02, seq=0, tcp_len=0, frame=4, stream=20),
    ]
    sessions = group_into_sessions(pkts, 5236)
    th = ThresholdConfig(retx_high_count=3, retx_high_duration_ms=1000, ack_stall_ms=500)
    retx = detect_persistent_retransmissions(sessions[20], th)
    assert len(retx) == 1
    assert retx[0].plane == "control"
    assert retx[0].anomaly_type == "CONTROL_PLANE_RETRANSMISSION"
    assert retx[0].severity.value != "HIGH"
    stalled = detect_ack_stalled(sessions[20], retx, th)
    assert stalled == []


def test_data_retransmission_classified():
    payload = "aabb"
    pkts = [
        _pkt(ts=1.0, flags=0x18, seq=100, tcp_len=2, payload_hex=payload, frame=1, stream=21),
        _pkt(ts=2.5, flags=0x18, seq=100, tcp_len=2, payload_hex=payload, frame=2, stream=21),
        _pkt(ts=3.5, flags=0x18, seq=100, tcp_len=2, payload_hex=payload, frame=3, stream=21),
    ]
    sessions = group_into_sessions(pkts, 5236)
    th = ThresholdConfig(retx_high_count=3, retx_high_duration_ms=1000)
    retx = detect_persistent_retransmissions(sessions[21], th)
    assert retx[0].plane == "data"
    assert retx[0].anomaly_type == "DATA_RETRANSMISSION"
    assert retx[0].severity == Severity.HIGH
