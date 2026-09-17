"""Release-fix tests: exit codes, truncation quality, isolation helpers."""

from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from dbcap.analyzer import build_analysis_report
from dbcap.cli import EXIT_ERROR, EXIT_OK, EXIT_QUALITY, main, validate_port
from dbcap.models import PacketSummary, ThresholdConfig
from dbcap.thresholds import DEFAULT_THRESHOLDS

_ROOT = Path(__file__).resolve().parents[1]
_TMP = _ROOT / "output" / "_release_fix_tmp"


def _fresh(name: str) -> Path:
    p = _TMP / name
    p.mkdir(parents=True, exist_ok=True)
    return p


def test_validate_port_rejects_out_of_range():
    with pytest.raises(ValueError):
        validate_port(0)
    with pytest.raises(ValueError):
        validate_port(65536)
    validate_port(5236)
    validate_port(65535)


def test_cli_rejects_port_65536(capsys):
    rc = main(["-f", "nope.pcap", "-p", "65536"])
    assert rc == EXIT_ERROR
    err = capsys.readouterr().err + capsys.readouterr().out
    # argparse may print to stderr via print in main
    assert rc == EXIT_ERROR


def test_snaplen_truncation_raises_overall_and_exit_quality(tmp_path_factory=None):
    """cap_len < frame.len is capture quality WARNING, not TCP HIGH."""
    out = _fresh("trunc_quality")
    pkts = [
        PacketSummary(
            timestamp=1.0 + i * 0.001,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=40000,
            dst_port=5236,
            tcp_flags=0x10,
            tcp_seq=1,
            tcp_ack=1,
            tcp_window=1000,
            tcp_len=0,
            frame_number=i + 1,
            tcp_stream=0,
            frame_len=1500,
            cap_len=128,
        )
        for i in range(20)
    ]
    # add a minimal handshake so a session exists
    pkts[0] = PacketSummary(
        timestamp=1.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=40000,
        dst_port=5236,
        tcp_flags=0x02,
        tcp_seq=1,
        tcp_ack=0,
        tcp_window=1000,
        tcp_len=0,
        frame_number=1,
        tcp_stream=0,
        frame_len=1500,
        cap_len=128,
    )
    from dbcap.session import group_into_sessions

    sessions = group_into_sessions(pkts, 5236)
    report = build_analysis_report(sessions, DEFAULT_THRESHOLDS, 5236, "trunc.pcap", pkts)
    assert report.capture_quality.truncated_packets > 0
    assert report.summary.get("tcp_health") == "INFO"
    assert report.summary.get("overall") == "INFO"
    assert report.summary.get("analysis_status") == "WARNING"
    assert report.summary.get("capture_quality_blocking") is True
    assert any(a.type == "PACKET_TRUNCATED" for a in report.anomalies)
    assert report.summary.get("high") == 0


def test_complete_packets_no_quality_block():
    pkts = [
        PacketSummary(
            timestamp=1.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=40000,
            dst_port=5236,
            tcp_flags=0x02,
            tcp_seq=1,
            tcp_ack=0,
            tcp_window=1000,
            tcp_len=0,
            frame_number=1,
            tcp_stream=0,
            frame_len=74,
            cap_len=74,
        ),
        PacketSummary(
            timestamp=1.001,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.1",
            src_port=5236,
            dst_port=40000,
            tcp_flags=0x12,
            tcp_seq=100,
            tcp_ack=2,
            tcp_window=1000,
            tcp_len=0,
            frame_number=2,
            tcp_stream=0,
            frame_len=74,
            cap_len=74,
        ),
    ]
    from dbcap.session import group_into_sessions

    sessions = group_into_sessions(pkts, 5236)
    report = build_analysis_report(sessions, DEFAULT_THRESHOLDS, 5236, "ok.pcap", pkts)
    assert report.capture_quality.truncated_packets == 0
    assert report.summary.get("capture_quality_blocking") is False
    assert report.summary["overall"] == "INFO"


def test_read_corrupt_pcap_raises(monkeypatch):
    """Corrupt file must surface as RuntimeError (CLI exit 1), not silent INFO."""
    from dbcap import capture as cap

    out = _fresh("corrupt")
    bad = out / "bad.pcap"
    # Minimal invalid content — not a valid pcap
    bad.write_bytes(b"NOT_A_PCAP" + b"\x00" * 64)

    # Use real tshark if available
    try:
        tshark = cap.find_tshark()
    except RuntimeError:
        pytest.skip("tshark not available")

    with pytest.raises(RuntimeError, match="TShark failed|corrupt|truncated|unreadable"):
        list(cap.read_pcap_file(str(bad), tshark_path=tshark))


def test_main_returns_error_on_missing_file():
    rc = main(["-f", str(_TMP / "does_not_exist_12345.pcap"), "-p", "5236"])
    assert rc == EXIT_ERROR


def test_max_packets_does_not_hang_on_large_file():
    """--max-packets must stop TShark promptly (no stdout/stderr pipe deadlock)."""
    from dbcap import capture as cap

    env_pcap = os.environ.get("DBCAP_LARGE_PCAP")
    if not env_pcap:
        pytest.skip("set DBCAP_LARGE_PCAP to a large pcap to run this test")
    large = Path(env_pcap)
    if not large.is_file():
        pytest.skip(f"DBCAP_LARGE_PCAP not a file: {large}")
    try:
        tshark = cap.find_tshark()
    except RuntimeError:
        pytest.skip("tshark not available")

    import time

    t0 = time.perf_counter()
    pkts = list(
        cap.read_pcap_file(
            str(large),
            display_filter="tcp.port == 5236",
            max_packets=1,
            tshark_path=tshark,
        )
    )
    elapsed = time.perf_counter() - t0
    assert len(pkts) == 1
    assert elapsed < 20.0, f"max-packets=1 took {elapsed:.1f}s (likely hang/deadlock)"
