"""Round-3 release tests: R14 capture vs TCP separation, R15 path helpers."""

from __future__ import annotations

from pathlib import Path

from dbcap.analyzer import build_analysis_report
from dbcap.cli import EXIT_ERROR, EXIT_QUALITY, main
from dbcap.models import PacketSummary, Severity
from dbcap.report import export_markdown_report
from dbcap.session import group_into_sessions
from dbcap.thresholds import DEFAULT_THRESHOLDS

_ROOT = Path(__file__).resolve().parents[1]
_TMP = _ROOT / "output" / "_r3_tmp"


def _fresh(name: str) -> Path:
    p = _TMP / name
    p.mkdir(parents=True, exist_ok=True)
    return p


def _trunc_only_packets(n: int = 20) -> list[PacketSummary]:
    """Handshake + idle ACKs with cap_len < frame_len; no TCP fault pattern."""
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
            frame_len=1500,
            cap_len=80,
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
            frame_len=1500,
            cap_len=80,
        ),
        PacketSummary(
            timestamp=1.002,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=40000,
            dst_port=5236,
            tcp_flags=0x10,
            tcp_seq=2,
            tcp_ack=101,
            tcp_window=1000,
            tcp_len=0,
            frame_number=3,
            tcp_stream=0,
            frame_len=1500,
            cap_len=80,
        ),
    ]
    for i in range(3, n):
        pkts.append(
            PacketSummary(
                timestamp=1.0 + i * 0.001,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=40000,
                dst_port=5236,
                tcp_flags=0x10,
                tcp_seq=2,
                tcp_ack=101,
                tcp_window=1000,
                tcp_len=0,
                frame_number=i + 1,
                tcp_stream=0,
                frame_len=1500,
                cap_len=80,
            )
        )
    return pkts


def _trunc_plus_ack_stalled_packets() -> list[PacketSummary]:
    """Truncated frames + repeated data segment without peer ACK advance."""
    pkts: list[PacketSummary] = [
        PacketSummary(
            timestamp=1.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=40000,
            dst_port=5236,
            tcp_flags=0x02,
            tcp_seq=1000,
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
            tcp_seq=5000,
            tcp_ack=1001,
            tcp_window=1000,
            tcp_len=0,
            frame_number=2,
            tcp_stream=0,
            frame_len=74,
            cap_len=74,
        ),
        PacketSummary(
            timestamp=1.002,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=40000,
            dst_port=5236,
            tcp_flags=0x10,
            tcp_seq=1001,
            tcp_ack=5001,
            tcp_window=1000,
            tcp_len=0,
            frame_number=3,
            tcp_stream=0,
            frame_len=74,
            cap_len=74,
        ),
    ]
    # Client repeatedly sends same data segment; server ACKs stay at 1001
    payload = "aabbccddeeff00112233445566778899"
    for i in range(8):
        pkts.append(
            PacketSummary(
                timestamp=2.0 + i * 0.5,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=40000,
                dst_port=5236,
                tcp_flags=0x18,
                tcp_seq=1001,
                tcp_ack=5001,
                tcp_window=1000,
                tcp_len=16,
                frame_number=10 + i,
                tcp_stream=0,
                frame_len=1500,
                cap_len=80,
                payload_hex=payload,
                ws_retransmission=(i > 0),
            )
        )
        # Server ACKs that never reach expected 1017
        pkts.append(
            PacketSummary(
                timestamp=2.05 + i * 0.5,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.1",
                src_port=5236,
                dst_port=40000,
                tcp_flags=0x10,
                tcp_seq=5001,
                tcp_ack=1001,
                tcp_window=1000,
                tcp_len=0,
                frame_number=50 + i,
                tcp_stream=0,
                frame_len=1500,
                cap_len=80,
            )
        )
    return pkts


def test_truncated_only_is_not_high_tcp_fault():
    pkts = _trunc_only_packets()
    sessions = group_into_sessions(pkts, 5236)
    report = build_analysis_report(sessions, DEFAULT_THRESHOLDS, 5236, "trunc.pcap", pkts)
    assert report.summary.get("tcp_health") == "INFO"
    assert report.summary.get("overall") == "INFO"
    assert report.summary.get("high") == 0
    assert "高优先级 TCP 异常" not in (report.conclusion or {}).get("verdict", "")
    out = _fresh("trunc_only_md_r14")
    export_markdown_report(report, str(out))
    md = (out / "report.md").read_text(encoding="utf-8")
    assert "高优先级 TCP 异常（持续重传" not in md
    assert "TCP Health: **INFO**" in md
    assert "PACKET_TRUNCATED" in md or "截断" in md or "Capture Quality" in md or "可信度" in md


def test_truncated_only_capture_quality_warning():
    pkts = _trunc_only_packets()
    sessions = group_into_sessions(pkts, 5236)
    report = build_analysis_report(sessions, DEFAULT_THRESHOLDS, 5236, "trunc.pcap", pkts)
    assert report.capture_quality.truncated_packets > 0
    assert report.summary.get("capture_quality_blocking") is True
    assert report.summary.get("analysis_status") == "WARNING"
    trunc = [a for a in report.anomalies if a.type == "PACKET_TRUNCATED"]
    assert trunc
    assert trunc[0].severity == Severity.WARNING
    assert trunc[0].evidence_level.value == "CONFIRMED"


def test_truncated_only_analysis_confidence_degraded():
    pkts = _trunc_only_packets()
    sessions = group_into_sessions(pkts, 5236)
    report = build_analysis_report(sessions, DEFAULT_THRESHOLDS, 5236, "trunc.pcap", pkts)
    assert report.summary.get("analysis_confidence") in ("DEGRADED", "LOW")
    out = _fresh("trunc_md")
    export_markdown_report(report, str(out))
    md = (out / "report.md").read_text(encoding="utf-8")
    assert "未确认高优先级 TCP 故障" in md or "TCP Health: **INFO**" in md
    assert "高优先级 TCP 异常（持续重传" not in md


def test_truncated_plus_ack_stalled_keeps_tcp_high():
    pkts = _trunc_plus_ack_stalled_packets()
    sessions = group_into_sessions(pkts, 5236)
    report = build_analysis_report(sessions, DEFAULT_THRESHOLDS, 5236, "both.pcap", pkts)
    assert report.capture_quality.truncated_packets > 0
    assert report.summary.get("tcp_health") == "HIGH"
    assert report.summary.get("overall") == "HIGH"
    assert report.summary.get("capture_quality_blocking") is True
    assert any(a.type == "PACKET_TRUNCATED" for a in report.anomalies)
    assert report.ack_stalled or any(
        a.type in ("ACK_STALLED", "DATA_RETRANSMISSION") for a in report.anomalies
    )
    out = _fresh("trunc_plus_high_md")
    export_markdown_report(report, str(out))
    md = (out / "report.md").read_text(encoding="utf-8")
    assert "TCP Health: **HIGH**" in md
    assert "高优先级 TCP 异常" in md


def test_evidence_level_confirmed_does_not_force_high():
    pkts = _trunc_only_packets()
    sessions = group_into_sessions(pkts, 5236)
    report = build_analysis_report(sessions, DEFAULT_THRESHOLDS, 5236, "trunc.pcap", pkts)
    trunc = next(a for a in report.anomalies if a.type == "PACKET_TRUNCATED")
    assert trunc.evidence_level.value == "CONFIRMED"
    assert trunc.severity != Severity.HIGH
    assert report.summary.get("tcp_health") != "HIGH"


def test_cli_non_numeric_port_is_exit_error():
    rc = main(["-f", "x.pcap", "-p", "abc"])
    assert rc == EXIT_ERROR


def test_cli_unknown_arg_is_exit_error():
    rc = main(["--not-a-real-flag"])
    assert rc == EXIT_ERROR
