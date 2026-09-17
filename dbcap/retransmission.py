"""Persistent TCP segment retransmission detection (with secondary confirmation)."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field

from dbcap.models import (
    EvidenceLevel,
    PacketSummary,
    PersistentRetransmission,
    Severity,
    TcpSession,
    ThresholdConfig,
)
from dbcap.seq_ack import advances_seq_space, expected_ack_from_packet
from dbcap.session import packet_direction


def payload_sha256(payload_hex: str) -> str:
    if not payload_hex:
        return hashlib.sha256(b"").hexdigest()
    try:
        raw = bytes.fromhex(payload_hex)
    except ValueError:
        raw = payload_hex.encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()


def segment_key(
    tcp_stream: int,
    direction: str,
    seq: int,
    tcp_len: int,
    payload_hash: str,
) -> tuple:
    return (tcp_stream, direction, seq, tcp_len, payload_hash)


@dataclass
class _SegBucket:
    frames: list[int] = field(default_factory=list)
    timestamps: list[float] = field(default_factory=list)
    ws_flags: list[bool] = field(default_factory=list)
    expected_ack: int = 0
    direction: str = ""
    seq: int = 0
    tcp_len: int = 0
    payload_sha256: str = ""
    syn: bool = False
    fin: bool = False


def classify_retx_plane(tcp_len: int, syn: bool = False, fin: bool = False) -> str:
    """Distinguish data-plane vs control-plane retransmissions."""
    if tcp_len > 0:
        return "data"
    return "control"


def _severity_for_retx(
    count: int,
    duration_ms: float,
    th: ThresholdConfig,
    plane: str,
) -> Severity:
    if plane == "control":
        # Control-plane (SYN/FIN/len=0) must not share data-plane HIGH severity.
        if count >= th.retx_burst_warn_count or duration_ms >= th.retx_high_duration_ms:
            return Severity.WARNING
        return Severity.INFO
    if count >= th.retx_high_count and duration_ms >= th.retx_high_duration_ms:
        return Severity.HIGH
    if count >= th.retx_burst_warn_count:
        return Severity.WARNING
    return Severity(th.retx_single_severity) if th.retx_single_severity in Severity.__members__ else Severity.INFO


def detect_persistent_retransmissions(
    session: TcpSession,
    thresholds: ThresholdConfig,
) -> list[PersistentRetransmission]:
    """
    Group identical TCP segments and detect continuous retransmission.

    Segment key: (tcp_stream, direction, seq, tcp_len, payload_sha256)

    Wireshark analysis flags are recorded as supporting evidence but are not
    required — identical segment keys are sufficient confirmation.
    """
    buckets: dict[tuple, _SegBucket] = {}

    for pkt in session.packets:
        if not advances_seq_space(pkt):
            continue
        # Keep SYN/FIN retransmissions visible, but segment identity for
        # data-plane analysis is driven by payload-bearing segments.
        direction = packet_direction(pkt, session.key.server_ip, session.key.server_port)
        phash = payload_sha256(pkt.payload_hex)
        key = segment_key(session.tcp_stream, direction, pkt.tcp_seq, pkt.tcp_len, phash)
        if key not in buckets:
            buckets[key] = _SegBucket(
                expected_ack=expected_ack_from_packet(pkt),
                direction=direction,
                seq=pkt.tcp_seq,
                tcp_len=pkt.tcp_len,
                payload_sha256=phash,
                syn=pkt.syn,
                fin=pkt.fin,
            )
        b = buckets[key]
        if pkt.frame_number is not None:
            b.frames.append(pkt.frame_number)
        b.timestamps.append(pkt.timestamp)
        b.ws_flags.append(
            pkt.ws_retransmission or pkt.ws_fast_retransmission or pkt.ws_spurious_retransmission
        )
        b.syn = b.syn or pkt.syn
        b.fin = b.fin or pkt.fin

    results: list[PersistentRetransmission] = []
    for key, b in buckets.items():
        if len(b.timestamps) < 2:
            continue
        first_ts = min(b.timestamps)
        last_ts = max(b.timestamps)
        duration_ms = (last_ts - first_ts) * 1000
        count = len(b.timestamps)
        plane = classify_retx_plane(b.tcp_len, b.syn, b.fin)
        sev = _severity_for_retx(count, duration_ms, thresholds, plane)
        anomaly_type = (
            "DATA_RETRANSMISSION" if plane == "data" else "CONTROL_PLANE_RETRANSMISSION"
        )

        frames = sorted(set(b.frames))
        frame_filter = " || ".join(f"frame.number == {n}" for n in frames[:30])
        ws_filter = (
            f"tcp.stream eq {session.tcp_stream} && "
            f"(tcp.analysis.retransmission || "
            f"tcp.analysis.fast_retransmission || "
            f"tcp.analysis.spurious_retransmission)"
        )
        if frame_filter:
            ws_filter = f"({ws_filter}) || ({frame_filter})"

        results.append(
            PersistentRetransmission(
                tcp_stream=session.tcp_stream,
                direction=b.direction,
                seq=b.seq,
                tcp_len=b.tcp_len,
                payload_sha256=b.payload_sha256,
                count=count,
                first_ts=first_ts,
                last_ts=last_ts,
                duration_ms=round(duration_ms, 3),
                frames=frames,
                expected_ack=b.expected_ack,
                severity=sev,
                wireshark_filter=ws_filter,
                evidence_level=EvidenceLevel.CONFIRMED,
                plane=plane,
                anomaly_type=anomaly_type,
            )
        )

    results.sort(key=lambda r: (-r.count, -r.duration_ms))
    return results


def count_retransmissions(retx_list: list[PersistentRetransmission]) -> int:
    """Total extra transmissions (appearances beyond the first)."""
    return sum(max(0, r.count - 1) for r in retx_list)
