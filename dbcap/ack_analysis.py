"""ACK advancement / ACK_STALLED detection."""

from __future__ import annotations

from dbcap.models import (
    AckStalledEvent,
    EvidenceLevel,
    PacketSummary,
    PersistentRetransmission,
    Severity,
    TcpSession,
    ThresholdConfig,
)
from dbcap.seq_ack import advances_seq_space, expected_ack_from_packet
from dbcap.session import packet_direction


def _opposite(direction: str) -> str:
    if direction == "client_to_server":
        return "server_to_client"
    if direction == "server_to_client":
        return "client_to_server"
    return "unknown"


def _ack_series(session: TcpSession, ack_direction: str) -> list[tuple[float, int, int | None]]:
    """Return (ts, ack, frame) for packets in ack_direction that carry ACK."""
    out = []
    for pkt in session.packets:
        d = packet_direction(pkt, session.key.server_ip, session.key.server_port)
        if d != ack_direction:
            continue
        if not pkt.ack_flag:
            continue
        out.append((pkt.timestamp, pkt.tcp_ack, pkt.frame_number))
    return out


def _max_ack_at_or_before(acks: list[tuple[float, int, int | None]], ts: float) -> int | None:
    """Track cumulative ACK: return highest ACK observed at or before ts."""
    best: int | None = None
    for t, ack, _ in acks:
        if t > ts:
            break
        if best is None or ack > best:
            best = ack
    return best


def detect_ack_stalled(
    session: TcpSession,
    persistent_retx: list[PersistentRetransmission],
    thresholds: ThresholdConfig,
) -> list[AckStalledEvent]:
    """
    Detect ACK_STALLED:

    Sender repeatedly transmits the same segment (seq, len, hash),
    while the peer's cumulative ACK remains below Expected ACK for
    longer than thresholds.ack_stall_ms.

    Uses cumulative ACK tracking — a single smaller ACK does not
    immediately mark anomaly if a higher ACK was already seen.
    """
    events: list[AckStalledEvent] = []

    for retx in persistent_retx:
        if retx.count < 2:
            continue
        if retx.duration_ms < thresholds.ack_stall_ms:
            continue
        # ACK_STALLED applies to data segments; pure SYN/FIN handshake
        # retransmissions are reported separately and must not invent stalls.
        if retx.tcp_len <= 0:
            continue

        ack_dir = _opposite(retx.direction)
        acks = _ack_series(session, ack_dir)
        acks.sort(key=lambda x: x[0])

        # Observed ACK over the retransmission window (cumulative max)
        observed: int | None = None
        for t, ack, _ in acks:
            if t < retx.first_ts:
                if observed is None or ack > observed:
                    observed = ack
                continue
            if t > retx.last_ts:
                break
            if observed is None or ack > observed:
                observed = ack

        if observed is None:
            # No ACK observed from peer in capture — still report as stalled
            observed = 0

        if observed >= retx.expected_ack:
            continue  # peer did advance past this segment

        frames = list(retx.frames)
        frame_filter = " || ".join(f"frame.number == {n}" for n in frames[:30])
        ws_filter = f"tcp.stream eq {session.tcp_stream}"
        if frame_filter:
            ws_filter = f"{ws_filter} && ({frame_filter})"

        events.append(
            AckStalledEvent(
                tcp_stream=session.tcp_stream,
                send_direction=retx.direction,
                seq=retx.seq,
                tcp_len=retx.tcp_len,
                expected_ack=retx.expected_ack,
                observed_ack=observed,
                stall_duration_ms=retx.duration_ms,
                retransmission_count=retx.count,
                frames=frames,
                severity=Severity.HIGH,
                wireshark_filter=ws_filter,
                evidence_level=EvidenceLevel.CONFIRMED,
            )
        )

    return events


def explain_ack_stalled(ev: AckStalledEvent) -> str:
    sender = (
        "数据库服务器"
        if ev.send_direction == "server_to_client"
        else "应用服务器"
    )
    peer = (
        "应用服务器"
        if ev.send_direction == "server_to_client"
        else "数据库服务器"
    )
    return (
        f"{sender}重复发送同一段 {ev.tcp_len} 字节数据（Seq={ev.seq}），"
        f"但{peer}返回的 TCP 确认号长期没有前进。\n"
        f"理论上应收到 ACK={ev.expected_ack}，"
        f"实际持续观察到 ACK={ev.observed_ack}。\n"
        f"说明这段数据在当前抓包观察范围内没有得到对端正常确认。"
        f"（未推进约 {ev.stall_duration_ms:.1f} ms，重复 {ev.retransmission_count} 次）"
    )
