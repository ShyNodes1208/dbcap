"""TCP three-way handshake analysis."""

from __future__ import annotations

from typing import Optional

from dbcap.models import HandshakeEvent, PacketSummary


def extract_handshake(packets: list[PacketSummary]) -> HandshakeEvent:
    """
    Extract SYN / SYN+ACK / ACK handshake.

    handshake_latency_ms = (synack_ts - syn_ts) * 1000 when both present.
    If SYN is missing, latency remains None (N/A). Never computes timestamp - 0.
    """
    hs = HandshakeEvent()

    for pkt in packets:
        if pkt.syn and not pkt.ack_flag:
            if hs.syn_ts is None:
                hs.syn_ts = pkt.timestamp
                hs.syn_frame = pkt.frame_number
            else:
                hs.syn_retransmissions += 1
        elif pkt.syn and pkt.ack_flag:
            # Only accept SYN+ACK after a real SYN was observed
            if hs.syn_ts is not None and hs.synack_ts is None:
                hs.synack_ts = pkt.timestamp
                hs.synack_frame = pkt.frame_number
        elif (
            hs.synack_ts is not None
            and hs.ack_ts is None
            and pkt.ack_flag
            and not pkt.syn
            and not pkt.rst
        ):
            # Completing ACK: typically client → server, no payload preferred
            hs.ack_ts = pkt.timestamp
            hs.ack_frame = pkt.frame_number
            hs.complete = True

    if hs.syn_ts is not None and hs.synack_ts is not None:
        hs.latency_ms = round((hs.synack_ts - hs.syn_ts) * 1000, 3)
    else:
        hs.latency_ms = None  # N/A — never invent Epoch-scale values

    return hs


def handshake_latency_ms(hs: HandshakeEvent) -> Optional[float]:
    """Return latency or None (caller must render as N/A)."""
    return hs.latency_ms
