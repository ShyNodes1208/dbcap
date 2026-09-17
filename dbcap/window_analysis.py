"""TCP window / zero-window analysis."""

from __future__ import annotations

from typing import Optional

from dbcap.models import PacketSummary, TcpSession, ZeroWindowEvent
from dbcap.session import packet_direction


def extract_zero_window_events(session: TcpSession) -> list[ZeroWindowEvent]:
    """
    Detect zero-window advertisements.

    RST/FIN packets with window=0 are ignored (not real ZW conditions).
    """
    events: list[ZeroWindowEvent] = []
    current: Optional[ZeroWindowEvent] = None

    for pkt in session.packets:
        is_ctl = pkt.rst or pkt.fin
        direction = packet_direction(pkt, session.key.server_ip, session.key.server_port)

        if pkt.tcp_window == 0 and not is_ctl:
            if current is None:
                current = ZeroWindowEvent(
                    start_ts=pkt.timestamp,
                    direction=direction,
                    frames=[pkt.frame_number] if pkt.frame_number is not None else [],
                )
            else:
                if pkt.frame_number is not None:
                    current.frames.append(pkt.frame_number)
        else:
            if current is not None:
                current.end_ts = pkt.timestamp
                events.append(current)
                current = None

    if current is not None:
        events.append(current)

    return events
