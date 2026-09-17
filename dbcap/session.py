"""TCP session grouping by tcp.stream (preferred) with 4-tuple fallback."""

from __future__ import annotations

from typing import Iterable, Optional

from dbcap.models import FlowKey, PacketSummary, TcpSession


def _canonical_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> tuple:
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return (src_ip, src_port, dst_ip, dst_port)
    return (dst_ip, dst_port, src_ip, src_port)


def _server_endpoint(pkt: PacketSummary, db_port: int) -> tuple[str, int]:
    if pkt.dst_port == db_port:
        return pkt.dst_ip, pkt.dst_port
    if pkt.src_port == db_port:
        return pkt.src_ip, pkt.src_port
    # Fallback: treat destination as server for first packet
    return pkt.dst_ip, pkt.dst_port


def _make_flow_key(pkt: PacketSummary, db_port: int) -> FlowKey:
    ckey = _canonical_key(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
    server_ip, server_port = _server_endpoint(pkt, db_port)
    return FlowKey(
        src_ip=ckey[0],
        src_port=ckey[1],
        dst_ip=ckey[2],
        dst_port=ckey[3],
        server_ip=server_ip,
        server_port=server_port,
    )


def packet_direction(pkt: PacketSummary, server_ip: str, server_port: int) -> str:
    """Return 'client_to_server' or 'server_to_client'."""
    if pkt.dst_ip == server_ip and pkt.dst_port == server_port:
        return "client_to_server"
    if pkt.src_ip == server_ip and pkt.src_port == server_port:
        return "server_to_client"
    return "unknown"


def group_into_sessions(
    packets: Iterable[PacketSummary],
    db_port: int,
) -> dict[int, TcpSession]:
    """
    Group packets into TCP sessions.

    Prefer tcp.stream as the session id (Wireshark semantics).
    Packets missing tcp.stream fall back to a synthetic negative id
    derived from the canonical 4-tuple (should be rare when using tshark).
    """
    sessions: dict[int, TcpSession] = {}
    fallback_ids: dict[tuple, int] = {}
    next_fallback = -1

    for pkt in packets:
        if pkt.tcp_stream is not None:
            sid = pkt.tcp_stream
        else:
            ckey = _canonical_key(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
            if ckey not in fallback_ids:
                fallback_ids[ckey] = next_fallback
                next_fallback -= 1
            sid = fallback_ids[ckey]
            pkt.tcp_stream = sid

        if sid not in sessions:
            sessions[sid] = TcpSession(tcp_stream=sid, key=_make_flow_key(pkt, db_port))

        session = sessions[sid]
        session.packets.append(pkt)
        if session.start_time is None or pkt.timestamp < session.start_time:
            session.start_time = pkt.timestamp
        if session.end_time is None or pkt.timestamp > session.end_time:
            session.end_time = pkt.timestamp
        if pkt.fin:
            session.fin_seen = True
        if pkt.rst:
            session.rst_seen = True

    return sessions


# Backward-compatible alias used by older call sites / tests
def group_into_flows(
    packets: Iterable[PacketSummary],
    db_port: int,
) -> dict[int, TcpSession]:
    return group_into_sessions(packets, db_port)
