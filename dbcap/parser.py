"""Compatibility shim — prefer dbcap.session / dbcap.handshake / dbcap.window_analysis."""

from dbcap.handshake import extract_handshake
from dbcap.models import PacketSummary, TcpSession
from dbcap.rst_analysis import classify_rst
from dbcap.session import (
    group_into_flows,
    group_into_sessions,
    packet_direction,
)
from dbcap.window_analysis import extract_zero_window_events as _zw_session


def detect_rst(packets: list[PacketSummary]) -> bool:
    return any(p.rst for p in packets)


def extract_zero_window_events(packets: list[PacketSummary]):
    """Legacy signature accepting a bare packet list."""
    # Minimal session wrapper for compatibility
    from dbcap.models import FlowKey

    key = FlowKey(
        src_ip="0.0.0.0",
        src_port=0,
        dst_ip="0.0.0.0",
        dst_port=0,
        server_ip="0.0.0.0",
        server_port=0,
    )
    session = TcpSession(tcp_stream=-1, key=key, packets=list(packets))
    return _zw_session(session)


def get_forward_sequence_numbers(packets, server_ip, server_port):
    result = []
    for pkt in packets:
        if pkt.dst_ip == server_ip and pkt.dst_port == server_port:
            result.append((pkt.tcp_seq, pkt.tcp_len, pkt.timestamp))
    return result


def get_reverse_sequence_numbers(packets, server_ip, server_port):
    result = []
    for pkt in packets:
        if pkt.src_ip == server_ip and pkt.src_port == server_port:
            result.append((pkt.tcp_seq, pkt.tcp_len, pkt.timestamp))
    return result


__all__ = [
    "group_into_flows",
    "group_into_sessions",
    "extract_handshake",
    "detect_rst",
    "extract_zero_window_events",
    "get_forward_sequence_numbers",
    "get_reverse_sequence_numbers",
    "packet_direction",
    "classify_rst",
]
