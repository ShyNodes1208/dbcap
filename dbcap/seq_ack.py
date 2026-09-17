"""Expected ACK calculation (SYN/FIN consume one sequence number each)."""

from __future__ import annotations

from dbcap.models import PacketSummary


def expected_ack(
    seq: int,
    tcp_len: int,
    syn: bool = False,
    fin: bool = False,
) -> int:
    """Return the ACK number a peer should send after receiving this segment."""
    value = seq + tcp_len
    if syn:
        value += 1
    if fin:
        value += 1
    return value


def expected_ack_from_packet(pkt: PacketSummary) -> int:
    """Compute Expected ACK for a packet using Seq/Len/SYN/FIN."""
    return expected_ack(pkt.tcp_seq, pkt.tcp_len, syn=pkt.syn, fin=pkt.fin)


def advances_seq_space(pkt: PacketSummary) -> bool:
    """True if the packet consumes sequence space (payload and/or SYN/FIN)."""
    return pkt.tcp_len > 0 or pkt.syn or pkt.fin
