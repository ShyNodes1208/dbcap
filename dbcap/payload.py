"""Payload extraction and SHA256 helpers for anomalous segments."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from dbcap.models import PacketSummary, PersistentRetransmission, TcpSession
from dbcap.retransmission import payload_sha256
from dbcap.session import packet_direction


def save_anomaly_payloads(
    session: TcpSession,
    retx_list: list[PersistentRetransmission],
    output_dir: str | Path,
) -> list[dict]:
    """
    Save payload bytes for persistently retransmitted segments.

    Layout:
      output/payload/stream_<id>/client_seq_<seq>_len_<len>.bin
      output/payload/stream_<id>/server_seq_<seq>_len_<len>.bin

    If PCAP was truncated, only captured bytes are saved — never invent data.
    """
    saved: list[dict] = []
    if not retx_list:
        return saved

    base = Path(output_dir) / "payload" / f"stream_{session.tcp_stream}"
    base.mkdir(parents=True, exist_ok=True)

    # Index first matching packet per retx key
    wanted = {
        (r.direction, r.seq, r.tcp_len, r.payload_sha256): r for r in retx_list
    }

    seen: set[tuple] = set()
    for pkt in session.packets:
        direction = packet_direction(pkt, session.key.server_ip, session.key.server_port)
        phash = payload_sha256(pkt.payload_hex)
        key = (direction, pkt.tcp_seq, pkt.tcp_len, phash)
        if key not in wanted or key in seen:
            continue
        seen.add(key)

        role = "client" if direction == "client_to_server" else "server"
        filename = f"{role}_seq_{pkt.tcp_seq}_len_{pkt.tcp_len}.bin"
        path = base / filename

        raw = b""
        if pkt.payload_hex:
            try:
                raw = bytes.fromhex(pkt.payload_hex)
            except ValueError:
                raw = b""

        with open(path, "wb") as f:
            f.write(raw)

        saved.append(
            {
                "tcp_stream": session.tcp_stream,
                "direction": direction,
                "seq": pkt.tcp_seq,
                "tcp_len": pkt.tcp_len,
                "sha256": phash,
                "path": str(path),
                "bytes_written": len(raw),
                "truncated": pkt.truncated,
                "note": (
                    "Payload may be incomplete due to snaplen truncation."
                    if pkt.truncated
                    else ""
                ),
            }
        )

    return saved
