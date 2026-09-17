"""Wireshark display filter helpers for human verification."""

from __future__ import annotations

from typing import Iterable, Optional


def stream_filter(tcp_stream: int) -> str:
    return f"tcp.stream eq {tcp_stream}"


def frame_filter(frames: Iterable[int]) -> str:
    frames = list(frames)
    if not frames:
        return ""
    return " || ".join(f"frame.number == {n}" for n in frames)


def retransmission_filter(tcp_stream: int, frames: Optional[Iterable[int]] = None) -> str:
    base = (
        f"tcp.stream eq {tcp_stream} && "
        f"(tcp.analysis.retransmission || "
        f"tcp.analysis.fast_retransmission || "
        f"tcp.analysis.spurious_retransmission)"
    )
    if frames:
        ff = frame_filter(frames)
        if ff:
            return f"({base}) || ({ff})"
    return base
