"""Capture integrity / truncation checks."""

from __future__ import annotations

from collections import Counter
from typing import Iterable

from dbcap.models import CaptureQuality, PacketSummary, ThresholdConfig


def analyze_capture_quality(
    packets: Iterable[PacketSummary],
    thresholds: ThresholdConfig,
    *,
    file_cut_short: bool = False,
    file_warning: str | None = None,
) -> CaptureQuality:
    """
    Detect PACKET_TRUNCATED when cap_len < frame.len.

    If many packets share cap_len == 128, hint snaplen=128 (not absolute proof).
    file_cut_short: TShark exit 14 / "cut short" with recovered packets.
    """
    pkts = list(packets)
    total = len(pkts)
    truncated = [p for p in pkts if p.truncated]
    truncated_count = len(truncated)
    ratio = (truncated_count / total) if total else 0.0

    cap_lens = [p.cap_len for p in pkts if p.cap_len is not None]
    common_cap_len = None
    snaplen_hint = None
    if cap_lens:
        common_cap_len, common_count = Counter(cap_lens).most_common(1)[0]
        if common_cap_len == 128 and common_count / len(cap_lens) >= 0.5:
            snaplen_hint = (
                "大量报文 Captured Length = 128，高度符合 snaplen=128 的特征，"
                "但不能绝对确认抓包工具配置。"
            )

    if ratio >= thresholds.truncated_high_ratio:
        credibility = "LOW"
    elif ratio >= thresholds.truncated_warn_ratio or truncated_count > 0:
        credibility = "DEGRADED"
    else:
        credibility = "HIGH"

    # File trailer cut-short: packets may be usable, but completeness is not OK.
    warn = file_warning
    if file_cut_short:
        if credibility == "HIGH":
            credibility = "DEGRADED"
        if not warn:
            warn = (
                "TShark reported the capture file was cut short "
                "(often a truncated last packet). Recovered packets were analyzed; "
                "do not treat this as a fully intact capture file."
            )

    return CaptureQuality(
        total_packets=total,
        truncated_packets=truncated_count,
        truncated_ratio=round(ratio, 4),
        common_cap_len=common_cap_len,
        snaplen_hint=snaplen_hint,
        credibility=credibility,
        file_cut_short=file_cut_short,
        file_warning=warn,
    )
