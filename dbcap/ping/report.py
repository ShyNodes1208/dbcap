"""Ping CSV exporters."""

from __future__ import annotations

import csv
import os
from typing import Optional

from dbcap.ping.models import PingAnalysisResult


def _na(v) -> str:
    return "" if v is None else str(v)


def export_ping_events_csv(result: PingAnalysisResult, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fields = [
        "timestamp",
        "timestamp_raw",
        "target_host",
        "status",
        "rtt_ms",
        "ttl",
        "icmp_seq",
        "source_file",
        "source_line",
        "raw_excerpt",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for e in result.events:
            w.writerow(
                {
                    "timestamp": _na(e.timestamp),
                    "timestamp_raw": e.timestamp_raw,
                    "target_host": e.target_host or "",
                    "status": e.status,
                    "rtt_ms": _na(e.rtt_ms),
                    "ttl": _na(e.ttl),
                    "icmp_seq": _na(e.icmp_seq),
                    "source_file": e.source_file,
                    "source_line": e.source_line,
                    "raw_excerpt": e.raw_excerpt,
                }
            )
    return path


def export_ping_correlation_csv(result: PingAnalysisResult, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fields = [
        "event_id",
        "jdbc_timestamp_raw",
        "target_host",
        "window_seconds",
        "samples",
        "replies",
        "timeouts",
        "unreachable",
        "errors",
        "min_rtt_ms",
        "avg_rtt_ms",
        "max_rtt_ms",
        "last_reply_before",
        "first_reply_after",
        "nearest_timeout_before",
        "nearest_timeout_after",
        "summary",
        "evidence_class",
        "caution",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for c in result.correlations:
            w.writerow(
                {
                    "event_id": c.event_id,
                    "jdbc_timestamp_raw": c.jdbc_timestamp_raw,
                    "target_host": c.target_host or "",
                    "window_seconds": c.window_seconds,
                    "samples": c.samples,
                    "replies": c.replies,
                    "timeouts": c.timeouts,
                    "unreachable": c.unreachable,
                    "errors": c.errors,
                    "min_rtt_ms": _na(c.min_rtt_ms),
                    "avg_rtt_ms": _na(c.avg_rtt_ms),
                    "max_rtt_ms": _na(c.max_rtt_ms),
                    "last_reply_before": _na(c.last_reply_before),
                    "first_reply_after": _na(c.first_reply_after),
                    "nearest_timeout_before": _na(c.nearest_timeout_before),
                    "nearest_timeout_after": _na(c.nearest_timeout_after),
                    "summary": c.summary,
                    "evidence_class": c.evidence_class,
                    "caution": c.caution,
                }
            )
    return path


def export_all_ping(result: PingAnalysisResult, output_dir: str) -> dict[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    out: dict[str, str] = {}
    if not result.provided:
        return out
    out["ping_events_csv"] = export_ping_events_csv(
        result, os.path.join(output_dir, "ping_events.csv")
    )
    out["ping_correlation_csv"] = export_ping_correlation_csv(
        result, os.path.join(output_dir, "ping_correlation.csv")
    )
    return out
