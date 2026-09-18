"""Parse continuous ping-monitor / Windows ping text logs."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from dbcap.ping.models import (
    STATUS_ERROR,
    STATUS_REPLY,
    STATUS_TIMEOUT,
    STATUS_UNKNOWN,
    STATUS_UNREACHABLE,
    PingEvent,
)

_TS = re.compile(
    r"^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\]\s*(?P<body>.*)$"
)
_LINUX_REPLY = re.compile(
    r"(?P<bytes>\d+)\s+bytes from (?P<host>[\d.]+):\s*"
    r"icmp_seq=(?P<seq>\d+)\s+ttl=(?P<ttl>\d+)\s+time=(?P<rtt>[\d.]+)\s*ms",
    re.I,
)
_WIN_REPLY = re.compile(
    r"Reply from (?P<host>[\d.]+):\s*bytes=(?P<bytes>\d+)\s*"
    r"time(?:=|<)(?P<rtt>[\d.]+)ms\s*TTL=(?P<ttl>\d+)",
    re.I,
)
_NO_ANSWER = re.compile(r"no answer yet for icmp_seq=(?P<seq>\d+)", re.I)
_START = re.compile(r"Ping monitor started:\s*(?P<host>[\d.]+)", re.I)
_PING_BANNER = re.compile(r"^PING\s+(?P<host>[\d.]+)", re.I)


def parse_ping_timestamp(raw: str) -> Optional[float]:
    raw = (raw or "").strip()
    if not raw:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt).timestamp()
        except ValueError:
            continue
    return None


def _classify_body(body: str) -> tuple[str, Optional[str], Optional[float], Optional[int], Optional[int]]:
    body = body.strip()
    m = _LINUX_REPLY.search(body)
    if m:
        return (
            STATUS_REPLY,
            m.group("host"),
            float(m.group("rtt")),
            int(m.group("ttl")),
            int(m.group("seq")),
        )
    m = _WIN_REPLY.search(body)
    if m:
        return (
            STATUS_REPLY,
            m.group("host"),
            float(m.group("rtt")),
            int(m.group("ttl")),
            None,
        )
    m = _NO_ANSWER.search(body)
    if m:
        return STATUS_TIMEOUT, None, None, None, int(m.group("seq"))
    low = body.lower()
    if "request timed out" in low or "请求超时" in body or "传输超时" in body:
        return STATUS_TIMEOUT, None, None, None, None
    if "destination" in low and "unreachable" in low:
        return STATUS_UNREACHABLE, None, None, None, None
    if "无法访问目标主机" in body or "目标主机无法访问" in body:
        return STATUS_UNREACHABLE, None, None, None, None
    if "general failure" in low or "一般故障" in body:
        return STATUS_ERROR, None, None, None, None
    return STATUS_UNKNOWN, None, None, None, None


def parse_ping_log(path: str) -> list[PingEvent]:
    """Linear O(N) parse. Skips banners / unknown non-events without timestamp body of interest."""
    p = Path(path)
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    events: list[PingEvent] = []
    default_host: Optional[str] = None

    for i, line in enumerate(lines, start=1):
        raw = line.rstrip("\n")
        m = _TS.match(raw)
        if not m:
            # malformed / no timestamp — skip as event (still countable via tests)
            continue
        ts_raw = m.group("ts")
        body = m.group("body") or ""
        sm = _START.search(body) or _PING_BANNER.search(body)
        if sm:
            default_host = sm.group("host")
            continue
        if body.startswith("=====") or not body.strip():
            continue

        status, host, rtt, ttl, seq = _classify_body(body)
        if status == STATUS_UNKNOWN:
            # ignore pure noise
            continue

        events.append(
            PingEvent(
                timestamp=parse_ping_timestamp(ts_raw),
                timestamp_raw=ts_raw,
                target_host=host or default_host,
                status=status,
                rtt_ms=rtt,
                ttl=ttl,
                icmp_seq=seq,
                source_file=str(p),
                source_line=i,
                raw_excerpt=raw[:240],
            )
        )
    return events
