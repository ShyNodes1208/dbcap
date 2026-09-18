"""Linear DM/JDBC log parser — exception blocks as single events."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from dbcap.jdbc.classifier import NOT_NETWORK, classify_exception
from dbcap.jdbc.grouping import assign_event_groups
from dbcap.jdbc.models import JdbcEvent
from dbcap.jdbc.redact import redact_secrets

# [ERROR - YYYY-MM-DD HH:MM:SS] tid:N - [thread] { conn-N } ...
_HEADER = re.compile(
    r"^\[(?P<level>ERROR|WARN|INFO|DEBUG|SQL)\s*-\s*"
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+"
    r"tid:(?P<tid>\d+)\s+-\s+\[(?P<thread>[^\]]+)\]\s*(?P<body>.*)$"
)
_EXC_LINE = re.compile(
    r"^(?P<cls>[\w.$]+(?:Exception|Error|Throwable))\s*:\s*(?P<msg>.*)$"
)
_CAUSED = re.compile(
    r"^Caused by:\s*(?P<cls>[\w.$]+)\s*:\s*(?P<msg>.*)$"
)
_HOST_PORT = re.compile(
    r"(?:try connect success\s*\[|(?:host|epgroup)\s*=)\s*"
    r"(?P<host>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<port>\d+))?",
    re.I,
)
_HOST_KV = re.compile(r"\bhost=(?P<host>\d{1,3}(?:\.\d{1,3}){3})\b", re.I)
_PORT_KV = re.compile(r"\bport=(?P<port>\d+)\b", re.I)
_CONN_HINT = re.compile(r"\{\s*(?P<hint>[^}]*)\}")
_USED_MS = re.compile(r"\[USED TIME\]:\s*(?P<ms>[\d.Ee+-]+)ms", re.I)
_IP_PORT = re.compile(r"(?P<host>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)")


def parse_jdbc_timestamp(raw: str) -> Optional[float]:
    """Parse wall-clock JDBC timestamp as naive local epoch seconds."""
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").timestamp()
    except ValueError:
        return None


def _extract_host_port(text: str) -> tuple[Optional[str], Optional[int]]:
    text = text or ""
    m = _HOST_PORT.search(text)
    if m:
        port = int(m.group("port")) if m.group("port") else None
        return m.group("host"), port
    host = None
    port = None
    hm = _HOST_KV.search(text)
    if hm:
        host = hm.group("host")
    pm = _PORT_KV.search(text)
    if pm:
        port = int(pm.group("port"))
    if host and port:
        return host, port
    ip = _IP_PORT.search(text)
    if ip:
        return ip.group("host"), int(ip.group("port"))
    return host, port


def _is_header(line: str) -> bool:
    return bool(_HEADER.match(line))


def _parse_exception_lines(
    block: list[str],
) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str], str]:
    exc_cls = exc_msg = cb_cls = cb_msg = None
    stack_bits: list[str] = []
    for line in block[1:]:
        s = line.strip()
        if not s:
            continue
        cm = _CAUSED.match(s)
        if cm:
            cb_cls, cb_msg = cm.group("cls"), cm.group("msg").strip()
            stack_bits.append(redact_secrets(s)[:200])
            continue
        em = _EXC_LINE.match(s)
        if em and exc_cls is None and not s.startswith("at "):
            exc_cls, exc_msg = em.group("cls"), em.group("msg").strip()
            stack_bits.append(redact_secrets(s)[:200])
            continue
        if s.startswith("at ") or s.startswith("...") or s.startswith("Caused by:"):
            stack_bits.append(redact_secrets(s)[:160])
    summary = " | ".join(stack_bits[:12])
    return exc_cls, exc_msg, cb_cls, cb_msg, summary


def iter_exception_blocks(lines: list[str]) -> Iterator[tuple[int, int, list[str]]]:
    """Yield (start_line_1based, end_line_1based, block_lines) for ERROR/WARN with stacks."""
    i = 0
    n = len(lines)
    while i < n:
        m = _HEADER.match(lines[i])
        if not m or m.group("level") not in ("ERROR", "WARN"):
            i += 1
            continue
        start = i
        i += 1
        # Peek: if next non-empty is exception-like, consume until next header
        while i < n and not _is_header(lines[i]):
            i += 1
        block = lines[start:i]
        # Keep only if looks like an exception block or ERROR
        body_joined = "\n".join(block)
        if m.group("level") == "ERROR" or "Exception" in body_joined or "Caused by:" in body_joined:
            yield start + 1, i, block
        # else WARN without stack — skip as non-event unless ERROR-like
        # (WARN alone without exception not emitted)


def parse_jdbc_log(
    path: str,
    *,
    default_host: Optional[str] = None,
    default_port: Optional[int] = None,
) -> list[JdbcEvent]:
    """Single linear pass — O(N) lines."""
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    events: list[JdbcEvent] = []
    # Pre-scan connect success lines for host/port fallback context (same pass extras)
    global_host, global_port = default_host, default_port
    for line in lines:
        if "try connect success" in line or "host=" in line.lower():
            h, pt = _extract_host_port(line)
            if h:
                global_host = global_host or h
            if pt:
                global_port = global_port or pt

    ev_n = 0
    for start_line, end_line, block in iter_exception_blocks(lines):
        header = _HEADER.match(block[0])
        if not header:
            continue
        level = header.group("level")
        ts_raw = header.group("ts")
        ts = parse_jdbc_timestamp(ts_raw)
        body = header.group("body") or ""
        hint_m = _CONN_HINT.search(body)
        hint = hint_m.group("hint").strip() if hint_m else None
        used_m = _USED_MS.search(body)
        used_ms = float(used_m.group("ms")) if used_m else None
        h, pt = _extract_host_port(body)
        if not h or not pt:
            # search whole block
            bh, bpt = _extract_host_port("\n".join(block))
            h = h or bh
            pt = pt or bpt
        h = h or global_host
        pt = pt or global_port

        exc_cls, exc_msg, cb_cls, cb_msg, stack = _parse_exception_lines(block)
        # ERROR without parsed exception class still an event if stack empty
        if level != "ERROR" and not exc_cls and not cb_cls:
            continue
        event_type = classify_exception(exc_cls, exc_msg, cb_cls, cb_msg)
        if event_type == NOT_NETWORK:
            continue
        excerpt = redact_secrets("\n".join(block[:40]))
        digest = hashlib.sha256(excerpt.encode("utf-8", errors="replace")).hexdigest()[:16]
        ev_n += 1
        events.append(
            JdbcEvent(
                event_id=f"JE{ev_n:04d}",
                timestamp=ts,
                timestamp_raw=ts_raw,
                level=level,
                exception_class=exc_cls,
                message=redact_secrets(exc_msg) if exc_msg else None,
                event_type=event_type,
                thread_name=header.group("thread"),
                tid=header.group("tid"),
                database_host=h,
                database_port=pt,
                connection_hint=hint,
                stack_summary=stack,
                source_file=str(p),
                start_line=start_line,
                end_line=end_line,
                raw_excerpt_hash=digest,
                used_time_ms=used_ms,
                caused_by_class=cb_cls,
                caused_by_message=redact_secrets(cb_msg) if cb_msg else None,
            )
        )
    return assign_event_groups(events)
