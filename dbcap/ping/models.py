"""Ping evidence models (V2.3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


STATUS_REPLY = "REPLY"
STATUS_TIMEOUT = "TIMEOUT"
STATUS_UNREACHABLE = "UNREACHABLE"
STATUS_ERROR = "ERROR"
STATUS_UNKNOWN = "UNKNOWN"


@dataclass
class PingEvent:
    timestamp: Optional[float]
    timestamp_raw: str
    target_host: Optional[str]
    status: str
    rtt_ms: Optional[float]
    ttl: Optional[int]
    icmp_seq: Optional[int]
    source_file: str
    source_line: int
    raw_excerpt: str


@dataclass
class PingCorrelation:
    event_id: str  # JDBC event id
    jdbc_timestamp: Optional[float]
    jdbc_timestamp_raw: str
    target_host: Optional[str]
    window_seconds: float
    samples: int = 0
    replies: int = 0
    timeouts: int = 0
    unreachable: int = 0
    errors: int = 0
    min_rtt_ms: Optional[float] = None
    avg_rtt_ms: Optional[float] = None
    max_rtt_ms: Optional[float] = None
    last_reply_before: Optional[float] = None
    first_reply_after: Optional[float] = None
    nearest_timeout_before: Optional[float] = None
    nearest_timeout_after: Optional[float] = None
    summary: str = ""
    evidence_class: str = "SUPPORTING"
    caution: str = (
        "ICMP evidence is supporting only; it does not prove TCP health "
        "or identify a network device root cause."
    )


@dataclass
class PingTimelineMarker:
    timestamp: Optional[float]
    event_type: str  # PING_TIMEOUT / PING_RECOVERY / PING_REPLY_STABLE / ...
    description: str
    target_host: Optional[str] = None


@dataclass
class PingAnalysisResult:
    ping_log: Optional[str]
    events: list[PingEvent] = field(default_factory=list)
    correlations: list[PingCorrelation] = field(default_factory=list)
    timeline_markers: list[PingTimelineMarker] = field(default_factory=list)
    provided: bool = False
