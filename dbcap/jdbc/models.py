"""JDBC timeline models (V2.2+ / V2.5 candidate precision)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


STATUS_MATCHED = "MATCHED"
STATUS_AMBIGUOUS = "AMBIGUOUS"
STATUS_NO_MATCH = "NO_MATCH"

EV_CONFIRMED = "CONFIRMED"
EV_STRONG = "STRONG"
EV_AMBIGUOUS = "AMBIGUOUS"
EV_NO_MATCH = "NO_MATCH"

FILTER_ELIGIBLE = "ELIGIBLE"
FILTER_ENDPOINT = "FILTERED_ENDPOINT"
FILTER_TIME = "FILTERED_TIME"


@dataclass
class JdbcEvent:
    event_id: str
    timestamp: Optional[float]
    timestamp_raw: str
    level: str
    exception_class: Optional[str]
    message: Optional[str]
    event_type: str
    thread_name: Optional[str]
    tid: Optional[str]
    database_host: Optional[str]
    database_port: Optional[int]
    connection_hint: Optional[str]
    stack_summary: str
    source_file: str
    start_line: int
    end_line: int
    raw_excerpt_hash: str
    used_time_ms: Optional[float] = None
    caused_by_class: Optional[str] = None
    caused_by_message: Optional[str] = None
    # V2.6 duplicate grouping
    group_id: Optional[str] = None
    occurrence_count: int = 1
    is_group_primary: bool = True


@dataclass
class FlowCandidate:
    dual_correlation_id: str
    app_stream: int
    db_stream: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    app_start: Optional[float]
    app_end: Optional[float]
    score: float
    reasons: list[str] = field(default_factory=list)
    # V2.5
    identity_score: float = 0.0
    health_score: float = 0.0
    filter_status: str = FILTER_ELIGIBLE
    filter_reason: str = ""
    distance_to_event: Optional[float] = None


@dataclass
class JdbcTcpCorrelation:
    event_id: str
    correlation_status: str
    evidence_level: str
    dual_correlation_id: Optional[str]
    client_ip: Optional[str]
    client_port: Optional[int]
    server_ip: Optional[str]
    server_port: Optional[int]
    app_stream: Optional[int]
    db_stream: Optional[int]
    event_timestamp: Optional[float]
    flow_start: Optional[float]
    flow_end: Optional[float]
    nearest_tcp_event: Optional[str]
    nearest_tcp_event_time: Optional[float]
    delta_seconds: Optional[float]
    candidate_count: int
    reason: str
    candidates: list[FlowCandidate] = field(default_factory=list)
    # V2.5 filter accounting
    flows_considered: int = 0
    filtered_endpoint: int = 0
    filtered_time: int = 0
    eligible_count: int = 0
    lifetime_grace_seconds: float = 5.0


@dataclass
class TimelineEntry:
    event_id: str
    timeline_timestamp: Optional[float]
    relative_seconds: Optional[float]
    source: str  # JDBC / APP_PCAP / DB_PCAP / DUAL
    event_type: str
    side: str
    frame: Optional[int]
    stream: Optional[int]
    seq: Optional[int]
    ack: Optional[int]
    tcp_len: Optional[int]
    description: str
    evidence_level: str
    # Candidate identity (required for AMBIGUOUS unified timeline — H-01)
    correlation_id: Optional[str] = None
    direction: Optional[str] = None
    app_stream: Optional[int] = None
    db_stream: Optional[int] = None


@dataclass
class JdbcTimelineResult:
    jdbc_log: str
    app_pcap: str
    db_pcap: str
    server_ip: Optional[str]
    db_port: int
    window_seconds: float
    events: list[JdbcEvent] = field(default_factory=list)
    correlations: list[JdbcTcpCorrelation] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)
    clock_status: str = "UNKNOWN"
    clock_note: str = ""
    limitations: list[str] = field(default_factory=list)
    lifetime_grace_seconds: float = 5.0
