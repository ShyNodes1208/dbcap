"""Dual-PCAP correlation models (V2 milestone 1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

DIR_APP_TO_DB = "APP_TO_DB"
DIR_DB_TO_APP = "DB_TO_APP"

STATUS_BOTH = "MATCHED_BOTH_SIDES"
STATUS_APP_ONLY = "ONLY_AT_APP_SIDE"
STATUS_DB_ONLY = "ONLY_AT_DB_SIDE"
STATUS_HASH_UNAVAIL = "HASH_UNAVAILABLE"
STATUS_AMBIGUOUS = "AMBIGUOUS"

EV_CONFIRMED = "CONFIRMED"
EV_STRONG = "STRONG"
EV_SUSPECTED = "SUSPECTED"
EV_UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class NormalizedFlowKey:
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    protocol: str = "TCP"

    def as_tuple(self) -> tuple:
        return (
            self.client_ip,
            self.client_port,
            self.server_ip,
            self.server_port,
            self.protocol,
        )


@dataclass
class CorrelatedFlow:
    correlation_id: str
    flow_key: NormalizedFlowKey
    app_stream: int
    db_stream: int
    app_start: Optional[float] = None
    app_end: Optional[float] = None
    db_start: Optional[float] = None
    db_end: Optional[float] = None
    confidence: str = EV_CONFIRMED
    note: str = ""


@dataclass
class DualSegment:
    correlation_id: str
    direction: str
    seq: int
    tcp_len: int
    expected_ack: Optional[int]
    ack: Optional[int]
    app_frame: Optional[int]
    app_timestamp: Optional[float]
    app_stream: Optional[int]
    db_frame: Optional[int]
    db_timestamp: Optional[float]
    db_stream: Optional[int]
    payload_hash_app: Optional[str]
    payload_hash_db: Optional[str]
    payload_hash_match: Optional[bool]
    observed_delta: Optional[float]
    match_status: str
    evidence_level: str
    note: str = ""
    retransmission_count_app: int = 0
    retransmission_count_db: int = 0


@dataclass
class ClockAlignment:
    status: str  # OK / UNRELIABLE / INSUFFICIENT
    estimated_offset_sec: Optional[float] = None  # app_ts - db_ts median
    median_delta: Optional[float] = None
    min_delta: Optional[float] = None
    max_delta: Optional[float] = None
    sample_count: int = 0
    note: str = ""


@dataclass
class DualAnalysisResult:
    app_pcap: str
    db_pcap: str
    server_ip: Optional[str]
    db_port: int
    capture_quality_app: dict = field(default_factory=dict)
    capture_quality_db: dict = field(default_factory=dict)
    correlated_flows: list[CorrelatedFlow] = field(default_factory=list)
    unmatched_app_streams: list[int] = field(default_factory=list)
    unmatched_db_streams: list[int] = field(default_factory=list)
    segments: list[DualSegment] = field(default_factory=list)
    clock: ClockAlignment = field(default_factory=lambda: ClockAlignment(status="INSUFFICIENT"))
    limitations: list[str] = field(default_factory=list)
    # Side artifacts for higher layers (V2.2 JDBC timeline). Matchers unchanged.
    app_report: object | None = None
    db_report: object | None = None
    app_sessions: dict = field(default_factory=dict)
    db_sessions: dict = field(default_factory=dict)
