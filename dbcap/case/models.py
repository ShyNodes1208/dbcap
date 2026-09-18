"""Unified case models (V2.4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from dbcap.dual.models import DualAnalysisResult
from dbcap.jdbc.models import JdbcTimelineResult
from dbcap.ping.models import PingAnalysisResult


EV_CONFIRMED = "CONFIRMED_FACTS"
EV_CORRELATED = "CORRELATED_EVIDENCE"
EV_SUPPORTING = "SUPPORTING_EVIDENCE"
EV_UNKNOWN = "UNKNOWN"


@dataclass
class UnifiedTimelineRow:
    case_id: str
    timestamp: Optional[float]
    relative_to_jdbc_seconds: Optional[float]
    source: str
    event_type: str
    correlation_id: Optional[str]
    app_stream: Optional[int]
    db_stream: Optional[int]
    frame: Optional[int]
    direction: Optional[str]
    seq: Optional[int]
    ack: Optional[int]
    tcp_len: Optional[int]
    description: str
    evidence_class: str
    confidence: str


@dataclass
class EvidenceItem:
    evidence_class: str
    text: str
    confidence: str = ""


@dataclass
class CaseAnalysisResult:
    case_id: str
    jdbc: JdbcTimelineResult
    dual: DualAnalysisResult
    ping: PingAnalysisResult
    unified_timeline: list[UnifiedTimelineRow] = field(default_factory=list)
    confirmed: list[EvidenceItem] = field(default_factory=list)
    correlated: list[EvidenceItem] = field(default_factory=list)
    supporting: list[EvidenceItem] = field(default_factory=list)
    unknown: list[EvidenceItem] = field(default_factory=list)
    key_jdbc_event_id: Optional[str] = None
