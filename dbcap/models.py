"""Core data models for DBCAP Offline Analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    HIGH = "HIGH"
    # Keep legacy aliases for compatibility with old JSON consumers
    HEALTHY = "HEALTHY"
    CRITICAL = "CRITICAL"


class EvidenceLevel(str, Enum):
    CONFIRMED = "CONFIRMED"
    STRONG = "STRONG"
    SUSPECTED = "SUSPECTED"
    UNKNOWN = "UNKNOWN"


class RstClass(str, Enum):
    RST_AFTER_SYN = "RST_AFTER_SYN"
    RST_DURING_DATA = "RST_DURING_DATA"
    ACK_TO_RST = "ACK_TO_RST"
    RST_AFTER_FIN = "RST_AFTER_FIN"
    RST_OTHER = "RST_OTHER"


@dataclass(frozen=True)
class FlowKey:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    server_ip: str
    server_port: int

    @property
    def client_ip(self) -> str:
        if self.src_ip == self.server_ip and self.src_port == self.server_port:
            return self.dst_ip
        return self.src_ip

    @property
    def client_port(self) -> int:
        if self.src_ip == self.server_ip and self.src_port == self.server_port:
            return self.dst_port
        return self.src_port


@dataclass
class PacketSummary:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    tcp_flags: int
    tcp_seq: int
    tcp_ack: int
    tcp_window: int
    tcp_len: int
    frame_number: Optional[int] = None
    tcp_stream: Optional[int] = None
    frame_len: Optional[int] = None
    cap_len: Optional[int] = None
    payload_hex: str = ""
    ws_retransmission: bool = False
    ws_fast_retransmission: bool = False
    ws_spurious_retransmission: bool = False
    tcp_options_tsval: Optional[int] = None
    tcp_options_tsecr: Optional[int] = None

    @property
    def syn(self) -> bool:
        return bool(self.tcp_flags & 0x02)

    @property
    def ack_flag(self) -> bool:
        return bool(self.tcp_flags & 0x10)

    @property
    def fin(self) -> bool:
        return bool(self.tcp_flags & 0x01)

    @property
    def rst(self) -> bool:
        return bool(self.tcp_flags & 0x04)

    @property
    def psh(self) -> bool:
        return bool(self.tcp_flags & 0x08)

    @property
    def truncated(self) -> bool:
        if self.frame_len is None or self.cap_len is None:
            return False
        return self.cap_len < self.frame_len

    def flags_str(self) -> str:
        parts = []
        if self.syn:
            parts.append("SYN")
        if self.ack_flag:
            parts.append("ACK")
        if self.fin:
            parts.append("FIN")
        if self.rst:
            parts.append("RST")
        if self.psh:
            parts.append("PSH")
        return ",".join(parts) if parts else "."


@dataclass
class HandshakeEvent:
    syn_ts: Optional[float] = None
    synack_ts: Optional[float] = None
    ack_ts: Optional[float] = None
    syn_frame: Optional[int] = None
    synack_frame: Optional[int] = None
    ack_frame: Optional[int] = None
    complete: bool = False
    syn_retransmissions: int = 0
    latency_ms: Optional[float] = None  # None => N/A


@dataclass
class ZeroWindowEvent:
    start_ts: float
    end_ts: Optional[float] = None
    direction: str = "unknown"
    frames: list[int] = field(default_factory=list)

    @property
    def duration_ms(self) -> Optional[float]:
        if self.end_ts is None:
            return None
        return (self.end_ts - self.start_ts) * 1000


@dataclass
class PersistentRetransmission:
    tcp_stream: int
    direction: str
    seq: int
    tcp_len: int
    payload_sha256: str
    count: int
    first_ts: float
    last_ts: float
    duration_ms: float
    frames: list[int]
    expected_ack: int
    severity: Severity = Severity.INFO
    wireshark_filter: str = ""
    evidence_level: EvidenceLevel = EvidenceLevel.CONFIRMED
    # "data" = payload-bearing segment; "control" = SYN/FIN/keepalive-style (len==0)
    plane: str = "data"
    anomaly_type: str = "DATA_RETRANSMISSION"


@dataclass
class AckStalledEvent:
    tcp_stream: int
    send_direction: str
    seq: int
    tcp_len: int
    expected_ack: int
    observed_ack: int
    stall_duration_ms: float
    retransmission_count: int
    frames: list[int]
    severity: Severity = Severity.HIGH
    wireshark_filter: str = ""
    evidence_level: EvidenceLevel = EvidenceLevel.CONFIRMED


@dataclass
class RstEvent:
    tcp_stream: int
    classification: RstClass
    frame: Optional[int]
    timestamp: float
    direction: str
    severity: Severity
    wireshark_filter: str = ""
    evidence_level: EvidenceLevel = EvidenceLevel.CONFIRMED
    note: str = ""


@dataclass
class FrameEvidence:
    frame_number: Optional[int]
    timestamp: float
    tcp_stream: Optional[int]
    direction: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    tcp_flags: str
    seq: int
    ack: int
    tcp_len: int
    expected_ack: Optional[int]
    window: int
    payload_sha256: str
    anomaly_type: str = ""
    severity: str = ""
    evidence_level: str = ""
    wireshark_filter: str = ""
    note: str = ""
    observed_ack: Optional[int] = None  # peer cumulative ACK when relevant (ACK_STALLED)


@dataclass
class TcpSession:
    tcp_stream: int
    key: FlowKey
    packets: list[PacketSummary] = field(default_factory=list)
    handshake: HandshakeEvent = field(default_factory=HandshakeEvent)
    rst_seen: bool = False
    fin_seen: bool = False
    zero_window_events: list[ZeroWindowEvent] = field(default_factory=list)
    start_time: Optional[float] = None
    end_time: Optional[float] = None

    @property
    def duration(self) -> Optional[float]:
        if self.start_time is None or self.end_time is None:
            return None
        return self.end_time - self.start_time

    @property
    def packet_count(self) -> int:
        return len(self.packets)


@dataclass
class SessionSummary:
    tcp_stream: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration: Optional[float] = None
    packet_count: int = 0
    client_packets: int = 0
    server_packets: int = 0
    payload_bytes: int = 0
    retransmissions: int = 0
    rst: bool = False
    fin: bool = False
    zero_window: int = 0
    handshake_latency_ms: Optional[float] = None
    rst_class: Optional[str] = None
    severity: Severity = Severity.INFO


@dataclass
class CaptureQuality:
    total_packets: int = 0
    truncated_packets: int = 0
    truncated_ratio: float = 0.0
    common_cap_len: Optional[int] = None
    snaplen_hint: Optional[str] = None
    credibility: str = "HIGH"  # HIGH / DEGRADED / LOW
    # TShark reported the capture file was cut short, but packets were recovered.
    file_cut_short: bool = False
    file_warning: Optional[str] = None


@dataclass
class Anomaly:
    type: str
    severity: Severity
    evidence_level: EvidenceLevel
    tcp_stream: Optional[int]
    summary: str
    detail: str
    frames: list[int] = field(default_factory=list)
    wireshark_filter: str = ""
    facts: list[str] = field(default_factory=list)
    inferences: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)


@dataclass
class AnalysisReport:
    metadata: dict = field(default_factory=dict)
    summary: dict = field(default_factory=dict)
    sessions: list[SessionSummary] = field(default_factory=list)
    flows: list[SessionSummary] = field(default_factory=list)  # alias for legacy
    anomalies: list[Anomaly] = field(default_factory=list)
    persistent_retx: list[PersistentRetransmission] = field(default_factory=list)
    ack_stalled: list[AckStalledEvent] = field(default_factory=list)
    rst_events: list[RstEvent] = field(default_factory=list)
    frame_evidence: list[FrameEvidence] = field(default_factory=list)
    capture_quality: CaptureQuality = field(default_factory=CaptureQuality)
    recommendations: list[str] = field(default_factory=list)
    conclusion: dict = field(default_factory=dict)
    wireshark_filters: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)


@dataclass
class ThresholdConfig:
    # Retransmission severity
    retx_single_severity: str = "INFO"
    retx_burst_warn_count: int = 2
    retx_high_count: int = 3
    retx_high_duration_ms: float = 1000.0
    # Handshake / RTT (kept for optional warnings)
    handshake_warn_ms: float = 100.0
    handshake_crit_ms: float = 500.0
    rtt_warn_ms: float = 50.0
    rtt_crit_ms: float = 100.0
    # Legacy rate thresholds (still used for session rollup)
    retx_rate_warn_pct: float = 2.0
    retx_rate_crit_pct: float = 5.0
    # Zero window
    zero_window_warn_count: int = 1
    zero_window_crit_count: int = 5
    # ACK stall
    ack_stall_ms: float = 1000.0
    # RST
    rst_after_syn_severity: str = "WARNING"
    rst_during_data_severity: str = "HIGH"
    ack_to_rst_severity: str = "WARNING"
    rst_after_fin_severity: str = "INFO"
    # Capture quality
    truncated_warn_ratio: float = 0.05
    truncated_high_ratio: float = 0.30
    # Short-flow RST legacy threshold
    rst_short_flow_packet_threshold: int = 50
