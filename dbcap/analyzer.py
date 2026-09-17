"""TCP anomaly analysis orchestration."""

from __future__ import annotations

import sys
from datetime import datetime
from typing import Optional

from dbcap.ack_analysis import detect_ack_stalled, explain_ack_stalled
from dbcap.capture_quality import analyze_capture_quality
from dbcap.db_ports import get_db_name
from dbcap.filters import retransmission_filter, stream_filter
from dbcap.handshake import extract_handshake
from dbcap.models import (
    AnalysisReport,
    Anomaly,
    EvidenceLevel,
    FrameEvidence,
    SessionSummary,
    Severity,
    TcpSession,
    ThresholdConfig,
)
from dbcap.retransmission import count_retransmissions, detect_persistent_retransmissions, payload_sha256
from dbcap.rst_analysis import classify_rst
from dbcap.seq_ack import expected_ack_from_packet
from dbcap.session import packet_direction
from dbcap.window_analysis import extract_zero_window_events


def _session_severity(
    retx_high: bool,
    ack_stalled: bool,
    rst_high: bool,
    zw_high: bool,
) -> Severity:
    if retx_high or ack_stalled or rst_high or zw_high:
        return Severity.HIGH
    return Severity.INFO


def summarize_session(
    session: TcpSession,
    thresholds: ThresholdConfig,
    retx_count: int,
    rst_class: Optional[str],
    handshake_latency: Optional[float],
    zw_count: int,
    has_high_retx: bool,
    has_ack_stall: bool,
    has_high_rst: bool,
) -> SessionSummary:
    client_pkts = 0
    server_pkts = 0
    payload_bytes = 0
    for pkt in session.packets:
        d = packet_direction(pkt, session.key.server_ip, session.key.server_port)
        if d == "client_to_server":
            client_pkts += 1
        elif d == "server_to_client":
            server_pkts += 1
        payload_bytes += pkt.tcp_len

    sev = _session_severity(
        has_high_retx,
        has_ack_stall,
        has_high_rst,
        zw_count >= thresholds.zero_window_crit_count,
    )
    if sev == Severity.INFO and (
        retx_count > 0 or zw_count >= thresholds.zero_window_warn_count
    ):
        sev = Severity.WARNING

    return SessionSummary(
        tcp_stream=session.tcp_stream,
        client_ip=session.key.client_ip,
        client_port=session.key.client_port,
        server_ip=session.key.server_ip,
        server_port=session.key.server_port,
        start_time=session.start_time,
        end_time=session.end_time,
        duration=session.duration,
        packet_count=session.packet_count,
        client_packets=client_pkts,
        server_packets=server_pkts,
        payload_bytes=payload_bytes,
        retransmissions=retx_count,
        rst=session.rst_seen,
        fin=session.fin_seen,
        zero_window=zw_count,
        handshake_latency_ms=handshake_latency,
        rst_class=rst_class,
        severity=sev,
    )


def _frame_evidence_for_packet(
    pkt,
    session: TcpSession,
    anomaly_type: str,
    severity: str,
    evidence_level: str,
    note: str,
    ws_filter: str,
) -> FrameEvidence:
    direction = packet_direction(pkt, session.key.server_ip, session.key.server_port)
    ea = expected_ack_from_packet(pkt) if (pkt.tcp_len > 0 or pkt.syn or pkt.fin) else None
    return FrameEvidence(
        frame_number=pkt.frame_number,
        timestamp=pkt.timestamp,
        tcp_stream=session.tcp_stream,
        direction=direction,
        source_ip=pkt.src_ip,
        destination_ip=pkt.dst_ip,
        source_port=pkt.src_port,
        destination_port=pkt.dst_port,
        tcp_flags=pkt.flags_str(),
        seq=pkt.tcp_seq,
        ack=pkt.tcp_ack,
        tcp_len=pkt.tcp_len,
        expected_ack=ea,
        window=pkt.tcp_window,
        payload_sha256=payload_sha256(pkt.payload_hex),
        anomaly_type=anomaly_type,
        severity=severity,
        evidence_level=evidence_level,
        wireshark_filter=ws_filter,
        note=note,
    )


def analyze_session(
    session: TcpSession,
    thresholds: ThresholdConfig,
) -> dict:
    session.handshake = extract_handshake(session.packets)
    session.zero_window_events = extract_zero_window_events(session)

    retx_list = detect_persistent_retransmissions(session, thresholds)
    ack_stalled = detect_ack_stalled(session, retx_list, thresholds)
    rst_events = classify_rst(session, thresholds)

    retx_extra = count_retransmissions(retx_list)
    has_high_retx = any(
        r.severity == Severity.HIGH and r.plane == "data" for r in retx_list
    )
    has_ack_stall = bool(ack_stalled)
    has_high_rst = any(r.severity == Severity.HIGH for r in rst_events)
    rst_class = rst_events[0].classification.value if rst_events else None

    summary = summarize_session(
        session,
        thresholds,
        retx_extra,
        rst_class,
        session.handshake.latency_ms,
        len(session.zero_window_events),
        has_high_retx,
        has_ack_stall,
        has_high_rst,
    )

    anomalies: list[Anomaly] = []
    frame_evidence: list[FrameEvidence] = []
    filters: list[str] = []

    # Handshake N/A note
    if session.handshake.syn_ts is None:
        anomalies.append(
            Anomaly(
                type="HANDSHAKE_INCOMPLETE",
                severity=Severity.INFO,
                evidence_level=EvidenceLevel.CONFIRMED,
                tcp_stream=session.tcp_stream,
                summary="Handshake Latency = N/A（捕获中未见 SYN）",
                detail="抓包可能从会话中途开始，不能计算握手延迟，也不会使用 timestamp-0。",
                frames=[],
                wireshark_filter=stream_filter(session.tcp_stream),
                facts=["捕获范围内未观察到 SYN"],
                unknowns=["真实握手时刻与握手 RTT"],
            )
        )

    for r in retx_list:
        direction_cn = (
            "数据库 → 应用" if r.direction == "server_to_client" else "应用 → 数据库"
        )
        plane_cn = "数据面" if r.plane == "data" else "控制面"
        detail = (
            f"{plane_cn}同一 TCP Segment 持续重传：方向={direction_cn}，"
            f"Seq={r.seq}，Len={r.tcp_len}，"
            f"重复 {r.count} 次，持续 {r.duration_ms:.1f} ms，"
            f"Payload SHA256={r.payload_sha256[:16]}…，"
            f"Expected ACK={r.expected_ack}。"
        )
        if r.plane == "control":
            detail += " 这是 SYN/FIN/零长度控制段重传，不是业务 Payload 重传。"
        anomalies.append(
            Anomaly(
                type=r.anomaly_type,
                severity=r.severity,
                evidence_level=r.evidence_level,
                tcp_stream=r.tcp_stream,
                summary=f"{r.anomaly_type} x{r.count} Seq={r.seq} Len={r.tcp_len}",
                detail=detail,
                frames=r.frames,
                wireshark_filter=r.wireshark_filter,
                facts=[
                    f"plane={r.plane}",
                    f"相同 Segment Key 出现 {r.count} 次",
                    f"Seq={r.seq} Len={r.tcp_len} SHA256={r.payload_sha256}",
                    f"Frame: {r.frames}",
                ],
                inferences=(
                    ["对端可能未及时确认，或路径存在丢包/延迟"]
                    if r.plane == "data"
                    else ["控制段重传常见于握手重试或连接清理，需结合上下文判断"]
                ),
                unknowns=[
                    "当前单侧 PCAP 无法进一步定位。",
                ],
                extra={
                    "seq": r.seq,
                    "len": r.tcp_len,
                    "expected_ack": r.expected_ack,
                    "duration_ms": r.duration_ms,
                    "payload_sha256": r.payload_sha256,
                    "direction": r.direction,
                    "plane": r.plane,
                },
            )
        )
        filters.append(r.wireshark_filter)
        for pkt in session.packets:
            if pkt.frame_number in r.frames and pkt.tcp_seq == r.seq and pkt.tcp_len == r.tcp_len:
                frame_evidence.append(
                    _frame_evidence_for_packet(
                        pkt,
                        session,
                        r.anomaly_type,
                        r.severity.value,
                        r.evidence_level.value,
                        detail,
                        r.wireshark_filter,
                    )
                )

    for ev in ack_stalled:
        detail = explain_ack_stalled(ev)
        anomalies.append(
            Anomaly(
                type="ACK_STALLED",
                severity=ev.severity,
                evidence_level=ev.evidence_level,
                tcp_stream=ev.tcp_stream,
                summary=(
                    f"ACK 未推进：Expected={ev.expected_ack} Observed={ev.observed_ack}"
                ),
                detail=detail,
                frames=ev.frames,
                wireshark_filter=ev.wireshark_filter,
                facts=[
                    f"发送方向 {ev.send_direction}",
                    f"Seq={ev.seq} Len={ev.tcp_len}",
                    f"Expected ACK={ev.expected_ack}",
                    f"Observed ACK={ev.observed_ack}",
                    f"未推进 {ev.stall_duration_ms:.1f} ms",
                    f"重传次数 {ev.retransmission_count}",
                    f"Frames {ev.frames}",
                ],
                inferences=[
                    "在当前抓包观察范围内，发送段未获得对端正常累计确认",
                ],
                unknowns=[
                    "当前单侧 PCAP 无法进一步定位。",
                ],
                extra={
                    "seq": ev.seq,
                    "len": ev.tcp_len,
                    "expected_ack": ev.expected_ack,
                    "observed_ack": ev.observed_ack,
                },
            )
        )
        filters.append(ev.wireshark_filter)
        for pkt in session.packets:
            if pkt.frame_number in ev.frames and pkt.tcp_seq == ev.seq and pkt.tcp_len == ev.tcp_len:
                fe = _frame_evidence_for_packet(
                    pkt,
                    session,
                    "ACK_STALLED",
                    ev.severity.value,
                    ev.evidence_level.value,
                    detail,
                    ev.wireshark_filter,
                )
                fe.observed_ack = ev.observed_ack
                fe.expected_ack = ev.expected_ack
                frame_evidence.append(fe)

    for rst in rst_events:
        anomalies.append(
            Anomaly(
                type=rst.classification.value,
                severity=rst.severity,
                evidence_level=rst.evidence_level,
                tcp_stream=rst.tcp_stream,
                summary=f"{rst.classification.value} @ frame {rst.frame}",
                detail=rst.note,
                frames=[rst.frame] if rst.frame is not None else [],
                wireshark_filter=rst.wireshark_filter,
                facts=[rst.note, f"direction={rst.direction}"],
                inferences=[],
                unknowns=["当前单侧 PCAP 无法进一步定位根因。"],
            )
        )
        filters.append(rst.wireshark_filter)
        for pkt in session.packets:
            if rst.frame is not None and pkt.frame_number == rst.frame:
                frame_evidence.append(
                    _frame_evidence_for_packet(
                        pkt,
                        session,
                        rst.classification.value,
                        rst.severity.value,
                        rst.evidence_level.value,
                        rst.note,
                        rst.wireshark_filter,
                    )
                )

    for zw in session.zero_window_events:
        anomalies.append(
            Anomaly(
                type="ZERO_WINDOW",
                severity=(
                    Severity.HIGH
                    if len(session.zero_window_events) >= thresholds.zero_window_crit_count
                    else Severity.WARNING
                ),
                evidence_level=EvidenceLevel.CONFIRMED,
                tcp_stream=session.tcp_stream,
                summary=f"Zero Window ({zw.direction})",
                detail=(
                    f"接收窗口为 0，方向={zw.direction}，"
                    f"持续 {zw.duration_ms if zw.duration_ms is not None else 'N/A'} ms。"
                ),
                frames=zw.frames,
                wireshark_filter=stream_filter(session.tcp_stream),
                facts=[f"window=0 frames={zw.frames}"],
                unknowns=["当前单侧 PCAP 无法进一步定位。"],
            )
        )
        for pkt in session.packets:
            if pkt.frame_number in zw.frames:
                frame_evidence.append(
                    _frame_evidence_for_packet(
                        pkt,
                        session,
                        "ZERO_WINDOW",
                        Severity.WARNING.value,
                        EvidenceLevel.CONFIRMED.value,
                        "TCP window = 0",
                        stream_filter(session.tcp_stream),
                    )
                )

    return {
        "summary": summary,
        "retx": retx_list,
        "ack_stalled": ack_stalled,
        "rst_events": rst_events,
        "anomalies": anomalies,
        "frame_evidence": frame_evidence,
        "filters": filters,
        "session": session,
    }


CAPTURE_QUALITY_ANOMALY_TYPES = frozenset(
    {"PACKET_TRUNCATED", "CAPTURE_FILE_CUT_SHORT"}
)


def _is_tcp_anomaly(anomaly: Anomaly) -> bool:
    """Capture-quality events are not TCP faults."""
    return anomaly.type not in CAPTURE_QUALITY_ANOMALY_TYPES


def _build_conclusion(report_anomalies: list[Anomaly], quality) -> dict:
    facts = []
    concerns = []
    unknowns = [
        "当前单侧 PCAP 无法进一步定位。",
        "需要双端 PCAP 或网络设备数据才能进一步缩小故障点。",
    ]

    tcp_anomalies = [a for a in report_anomalies if _is_tcp_anomaly(a)]
    high = [a for a in tcp_anomalies if a.severity == Severity.HIGH]
    warn = [a for a in tcp_anomalies if a.severity == Severity.WARNING]
    quality_issues = [a for a in report_anomalies if not _is_tcp_anomaly(a)]

    if quality.truncated_packets or getattr(quality, "file_cut_short", False):
        concerns.append(
            f"抓包质量问题：truncated={quality.truncated_packets}/{quality.total_packets}，"
            f"可信度 {quality.credibility}"
            + (", file_cut_short" if getattr(quality, "file_cut_short", False) else "")
        )
        unknowns.append("截断或不完整抓包可能导致部分 TCP/Payload 结论不完整。")

    for a in report_anomalies:
        facts.extend(a.facts)

    if high:
        verdict = "PCAP 可确认存在高优先级 TCP 异常（持续重传 / ACK 未推进 / 数据中 RST 等）。"
        color = "red"
    elif warn:
        verdict = "存在需关注的 TCP 现象，请结合 Frame 证据与 Wireshark 复核。"
        color = "yellow"
    elif quality_issues or quality.truncated_packets or getattr(quality, "file_cut_short", False):
        verdict = (
            "未确认高优先级 TCP 故障。"
            "检测到抓包质量问题（如 PACKET_TRUNCATED / 文件截断）；"
            "部分 TCP 结论可能不完整，不能将抓包截断本身表述为已确认的网络故障。"
        )
        color = "yellow"
    else:
        verdict = "在当前 PCAP 证据范围内，未观察到持续重传、ACK 停滞或高危 RST。"
        color = "green"

    return {
        "verdict": verdict,
        "color": color,
        "findings": facts[:20],
        "concerns": concerns + [a.summary for a in high + warn + quality_issues][:20],
        "conclusions": [
            "以下结论仅基于本 PCAP 可观察事实。",
            "程序不编造未经 PCAP 证实的设备根因。",
            "Capture Quality 与 TCP Health 分开评估；CONFIRMED 的截断事实不等于 CONFIRMED 的 TCP 故障。",
            "请使用报告中的 Wireshark Filter 人工复核。",
        ],
        "unknowns": unknowns,
        "tcp_health": (
            "HIGH" if high else ("WARNING" if warn else "INFO")
        ),
    }


def build_analysis_report(
    sessions: dict,
    thresholds: ThresholdConfig,
    db_port: int,
    source: str,
    all_packets: Optional[list] = None,
    *,
    file_cut_short: bool = False,
    file_warning: Optional[str] = None,
) -> AnalysisReport:
    """Analyze all sessions and produce an AnalysisReport."""
    packets = all_packets
    if packets is None:
        packets = []
        for s in sessions.values():
            packets.extend(s.packets)

    quality = analyze_capture_quality(
        packets,
        thresholds,
        file_cut_short=file_cut_short,
        file_warning=file_warning,
    )

    all_summaries: list[SessionSummary] = []
    all_anomalies: list[Anomaly] = []
    all_retx = []
    all_ack = []
    all_rst = []
    all_frames: list[FrameEvidence] = []
    all_filters: list[str] = []

    # Truncation anomalies — CAPTURE_QUALITY only (never TCP HIGH)
    trunc_frames = [p.frame_number for p in packets if p.truncated and p.frame_number is not None]
    if trunc_frames:
        all_anomalies.append(
            Anomaly(
                type="PACKET_TRUNCATED",
                severity=Severity.WARNING,
                evidence_level=EvidenceLevel.CONFIRMED,
                tcp_stream=None,
                summary=f"PACKET_TRUNCATED: {quality.truncated_packets} packets",
                detail=(
                    f"cap_len < frame.len 共 {quality.truncated_packets} 个报文。"
                    " CONFIRMED 仅表示抓包截断事实已确认，不表示已确认高优先级 TCP 故障。"
                    + (f" {quality.snaplen_hint}" if quality.snaplen_hint else "")
                ),
                frames=trunc_frames[:50],
                wireshark_filter="frame.cap_len < frame.len",
                facts=[
                    f"truncated_ratio={quality.truncated_ratio}",
                    f"credibility={quality.credibility}",
                    "category=CAPTURE_QUALITY",
                ],
                unknowns=["无法恢复 PCAP 中不存在的字节；当前单侧 PCAP 无法进一步定位。"],
            )
        )
        # Sample truncated frames into evidence.csv for cross-file consistency
        for pkt in packets:
            if pkt.truncated and pkt.frame_number in set(trunc_frames[:20]):
                # Use a lightweight synthetic session key from packet endpoints
                from dbcap.models import FlowKey, TcpSession

                key = FlowKey(
                    src_ip=pkt.src_ip,
                    src_port=pkt.src_port,
                    dst_ip=pkt.dst_ip,
                    dst_port=pkt.dst_port,
                    server_ip=pkt.dst_ip if pkt.dst_port == db_port else pkt.src_ip,
                    server_port=db_port,
                )
                tmp = TcpSession(tcp_stream=pkt.tcp_stream or -1, key=key)
                all_frames.append(
                    _frame_evidence_for_packet(
                        pkt,
                        tmp,
                        "PACKET_TRUNCATED",
                        Severity.WARNING.value,
                        EvidenceLevel.CONFIRMED.value,
                        "cap_len < frame.len; category=CAPTURE_QUALITY",
                        "frame.cap_len < frame.len",
                    )
                )

    multi_stream_high_retx = 0

    for session in sessions.values():
        result = analyze_session(session, thresholds)
        all_summaries.append(result["summary"])
        all_anomalies.extend(result["anomalies"])
        all_retx.extend(result["retx"])
        all_ack.extend(result["ack_stalled"])
        all_rst.extend(result["rst_events"])
        all_frames.extend(result["frame_evidence"])
        all_filters.extend(result["filters"])
        if any(r.severity == Severity.HIGH and r.plane == "data" for r in result["retx"]):
            multi_stream_high_retx += 1

    if multi_stream_high_retx >= 2:
        all_anomalies.append(
            Anomaly(
                type="MULTI_STREAM_RETRANSMISSION",
                severity=Severity.HIGH,
                evidence_level=EvidenceLevel.STRONG,
                tcp_stream=None,
                summary=f"{multi_stream_high_retx} 个独立 TCP Stream 同时存在持续重传",
                detail="多个会话同时持续重传，更像路径/环境问题而非单连接偶发。",
                frames=[],
                wireshark_filter="tcp.analysis.retransmission",
                facts=[f"high_retx_streams={multi_stream_high_retx}"],
                unknowns=["仍需双端证据定位具体故障点"],
            )
        )

    all_summaries.sort(
        key=lambda s: (
            s.severity != Severity.HIGH,
            s.severity != Severity.WARNING,
            -s.retransmissions,
        )
    )

    high = sum(1 for s in all_summaries if s.severity == Severity.HIGH)
    warn = sum(1 for s in all_summaries if s.severity == Severity.WARNING)
    info = len(all_summaries) - high - warn

    # TCP Health: sessions + TCP anomalies only (never capture-quality events)
    tcp_health = "INFO"
    if high:
        tcp_health = "HIGH"
    elif warn:
        tcp_health = "WARNING"
    for a in all_anomalies:
        if not _is_tcp_anomaly(a):
            continue
        if a.severity == Severity.HIGH:
            tcp_health = "HIGH"
        elif a.severity == Severity.WARNING and tcp_health == "INFO":
            tcp_health = "WARNING"

    quality_blocking = (
        quality.credibility in ("DEGRADED", "LOW")
        or quality.truncated_packets > 0
        or bool(getattr(quality, "file_cut_short", False))
    )

    # Analysis status: may be WARNING due to capture quality alone, without
    # inventing TCP HIGH. Real TCP HIGH is preserved alongside quality warnings.
    if tcp_health == "HIGH":
        analysis_status = "HIGH"
    elif tcp_health == "WARNING":
        analysis_status = "WARNING"
    elif quality_blocking:
        analysis_status = "WARNING"
    else:
        analysis_status = "INFO"

    analysis_confidence = "OK"
    if quality.credibility == "LOW":
        analysis_confidence = "LOW"
    elif quality_blocking or quality.credibility == "DEGRADED":
        analysis_confidence = "DEGRADED"

    # Legacy key "overall" = TCP Health (must not claim TCP HIGH for truncation-only)
    overall = tcp_health

    summary = {
        "total_flows": len(all_summaries),
        "total_sessions": len(all_summaries),
        "info": info,
        "healthy": info,  # legacy key
        "warning": warn,
        "high": high,
        "critical": high,  # legacy key mapping
        "overall": overall,
        "tcp_health": tcp_health,
        "analysis_status": analysis_status,
        "analysis_confidence": analysis_confidence,
        "flows_with_rst": sum(1 for s in all_summaries if s.rst),
        "flows_with_zero_window": sum(1 for s in all_summaries if s.zero_window > 0),
        "persistent_retx_segments": len(all_retx),
        "ack_stalled_events": len(all_ack),
        "capture_credibility": quality.credibility,
        "capture_quality_blocking": quality_blocking,
        "input_quality": (
            "BLOCKING"
            if quality.credibility == "LOW"
            else ("DEGRADED" if quality_blocking else "OK")
        ),
    }

    conclusion = _build_conclusion(all_anomalies, quality)
    unknowns = list(conclusion.get("unknowns", []))

    # Deduplicate filters
    uniq_filters = []
    seen = set()
    for f in all_filters:
        if f and f not in seen:
            seen.add(f)
            uniq_filters.append(f)

    recommendations = [
        "使用报告中的 Wireshark Filter 对关键 Frame 进行人工复核。",
        "若存在 ACK_STALLED / 持续重传，优先补充对端 PCAP 做交叉验证。",
        "若存在 PACKET_TRUNCATED，请使用更大 snaplen 重新抓包后再做 Payload/协议分析。",
    ]

    from dbcap import __version__ as _ver

    return AnalysisReport(
        metadata={
            "tool": "dbcap",
            "version": _ver,
            "timestamp": datetime.now().isoformat(),
            "source": source,
            "db_port": db_port,
            "db_type": get_db_name(db_port),
            "total_flows": len(all_summaries),
            "python_version": sys.version.split()[0],
        },
        summary=summary,
        sessions=all_summaries,
        flows=all_summaries,
        anomalies=all_anomalies,
        persistent_retx=all_retx,
        ack_stalled=all_ack,
        rst_events=all_rst,
        frame_evidence=all_frames,
        capture_quality=quality,
        recommendations=recommendations,
        conclusion=conclusion,
        wireshark_filters=uniq_filters,
        unknowns=unknowns,
    )
