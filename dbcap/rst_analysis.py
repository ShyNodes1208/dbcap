"""RST classification."""

from __future__ import annotations

from dbcap.models import (
    EvidenceLevel,
    RstClass,
    RstEvent,
    Severity,
    TcpSession,
    ThresholdConfig,
)
from dbcap.session import packet_direction


def _sev(name: str, default: Severity) -> Severity:
    try:
        return Severity(name)
    except ValueError:
        return default


def classify_rst(
    session: TcpSession,
    thresholds: ThresholdConfig,
) -> list[RstEvent]:
    """
    Classify RST packets into:
      RST_AFTER_SYN / RST_DURING_DATA / ACK_TO_RST / RST_AFTER_FIN
    """
    events: list[RstEvent] = []
    saw_syn = False
    saw_synack = False
    saw_fin = False
    saw_data = False
    last_was_pure_ack = False

    for pkt in session.packets:
        direction = packet_direction(pkt, session.key.server_ip, session.key.server_port)

        if pkt.syn and not pkt.ack_flag:
            saw_syn = True
        if pkt.syn and pkt.ack_flag:
            saw_synack = True
        if pkt.fin:
            saw_fin = True
        if pkt.tcp_len > 0 and not pkt.syn:
            saw_data = True

        if pkt.rst:
            if saw_fin:
                cls = RstClass.RST_AFTER_FIN
                sev = _sev(thresholds.rst_after_fin_severity, Severity.INFO)
                note = "FIN 之后出现 RST，常见于应用主动关闭后的连接清理，不一定是严重网络故障。"
            elif last_was_pure_ack and saw_data:
                cls = RstClass.ACK_TO_RST
                sev = _sev(thresholds.ack_to_rst_severity, Severity.WARNING)
                note = "数据交互后在 ACK 之后出现 RST。"
            elif saw_data:
                cls = RstClass.RST_DURING_DATA
                sev = _sev(thresholds.rst_during_data_severity, Severity.HIGH)
                note = "数据传输过程中出现 RST，连接被中途重置。"
            elif saw_syn or saw_synack:
                cls = RstClass.RST_AFTER_SYN
                sev = _sev(thresholds.rst_after_syn_severity, Severity.WARNING)
                note = "握手阶段或握手刚完成后出现 RST，可能是监听拒绝、防火墙或服务未就绪。"
            else:
                cls = RstClass.RST_OTHER
                sev = Severity.WARNING
                note = "捕获范围内未见完整握手/数据上下文的 RST。"

            frame = pkt.frame_number
            ws_filter = f"tcp.stream eq {session.tcp_stream}"
            if frame is not None:
                ws_filter = f"{ws_filter} && frame.number == {frame}"

            events.append(
                RstEvent(
                    tcp_stream=session.tcp_stream,
                    classification=cls,
                    frame=frame,
                    timestamp=pkt.timestamp,
                    direction=direction,
                    severity=sev,
                    wireshark_filter=ws_filter,
                    evidence_level=EvidenceLevel.CONFIRMED,
                    note=note,
                )
            )

        last_was_pure_ack = bool(
            pkt.ack_flag and not pkt.syn and not pkt.fin and not pkt.rst and pkt.tcp_len == 0
        )

    return events
