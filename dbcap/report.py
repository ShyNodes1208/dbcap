"""Terminal, Markdown, CSV and JSON report generation."""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dbcap.models import AnalysisReport, Anomaly, Severity

SEVERITY_COLORS = {
    Severity.INFO: "cyan",
    Severity.WARNING: "yellow",
    Severity.HIGH: "red",
    Severity.HEALTHY: "green",
    Severity.CRITICAL: "red",
}


def render_terminal_report(report: AnalysisReport, console: Console) -> None:
    _print_header(report, console)
    _print_quality(report, console)
    _print_summary(report, console)
    _print_sessions(report, console)
    _print_anomalies(report, console)
    _print_recommendations(report, console)
    _print_conclusion(report, console)


def _print_header(report: AnalysisReport, console: Console) -> None:
    meta = report.metadata
    header = (
        f"[bold cyan]dbcap[/bold cyan] — DBCAP Offline Analyzer\n"
        f"Time: {meta.get('timestamp', 'N/A')}\n"
        f"Source: {meta.get('source')}\n"
        f"Database: {meta.get('db_type')} (port {meta.get('db_port')})\n"
        f"Sessions: {meta.get('total_flows')}"
    )
    console.print(Panel(header, title="Analysis Report"))


def _print_quality(report: AnalysisReport, console: Console) -> None:
    q = report.capture_quality
    cred = q.credibility
    color = "green" if cred == "HIGH" else ("yellow" if cred == "DEGRADED" else "red")
    console.print(
        f"[bold {color}]Capture Quality: {cred}[/bold {color}]  "
        f"truncated={q.truncated_packets}/{q.total_packets}"
    )
    if q.truncated_packets > 0:
        console.print(
            "[yellow]PACKET_TRUNCATED detected — "
            "Payload / protocol analysis may be incomplete.[/yellow]"
        )
    if getattr(q, "file_cut_short", False):
        console.print(
            "[yellow]CAPTURE_FILE_CUT_SHORT — TShark reported the capture file "
            "was cut short; recovered packets were analyzed.[/yellow]"
        )
    if getattr(q, "file_warning", None):
        console.print(f"[yellow]{q.file_warning}[/yellow]")
    if q.snaplen_hint:
        console.print(f"[yellow]{q.snaplen_hint}[/yellow]")


def _print_summary(report: AnalysisReport, console: Console) -> None:
    s = report.summary
    tcp_health = s.get("tcp_health", s.get("overall", "INFO"))
    analysis_status = s.get("analysis_status", tcp_health)
    confidence = s.get("analysis_confidence", "OK")
    color = (
        SEVERITY_COLORS.get(Severity(tcp_health), "white")
        if tcp_health in Severity.__members__
        else "white"
    )

    table = Table(title="TCP Health Summary", title_style="bold")
    table.add_column("Metric", style="dim")
    table.add_column("Value")
    table.add_row("Total Sessions", str(s.get("total_sessions", s.get("total_flows", 0))))
    table.add_row("INFO", str(s.get("info", s.get("healthy", 0))))
    table.add_row("WARNING", f"[yellow]{s.get('warning', 0)}[/yellow]")
    table.add_row("HIGH", f"[red]{s.get('high', s.get('critical', 0))}[/red]")
    table.add_row("Persistent Retx Segments", str(s.get("persistent_retx_segments", 0)))
    table.add_row("ACK Stalled", str(s.get("ack_stalled_events", 0)))
    table.add_row("Sessions with RST", str(s.get("flows_with_rst", 0)))
    table.add_row("Zero-Window Sessions", str(s.get("flows_with_zero_window", 0)))
    table.add_row("TCP Health", f"[bold {color}]{tcp_health}[/bold {color}]")
    table.add_row("Analysis Status", str(analysis_status))
    table.add_row("Analysis Confidence", str(confidence))
    console.print(table)


def _print_sessions(report: AnalysisReport, console: Console) -> None:
    sessions = report.sessions or report.flows
    if not sessions:
        console.print("[dim]No sessions.[/dim]")
        return

    table = Table(title="TCP Sessions", title_style="bold")
    table.add_column("Stream", justify="right")
    table.add_column("Client")
    table.add_column("Server")
    table.add_column("Pkts", justify="right")
    table.add_column("HS Lat")
    table.add_column("Retx", justify="right")
    table.add_column("Flags")

    for s in sessions[:50]:
        hs = f"{s.handshake_latency_ms}ms" if s.handshake_latency_ms is not None else "N/A"
        flags = []
        if s.rst:
            flags.append("RST")
        if s.fin:
            flags.append("FIN")
        if s.zero_window:
            flags.append("ZW")
        table.add_row(
            str(s.tcp_stream),
            f"{s.client_ip}:{s.client_port}",
            f"{s.server_ip}:{s.server_port}",
            str(s.packet_count),
            hs,
            str(s.retransmissions),
            " ".join(flags) or "-",
        )
    console.print(table)


def _print_anomalies(report: AnalysisReport, console: Console) -> None:
    if not report.anomalies:
        console.print("[green]No anomalies detected in current evidence scope.[/green]")
        return
    console.print("\n[bold]Anomalies[/bold]")
    for a in report.anomalies:
        if isinstance(a, Anomaly):
            sev = a.severity.value
            color = SEVERITY_COLORS.get(a.severity, "white")
            console.print(f"  [{color}]{sev}[/{color}] {a.type}: {a.summary}")
            console.print(f"    → {a.detail.splitlines()[0]}")
            if a.wireshark_filter:
                console.print(f"    filter: [dim]{a.wireshark_filter}[/dim]")
        else:
            console.print(f"  {a}")


def _print_recommendations(report: AnalysisReport, console: Console) -> None:
    console.print("\n[bold]Recommendations[/bold]")
    for i, rec in enumerate(report.recommendations, 1):
        console.print(f"  {i}. {rec}")


def _print_conclusion(report: AnalysisReport, console: Console) -> None:
    c = report.conclusion or {}
    if not c:
        return
    color = c.get("color", "white")
    console.print()
    console.print(Panel(f"[bold {color}]{c.get('verdict', '')}[/bold {color}]", title="结论"))
    if c.get("unknowns"):
        console.print("\n[bold]当前无法确认[/bold]")
        for u in c["unknowns"]:
            console.print(f"  - {u}")


def _serialize(obj: Any) -> Any:
    if hasattr(obj, "__dataclass_fields__"):
        return {f: _serialize(getattr(obj, f)) for f in obj.__dataclass_fields__}
    if isinstance(obj, Severity):
        return obj.value
    if hasattr(obj, "value") and hasattr(obj, "name") and not isinstance(obj, type):
        try:
            return obj.value
        except Exception:
            pass
    if isinstance(obj, list):
        return [_serialize(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    return obj


def export_json_report(report: AnalysisReport, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "anomalies.json")
    # Also keep timestamped full report for compatibility
    ts_path = os.path.join(
        output_dir, f"dbcap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    payload = _serialize(report)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "anomalies": payload.get("anomalies", []),
                "persistent_retx": payload.get("persistent_retx", []),
                "ack_stalled": payload.get("ack_stalled", []),
                "rst_events": payload.get("rst_events", []),
                "capture_quality": payload.get("capture_quality", {}),
                "unknowns": payload.get("unknowns", []),
            },
            f,
            ensure_ascii=False,
            indent=2,
        )
    with open(ts_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return ts_path


def export_flows_csv(report: AnalysisReport, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "flows.csv")
    sessions = report.sessions or report.flows
    fields = [
        "tcp_stream",
        "client_ip",
        "client_port",
        "server_ip",
        "server_port",
        "start_time",
        "end_time",
        "duration",
        "packet_count",
        "client_packets",
        "server_packets",
        "payload_bytes",
        "retransmissions",
        "RST",
        "FIN",
        "Zero_Window",
        "handshake_latency_ms",
        "rst_class",
        "severity",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for s in sessions:
            w.writerow(
                {
                    "tcp_stream": s.tcp_stream,
                    "client_ip": s.client_ip,
                    "client_port": s.client_port,
                    "server_ip": s.server_ip,
                    "server_port": s.server_port,
                    "start_time": s.start_time,
                    "end_time": s.end_time,
                    "duration": s.duration,
                    "packet_count": s.packet_count,
                    "client_packets": s.client_packets,
                    "server_packets": s.server_packets,
                    "payload_bytes": s.payload_bytes,
                    "retransmissions": s.retransmissions,
                    "RST": s.rst,
                    "FIN": s.fin,
                    "Zero_Window": s.zero_window,
                    "handshake_latency_ms": (
                        s.handshake_latency_ms if s.handshake_latency_ms is not None else "N/A"
                    ),
                    "rst_class": s.rst_class or "",
                    "severity": s.severity.value if hasattr(s.severity, "value") else s.severity,
                }
            )
    return path


def export_evidence_csv(report: AnalysisReport, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "evidence.csv")
    fields = [
        "frame_number",
        "timestamp",
        "tcp_stream",
        "direction",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "tcp_flags",
        "seq",
        "ack",
        "len",
        "expected_ack",
        "observed_ack",
        "window",
        "payload_sha256",
        "anomaly_type",
        "severity",
        "evidence_level",
        "wireshark_filter",
        "note",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for e in report.frame_evidence:
            w.writerow(
                {
                    "frame_number": e.frame_number if e.frame_number is not None else "",
                    "timestamp": e.timestamp if e.timestamp is not None else "",
                    "tcp_stream": e.tcp_stream if e.tcp_stream is not None else "",
                    "direction": e.direction or "",
                    "source_ip": e.source_ip or "",
                    "destination_ip": e.destination_ip or "",
                    "source_port": e.source_port,
                    "destination_port": e.destination_port,
                    "tcp_flags": e.tcp_flags or "",
                    "seq": e.seq,
                    "ack": e.ack,
                    "len": e.tcp_len,
                    "expected_ack": e.expected_ack if e.expected_ack is not None else "",
                    "observed_ack": (
                        e.observed_ack if e.observed_ack is not None else ""
                    ),
                    "window": e.window,
                    "payload_sha256": e.payload_sha256 or "",
                    "anomaly_type": e.anomaly_type or "",
                    "severity": e.severity or "",
                    "evidence_level": e.evidence_level or "",
                    "wireshark_filter": e.wireshark_filter or "",
                    "note": e.note or "",
                }
            )
    return path


def export_markdown_report(report: AnalysisReport, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "report.md")
    meta = report.metadata
    q = report.capture_quality
    c = report.conclusion or {}

    lines: list[str] = []
    lines.append("# PCAP 网络分析报告")
    lines.append("")
    lines.append("## 1. 分析对象")
    lines.append(f"- 文件: `{meta.get('source')}`")
    lines.append(f"- 数据库类型: {meta.get('db_type')}")
    lines.append(f"- 数据库端口: {meta.get('db_port')}")
    lines.append(f"- 分析时间: {meta.get('timestamp')}")
    lines.append(f"- 工具版本: {meta.get('version', '0.2.0')}")
    lines.append("")

    lines.append("## 2. 抓包完整性")
    lines.append(f"- 总包数: {q.total_packets}")
    lines.append(f"- 截断包数: {q.truncated_packets} (ratio={q.truncated_ratio})")
    lines.append(f"- 可信度: **{q.credibility}**")
    if q.truncated_packets > 0:
        lines.append("")
        lines.append("> **WARNING: PACKET_TRUNCATED detected**")
        lines.append(">")
        lines.append("> Capture Quality is DEGRADED/LOW. Payload / protocol analysis may be incomplete.")
        lines.append("> Do not treat this report as a complete view of application payloads.")
    if getattr(q, "file_cut_short", False):
        lines.append("")
        lines.append("> **WARNING: CAPTURE_FILE_CUT_SHORT**")
        lines.append(">")
        lines.append(
            "> TShark reported the capture file was cut short; recovered packets were analyzed."
        )
        if getattr(q, "file_warning", None):
            lines.append(f"> {q.file_warning}")
    if q.snaplen_hint:
        lines.append(f"- 提示: {q.snaplen_hint}")
    lines.append("")
    lines.append(f"- DBCAP Version: {meta.get('version')}")
    lines.append(f"- Python Version: {meta.get('python_version', 'N/A')}")
    lines.append(f"- TShark Version: {meta.get('tshark_version', 'N/A')}")
    lines.append(f"- Analysis Time: {meta.get('timestamp')}")
    lines.append("")

    lines.append("## 3. 总体结论")
    lines.append(c.get("verdict", ""))
    lines.append("")
    lines.append(f"- TCP Health: **{report.summary.get('tcp_health', report.summary.get('overall', 'INFO'))}**")
    lines.append(
        f"- Analysis Status: **{report.summary.get('analysis_status', report.summary.get('overall', 'INFO'))}**"
    )
    lines.append(
        f"- Analysis Confidence: **{report.summary.get('analysis_confidence', 'OK')}**"
    )
    lines.append("")
    for item in c.get("conclusions", []):
        lines.append(f"- {item}")
    lines.append("")

    lines.append("## 4. TCP 会话统计")
    lines.append("")
    lines.append(
        "| Stream | Client | Server | Pkts | C→S | S→C | Payload | Retx | RST | FIN | ZW | HS Lat |"
    )
    lines.append("|---:|---|---|---:|---:|---:|---:|---:|:---:|:---:|---:|---|")
    for s in report.sessions or []:
        hs = f"{s.handshake_latency_ms} ms" if s.handshake_latency_ms is not None else "N/A"
        lines.append(
            f"| {s.tcp_stream} | {s.client_ip}:{s.client_port} | "
            f"{s.server_ip}:{s.server_port} | {s.packet_count} | "
            f"{s.client_packets} | {s.server_packets} | {s.payload_bytes} | "
            f"{s.retransmissions} | {s.rst} | {s.fin} | {s.zero_window} | {hs} |"
        )
    lines.append("")

    lines.append("## 5. TCP 握手")
    for s in report.sessions or []:
        hs = f"{s.handshake_latency_ms} ms" if s.handshake_latency_ms is not None else "N/A"
        lines.append(f"- stream {s.tcp_stream}: Handshake Latency = **{hs}**")
    lines.append("")

    lines.append("## 6. 持续重传")
    if not report.persistent_retx:
        lines.append("未发现同一 Segment 的持续重传。")
    for r in report.persistent_retx:
        direction_cn = (
            "数据库 → 应用" if r.direction == "server_to_client" else "应用 → 数据库"
        )
        plane_label = getattr(r, "anomaly_type", "DATA_RETRANSMISSION")
        lines.append(
            f"### Stream {r.tcp_stream} / {plane_label} / {direction_cn} / "
            f"Seq={r.seq} Len={r.tcp_len}"
        )
        if getattr(r, "plane", "data") == "control":
            lines.append(
                "这是控制面重传（SYN/FIN/零长度段），不是业务 Payload 持续重传。"
            )
        else:
            lines.append(
                f"同一段 {r.tcp_len} 字节业务数据被重复发送。"
                f"重复次数={r.count}，持续={r.duration_ms:.1f} ms。"
            )
        lines.append(f"- Expected ACK = Seq + Len (+SYN/FIN) = **{r.expected_ack}**")
        lines.append(f"- Payload SHA256 = `{r.payload_sha256}`")
        lines.append(f"- Frames = {r.frames}")
        lines.append(f"- Severity = {r.severity.value}")
        lines.append(f"- Evidence = {r.evidence_level.value}")
        lines.append(f"- Wireshark Filter:")
        lines.append("```")
        lines.append(r.wireshark_filter)
        lines.append("```")
        lines.append("")

    lines.append("## 7. ACK 未推进")
    if not report.ack_stalled:
        lines.append("未发现 ACK_STALLED。")
    for ev in report.ack_stalled:
        lines.append(f"### Stream {ev.tcp_stream}")
        lines.append(f"- Severity: **{ev.severity.value}**")
        lines.append(f"- Evidence Level: **{ev.evidence_level.value}**")
        lines.append(
            f"发送方向 `{ev.send_direction}` 的数据 Seq={ev.seq} Len={ev.tcp_len} "
            f"理论 Expected ACK={ev.expected_ack}，"
            f"但观察 ACK 长期停留在 {ev.observed_ack}。"
        )
        lines.append(
            f"未推进持续 {ev.stall_duration_ms:.1f} ms，重传 {ev.retransmission_count} 次。"
        )
        lines.append(f"- Frames: {ev.frames}")
        lines.append(f"- Filter: `{ev.wireshark_filter}`")
        lines.append("")

    lines.append("## 8. RST 分析")
    if not report.rst_events:
        lines.append("未观察到 RST。")
    for rst in report.rst_events:
        lines.append(
            f"- stream {rst.tcp_stream}: **{rst.classification.value}** "
            f"(frame {rst.frame}, {rst.severity.value}) — {rst.note}"
        )
        lines.append(f"  - Filter: `{rst.wireshark_filter}`")
    lines.append("")

    lines.append("## 9. Zero Window / Window")
    zw_sessions = [s for s in (report.sessions or []) if s.zero_window]
    if not zw_sessions:
        lines.append("未发现 Zero Window。")
    for s in zw_sessions:
        lines.append(f"- stream {s.tcp_stream}: Zero Window 事件 {s.zero_window} 次")
    lines.append("")

    lines.append("## 10. 异常事件时间线")
    for a in report.anomalies:
        if isinstance(a, Anomaly):
            lines.append(
                f"- [{a.severity.value}] {a.type}: {a.summary} "
                f"(stream={a.tcp_stream}, frames={a.frames})"
            )
    lines.append("")

    lines.append("## 11. Payload")
    lines.append("异常 Segment 的 Payload 保存在 `payload/stream_<id>/` 目录。")
    lines.append("若抓包被 snaplen 截断，不能恢复 PCAP 中不存在的数据；禁止猜测 SQL。")
    lines.append("")

    lines.append("## 12. 协议层辅助分析")
    lines.append("第一阶段以 TCP 证据为主；达梦/Oracle/MySQL Decoder 仅为可选接口，本报告不依赖协议逆向。")
    lines.append("")

    lines.append("## 13. 原始报文证据")
    lines.append("详见 `evidence.csv`（含 Frame Number / Seq / Ack / Len / Expected ACK / SHA256）。")
    lines.append("")

    lines.append("## 14. Wireshark 人工复核过滤器")
    for f in report.wireshark_filters:
        lines.append("```")
        lines.append(f)
        lines.append("```")
    if not report.wireshark_filters:
        lines.append("（无异常过滤器）")
    lines.append("")

    lines.append("## 15. 当前无法确认的事项")
    for u in report.unknowns or c.get("unknowns", []):
        lines.append(f"- {u}")
    lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def export_all_reports(report: AnalysisReport, output_dir: str) -> dict[str, str]:
    """Export markdown/csv/json artifacts. Keeps legacy timestamped JSON."""
    return {
        "report_md": export_markdown_report(report, output_dir),
        "flows_csv": export_flows_csv(report, output_dir),
        "evidence_csv": export_evidence_csv(report, output_dir),
        "json": export_json_report(report, output_dir),
    }
