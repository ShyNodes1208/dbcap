"""JDBC timeline report exporters."""

from __future__ import annotations

import csv
import os
from datetime import datetime, timezone
from typing import Optional

from dbcap.jdbc.models import JdbcTimelineResult
from dbcap.jdbc.redact import redact_secrets


def _fmt(ts: Optional[float]) -> str:
    if ts is None:
        return ""
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def export_jdbc_events_csv(result: JdbcTimelineResult, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fields = [
        "event_id",
        "timestamp",
        "timestamp_raw",
        "event_type",
        "exception_class",
        "message",
        "caused_by_class",
        "caused_by_message",
        "thread_name",
        "database_host",
        "database_port",
        "connection_hint",
        "source_file",
        "source_line_start",
        "source_line_end",
        "used_time_ms",
        "group_id",
        "occurrence_count",
        "is_group_primary",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for e in result.events:
            w.writerow(
                {
                    "event_id": e.event_id,
                    "timestamp": e.timestamp,
                    "timestamp_raw": e.timestamp_raw,
                    "event_type": e.event_type,
                    "exception_class": e.exception_class or "",
                    "message": e.message or "",
                    "caused_by_class": e.caused_by_class or "",
                    "caused_by_message": e.caused_by_message or "",
                    "thread_name": e.thread_name or "",
                    "database_host": e.database_host or "",
                    "database_port": e.database_port or "",
                    "connection_hint": e.connection_hint or "",
                    "source_file": e.source_file,
                    "source_line_start": e.start_line,
                    "source_line_end": e.end_line,
                    "used_time_ms": e.used_time_ms if e.used_time_ms is not None else "",
                    "group_id": e.group_id or "",
                    "occurrence_count": e.occurrence_count,
                    "is_group_primary": e.is_group_primary,
                }
            )
    return path


def export_jdbc_correlations_csv(result: JdbcTimelineResult, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fields = [
        "event_id",
        "correlation_status",
        "evidence_level",
        "dual_correlation_id",
        "client_ip",
        "client_port",
        "server_ip",
        "server_port",
        "app_stream",
        "db_stream",
        "event_timestamp",
        "flow_start",
        "flow_end",
        "nearest_tcp_event",
        "nearest_tcp_event_time",
        "delta_seconds",
        "candidate_count",
        "flows_considered",
        "filtered_endpoint",
        "filtered_time",
        "eligible_count",
        "identity_score",
        "health_score",
        "reason",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for c in result.correlations:
            top = c.candidates[0] if c.candidates else None
            w.writerow(
                {
                    "event_id": c.event_id,
                    "correlation_status": c.correlation_status,
                    "evidence_level": c.evidence_level,
                    "dual_correlation_id": c.dual_correlation_id or "",
                    "client_ip": c.client_ip or "",
                    "client_port": c.client_port or "",
                    "server_ip": c.server_ip or "",
                    "server_port": c.server_port or "",
                    "app_stream": c.app_stream if c.app_stream is not None else "",
                    "db_stream": c.db_stream if c.db_stream is not None else "",
                    "event_timestamp": c.event_timestamp if c.event_timestamp is not None else "",
                    "flow_start": c.flow_start if c.flow_start is not None else "",
                    "flow_end": c.flow_end if c.flow_end is not None else "",
                    "nearest_tcp_event": c.nearest_tcp_event or "",
                    "nearest_tcp_event_time": c.nearest_tcp_event_time
                    if c.nearest_tcp_event_time is not None
                    else "",
                    "delta_seconds": c.delta_seconds if c.delta_seconds is not None else "",
                    "candidate_count": c.candidate_count,
                    "flows_considered": c.flows_considered,
                    "filtered_endpoint": c.filtered_endpoint,
                    "filtered_time": c.filtered_time,
                    "eligible_count": c.eligible_count,
                    "identity_score": top.identity_score if top else "",
                    "health_score": top.health_score if top else "",
                    "reason": c.reason,
                }
            )
    return path


def export_jdbc_timeline_csv(result: JdbcTimelineResult, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fields = [
        "event_id",
        "timeline_timestamp",
        "relative_seconds",
        "source",
        "event_type",
        "side",
        "frame",
        "stream",
        "correlation_id",
        "direction",
        "app_stream",
        "db_stream",
        "seq",
        "ack",
        "len",
        "description",
        "evidence_level",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for t in result.timeline:
            w.writerow(
                {
                    "event_id": t.event_id,
                    "timeline_timestamp": t.timeline_timestamp
                    if t.timeline_timestamp is not None
                    else "",
                    "relative_seconds": t.relative_seconds
                    if t.relative_seconds is not None
                    else "",
                    "source": t.source,
                    "event_type": t.event_type,
                    "side": t.side,
                    "frame": t.frame if t.frame is not None else "",
                    "stream": t.stream if t.stream is not None else "",
                    "correlation_id": t.correlation_id or "",
                    "direction": t.direction or "",
                    "app_stream": t.app_stream if t.app_stream is not None else "",
                    "db_stream": t.db_stream if t.db_stream is not None else "",
                    "seq": t.seq if t.seq is not None else "",
                    "ack": t.ack if t.ack is not None else "",
                    "len": t.tcp_len if t.tcp_len is not None else "",
                    "description": redact_secrets(t.description),
                    "evidence_level": t.evidence_level,
                }
            )
    return path


def export_jdbc_report_md(result: JdbcTimelineResult, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    lines: list[str] = []
    lines.append("# DBCAP JDBC/TCP Timeline Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    key = next((e for e in result.events if e.event_type == "CONNECTION_RESET"), None)
    key = key or (result.events[0] if result.events else None)
    corr = None
    if key:
        corr = next((c for c in result.correlations if c.event_id == key.event_id), None)
    if key and corr:
        lines.append(
            f"应用日志在 `{key.timestamp_raw}` 记录了 `{key.event_type}`"
            f"（{key.caused_by_class or key.exception_class or 'exception'}）。"
        )
        if corr.app_stream is not None:
            if corr.correlation_status == "AMBIGUOUS":
                lines.append(
                    f"在该时间附近，与数据库 `{corr.server_ip}:{corr.server_port}` "
                    f"通信的 TCP 连接存在多个候选（`{corr.candidate_count}` 个），"
                    f"因此关联状态为 **AMBIGUOUS**（证据不足唯一确认）。"
                )
                lines.append(
                    f"得分最高建议候选为 `{corr.dual_correlation_id}` "
                    f"（应用侧 stream `{corr.app_stream}` / 数据库侧 stream `{corr.db_stream}`）；"
                    "完整候选列表见第 6 节。JDBC 日志未提供客户端源端口，故不做 CONFIRMED。"
                )
            else:
                lines.append(
                    f"程序在该时间附近关联到与数据库 `{corr.server_ip}:{corr.server_port}` "
                    f"通信的 TCP 连接（`{corr.dual_correlation_id}`）："
                    f"应用侧 stream `{corr.app_stream}`，数据库侧 stream `{corr.db_stream}`。"
                )
                lines.append(
                    f"关联状态：`{corr.correlation_status}` / 证据等级：`{corr.evidence_level}`。"
                )
            lines.append(
                "JDBC 时间与 App-side 抓包时间做相关，不宣称两台主机时钟绝对同步。"
            )
        else:
            lines.append("未能自动关联到 TCP 连接；见候选与 Unknown 章节。")
    else:
        lines.append("未解析到 JDBC 网络异常事件。")
    lines.append("")
    lines.append("Ping evidence was not analyzed in V2.2.")
    lines.append("")

    lines.append("## 1. Input Files")
    lines.append(f"- JDBC log: `{result.jdbc_log}`")
    lines.append(f"- App-side PCAP: `{result.app_pcap}`")
    lines.append(f"- DB-side PCAP: `{result.db_pcap}`")
    lines.append(f"- Server IP: `{result.server_ip}`  Port: `{result.db_port}`")
    lines.append(f"- Correlation window: ±{result.window_seconds}s")
    lines.append(
        f"- Candidate lifetime grace: {result.lifetime_grace_seconds:g}s "
        "(flow end shortly before JDBC event remains eligible)"
    )
    lines.append("")

    lines.append("## 2. JDBC Events Summary")
    lines.append(f"- Events: **{len(result.events)}**")
    for e in result.events:
        lines.append(
            f"- `{e.event_id}` `{e.timestamp_raw}` `{e.event_type}` "
            f"lines {e.start_line}-{e.end_line} thread=`{e.thread_name}`"
        )
    lines.append("")

    lines.append("## 3. TCP Correlation Summary")
    for c in result.correlations:
        lines.append(
            f"- `{c.event_id}` → `{c.correlation_status}` / `{c.evidence_level}` "
            f"dual=`{c.dual_correlation_id}` app_stream={c.app_stream} db_stream={c.db_stream} "
            f"eligible={c.eligible_count}"
        )
        lines.append(
            f"  - Filter: considered={c.flows_considered} "
            f"endpoint={c.filtered_endpoint} time={c.filtered_time} "
            f"eligible={c.eligible_count}"
        )
        if c.candidates:
            top = c.candidates[0]
            lines.append(
                f"  - Top identity={top.identity_score:.1f} health={top.health_score:.1f} "
                f"(ranking is primarily identity-based)"
            )
        lines.append(f"  - Reason: {c.reason}")
    lines.append("")

    lines.append("## 4. Clock / Time Alignment")
    lines.append(f"- Dual clock status: **{result.clock_status}**")
    lines.append(f"- Note: {result.clock_note}")
    lines.append(
        "- JDBC log time is correlated with app-side capture time "
        "(Observed time difference; not proven identical clocks)."
    )
    if result.clock_status != "OK":
        lines.append("- Clock alignment confidence: **LOW**")
    lines.append("")

    if key:
        lines.append("## 5. Key JDBC Event")
        lines.append(f"- ID: `{key.event_id}`")
        lines.append(f"- Time: `{key.timestamp_raw}`")
        lines.append(f"- Type: `{key.event_type}`")
        lines.append(f"- Exception: `{key.exception_class}` — {key.message}")
        lines.append(f"- Caused by: `{key.caused_by_class}` — {key.caused_by_message}")
        lines.append(f"- Thread: `{key.thread_name}` tid={key.tid}")
        lines.append(f"- Connection hint: `{key.connection_hint}`")
        lines.append(f"- Source: lines {key.start_line}-{key.end_line}")
        lines.append(f"- USED TIME: {key.used_time_ms} ms")
        lines.append("")

    if corr:
        lines.append("## 6. Related TCP Flow")
        lines.append(
            f"- Suggested top candidate: `{corr.client_ip}:{corr.client_port}` ↔ "
            f"`{corr.server_ip}:{corr.server_port}`"
        )
        lines.append(f"- Dual correlation (top): `{corr.dual_correlation_id}`")
        lines.append(f"- App stream: `{corr.app_stream}`  DB stream: `{corr.db_stream}`")
        lines.append(f"- Flow lifetime (app clock): {_fmt(corr.flow_start)} → {_fmt(corr.flow_end)}")
        if corr.candidates:
            lines.append(f"- Ranked candidates ({corr.candidate_count} total, showing top):")
            for cand in corr.candidates[:8]:
                lines.append(
                    f"  - {cand.dual_correlation_id} "
                    f"{cand.client_ip}:{cand.client_port} "
                    f"app_stream={cand.app_stream} db_stream={cand.db_stream} "
                    f"identity={cand.identity_score:.1f} health={cand.health_score:.1f} "
                    f"total={cand.score:.1f} — {'; '.join(cand.reasons[:4])}"
                )
        lines.append("")

    tl = [t for t in result.timeline if key and t.event_id == key.event_id]
    before = [t for t in tl if t.relative_seconds is not None and t.relative_seconds < 0]
    after = [t for t in tl if t.relative_seconds is not None and t.relative_seconds > 0]
    lines.append("## 7. Timeline Before JDBC Error")
    for t in before[-30:]:
        lines.append(
            f"- `{_fmt(t.timeline_timestamp)}` ({t.relative_seconds:+.3f}s) "
            f"[{t.source}/{t.side}] `{t.event_type}` {t.description}"
        )
    if not before:
        lines.append("- (none in window)")
    lines.append("")
    lines.append("## 8. Timeline After JDBC Error")
    for t in after[:30]:
        lines.append(
            f"- `{_fmt(t.timeline_timestamp)}` ({t.relative_seconds:+.3f}s) "
            f"[{t.source}/{t.side}] `{t.event_type}` {t.description}"
        )
    if not after:
        lines.append("- (none in window)")
    lines.append("")

    lines.append("## 9. Dual-PCAP Evidence")
    lines.append("- Dual matched segments near the JDBC time appear as `MATCHED_SEGMENT` in the timeline.")
    lines.append("- Negative relative_seconds = before JDBC error; positive = after.")
    lines.append(
        "- Temporal correlation does not by itself prove causation "
        "(e.g. ACK_STALLED preceded JDBC Connection reset)."
    )
    lines.append("")

    lines.append("## 10. Key Frames")
    for t in tl:
        if t.frame is not None and t.event_type in (
            "MATCHED_SEGMENT",
            "RST",
            "FIN",
            "ACK_STALLED",
            "DATA_RETRANSMISSION",
        ):
            lines.append(
                f"- {t.side} frame.number == {t.frame}  stream={t.stream}  "
                f"{t.event_type} seq={t.seq} len={t.tcp_len}"
            )
    lines.append("")

    lines.append("## 11. Wireshark Verification")
    if corr and corr.candidates:
        for cand in corr.candidates[:5]:
            lines.append(
                f"- Candidate `{cand.dual_correlation_id}`: "
                f"App `tcp.stream eq {cand.app_stream}` / "
                f"DB `tcp.stream eq {cand.db_stream}` "
                f"({cand.client_ip}:{cand.client_port})"
            )
    elif corr and corr.app_stream is not None:
        lines.append(f"- App-side Filter: `tcp.stream eq {corr.app_stream}`")
        lines.append(f"- DB-side Filter: `tcp.stream eq {corr.db_stream}`")
    else:
        lines.append("- (no flow selected)")
    lines.append("")

    lines.append("## 12. Confirmed Facts")
    lines.append("- JDBC ERROR block timestamps and exception text as parsed from the log.")
    lines.append("- Dual-PCAP stream pairs come from V2.1 correlation (not from JDBC).")
    lines.append("")

    lines.append("## 13. Correlated Evidence")
    lines.append("- JDBC event time vs app-side TCP activity within the configured window.")
    lines.append("- Selected DualFlow host/port/lifetime scoring (see correlation reason).")
    lines.append("")

    lines.append("## 14. Unknown / Cannot Determine")
    lines.append("- Absolute clock equality between JDBC host and capture hosts.")
    lines.append("- Device-level root cause (firewall/switch/NIC) from JDBC+TCP alone.")
    lines.append("- Mapping JDBC `conn-N` pool id to a TCP source port (not present in log).")
    lines.append("")

    lines.append("## 15. Investigation Directions")
    lines.append("- Manually verify per-side Wireshark filters and key frames above.")
    lines.append("- Cross-check capture quality and time coverage around the JDBC timestamp.")
    lines.append("- Ping evidence was not analyzed in V2.2.")
    lines.append("")

    lines.append("## Limitations")
    for lim in result.limitations:
        lines.append(f"- {lim}")
    lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def export_all_jdbc(result: JdbcTimelineResult, output_dir: str) -> dict[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    return {
        "jdbc_events_csv": export_jdbc_events_csv(
            result, os.path.join(output_dir, "jdbc_events.csv")
        ),
        "jdbc_correlations_csv": export_jdbc_correlations_csv(
            result, os.path.join(output_dir, "jdbc_tcp_correlations.csv")
        ),
        "jdbc_timeline_csv": export_jdbc_timeline_csv(
            result, os.path.join(output_dir, "jdbc_timeline.csv")
        ),
        "jdbc_report_md": export_jdbc_report_md(
            result, os.path.join(output_dir, "jdbc_report.md")
        ),
    }
