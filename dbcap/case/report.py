"""Unified case report exporters (V2.4)."""

from __future__ import annotations

import csv
import os
from datetime import datetime
from typing import Optional

from dbcap.case.html_report import export_case_html
from dbcap.case.models import CaseAnalysisResult
from dbcap.dual.dual_report import export_all_dual
from dbcap.jdbc.redact import redact_secrets
from dbcap.jdbc.report import export_all_jdbc
from dbcap.ping.report import export_all_ping


def _fmt(ts: Optional[float]) -> str:
    if ts is None:
        return ""
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def export_unified_timeline_csv(result: CaseAnalysisResult, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fields = [
        "case_id",
        "timestamp",
        "relative_to_jdbc_seconds",
        "source",
        "event_type",
        "correlation_id",
        "app_stream",
        "db_stream",
        "frame",
        "direction",
        "seq",
        "ack",
        "len",
        "description",
        "evidence_class",
        "confidence",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in result.unified_timeline:
            w.writerow(
                {
                    "case_id": r.case_id,
                    "timestamp": "" if r.timestamp is None else r.timestamp,
                    "relative_to_jdbc_seconds": ""
                    if r.relative_to_jdbc_seconds is None
                    else r.relative_to_jdbc_seconds,
                    "source": r.source,
                    "event_type": r.event_type,
                    "correlation_id": r.correlation_id or "",
                    "app_stream": "" if r.app_stream is None else r.app_stream,
                    "db_stream": "" if r.db_stream is None else r.db_stream,
                    "frame": "" if r.frame is None else r.frame,
                    "direction": r.direction or "",
                    "seq": "" if r.seq is None else r.seq,
                    "ack": "" if r.ack is None else r.ack,
                    "len": "" if r.tcp_len is None else r.tcp_len,
                    "description": redact_secrets(r.description),
                    "evidence_class": r.evidence_class,
                    "confidence": r.confidence,
                }
            )
    return path


def export_unified_report_md(result: CaseAnalysisResult, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    jdbc = result.jdbc
    dual = result.dual
    ping = result.ping
    key = next((e for e in jdbc.events if e.event_id == result.key_jdbc_event_id), None)
    corr = next(
        (c for c in jdbc.correlations if c.event_id == result.key_jdbc_event_id), None
    )
    ping_corr = next(
        (c for c in ping.correlations if c.event_id == result.key_jdbc_event_id), None
    )

    lines: list[str] = []
    lines.append("# DBCAP Database Connection Fault Report")
    lines.append("")
    lines.append("## 1. Executive Summary")
    lines.append("")
    if key and corr:
        lines.append(
            f"应用日志在 `{key.timestamp_raw}` 记录了 `{key.event_type}`"
            f"（{key.caused_by_class or key.exception_class}）。"
        )
        lines.append("")
        if corr.correlation_status == "AMBIGUOUS":
            lines.append(
                f"程序在该时间附近识别到 **{corr.candidate_count}** 个可能的数据库 TCP 连接，"
                "但 JDBC 日志缺少客户端源端口，因此 **无法唯一确认** "
                "该异常对应哪一条 TCP 连接（状态：`AMBIGUOUS`）。"
            )
            lines.append("")
            lines.append(
                f"目前得分最高候选为 `{corr.dual_correlation_id}` "
                f"（App stream `{corr.app_stream}` / DB stream `{corr.db_stream}`）。"
            )
            if corr.candidates and len(corr.candidates) > 1:
                c2 = corr.candidates[1]
                lines.append(
                    f"接近候选包括 `{c2.dual_correlation_id}` "
                    f"（App stream `{c2.app_stream}` / DB stream `{c2.db_stream}`, "
                    f"score={c2.score:.1f}）。"
                )
        else:
            lines.append(
                f"关联状态 `{corr.correlation_status}` / `{corr.evidence_level}`："
                f"`{corr.dual_correlation_id}` "
                f"（App stream `{corr.app_stream}` / DB stream `{corr.db_stream}`）。"
            )
        lines.append("")
        if ping_corr:
            lines.append(f"Ping（SUPPORTING）：{ping_corr.summary}")
        elif not ping.provided:
            lines.append("Ping Evidence: **NOT PROVIDED**.")
        lines.append("")
        lines.append(
            "因此：可确认 JDBC 异常文本与时间、以及双端 PCAP 中的候选连接证据；"
            "不能仅凭当前材料判定具体网络设备根因，也不能把 ICMP 等同于 TCP 健康。"
        )
    else:
        lines.append("未找到可用的 JDBC 网络异常事件。")
    lines.append("")

    lines.append("## 2. Inputs")
    lines.append(f"- Case ID: `{result.case_id}`")
    lines.append(f"- JDBC log: `{jdbc.jdbc_log}`")
    lines.append(f"- App PCAP: `{jdbc.app_pcap}`")
    lines.append(f"- DB PCAP: `{jdbc.db_pcap}`")
    lines.append(
        f"- Ping log: `{ping.ping_log if ping.provided else 'NOT PROVIDED'}`"
    )
    lines.append(f"- Server: `{jdbc.server_ip}` port `{jdbc.db_port}`")
    lines.append("")

    lines.append("## 3. JDBC Error")
    if key:
        lines.append(f"- Event: `{key.event_id}`")
        lines.append(f"- Time: `{key.timestamp_raw}`")
        lines.append(f"- Type: `{key.event_type}`")
        lines.append(f"- Exception: `{key.exception_class}` — {key.message}")
        lines.append(
            f"- Caused by: `{key.caused_by_class}` — {key.caused_by_message}"
        )
        lines.append(f"- Thread: `{key.thread_name}` hint=`{key.connection_hint}`")
        lines.append(f"- Lines: {key.start_line}-{key.end_line}")
        lines.append(f"- USED TIME: {key.used_time_ms} ms")
    lines.append("")

    lines.append("## 4. TCP Connection Candidates")
    if corr and corr.candidates:
        lines.append(
            f"- Status: `{corr.correlation_status}` / `{corr.evidence_level}`"
        )
        lines.append(
            f"- Filter: considered={corr.flows_considered} "
            f"filtered_endpoint={corr.filtered_endpoint} "
            f"filtered_time={corr.filtered_time} "
            f"eligible={corr.eligible_count} "
            f"(grace={corr.lifetime_grace_seconds:g}s)"
        )
        lines.append(
            "- Candidate ranking is primarily identity-based. "
            "TCP anomaly severity is not treated as connection identity."
        )
        for i, c in enumerate(corr.candidates[:5], 1):
            lines.append(
                f"{i}. `{c.dual_correlation_id}` "
                f"identity={c.identity_score:.1f} health={c.health_score:.1f} "
                f"total={c.score:.1f} "
                f"app_stream={c.app_stream} db_stream={c.db_stream} "
                f"{c.client_ip}:{c.client_port} ↔ {c.server_ip}:{c.server_port} — "
                + "; ".join(c.reasons[:3])
            )
        if corr.correlation_status == "AMBIGUOUS":
            lines.append("")
            lines.append(
                "> Top-1 is a ranking suggestion only. Near-tie candidates remain open."
            )
    lines.append("")

    lines.append("## 5. Dual-PCAP Evidence")
    lines.append(f"- Dual correlated flows: {len(dual.correlated_flows)}")
    lines.append(f"- Clock: `{dual.clock.status}` — {dual.clock.note}")
    lines.append(
        f"- App capture quality: {dual.capture_quality_app.get('credibility')} "
        f"(file_cut_short={dual.capture_quality_app.get('file_cut_short')})"
    )
    lines.append(
        f"- DB capture quality: {dual.capture_quality_db.get('credibility')} "
        f"(file_cut_short={dual.capture_quality_db.get('file_cut_short')})"
    )
    lines.append("- Key MATCHED_SEGMENT / ACK_STALLED rows appear in Unified Timeline.")
    lines.append("")

    lines.append("## 6. TCP Timeline")
    lines.append("See `unified_timeline.csv` (important events only; retransmissions aggregated).")
    lines.append("")

    lines.append("## 7. Ping Supporting Evidence")
    if not ping.provided:
        lines.append("- Ping Evidence: **NOT PROVIDED**")
    elif ping_corr:
        lines.append(f"- Target: `{ping_corr.target_host}`")
        lines.append(f"- Window: ±{ping_corr.window_seconds}s")
        lines.append(
            f"- Samples={ping_corr.samples} Replies={ping_corr.replies} "
            f"Timeouts={ping_corr.timeouts} Unreachable={ping_corr.unreachable}"
        )
        lines.append(
            f"- RTT ms: min={ping_corr.min_rtt_ms} avg={ping_corr.avg_rtt_ms} "
            f"max={ping_corr.max_rtt_ms}"
        )
        lines.append(f"- Last reply before JDBC: `{_fmt(ping_corr.last_reply_before)}`")
        lines.append(f"- First reply after JDBC: `{_fmt(ping_corr.first_reply_after)}`")
        lines.append(
            f"- Nearest timeout before: `{_fmt(ping_corr.nearest_timeout_before)}`"
        )
        lines.append(
            f"- Nearest timeout after: `{_fmt(ping_corr.nearest_timeout_after)}`"
        )
        lines.append(f"- Summary: {ping_corr.summary}")
        lines.append(f"- Caution: {ping_corr.caution}")
    lines.append("")

    lines.append("## 8. Unified Timeline")
    lines.append(f"- Rows: {len(result.unified_timeline)} (see CSV)")
    # When AMBIGUOUS, group Dual/TCP rows by candidate so mixed candidates
    # are not read as one confirmed connection (H-01).
    is_ambiguous = bool(corr and corr.correlation_status == "AMBIGUOUS")
    if is_ambiguous:
        lines.append(
            "- Correlation is **AMBIGUOUS**: TCP evidence below is grouped by "
            "candidate `correlation_id` (not a single confirmed connection)."
        )
        by_cid: dict[str, list] = {}
        other: list = []
        for r in result.unified_timeline:
            if r.source in ("DUAL", "APP_PCAP", "DB_PCAP") and r.correlation_id:
                by_cid.setdefault(r.correlation_id, []).append(r)
            else:
                other.append(r)
        for r in other[:15]:
            lines.append(
                f"- `{_fmt(r.timestamp)}` "
                f"({'' if r.relative_to_jdbc_seconds is None else f'{r.relative_to_jdbc_seconds:+.3f}s'}) "
                f"[{r.source}] `{r.event_type}` {redact_secrets(r.description)}"
            )
        for cid, rows in by_cid.items():
            lines.append(f"### Candidate `{cid}`")
            for r in rows[:20]:
                dir_s = f" {r.direction}" if r.direction else ""
                streams = ""
                if r.app_stream is not None or r.db_stream is not None:
                    streams = f" app={r.app_stream} db={r.db_stream}"
                lines.append(
                    f"- `{_fmt(r.timestamp)}` "
                    f"({'' if r.relative_to_jdbc_seconds is None else f'{r.relative_to_jdbc_seconds:+.3f}s'}) "
                    f"[{r.source}] `{r.event_type}`{dir_s}{streams} "
                    f"{redact_secrets(r.description)}"
                )
            if len(rows) > 20:
                lines.append(f"- ... ({len(rows) - 20} more for `{cid}` in CSV)")
    else:
        for r in result.unified_timeline[:40]:
            cid = f" corr=`{r.correlation_id}`" if r.correlation_id else ""
            lines.append(
                f"- `{_fmt(r.timestamp)}` "
                f"({'' if r.relative_to_jdbc_seconds is None else f'{r.relative_to_jdbc_seconds:+.3f}s'}) "
                f"[{r.source}] `{r.event_type}`{cid} {redact_secrets(r.description)}"
            )
        if len(result.unified_timeline) > 40:
            lines.append(f"- ... ({len(result.unified_timeline) - 40} more in CSV)")
    lines.append("")

    lines.append("## 9. Confirmed Facts")
    for i, e in enumerate(result.confirmed, 1):
        lines.append(f"{i}. {redact_secrets(e.text)}")
    lines.append("")

    lines.append("## 10. Correlated Evidence")
    for i, e in enumerate(result.correlated, 1):
        lines.append(f"{i}. {redact_secrets(e.text)}")
    lines.append("")

    lines.append("## 11. Supporting Evidence")
    for i, e in enumerate(result.supporting, 1):
        lines.append(f"{i}. {redact_secrets(e.text)}")
    if not result.supporting:
        lines.append("- (none)")
    lines.append("")

    lines.append("## 12. Unknown / Cannot Determine")
    for i, e in enumerate(result.unknown, 1):
        lines.append(f"{i}. {e.text}")
    lines.append("")

    lines.append("## 13. Investigation Direction")
    lines.append(
        "- Manually verify top DualFlow candidates with per-side Wireshark filters."
    )
    lines.append(
        "- Review application connection-pool / socket logs around the JDBC timestamp."
    )
    lines.append(
        "- If ICMP timeouts cluster near the JDBC error, collect network-device logs "
        "between the two capture points — without treating Ping as TCP proof."
    )
    lines.append("")

    lines.append("## 14. Wireshark Manual Verification")
    if corr and corr.candidates:
        for c in corr.candidates[:5]:
            lines.append(
                f"- `{c.dual_correlation_id}`: "
                f"App `tcp.stream eq {c.app_stream}` / "
                f"DB `tcp.stream eq {c.db_stream}`"
            )
    # key frames from unified timeline
    for r in result.unified_timeline:
        if r.frame is not None and r.event_type in (
            "MATCHED_SEGMENT",
            "ACK_STALLED",
            "RST",
            "FIN",
        ):
            lines.append(
                f"- frame.number == {r.frame} ({r.event_type}) seq={r.seq} len={r.tcp_len}"
            )
    lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def export_all_case(result: CaseAnalysisResult, output_dir: str) -> dict[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    paths: dict[str, str] = {}
    paths.update(export_all_jdbc(result.jdbc, output_dir))
    paths.update(export_all_dual(result.dual, os.path.join(output_dir, "dual")))
    paths.update(export_all_ping(result.ping, output_dir))
    paths["unified_timeline_csv"] = export_unified_timeline_csv(
        result, os.path.join(output_dir, "unified_timeline.csv")
    )
    paths["unified_report_md"] = export_unified_report_md(
        result, os.path.join(output_dir, "unified_report.md")
    )
    # also alias
    paths["dbcap_report_md"] = export_unified_report_md(
        result, os.path.join(output_dir, "dbcap_report.md")
    )
    paths["report_html"] = export_case_html(
        result, os.path.join(output_dir, "report.html")
    )
    return paths
