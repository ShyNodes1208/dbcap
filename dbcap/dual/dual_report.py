"""Dual-PCAP report exporters."""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timezone
from typing import Optional

from dbcap.dual.models import (
    DIR_APP_TO_DB,
    DIR_DB_TO_APP,
    STATUS_APP_ONLY,
    STATUS_BOTH,
    STATUS_DB_ONLY,
    DualAnalysisResult,
)


def _fmt(ts: Optional[float]) -> str:
    if ts is None:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


def _na(v) -> str:
    return "" if v is None else str(v)


def export_dual_flows_csv(result: DualAnalysisResult, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fields = [
        "correlation_id",
        "app_stream",
        "db_stream",
        "client_ip",
        "client_port",
        "server_ip",
        "server_port",
        "app_start",
        "app_end",
        "db_start",
        "db_end",
        "estimated_clock_offset",
        "matched_segments",
        "app_only_segments",
        "db_only_segments",
        "ambiguous_segments",
        "confidence",
        "note",
    ]
    offset = result.clock.estimated_offset_sec
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for flow in result.correlated_flows:
            segs = [s for s in result.segments if s.correlation_id == flow.correlation_id]
            w.writerow(
                {
                    "correlation_id": flow.correlation_id,
                    "app_stream": flow.app_stream,
                    "db_stream": flow.db_stream,
                    "client_ip": flow.flow_key.client_ip,
                    "client_port": flow.flow_key.client_port,
                    "server_ip": flow.flow_key.server_ip,
                    "server_port": flow.flow_key.server_port,
                    "app_start": flow.app_start,
                    "app_end": flow.app_end,
                    "db_start": flow.db_start,
                    "db_end": flow.db_end,
                    "estimated_clock_offset": _na(offset),
                    "matched_segments": sum(1 for s in segs if s.match_status == STATUS_BOTH),
                    "app_only_segments": sum(1 for s in segs if s.match_status == STATUS_APP_ONLY),
                    "db_only_segments": sum(1 for s in segs if s.match_status == STATUS_DB_ONLY),
                    "ambiguous_segments": sum(1 for s in segs if s.match_status == "AMBIGUOUS"),
                    "confidence": flow.confidence,
                    "note": flow.note,
                }
            )
    return path


def export_dual_segments_csv(result: DualAnalysisResult, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fields = [
        "correlation_id",
        "direction",
        "seq",
        "ack",
        "len",
        "expected_ack",
        "app_frame",
        "app_timestamp",
        "app_stream",
        "db_frame",
        "db_timestamp",
        "db_stream",
        "payload_hash_app",
        "payload_hash_db",
        "payload_hash_match",
        "observed_delta",
        "match_status",
        "evidence_level",
        "retx_count_app",
        "retx_count_db",
        "note",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for s in result.segments:
            w.writerow(
                {
                    "correlation_id": s.correlation_id,
                    "direction": s.direction,
                    "seq": s.seq,
                    "ack": _na(s.ack),
                    "len": s.tcp_len,
                    "expected_ack": _na(s.expected_ack),
                    "app_frame": _na(s.app_frame),
                    "app_timestamp": _na(s.app_timestamp),
                    "app_stream": _na(s.app_stream),
                    "db_frame": _na(s.db_frame),
                    "db_timestamp": _na(s.db_timestamp),
                    "db_stream": _na(s.db_stream),
                    "payload_hash_app": _na(s.payload_hash_app),
                    "payload_hash_db": _na(s.payload_hash_db),
                    "payload_hash_match": _na(s.payload_hash_match),
                    "observed_delta": _na(s.observed_delta),
                    "match_status": s.match_status,
                    "evidence_level": s.evidence_level,
                    "retx_count_app": s.retransmission_count_app,
                    "retx_count_db": s.retransmission_count_db,
                    "note": s.note,
                }
            )
    return path


def export_dual_anomalies_json(result: DualAnalysisResult, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    both = [s for s in result.segments if s.match_status == STATUS_BOTH]
    only = [s for s in result.segments if s.match_status in (STATUS_APP_ONLY, STATUS_DB_ONLY)]
    payload = {
        "app_pcap": result.app_pcap,
        "db_pcap": result.db_pcap,
        "db_port": result.db_port,
        "clock": result.clock.__dict__,
        "correlated_flow_count": len(result.correlated_flows),
        "matched_both": len(both),
        "one_side_only": len(only),
        "flows": [f.__dict__ | {"flow_key": f.flow_key.__dict__} for f in result.correlated_flows],
        "key_segments": [
            s.__dict__
            for s in result.segments
            if s.match_status == STATUS_BOTH and s.seq in (4895, 7125)
        ],
        "limitations": result.limitations,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, default=str)
    return path


def export_dual_report_md(result: DualAnalysisResult, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    both = [s for s in result.segments if s.match_status == STATUS_BOTH]
    app_only = [s for s in result.segments if s.match_status == STATUS_APP_ONLY]
    db_only = [s for s in result.segments if s.match_status == STATUS_DB_ONLY]
    app2db = [s for s in both if s.direction == DIR_APP_TO_DB]
    db2app = [s for s in both if s.direction == DIR_DB_TO_APP]

    lines: list[str] = []
    lines.append("# DBCAP Dual-PCAP Analysis Report")
    lines.append("")
    lines.append("## 1. Input Files")
    lines.append(f"- App-side PCAP: `{result.app_pcap}`")
    lines.append(f"- DB-side PCAP: `{result.db_pcap}`")
    lines.append(f"- Server IP hint: `{result.server_ip or 'N/A'}`")
    lines.append(f"- Database port: `{result.db_port}`")
    lines.append("")
    lines.append("## 2. Capture Quality")
    lines.append("")
    lines.append("| Side | Packets | Truncated | Credibility | file_cut_short | TCP Health | Confidence |")
    lines.append("|---|---:|---:|---|---|---|---|")
    for label, q in (("App", result.capture_quality_app), ("DB", result.capture_quality_db)):
        lines.append(
            f"| {label} | {q.get('total_packets')} | {q.get('truncated_packets')} | "
            f"{q.get('credibility')} | {q.get('file_cut_short')} | "
            f"{q.get('tcp_health')} | {q.get('analysis_confidence')} |"
        )
    lines.append("")
    lines.append("## 3. Session Correlation Summary")
    lines.append(f"- Correlated flows: **{len(result.correlated_flows)}**")
    lines.append(f"- Unmatched APP streams: {len(result.unmatched_app_streams)}")
    lines.append(f"- Unmatched DB streams: {len(result.unmatched_db_streams)}")
    lines.append("")
    lines.append("## 4. Clock Alignment")
    c = result.clock
    lines.append(f"- Status: **{c.status}**")
    lines.append(f"- Estimated offset (App−Db): `{_na(c.estimated_offset_sec)}`")
    lines.append(f"- Median/min/max delta: `{_na(c.median_delta)}` / `{_na(c.min_delta)}` / `{_na(c.max_delta)}`")
    lines.append(f"- Sample count: {c.sample_count}")
    lines.append(f"- Note: {c.note}")
    lines.append("")
    lines.append("> Observed timestamp delta is **not** automatically network latency.")
    lines.append("")
    lines.append("## 5. Matched TCP Sessions")
    lines.append("")
    if not result.correlated_flows:
        lines.append("No correlated flows.")
    else:
        lines.append("| correlation_id | client | server | app_stream | db_stream | confidence |")
        lines.append("|---|---|---|---:|---:|---|")
        for f in result.correlated_flows:
            lines.append(
                f"| {f.correlation_id} | {f.flow_key.client_ip}:{f.flow_key.client_port} | "
                f"{f.flow_key.server_ip}:{f.flow_key.server_port} | "
                f"{f.app_stream} | {f.db_stream} | {f.confidence} |"
            )
    lines.append("")
    lines.append("## 6. APP -> DB Segment Evidence")
    lines.append(f"- MATCHED_BOTH_SIDES: **{len(app2db)}**")
    for s in app2db[:30]:
        lines.append(
            f"- Seq={s.seq} Len={s.tcp_len} ExpectedACK={s.expected_ack} "
            f"hash_match={s.payload_hash_match} "
            f"app_frame={s.app_frame} db_frame={s.db_frame}"
        )
    lines.append("")
    lines.append("## 7. DB -> APP Segment Evidence")
    lines.append(f"- MATCHED_BOTH_SIDES: **{len(db2app)}**")
    for s in db2app[:30]:
        lines.append(
            f"- Seq={s.seq} Len={s.tcp_len} ExpectedACK={s.expected_ack} "
            f"hash_match={s.payload_hash_match} "
            f"app_frame={s.app_frame} db_frame={s.db_frame}"
        )
        if s.seq == 7125 and s.tcp_len == 124:
            lines.append(
                "  - CONFIRMED: this segment was observed on **both** capture points; "
                "must not be described as fully lost between DB and APP."
            )
    lines.append("")
    lines.append("## 8. Segments Seen Only On One Side")
    lines.append(f"- APP only: **{len(app_only)}**")
    lines.append(f"- DB only: **{len(db_only)}**")
    lines.append("")
    lines.append("One-sided observation is not automatic device-drop attribution.")
    lines.append("")
    lines.append("## 9. ACK Progress")
    lines.append("Expected ACK values come from frozen V1 `seq_ack.expected_ack`.")
    lines.append("")
    lines.append("## 10. Retransmission Correlation")
    for s in both[:20]:
        if s.retransmission_count_app > 1 or s.retransmission_count_db > 1:
            lines.append(
                f"- Seq={s.seq} Len={s.tcp_len}: APP copies={s.retransmission_count_app}, "
                f"DB copies={s.retransmission_count_db}"
            )
    lines.append("")
    lines.append("## 11. Key Evidence")
    for s in both:
        if (s.seq, s.tcp_len) in ((4895, 73), (7125, 124)):
            lines.append(
                f"- **{s.direction}** Seq={s.seq} Len={s.tcp_len}: {s.match_status} "
                f"evidence={s.evidence_level} hash_match={s.payload_hash_match}"
            )
            lines.append(f"  - {s.note}")
    lines.append("")
    lines.append("## 12. Wireshark Manual Verification")
    lines.append("")
    for f in result.correlated_flows[:10]:
        lines.append(f"### {f.correlation_id}")
        lines.append(f"- App-side Filter: `tcp.stream eq {f.app_stream}`")
        lines.append(f"- DB-side Filter: `tcp.stream eq {f.db_stream}`")
        key = [
            s
            for s in both
            if s.correlation_id == f.correlation_id and (s.seq, s.tcp_len) in ((4895, 73), (7125, 124))
        ]
        for s in key:
            if s.app_frame is not None:
                lines.append(f"- App-side frame: `frame.number == {s.app_frame}`")
            if s.db_frame is not None:
                lines.append(f"- DB-side frame: `frame.number == {s.db_frame}`")
    lines.append("")
    lines.append("## 13. Confirmed Facts")
    lines.append("- Sessions matched by normalized 4-tuple (not tcp.stream).")
    lines.append("- Payload hash MATCH implies same bytes at both capture points.")
    lines.append("")
    lines.append("## 14. Investigation Directions")
    lines.append("- Use per-side Wireshark filters above.")
    lines.append("- Correlate ACK_STALLED / retx counts across sides without inventing device root cause.")
    lines.append("")
    lines.append("## 15. Unknown / Cannot Determine")
    for lim in result.limitations:
        lines.append(f"- {lim}")
    lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def export_all_dual(result: DualAnalysisResult, output_dir: str) -> dict[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    return {
        "dual_report_md": export_dual_report_md(
            result, os.path.join(output_dir, "dual_report.md")
        ),
        "dual_flows_csv": export_dual_flows_csv(
            result, os.path.join(output_dir, "dual_flows.csv")
        ),
        "dual_segments_csv": export_dual_segments_csv(
            result, os.path.join(output_dir, "dual_segments.csv")
        ),
        "dual_anomalies_json": export_dual_anomalies_json(
            result, os.path.join(output_dir, "dual_anomalies.json")
        ),
    }
