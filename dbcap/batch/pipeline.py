"""Batch case runner (V2.9). One subdirectory = one isolated case."""

from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Optional

from dbcap.autocase.pipeline import run_auto_case


def _esc(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _case_dirs(root: Path) -> list[Path]:
    return [p for p in sorted(root.iterdir()) if p.is_dir() and p.name != "dbcap_batch_output"]


def _summary_from_result(case_id: str, case_path: Path, rc: int, found, result, report_rel: str) -> dict:
    status = "SUCCESS"
    error_code = ""
    error_message = ""
    if rc != 0:
        status = found.status if found and found.status != "READY" else "ANALYSIS_FAILED"
        error_code = status
        error_message = (found.message if found else "")[:500]
    elif found and found.warnings:
        status = "SUCCESS_WITH_WARNINGS"

    primary = ""
    corr = ""
    cand = ""
    jdbc_n = 0
    ping_status = "NOT PROVIDED"
    capture = ""
    tcp_health = ""
    if result is not None:
        jdbc_n = len(result.jdbc.events)
        key = result.key_jdbc_event_id
        ev = next((e for e in result.jdbc.events if e.event_id == key), None)
        c = next((x for x in result.jdbc.correlations if x.event_id == key), None)
        if ev:
            primary = ev.event_type
        if c:
            corr = c.correlation_status
            cand = c.eligible_count
        if result.ping.provided:
            ping_status = "PROVIDED"
        app_q = (result.dual.capture_quality_app or {}).get("credibility")
        capture = str(app_q or "")
    return {
        "case_id": case_id,
        "case_path": str(case_path),
        "status": status,
        "jdbc_event_count": jdbc_n,
        "primary_event_type": primary,
        "correlation_status": corr,
        "candidate_count": cand,
        "tcp_health": tcp_health,
        "capture_quality": capture,
        "ping_status": ping_status,
        "report_html": report_rel,
        "error_code": error_code,
        "error_message": error_message.replace("\n", " "),
    }


def run_batch(
    root_dir: str,
    *,
    server_ip: Optional[str] = None,
    server_port: Optional[int] = None,
    output: Optional[str] = None,
    role_overrides: Optional[dict[str, str]] = None,
    thresholds=None,
    probe=None,
) -> tuple[int, list[dict]]:
    root = Path(root_dir)
    if not root.is_dir():
        return 2, []
    cases = _case_dirs(root)
    if not cases:
        return 2, []

    batch_out = Path(output) if output else root / "dbcap_batch_output"
    batch_out.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []

    for case in cases:
        case_id = case.name
        # Disambiguate identical names via relative path if needed (single level: name is unique)
        rel_id = case_id
        out = batch_out / rel_id
        rc, found, result = run_auto_case(
            str(case),
            server_ip=server_ip,
            server_port=server_port,
            output=str(out),
            role_overrides=role_overrides,
            case_id=rel_id,
            thresholds=thresholds,
            probe=probe,
        )
        report_rel = f"{rel_id}/report.html" if (out / "report.html").is_file() else ""
        rows.append(_summary_from_result(rel_id, case, rc, found, result, report_rel))

    _write_csv(batch_out / "batch_summary.csv", rows)
    (batch_out / "batch_summary.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _write_html(batch_out / "batch_report.html", rows)
    failed = [r for r in rows if r["status"] not in {"SUCCESS", "SUCCESS_WITH_WARNINGS"}]
    return (1 if failed else 0), rows


def _write_csv(path: Path, rows: list[dict]) -> None:
    fields = [
        "case_id",
        "case_path",
        "status",
        "jdbc_event_count",
        "primary_event_type",
        "correlation_status",
        "candidate_count",
        "tcp_health",
        "capture_quality",
        "ping_status",
        "report_html",
        "error_code",
        "error_message",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def _write_html(path: Path, rows: list[dict]) -> None:
    def n(status: str) -> int:
        return sum(1 for r in rows if r["status"] == status)

    corr_counts: dict[str, int] = {}
    for r in rows:
        k = r["correlation_status"] or "(none)"
        corr_counts[k] = corr_counts.get(k, 0) + 1
    body_rows = []
    for r in rows:
        link = (
            f'<a href="{_esc(r["report_html"])}">report</a>'
            if r["report_html"]
            else ""
        )
        body_rows.append(
            "<tr>"
            f"<td>{_esc(r['case_id'])}</td>"
            f"<td>{_esc(r['status'])}</td>"
            f"<td>{_esc(r['primary_event_type'])}</td>"
            f"<td>{_esc(r['correlation_status'])}</td>"
            f"<td>{_esc(r['candidate_count'])}</td>"
            f"<td>{_esc(r['ping_status'])}</td>"
            f"<td>{_esc(r['error_message'])}</td>"
            f"<td>{link}</td>"
            "</tr>"
        )
    corr_line = " ".join(f"{_esc(k)}={v}" for k, v in sorted(corr_counts.items()))
    doc = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"/>
<title>DBCAP Batch Report</title>
<style>
body {{ font-family: Segoe UI, Tahoma, sans-serif; margin: 1.2rem; background:#f7f5f0; }}
table {{ border-collapse: collapse; width: 100%; background:#fff; }}
th,td {{ border-bottom: 1px solid #ddd; padding: .4rem; text-align:left; font-size:.9rem; }}
th {{ background:#eef6f2; }}
.cards span {{ display:inline-block; margin:.3rem .6rem .3rem 0; background:#fff; padding:.4rem .6rem; border:1px solid #ddd; }}
</style></head><body>
<h1>DBCAP Batch Report</h1>
<p>Summary only. No cross-case root-cause inference.</p>
<div class="cards">
<span>Total: {len(rows)}</span>
<span>Success: {n('SUCCESS') + n('SUCCESS_WITH_WARNINGS')}</span>
<span>Warnings: {n('SUCCESS_WITH_WARNINGS')}</span>
<span>Failed: {len(rows) - n('SUCCESS') - n('SUCCESS_WITH_WARNINGS')}</span>
</div>
<p>Correlation counts: {corr_line}</p>
<table>
<thead><tr><th>Case</th><th>Status</th><th>Primary</th><th>Correlation</th>
<th>Candidates</th><th>Ping</th><th>Error</th><th>Report</th></tr></thead>
<tbody>{''.join(body_rows)}</tbody>
</table>
</body></html>
"""
    path.write_text(doc, encoding="utf-8")
