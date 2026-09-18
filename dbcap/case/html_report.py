"""Offline self-contained HTML case report (V2.7) — presentation only."""

from __future__ import annotations

import html
import os
from datetime import datetime
from typing import Any, Optional

from dbcap.case.models import CaseAnalysisResult
from dbcap.jdbc.redact import redact_secrets


def _esc(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _fmt_ts(ts: Optional[float]) -> str:
    if ts is None:
        return ""
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _badge(text: str, kind: str) -> str:
    return f'<span class="badge badge-{_esc(kind)}">{_esc(text)}</span>'


def export_case_html(result: CaseAnalysisResult, path: str) -> str:
    """Render analysis result to a single offline HTML file."""
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

    app_q = dual.capture_quality_app or {}
    db_q = dual.capture_quality_db or {}
    corr_status = corr.correlation_status if corr else "N/A"
    primary_type = key.event_type if key else "N/A"
    primary_ts = key.timestamp_raw if key else "N/A"

    # --- JDBC events table ---
    ev_rows = []
    for e in jdbc.events:
        c = next((x for x in jdbc.correlations if x.event_id == e.event_id), None)
        top = c.dual_correlation_id if c else ""
        st = c.correlation_status if c else ""
        ev_rows.append(
            "<tr>"
            f"<td>{_esc(e.event_id)}</td>"
            f"<td>{_esc(e.timestamp_raw)}</td>"
            f"<td>{_esc(e.event_type)}</td>"
            f"<td>{_esc(e.occurrence_count)}</td>"
            f"<td>{_badge(st, st.lower() if st else 'info')}</td>"
            f"<td>{_esc(top)}</td>"
            f"<td>{_esc(c.eligible_count if c else '')}</td>"
            "</tr>"
        )

    # --- Candidates ---
    cand_rows = []
    if corr and corr.candidates:
        for i, c in enumerate(corr.candidates, 1):
            cand_rows.append(
                "<tr>"
                f"<td>{i}</td>"
                f"<td>{_esc(c.dual_correlation_id)}</td>"
                f"<td>{_esc(c.app_stream)}</td>"
                f"<td>{_esc(c.db_stream)}</td>"
                f"<td>{c.identity_score:.1f}</td>"
                f"<td>{c.health_score:.1f}</td>"
                f"<td>{c.score:.1f}</td>"
                f"<td>{_esc(c.filter_status)}</td>"
                f"<td>{_esc('; '.join(c.reasons[:3]))}</td>"
                "</tr>"
            )

    # --- Timeline (cap for size) ---
    tl_rows = []
    for r in result.unified_timeline[:200]:
        tl_rows.append(
            "<tr>"
            f"<td>{_esc(_fmt_ts(r.timestamp))}</td>"
            f"<td>{'' if r.relative_to_jdbc_seconds is None else f'{r.relative_to_jdbc_seconds:+.3f}'}</td>"
            f"<td>{_esc(r.source)}</td>"
            f"<td>{_esc(r.event_type)}</td>"
            f"<td>{_esc(r.correlation_id)}</td>"
            f"<td>{_esc(r.direction)}</td>"
            f"<td>{_esc(r.app_stream)}</td>"
            f"<td>{_esc(r.db_stream)}</td>"
            f"<td>{_esc(r.frame)}</td>"
            f"<td>{_esc(r.seq)}</td>"
            f"<td>{_esc(r.tcp_len)}</td>"
            f"<td>{_esc(redact_secrets(r.description))}</td>"
            f"<td>{_esc(r.evidence_class)}</td>"
            "</tr>"
        )
    tl_note = ""
    if len(result.unified_timeline) > 200:
        tl_note = (
            f"<p class='muted'>Showing 200 of {len(result.unified_timeline)} rows; "
            "see unified_timeline.csv for full export.</p>"
        )

    # --- Evidence lists ---
    def _elist(items):
        if not items:
            return "<li>(none)</li>"
        return "".join(f"<li>{_esc(redact_secrets(x.text))}</li>" for x in items)

    # --- Wireshark ---
    ws_bits = []
    if corr and corr.candidates:
        for c in corr.candidates[:5]:
            ws_bits.append(
                f"<li><strong>{_esc(c.dual_correlation_id)}</strong>: "
                f"<code>tcp.stream eq { _esc(c.app_stream) }</code> (APP) / "
                f"<code>tcp.stream eq { _esc(c.db_stream) }</code> (DB)</li>"
            )
    for r in result.unified_timeline:
        if r.frame is not None and r.event_type in (
            "MATCHED_SEGMENT",
            "ACK_STALLED",
            "RST",
            "FIN",
        ):
            ws_bits.append(
                f"<li><code>frame.number == {_esc(r.frame)}</code> "
                f"({_esc(r.event_type)}) corr={_esc(r.correlation_id)} "
                f"seq={_esc(r.seq)} len={_esc(r.tcp_len)}</li>"
            )
            if len(ws_bits) > 40:
                break

    ambiguous_banner = ""
    if corr and corr.correlation_status == "AMBIGUOUS":
        ambiguous_banner = (
            '<div class="callout callout-warn">'
            "<strong>AMBIGUOUS:</strong> 当前证据不足以唯一确定该 JDBC 错误对应的 TCP 连接。"
            " Top candidate 仅为身份排名建议，不是 Confirmed connection。"
            "</div>"
        )

    exec_bits = []
    if key:
        exec_bits.append(
            f"应用日志在 <code>{_esc(key.timestamp_raw)}</code> 记录了 "
            f"<code>{_esc(key.event_type)}</code>"
            f"（{_esc(key.caused_by_class or key.exception_class)}）。"
        )
    if corr and corr.correlation_status == "AMBIGUOUS":
        exec_bits.append(
            f"程序在该时间附近识别到 <strong>{_esc(corr.candidate_count)}</strong> 个 "
            "ELIGIBLE 数据库 TCP 候选，但 JDBC 日志缺少客户端源端口，"
            "因此 <strong>无法唯一确认</strong> 异常对应哪一条 TCP 连接"
            f"（状态：{_badge('AMBIGUOUS', 'ambiguous')}）。"
        )
        if corr.dual_correlation_id:
            exec_bits.append(
                f"目前身份得分最高候选为 <code>{_esc(corr.dual_correlation_id)}</code> "
                f"（App stream {_esc(corr.app_stream)} / DB stream {_esc(corr.db_stream)}）。"
            )
            if corr.candidates and len(corr.candidates) > 1:
                c2 = corr.candidates[1]
                exec_bits.append(
                    f"接近候选包括 <code>{_esc(c2.dual_correlation_id)}</code> "
                    f"（App {_esc(c2.app_stream)} / DB {_esc(c2.db_stream)}, "
                    f"identity={c2.identity_score:.1f}）。"
                )
    elif corr:
        exec_bits.append(
            f"关联状态 {_badge(corr.correlation_status, corr.correlation_status.lower())}："
            f"<code>{_esc(corr.dual_correlation_id)}</code>。"
        )
    if ping_corr:
        exec_bits.append(
            f"Ping（SUPPORTING）：{_esc(ping_corr.summary)}"
        )
    elif not ping.provided:
        exec_bits.append("Ping Evidence: <strong>NOT PROVIDED</strong>.")

    ping_block = (
        "<p>Ping Evidence: <strong>NOT PROVIDED</strong></p>"
        "<p class=\"callout callout-info\"><strong>ICMP evidence is supporting evidence only. "
        "It does not prove TCP health or root cause.</strong></p>"
    )
    if ping.provided and ping_corr:
        ping_block = f"""
        <ul>
          <li>Target: <code>{_esc(ping_corr.target_host)}</code></li>
          <li>Window: ±{_esc(ping_corr.window_seconds)}s</li>
          <li>Samples={_esc(ping_corr.samples)} Replies={_esc(ping_corr.replies)}
              Timeouts={_esc(ping_corr.timeouts)} Unreachable={_esc(ping_corr.unreachable)}</li>
          <li>Summary: {_esc(ping_corr.summary)}</li>
          <li>Caution: {_esc(ping_corr.caution)}</li>
        </ul>
        <p class="callout callout-info"><strong>ICMP evidence is supporting evidence only.
        It does not prove TCP health or root cause.</strong></p>
        """

    filter_block = ""
    if corr:
        filter_block = (
            f"<p>Total TCP flows considered: <strong>{_esc(corr.flows_considered)}</strong>; "
            f"Filtered by endpoint: {_esc(corr.filtered_endpoint)}; "
            f"Filtered by time/lifetime: {_esc(corr.filtered_time)}; "
            f"Eligible candidates: <strong>{_esc(corr.eligible_count)}</strong> "
            f"(grace={_esc(corr.lifetime_grace_seconds)}s).</p>"
            "<p class='muted'>Candidate ranking is primarily identity-based. "
            "TCP anomaly severity is not treated as connection identity.</p>"
        )

    css = """
:root { --bg:#f7f5f0; --card:#fff; --ink:#1c1c1c; --muted:#5c5c5c;
  --line:#d9d4c8; --accent:#0b6e4f; --warn:#8a5a00; --high:#8b1e1e;
  --amb:#7a5b00; --ok:#0b6e4f; }
* { box-sizing:border-box; }
body { margin:0; font-family:"Segoe UI",Tahoma,sans-serif; background:var(--bg);
  color:var(--ink); line-height:1.45; }
header { background:linear-gradient(135deg,#0b6e4f,#134e4a); color:#fff; padding:1.25rem 1.5rem; }
header h1 { margin:0 0 .35rem; font-size:1.6rem; letter-spacing:.02em; }
header .meta { opacity:.92; font-size:.95rem; }
main { max-width:1100px; margin:0 auto; padding:1rem 1.25rem 3rem; }
section { background:var(--card); border:1px solid var(--line); border-radius:8px;
  padding:1rem 1.1rem; margin:1rem 0; }
h2 { margin:0 0 .75rem; font-size:1.15rem; color:var(--accent); border-bottom:1px solid var(--line);
  padding-bottom:.35rem; }
table { width:100%; border-collapse:collapse; font-size:.88rem; }
th,td { border-bottom:1px solid var(--line); padding:.4rem .45rem; text-align:left; vertical-align:top; }
th { background:#eef6f2; }
code { background:#eef2ef; padding:.05rem .3rem; border-radius:3px; font-size:.86em; }
.badge { display:inline-block; padding:.1rem .45rem; border-radius:4px; font-size:.78rem;
  font-weight:600; letter-spacing:.02em; }
.badge-ambiguous,.badge-warning { background:#fff3cd; color:var(--amb); }
.badge-confirmed,.badge-matched,.badge-strong,.badge-info { background:#d8f3e7; color:var(--ok); }
.badge-high,.badge-no_match { background:#f8d7da; color:var(--high); }
.status-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:.6rem; }
.status-card { background:#f3faf6; border:1px solid var(--line); border-radius:6px; padding:.55rem .7rem; }
.status-card .label { font-size:.72rem; text-transform:uppercase; color:var(--muted); }
.status-card .value { font-weight:650; margin-top:.15rem; word-break:break-word; }
.callout { border-left:4px solid var(--accent); background:#eef8f3; padding:.65rem .8rem; margin:.6rem 0; }
.callout-warn { border-left-color:var(--warn); background:#fff8e8; }
.callout-info { border-left-color:#2b6cb0; background:#eef6ff; }
.muted { color:var(--muted); font-size:.9rem; }
details { margin:.4rem 0; }
summary { cursor:pointer; font-weight:600; }
ul { padding-left:1.2rem; }
"""

    js = """
function copyText(id){
  var el=document.getElementById(id);
  if(!el) return;
  var t=el.innerText || el.textContent;
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(t);
  } else {
    var ta=document.createElement('textarea');
    ta.value=t; document.body.appendChild(ta); ta.select();
    try{document.execCommand('copy');}catch(e){}
    document.body.removeChild(ta);
  }
}
"""

    body = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>DBCAP Case Report — {_esc(result.case_id)}</title>
<style>{css}</style>
</head>
<body>
<header>
  <h1>DBCAP Case Report</h1>
  <div class="meta">Case <strong>{_esc(result.case_id)}</strong> · Offline self-contained report</div>
</header>
<main>
<section>
  <div class="status-grid">
    <div class="status-card"><div class="label">Case</div><div class="value">{_esc(result.case_id)}</div></div>
    <div class="status-card"><div class="label">JDBC Events</div><div class="value">{len(jdbc.events)}</div></div>
    <div class="status-card"><div class="label">Primary Error</div><div class="value">{_esc(primary_type)}<br/><span class="muted">{_esc(primary_ts)}</span></div></div>
    <div class="status-card"><div class="label">Correlation</div><div class="value">{_badge(corr_status, corr_status.lower())}</div></div>
    <div class="status-card"><div class="label">App Capture</div><div class="value">{_esc(app_q.get('credibility'))}<br/><span class="muted">cut_short={_esc(app_q.get('file_cut_short'))}</span></div></div>
    <div class="status-card"><div class="label">DB Capture</div><div class="value">{_esc(db_q.get('credibility'))}</div></div>
    <div class="status-card"><div class="label">Ping</div><div class="value">{'PROVIDED' if ping.provided else 'NOT PROVIDED'}</div></div>
  </div>
</section>

<section id="exec">
  <h2>1. Executive Summary</h2>
  {ambiguous_banner}
  {''.join(f'<p>{b}</p>' for b in exec_bits)}
  <p class="muted">因此：可确认 JDBC 异常文本与时间、以及双端 PCAP 中的候选连接证据；
  不能仅凭当前材料判定具体网络设备根因，也不能把 ICMP 等同于 TCP 健康。</p>
</section>

<section>
  <h2>2. Input Files</h2>
  <ul>
    <li>JDBC log: <code>{_esc(jdbc.jdbc_log)}</code></li>
    <li>App PCAP: <code>{_esc(jdbc.app_pcap)}</code></li>
    <li>DB PCAP: <code>{_esc(jdbc.db_pcap)}</code></li>
    <li>Ping log: <code>{_esc(ping.ping_log if ping.provided else 'NOT PROVIDED')}</code></li>
    <li>Server: <code>{_esc(jdbc.server_ip)}</code> port <code>{_esc(jdbc.db_port)}</code></li>
  </ul>
</section>

<section>
  <h2>3. JDBC Events</h2>
  <table>
    <thead><tr>
      <th>Event ID</th><th>Timestamp</th><th>Type</th><th>Occurrences</th>
      <th>Correlation</th><th>Top Candidate</th><th>Eligible</th>
    </tr></thead>
    <tbody>
    {''.join(ev_rows) or '<tr><td colspan="7">(none)</td></tr>'}
    </tbody>
  </table>
</section>

<section>
  <h2>4. TCP Candidate Summary</h2>
  {filter_block}
  <table>
    <thead><tr>
      <th>Rank</th><th>Correlation ID</th><th>App Stream</th><th>DB Stream</th>
      <th>Identity Score</th><th>Health Score</th><th>Total</th><th>Status</th><th>Reason</th>
    </tr></thead>
    <tbody>
    {''.join(cand_rows) or '<tr><td colspan="9">(none)</td></tr>'}
    </tbody>
  </table>
</section>

<section>
  <h2>5. Dual-PCAP Evidence</h2>
  <ul>
    <li>Dual correlated flows: {_esc(len(dual.correlated_flows))}</li>
    <li>Clock: <code>{_esc(dual.clock.status)}</code> — {_esc(dual.clock.note)}</li>
    <li>Key MATCHED_SEGMENT rows appear in Unified Timeline with correlation_id.</li>
  </ul>
</section>

<section>
  <h2>6. Unified Timeline</h2>
  <p class="muted">Important events only. Relative seconds are vs primary JDBC event
  (− before / + after). Each Dual/TCP row keeps candidate correlation_id.</p>
  {tl_note}
  <div style="overflow-x:auto">
  <table>
    <thead><tr>
      <th>Time</th><th>Rel(s)</th><th>Source</th><th>Type</th><th>Corr ID</th>
      <th>Dir</th><th>App</th><th>DB</th><th>Frame</th><th>Seq</th><th>Len</th>
      <th>Description</th><th>Class</th>
    </tr></thead>
    <tbody>{''.join(tl_rows)}</tbody>
  </table>
  </div>
</section>

<section>
  <h2>7. Ping Evidence</h2>
  {ping_block}
</section>

<section>
  <h2>8. Confirmed Facts</h2>
  <ul>{_elist(result.confirmed)}</ul>
</section>
<section>
  <h2>9. Correlated Evidence</h2>
  <ul>{_elist(result.correlated)}</ul>
</section>
<section>
  <h2>10. Supporting Evidence</h2>
  <ul>{_elist(result.supporting)}</ul>
</section>
<section>
  <h2>11. Unknown / Cannot Determine</h2>
  <ul>{_elist(result.unknown)}</ul>
</section>

<section>
  <h2>12. Capture Quality</h2>
  <ul>
    <li>App-side: credibility=<strong>{_esc(app_q.get('credibility'))}</strong>
        file_cut_short=<strong>{_esc(app_q.get('file_cut_short'))}</strong>
        truncated={_esc(app_q.get('truncated_packets'))}</li>
    <li>DB-side: credibility=<strong>{_esc(db_q.get('credibility'))}</strong>
        file_cut_short=<strong>{_esc(db_q.get('file_cut_short'))}</strong>
        truncated={_esc(db_q.get('truncated_packets'))}</li>
  </ul>
</section>

<section>
  <h2>13. Wireshark Verification</h2>
  <ul id="ws-filters">{''.join(ws_bits) or '<li>(none)</li>'}</ul>
  <p><button type="button" onclick="copyText('ws-filters')">Copy filters</button></p>
</section>

<section>
  <h2>14. Known Limitations</h2>
  <ul>
    {''.join(f'<li>{_esc(x)}</li>' for x in (jdbc.limitations or [
      'Presentation layer only — no re-analysis in HTML.',
      'Without JDBC client source port, identity cannot be CONFIRMED.',
      'Ping is supporting evidence only.',
    ]))}
  </ul>
</section>
</main>
<script>{js}</script>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)
    return path
