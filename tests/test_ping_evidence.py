"""V2.3 Ping evidence unit tests."""

from __future__ import annotations

import shutil
from pathlib import Path

from dbcap.jdbc.models import JdbcEvent
from dbcap.jdbc.parser import parse_jdbc_timestamp
from dbcap.ping.correlator import analyze_ping_for_jdbc_events, correlate_ping_to_jdbc
from dbcap.ping.parser import parse_ping_log

_TMP = Path(__file__).resolve().parents[1] / "output" / "_ping_test_tmp"


def _fresh(name: str) -> Path:
    p = _TMP / name
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _write(d: Path, name: str, text: str) -> Path:
    p = d / name
    p.write_text(text, encoding="utf-8")
    return p


def _jdbc(ts_raw: str, eid: str = "JE0001") -> JdbcEvent:
    return JdbcEvent(
        event_id=eid,
        timestamp=parse_jdbc_timestamp(ts_raw),
        timestamp_raw=ts_raw,
        level="ERROR",
        exception_class="X",
        message="y",
        event_type="CONNECTION_RESET",
        thread_name="t",
        tid="1",
        database_host="10.4.34.95",
        database_port=5236,
        connection_hint=None,
        stack_summary="",
        source_file="x",
        start_line=1,
        end_line=1,
        raw_excerpt_hash="a",
    )


def test_parse_linux_reply():
    d = _fresh("reply")
    log = _write(
        d,
        "p.log",
        "[2026-09-16 09:15:51.400] ===== Ping monitor started: 10.4.7.233 =====\n"
        "[2026-09-16 09:15:51.406] 64 bytes from 10.4.7.233: icmp_seq=1 ttl=63 time=0.647 ms\n",
    )
    ev = parse_ping_log(str(log))
    assert len(ev) == 1
    assert ev[0].status == "REPLY"
    assert ev[0].target_host == "10.4.7.233"
    assert abs((ev[0].rtt_ms or 0) - 0.647) < 1e-6
    assert ev[0].ttl == 63


def test_parse_no_answer_timeout():
    d = _fresh("to")
    log = _write(
        d,
        "p.log",
        "[2026-09-16 09:38:35.850] no answer yet for icmp_seq=1312\n",
    )
    ev = parse_ping_log(str(log))
    assert len(ev) == 1
    assert ev[0].status == "TIMEOUT"
    assert ev[0].icmp_seq == 1312


def test_parse_windows_request_timed_out():
    d = _fresh("win_to")
    log = _write(
        d,
        "p.log",
        "[2026-09-16 09:00:00.000] Request timed out.\n",
    )
    ev = parse_ping_log(str(log))
    assert ev[0].status == "TIMEOUT"


def test_parse_destination_unreachable():
    d = _fresh("unreach")
    log = _write(
        d,
        "p.log",
        "[2026-09-16 09:00:00.000] Reply from 10.0.0.1: Destination host unreachable.\n",
    )
    ev = parse_ping_log(str(log))
    assert ev[0].status == "UNREACHABLE"


def test_consecutive_replies_and_timeouts():
    d = _fresh("mix")
    lines = ["[2026-09-16 09:00:00.000] ===== Ping monitor started: 10.1.1.1 ====="]
    for i in range(3):
        lines.append(
            f"[2026-09-16 09:00:0{i+1}.000] 64 bytes from 10.1.1.1: icmp_seq={i} ttl=64 time=1.0 ms"
        )
    for i in range(3):
        lines.append(f"[2026-09-16 09:00:1{i}.000] no answer yet for icmp_seq={10+i}")
    log = _write(d, "p.log", "\n".join(lines) + "\n")
    ev = parse_ping_log(str(log))
    assert sum(1 for e in ev if e.status == "REPLY") == 3
    assert sum(1 for e in ev if e.status == "TIMEOUT") == 3


def test_jdbc_window_correlation_nearest():
    d = _fresh("win")
    log = _write(
        d,
        "p.log",
        "\n".join(
            [
                "[2026-09-16 09:38:00.000] ===== Ping monitor started: 10.4.7.233 =====",
                "[2026-09-16 09:38:30.000] 64 bytes from 10.4.7.233: icmp_seq=1 ttl=63 time=0.4 ms",
                "[2026-09-16 09:38:36.000] no answer yet for icmp_seq=2",
                "[2026-09-16 09:38:41.050] 64 bytes from 10.4.7.233: icmp_seq=3 ttl=63 time=0.5 ms",
                "[2026-09-16 09:38:50.000] no answer yet for icmp_seq=4",
            ]
        )
        + "\n",
    )
    events = parse_ping_log(str(log))
    je = _jdbc("2026-09-16 09:38:41")
    corr = correlate_ping_to_jdbc(events, je, window_seconds=30)
    assert corr.replies >= 2
    assert corr.timeouts >= 1
    assert corr.last_reply_before is not None or corr.first_reply_after is not None
    assert corr.nearest_timeout_before is not None
    assert "SUPPORTING" == corr.evidence_class


def test_ping_log_without_timestamp_skipped():
    d = _fresh("badts")
    log = _write(d, "p.log", "64 bytes from 10.1.1.1: icmp_seq=1 ttl=64 time=1 ms\n")
    assert parse_ping_log(str(log)) == []


def test_malformed_line_ignored():
    d = _fresh("mal")
    log = _write(
        d,
        "p.log",
        "[2026-09-16 09:00:00.000] ===== Ping monitor started: 10.1.1.1 =====\n"
        "[2026-09-16 09:00:01.000] garbage line not a ping\n"
        "[2026-09-16 09:00:02.000] 64 bytes from 10.1.1.1: icmp_seq=1 ttl=64 time=1.0 ms\n",
    )
    ev = parse_ping_log(str(log))
    assert len(ev) == 1
    assert ev[0].status == "REPLY"


def test_all_replies_do_not_claim_tcp_healthy():
    d = _fresh("ok")
    lines = ["[2026-09-16 09:38:00.000] ===== Ping monitor started: 10.4.7.233 ====="]
    for i in range(5):
        lines.append(
            f"[2026-09-16 09:38:{20+i:02d}.000] 64 bytes from 10.4.7.233: "
            f"icmp_seq={i} ttl=63 time=0.4 ms"
        )
    log = _write(d, "p.log", "\n".join(lines) + "\n")
    events = parse_ping_log(str(log))
    corr = correlate_ping_to_jdbc(events, _jdbc("2026-09-16 09:38:41"), window_seconds=30)
    assert corr.timeouts == 0
    assert corr.replies >= 1
    blob = (corr.summary + corr.caution).lower()
    assert "tcp" in blob or "supporting" in blob
    assert "网络正常" not in corr.summary
    assert "firewall" not in blob
    assert "root cause" in corr.caution.lower() or "device" in corr.caution.lower()


def test_timeout_does_not_claim_root_cause():
    d = _fresh("bad")
    log = _write(
        d,
        "p.log",
        "[2026-09-16 09:38:00.000] ===== Ping monitor started: 10.4.7.233 =====\n"
        "[2026-09-16 09:38:40.000] no answer yet for icmp_seq=1\n"
        "[2026-09-16 09:38:41.000] no answer yet for icmp_seq=2\n"
        "[2026-09-16 09:38:42.000] no answer yet for icmp_seq=3\n",
    )
    corr = correlate_ping_to_jdbc(
        parse_ping_log(str(log)), _jdbc("2026-09-16 09:38:41"), window_seconds=30
    )
    assert corr.timeouts >= 3
    assert "caused" not in corr.summary.lower()
    assert "connection reset" not in corr.summary.lower()
    assert corr.evidence_class == "SUPPORTING"


def test_ping_not_provided():
    r = analyze_ping_for_jdbc_events(None, [_jdbc("2026-09-16 09:38:41")])
    assert r.provided is False
    assert r.events == []
