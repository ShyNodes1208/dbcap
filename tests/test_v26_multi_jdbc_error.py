"""V2.6 multi-JDBC error classification and grouping tests."""

from __future__ import annotations

import shutil
from pathlib import Path

from dbcap.jdbc.classifier import NOT_NETWORK, classify_exception
from dbcap.jdbc.grouping import assign_event_groups
from dbcap.jdbc.models import JdbcEvent
from dbcap.jdbc.parser import parse_jdbc_log, parse_jdbc_timestamp


_TMP = Path(__file__).resolve().parents[1] / "output" / "_jdbc_v26_tmp"


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


def test_v26_connection_reset():
    assert (
        classify_exception(
            "dm.jdbc.driver.DMException",
            "网络通信异常",
            "java.net.SocketException",
            "Connection reset",
        )
        == "CONNECTION_RESET"
    )


def test_v26_connection_refused():
    assert (
        classify_exception(None, None, "java.net.ConnectException", "Connection refused")
        == "CONNECTION_REFUSED"
    )
    assert (
        classify_exception(None, None, "java.net.ConnectException", "actively refused")
        == "CONNECTION_REFUSED"
    )


def test_v26_connect_timeout():
    assert (
        classify_exception(
            None, None, "java.net.SocketTimeoutException", "connect timed out"
        )
        == "CONNECT_TIMEOUT"
    )


def test_v26_read_timeout():
    assert (
        classify_exception(None, None, "java.net.SocketTimeoutException", "Read timed out")
        == "READ_TIMEOUT"
    )


def test_v26_socket_timeout():
    assert (
        classify_exception("java.net.SocketTimeoutException", "timeout waiting", None, None)
        == "SOCKET_TIMEOUT"
    )


def test_v26_broken_pipe():
    assert (
        classify_exception(None, None, "java.net.SocketException", "Broken pipe")
        == "BROKEN_PIPE"
    )


def test_v26_connection_closed_fault():
    assert (
        classify_exception(
            "java.sql.SQLException",
            "Connection is closed",
            None,
            None,
        )
        == "CONNECTION_CLOSED"
    )


def test_v26_unknown_network():
    assert (
        classify_exception("java.sql.SQLException", "I/O error writing request", None, None)
        == "UNKNOWN_NETWORK_ERROR"
    )


def test_v26_generic_sqlexception_not_network():
    assert (
        classify_exception("java.sql.SQLException", "ORA-00942 table not found", None, None)
        == NOT_NETWORK
    )


def test_v26_normal_close_not_fault_event():
    d = _fresh("close")
    log = _write(
        d,
        "c.log",
        """[INFO  - 2026-09-16 09:38:42] tid:1 - [pool-1] { conn-1 } isClosed(): true;
[INFO  - 2026-09-16 09:38:43] tid:1 - [pool-1] connection closed successfully
""",
    )
    events = parse_jdbc_log(str(log))
    assert events == []


def test_v26_multiple_event_types():
    d = _fresh("multi")
    log = _write(
        d,
        "m.log",
        """[ERROR - 2026-09-16 08:00:00] tid:1 - [t] connect
java.net.ConnectException: Connection refused
[ERROR - 2026-09-16 09:00:00] tid:2 - [t] exec
Caused by: java.net.SocketException: Connection reset
""",
    )
    events = parse_jdbc_log(str(log))
    assert len(events) == 2
    assert events[0].event_type == "CONNECTION_REFUSED"
    assert events[1].event_type == "CONNECTION_RESET"


def test_v26_duplicate_grouping_near():
    t = parse_jdbc_timestamp("2026-09-16 09:38:41")
    assert t is not None
    events = [
        JdbcEvent(
            event_id="JE0001",
            timestamp=t,
            timestamp_raw="2026-09-16 09:38:41",
            level="ERROR",
            exception_class="X",
            message="m",
            event_type="CONNECTION_RESET",
            thread_name="pool",
            tid="1",
            database_host=None,
            database_port=None,
            connection_hint="conn-1",
            stack_summary="",
            source_file="x",
            start_line=1,
            end_line=2,
            raw_excerpt_hash="a",
            caused_by_message="Connection reset",
        ),
        JdbcEvent(
            event_id="JE0002",
            timestamp=t + 1.0,
            timestamp_raw="2026-09-16 09:38:42",
            level="ERROR",
            exception_class="X",
            message="m",
            event_type="CONNECTION_RESET",
            thread_name="pool",
            tid="1",
            database_host=None,
            database_port=None,
            connection_hint="conn-1",
            stack_summary="",
            source_file="x",
            start_line=3,
            end_line=4,
            raw_excerpt_hash="b",
            caused_by_message="Connection reset",
        ),
    ]
    assign_event_groups(events, window_seconds=3.0)
    assert events[0].group_id == events[1].group_id
    assert events[0].occurrence_count == 2
    assert events[0].is_group_primary
    assert not events[1].is_group_primary


def test_v26_far_apart_identical_not_merged():
    t = parse_jdbc_timestamp("2026-09-16 09:00:00")
    assert t is not None
    events = [
        JdbcEvent(
            event_id="JE0001",
            timestamp=t,
            timestamp_raw="2026-09-16 09:00:00",
            level="ERROR",
            exception_class="X",
            message="m",
            event_type="CONNECTION_RESET",
            thread_name="pool",
            tid="1",
            database_host=None,
            database_port=None,
            connection_hint="conn-1",
            stack_summary="",
            source_file="x",
            start_line=1,
            end_line=2,
            raw_excerpt_hash="a",
            caused_by_message="Connection reset",
        ),
        JdbcEvent(
            event_id="JE0002",
            timestamp=t + 3600,
            timestamp_raw="2026-09-16 10:00:00",
            level="ERROR",
            exception_class="X",
            message="m",
            event_type="CONNECTION_RESET",
            thread_name="pool",
            tid="1",
            database_host=None,
            database_port=None,
            connection_hint="conn-1",
            stack_summary="",
            source_file="x",
            start_line=3,
            end_line=4,
            raw_excerpt_hash="b",
            caused_by_message="Connection reset",
        ),
    ]
    assign_event_groups(events, window_seconds=3.0)
    assert events[0].group_id != events[1].group_id
    assert events[0].occurrence_count == 1
    assert events[1].occurrence_count == 1
