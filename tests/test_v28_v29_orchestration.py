"""V2.8 auto-case and V2.9 batch tests."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from dbcap.autocase.discover import discover_case
from dbcap.autocase.pipeline import run_auto_case
from dbcap.batch.pipeline import run_batch
from dbcap.cli import main

_TMP = Path(__file__).resolve().parents[1] / "output" / "_v28_tmp"


def _fresh(name: str) -> Path:
    p = _TMP / name
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _jdbc(path: Path) -> None:
    path.write_text(
        "[ERROR - 2026-09-16 09:38:41] tid:1 - [pool] { conn-1 } execute();\n"
        "dm.jdbc.driver.DMException: network\n"
        "Caused by: java.net.SocketException: Connection reset\n",
        encoding="utf-8",
    )


def _ping(path: Path) -> None:
    path.write_text(
        "[2026-09-16 09:38:40.000] ===== Ping monitor started: 10.0.0.1 =====\n"
        "[2026-09-16 09:38:41.000] 64 bytes from 10.0.0.1: icmp_seq=1 ttl=63 time=0.4 ms\n",
        encoding="utf-8",
    )


def _pcap(path: Path, marker: bytes) -> None:
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + marker + b"\x00" * 16)


def _probe(path, server_ip=None, server_port=None, max_packets=4000):
    raw = Path(path).read_bytes()
    mark = raw[4:5]
    if mark == b"A":
        return {
            "readable": True,
            "packet_count": 10,
            "to_server": 10,
            "from_server": 0,
            "time_start": 1.0,
            "time_end": 2.0,
            "error": None,
        }
    if mark == b"D":
        return {
            "readable": True,
            "packet_count": 10,
            "to_server": 0,
            "from_server": 10,
            "time_start": 1.0,
            "time_end": 2.0,
            "error": None,
        }
    if mark == b"X":
        return {"readable": False, "error": "corrupt", "to_server": 0, "from_server": 0}
    return {
        "readable": True,
        "packet_count": 4,
        "to_server": 2,
        "from_server": 2,
        "time_start": 1.0,
        "time_end": 2.0,
        "error": None,
    }


def _good(dirpath: Path) -> None:
    _jdbc(dirpath / "notes.txt")
    _ping(dirpath / "mon.log")
    _pcap(dirpath / "q1.bin", b"A")
    _pcap(dirpath / "q2.bin", b"D")
    (dirpath / "readme_unrelated.txt").write_text("just a note\n", encoding="utf-8")


def test_v28_standard_and_meaningless_names():
    d = _fresh("std")
    _good(d)
    found = discover_case(str(d), server_ip="10.0.0.1", server_port=5236, probe=_probe)
    assert found.status == "READY"
    assert found.jdbc_log and found.jdbc_log.endswith("notes.txt")
    assert found.ping_log and found.ping_log.endswith("mon.log")
    assert Path(found.app_pcap).name == "q1.bin"
    assert Path(found.db_pcap).name == "q2.bin"


def test_v28_paths_unicode_space_paren():
    for name in ["中文案例", "db cap", "case(1)"]:
        d = _fresh(name)
        _good(d)
        found = discover_case(str(d), server_ip="10.0.0.1", server_port=5236, probe=_probe)
        assert found.status == "READY", name


def test_v28_single_pcap_missing():
    d = _fresh("one")
    _jdbc(d / "a.txt")
    _pcap(d / "only.bin", b"A")
    found = discover_case(str(d), server_ip="10.0.0.1", server_port=5236, probe=_probe)
    assert found.status == "MISSING_INPUT"
    assert "2 captures" in found.message


def test_v28_three_pcaps_ambiguous():
    d = _fresh("three")
    _jdbc(d / "j.txt")
    _pcap(d / "a.bin", b"A")
    _pcap(d / "b.bin", b"A")
    _pcap(d / "c.bin", b"D")
    found = discover_case(str(d), server_ip="10.0.0.1", server_port=5236, probe=_probe)
    assert found.status == "INPUT_AMBIGUOUS"


def test_v28_missing_jdbc_and_optional_ping():
    d = _fresh("nojdbc")
    _pcap(d / "a.bin", b"A")
    _pcap(d / "b.bin", b"D")
    found = discover_case(str(d), server_ip="10.0.0.1", server_port=5236, probe=_probe)
    assert found.status == "MISSING_INPUT"
    assert "JDBC" in found.message

    d2 = _fresh("noping")
    _jdbc(d2 / "j.txt")
    _pcap(d2 / "a.bin", b"A")
    _pcap(d2 / "b.bin", b"D")
    found2 = discover_case(str(d2), server_ip="10.0.0.1", server_port=5236, probe=_probe)
    assert found2.status == "READY"
    assert found2.ping_log is None


def test_v28_multi_jdbc_and_ping_ambiguous():
    d = _fresh("mj")
    _jdbc(d / "j1.txt")
    _jdbc(d / "j2.txt")
    _pcap(d / "a.bin", b"A")
    _pcap(d / "b.bin", b"D")
    found = discover_case(str(d), server_ip="10.0.0.1", server_port=5236, probe=_probe)
    assert found.status == "INPUT_AMBIGUOUS"

    d2 = _fresh("mp")
    _jdbc(d2 / "j.txt")
    _ping(d2 / "p1.log")
    _ping(d2 / "p2.log")
    _pcap(d2 / "a.bin", b"A")
    _pcap(d2 / "b.bin", b"D")
    found2 = discover_case(str(d2), server_ip="10.0.0.1", server_port=5236, probe=_probe)
    assert found2.status == "INPUT_AMBIGUOUS"


def test_v28_role_ambiguous_and_corrupt_ignored_when_pair_exists():
    d = _fresh("role")
    _jdbc(d / "j.txt")
    _pcap(d / "a.bin", b"M")
    _pcap(d / "b.bin", b"M")
    found = discover_case(str(d), server_ip="10.0.0.1", server_port=5236, probe=_probe)
    assert found.status == "INPUT_AMBIGUOUS"

    d2 = _fresh("bad")
    _jdbc(d2 / "j.txt")
    _pcap(d2 / "a.bin", b"A")
    _pcap(d2 / "b.bin", b"D")
    (d2 / "bad.pcap").write_bytes(b"not-a-pcap")
    found2 = discover_case(str(d2), server_ip="10.0.0.1", server_port=5236, probe=_probe)
    assert found2.status == "READY"


def test_v28_unrelated_ignored_dry_run_manifest():
    d = _fresh("dry")
    _good(d)
    rc, found, result = run_auto_case(
        str(d),
        server_ip="10.0.0.1",
        server_port=5236,
        dry_run=True,
        probe=_probe,
    )
    assert rc == 0 and result is None and found.status == "READY"
    man = json.loads((d / "dbcap_output" / "input_manifest.json").read_text(encoding="utf-8"))
    types = {Path(f["file"]).name: f["detected_type"] for f in man["files"]}
    assert types["readme_unrelated.txt"] == "UNKNOWN"
    assert any(f["selected"] for f in man["files"])


def test_v28_calls_existing_case_pipeline(monkeypatch):
    d = _fresh("orch")
    _good(d)
    called = {}

    def fake_analyze(jdbc, app, db, port, **kwargs):
        called["args"] = (jdbc, app, db, port, kwargs.get("ping_log"))
        class R:
            pass
        return R()

    def fake_export(result, out):
        Path(out, "report.html").write_text("ok", encoding="utf-8")
        return {"report_html": str(Path(out) / "report.html")}

    monkeypatch.setattr("dbcap.case.analyze_case", fake_analyze)
    monkeypatch.setattr("dbcap.case.export_all_case", fake_export)
    rc, found, _ = run_auto_case(
        str(d), server_ip="10.0.0.1", server_port=5236, probe=_probe
    )
    assert rc == 0
    assert called["args"][0] == found.jdbc_log
    assert called["args"][1] == found.app_pcap
    assert called["args"][2] == found.db_pcap


def test_v29_batch_isolation_and_exit(monkeypatch):
    root = _fresh("batch root")
    good1 = root / "case good 1"
    good2 = root / "中文case"
    missing = root / "case_missing_jdbc"
    amb = root / "case_ambiguous"
    for p in (good1, good2):
        p.mkdir()
        _good(p)
    missing.mkdir()
    _pcap(missing / "a.bin", b"A")
    _pcap(missing / "b.bin", b"D")
    amb.mkdir()
    _jdbc(amb / "j.txt")
    _pcap(amb / "a.bin", b"M")
    _pcap(amb / "b.bin", b"M")

    def fake_analyze(jdbc, app, db, port, **kwargs):
        class R:
            case_id = kwargs.get("case_id")
            class jdbc:
                events = []
                correlations = []
            class ping:
                provided = False
            class dual:
                capture_quality_app = {}
            key_jdbc_event_id = None
        R.case_id = kwargs.get("case_id")
        return R()

    def fake_export(result, out):
        Path(out).mkdir(parents=True, exist_ok=True)
        Path(out, "report.html").write_text(str(getattr(result, "case_id", "")), encoding="utf-8")
        return {}

    monkeypatch.setattr("dbcap.case.analyze_case", fake_analyze)
    monkeypatch.setattr("dbcap.case.export_all_case", fake_export)
    rc, rows = run_batch(str(root), server_ip="10.0.0.1", server_port=5236, probe=_probe)
    assert rc == 1
    by = {r["case_id"]: r for r in rows}
    assert by["case good 1"]["status"] in {"SUCCESS", "SUCCESS_WITH_WARNINGS"}
    assert by["中文case"]["status"] in {"SUCCESS", "SUCCESS_WITH_WARNINGS"}
    assert by["case_missing_jdbc"]["status"] == "MISSING_INPUT"
    assert by["case_ambiguous"]["status"] == "INPUT_AMBIGUOUS"
    out = root / "dbcap_batch_output"
    assert (out / "batch_summary.csv").is_file()
    assert (out / "batch_summary.json").is_file()
    html = (out / "batch_report.html").read_text(encoding="utf-8")
    assert "http://" not in html.lower()
    assert "case good 1" in html
    # isolation: each success wrote its own report
    assert (out / "case good 1" / "report.html").is_file()
    assert (out / "中文case" / "report.html").is_file()
    assert (out / "case_missing_jdbc" / "case_error.json").is_file()


def test_v28_cli_missing_dir():
    rc = main(["auto-case", str(_TMP / "no_such_case_dir"), "--port", "5236"])
    assert rc == 1


def test_v29_batch_empty_exit():
    d = _fresh("emptybatch")
    rc, rows = run_batch(str(d), server_port=5236, probe=_probe)
    assert rc == 2
    assert rows == []
