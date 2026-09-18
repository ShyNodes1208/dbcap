"""CLI entry point for dbcap."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console

from dbcap import __version__
from dbcap.analyzer import build_analysis_report
from dbcap.capture import load_pcap_file
from dbcap.db_ports import DB_PORTS
from dbcap.doctor import run_doctor
from dbcap.models import ThresholdConfig
from dbcap.payload import save_anomaly_payloads
from dbcap.report import export_all_reports, render_terminal_report
from dbcap.session import group_into_sessions
from dbcap.thresholds import DEFAULT_THRESHOLDS

# Exit codes (program / input-quality oriented — not network severity):
#   0 = analysis finished; input has no blocking quality issue
#   1 = program execution failure
#   2 = analysis finished; PCAP has blocking quality issue (e.g. PACKET_TRUNCATED)
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_QUALITY = 2


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dbcap",
        description="DBCAP Offline Analyzer — 应用↔数据库 TCP 抓包离线故障分析",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_examples(),
    )
    p.add_argument("--version", action="version", version=f"dbcap {__version__}")

    src = p.add_argument_group("数据源")
    src_group = src.add_mutually_exclusive_group(required=False)
    src_group.add_argument("-f", "--file", help="分析 pcap/pcapng 文件")

    db = p.add_argument_group("数据库目标 (二选一)")
    db_group = db.add_mutually_exclusive_group(required=False)
    db_group.add_argument("-p", "--port", type=int, help="数据库端口号（1-65535）")
    db_group.add_argument(
        "-d",
        "--db",
        choices=list(DB_PORTS.keys()),
        help="数据库类型（使用默认端口）",
    )

    out = p.add_argument_group("输出选项")
    out.add_argument(
        "-o",
        "--output",
        default="output",
        help="报告输出目录 (默认: output/)",
    )
    out.add_argument("--no-color", action="store_true", help="禁用彩色输出")

    ana = p.add_argument_group("分析选项")
    ana.add_argument("--max-packets", type=int, default=None, help="最大处理数据包数")
    ana.add_argument(
        "--thresholds",
        type=str,
        default=None,
        help='自定义阈值 JSON，例: \'{"retx_high_count": 3, "ack_stall_ms": 1000}\'',
    )
    return p


def _examples() -> str:
    return """
示例:
  python -m dbcap -f capture.pcap -d dameng
  python -m dbcap -f trace.pcapng -p 5236 -o ./output
  python -m dbcap doctor
  python -m dbcap dual --app-pcap app.pcap --db-pcap db.pcap --port 5236 -o output\\dual
  python -m dbcap jdbc --jdbc-log app.log --app-pcap app.pcap --db-pcap db.pcap --port 5236 -o output\\jdbc
  python -m dbcap case --jdbc-log app.log --app-pcap app.pcap --db-pcap db.pcap --ping-log ping.log --port 5236 -o output\\case
  run.bat H:\\pcap\\case01.pcap 5236

退出码:
  0 = 分析完成，输入无阻断性质量问题
  1 = 程序执行失败
  2 = 分析完成，但 PCAP 存在影响完整性的质量问题（如 PACKET_TRUNCATED）
"""


def _run_dual(argv: list[str]) -> int:
    """V2 Dual-PCAP correlation CLI."""
    p = argparse.ArgumentParser(
        prog="dbcap dual",
        description="DBCAP Dual-PCAP Correlation — match sessions/segments across app and db captures",
    )
    p.add_argument("--app-pcap", required=True, help="Application-side PCAP")
    p.add_argument("--db-pcap", required=True, help="Database-side PCAP")
    p.add_argument("-p", "--port", type=int, required=True, help="Database port")
    p.add_argument(
        "--server-ip",
        default=None,
        help="Optional DB server IP hint (soft check only)",
    )
    p.add_argument(
        "-o",
        "--output",
        default="output/dual",
        help="Output directory (default: output/dual)",
    )
    p.add_argument("--max-packets", type=int, default=None)
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--thresholds", type=str, default=None)

    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        if e.code in (0, None):
            return EXIT_OK
        return EXIT_ERROR

    try:
        validate_port(args.port)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_ERROR

    console = Console(color_system=None if args.no_color else "auto")
    thresholds = load_thresholds(args)
    try:
        from dbcap.dual import analyze_dual_pcaps, export_all_dual

        console.print(f"[dim]Dual: app={args.app_pcap}[/dim]")
        console.print(f"[dim]      db ={args.db_pcap}[/dim]")
        result = analyze_dual_pcaps(
            args.app_pcap,
            args.db_pcap,
            args.port,
            server_ip=args.server_ip,
            thresholds=thresholds,
            max_packets=args.max_packets,
        )
        paths = export_all_dual(result, args.output)
        both = sum(1 for s in result.segments if s.match_status == "MATCHED_BOTH_SIDES")
        console.print()
        console.print(
            f"[bold]Correlated flows:[/bold] {len(result.correlated_flows)}  "
            f"[bold]MATCHED_BOTH_SIDES:[/bold] {both}"
        )
        console.print(f"[bold]Clock:[/bold] {result.clock.status}  {result.clock.note[:80]}")
        for f in result.correlated_flows[:20]:
            console.print(
                f"  {f.correlation_id}  "
                f"{f.flow_key.client_ip}:{f.flow_key.client_port} <-> "
                f"{f.flow_key.server_ip}:{f.flow_key.server_port}  "
                f"app_stream={f.app_stream} db_stream={f.db_stream}"
            )
        console.print()
        console.print(f"[dim]dual_report.md      -> {paths['dual_report_md']}[/dim]")
        console.print(f"[dim]dual_flows.csv      -> {paths['dual_flows_csv']}[/dim]")
        console.print(f"[dim]dual_segments.csv   -> {paths['dual_segments_csv']}[/dim]")
        console.print(f"[dim]dual_anomalies.json -> {paths['dual_anomalies_json']}[/dim]")
        # Exit 2 if either side has blocking quality
        qa = result.capture_quality_app
        qb = result.capture_quality_db
        if qa.get("file_cut_short") or qb.get("file_cut_short") or (
            qa.get("credibility") in ("DEGRADED", "LOW")
        ) or (qb.get("credibility") in ("DEGRADED", "LOW")):
            return EXIT_QUALITY
        return EXIT_OK
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        return EXIT_ERROR
    except Exception as e:
        console.print(f"[red]Unexpected error:[/red] {e}")
        return EXIT_ERROR


def resolve_port(db_type: Optional[str], port: Optional[int]) -> int:
    if db_type:
        return DB_PORTS[db_type]
    assert port is not None
    return port


def validate_port(port: int) -> None:
    if port < 1 or port > 65535:
        raise ValueError(
            f"Invalid database port {port}. TCP port must be an integer in 1..65535."
        )


def _default_config_path() -> Optional[str]:
    home = os.environ.get("DBCAP_HOME")
    candidates = []
    if home:
        candidates.append(Path(home) / "config" / "thresholds.json")
    here = Path(__file__).resolve()
    for parent in list(here.parents)[:4]:
        candidates.append(parent / "config" / "thresholds.json")
    for path in candidates:
        if path.is_file():
            return str(path)
    return None


def load_thresholds(args: argparse.Namespace) -> ThresholdConfig:
    defaults = DEFAULT_THRESHOLDS.__dict__.copy()

    cfg = _default_config_path()
    if cfg:
        try:
            with open(cfg, encoding="utf-8") as f:
                defaults.update(json.load(f))
        except (OSError, json.JSONDecodeError) as e:
            print(f"Warning: cannot load {cfg}: {e}", file=sys.stderr)

    if args.thresholds:
        try:
            overrides = json.loads(args.thresholds)
            defaults.update(overrides)
        except (json.JSONDecodeError, TypeError) as e:
            print(
                f"Warning: invalid --thresholds JSON: {e}. Using defaults.",
                file=sys.stderr,
            )
    try:
        return ThresholdConfig(**defaults)
    except TypeError as e:
        print(
            f"Warning: threshold config error: {e}. Using built-in defaults.",
            file=sys.stderr,
        )
        return DEFAULT_THRESHOLDS


def _exit_for_report(report) -> int:
    """Map report to process exit code (quality-oriented)."""
    quality = report.capture_quality
    blocking = bool(report.summary.get("capture_quality_blocking")) or (
        quality.truncated_packets > 0 and quality.credibility in ("DEGRADED", "LOW")
    ) or bool(getattr(quality, "file_cut_short", False))
    if blocking:
        return EXIT_QUALITY
    return EXIT_OK


def _run_jdbc(argv: list[str]) -> int:
    """V2.2 JDBC ↔ Dual-PCAP timeline CLI."""
    p = argparse.ArgumentParser(
        prog="dbcap jdbc",
        description="DBCAP JDBC Timeline — correlate JDBC exceptions with Dual-PCAP evidence",
    )
    p.add_argument("--jdbc-log", required=True, help="JDBC / application log file")
    p.add_argument("--app-pcap", required=True, help="Application-side PCAP")
    p.add_argument("--db-pcap", required=True, help="Database-side PCAP")
    p.add_argument("-p", "--port", type=int, required=True, help="Database port")
    p.add_argument("--server-ip", default=None, help="Optional DB server IP")
    p.add_argument(
        "-o",
        "--output",
        default="output/jdbc",
        help="Output directory (default: output/jdbc)",
    )
    p.add_argument(
        "--jdbc-window-seconds",
        type=float,
        default=10.0,
        help="Correlation search window around JDBC event (default: 10)",
    )
    p.add_argument(
        "--timeline-window-seconds",
        type=float,
        default=30.0,
        help="Timeline inclusion window (default: 30)",
    )
    p.add_argument(
        "--candidate-lifetime-grace-seconds",
        type=float,
        default=5.0,
        help="Keep flows that ended shortly before JDBC time (default 5s)",
    )
    p.add_argument("--max-packets", type=int, default=None)
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--thresholds", type=str, default=None)

    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        if e.code in (0, None):
            return EXIT_OK
        return EXIT_ERROR

    try:
        validate_port(args.port)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_ERROR

    console = Console(color_system=None if args.no_color else "auto")
    thresholds = load_thresholds(args)
    try:
        from dbcap.jdbc import analyze_jdbc_timeline, export_all_jdbc

        console.print(f"[dim]JDBC: {args.jdbc_log}[/dim]")
        console.print(f"[dim]App : {args.app_pcap}[/dim]")
        console.print(f"[dim]DB  : {args.db_pcap}[/dim]")
        result = analyze_jdbc_timeline(
            args.jdbc_log,
            args.app_pcap,
            args.db_pcap,
            args.port,
            server_ip=args.server_ip,
            window_seconds=args.jdbc_window_seconds,
            timeline_window_seconds=args.timeline_window_seconds,
            lifetime_grace_seconds=args.candidate_lifetime_grace_seconds,
            thresholds=thresholds,
            max_packets=args.max_packets,
            also_export_dual=str(Path(args.output) / "dual"),
        )
        paths = export_all_jdbc(result, args.output)
        console.print()
        console.print(f"[bold]JDBC events:[/bold] {len(result.events)}")
        for e in result.events:
            console.print(
                f"  {e.event_id}  {e.timestamp_raw}  {e.event_type}  "
                f"lines {e.start_line}-{e.end_line}"
            )
        console.print(f"[bold]Correlations:[/bold] {len(result.correlations)}")
        for c in result.correlations:
            console.print(
                f"  {c.event_id}  {c.correlation_status}/{c.evidence_level}  "
                f"dual={c.dual_correlation_id}  "
                f"app_stream={c.app_stream} db_stream={c.db_stream}  "
                f"candidates={c.candidate_count}"
            )
        console.print()
        console.print(f"[dim]jdbc_report.md              -> {paths['jdbc_report_md']}[/dim]")
        console.print(f"[dim]jdbc_events.csv             -> {paths['jdbc_events_csv']}[/dim]")
        console.print(f"[dim]jdbc_tcp_correlations.csv   -> {paths['jdbc_correlations_csv']}[/dim]")
        console.print(f"[dim]jdbc_timeline.csv           -> {paths['jdbc_timeline_csv']}[/dim]")
        return EXIT_OK
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        return EXIT_ERROR


def _run_case(argv: list[str]) -> int:
    """V2.4 unified case: JDBC + Dual-PCAP + optional Ping."""
    p = argparse.ArgumentParser(
        prog="dbcap case",
        description="DBCAP Case — unified JDBC / Dual-PCAP / Ping fault evidence report",
    )
    p.add_argument("--jdbc-log", required=True, help="JDBC / application log")
    p.add_argument("--app-pcap", required=True, help="Application-side PCAP")
    p.add_argument("--db-pcap", required=True, help="Database-side PCAP")
    p.add_argument("--ping-log", default=None, help="Optional ping monitor log")
    p.add_argument("-p", "--port", type=int, required=True, help="Database port")
    p.add_argument("--server-ip", default=None, help="Optional DB server IP")
    p.add_argument("-o", "--output", default="output/case", help="Output directory")
    p.add_argument("--case-id", default="case", help="Case identifier")
    p.add_argument("--jdbc-window-seconds", type=float, default=10.0)
    p.add_argument("--timeline-window-seconds", type=float, default=30.0)
    p.add_argument(
        "--candidate-lifetime-grace-seconds",
        type=float,
        default=5.0,
        help="Keep flows that ended shortly before JDBC time (default 5s)",
    )
    p.add_argument("--ping-window-seconds", type=float, default=30.0)
    p.add_argument("--max-packets", type=int, default=None)
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--thresholds", type=str, default=None)

    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        if e.code in (0, None):
            return EXIT_OK
        return EXIT_ERROR

    try:
        validate_port(args.port)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_ERROR

    console = Console(color_system=None if args.no_color else "auto")
    thresholds = load_thresholds(args)
    try:
        from dbcap.case import analyze_case, export_all_case

        console.print(f"[dim]Case: {args.case_id}[/dim]")
        console.print(f"[dim]JDBC: {args.jdbc_log}[/dim]")
        console.print(f"[dim]App : {args.app_pcap}[/dim]")
        console.print(f"[dim]DB  : {args.db_pcap}[/dim]")
        console.print(f"[dim]Ping: {args.ping_log or 'NOT PROVIDED'}[/dim]")
        result = analyze_case(
            args.jdbc_log,
            args.app_pcap,
            args.db_pcap,
            args.port,
            server_ip=args.server_ip,
            ping_log=args.ping_log,
            case_id=args.case_id,
            jdbc_window_seconds=args.jdbc_window_seconds,
            timeline_window_seconds=args.timeline_window_seconds,
            ping_window_seconds=args.ping_window_seconds,
            lifetime_grace_seconds=args.candidate_lifetime_grace_seconds,
            thresholds=thresholds,
            max_packets=args.max_packets,
        )
        paths = export_all_case(result, args.output)
        key = result.key_jdbc_event_id
        corr = next((c for c in result.jdbc.correlations if c.event_id == key), None)
        console.print()
        console.print(f"[bold]Key JDBC:[/bold] {key}")
        if corr:
            console.print(
                f"[bold]Correlation:[/bold] {corr.correlation_status}/{corr.evidence_level} "
                f"top={corr.dual_correlation_id} candidates={corr.candidate_count}"
            )
        console.print(
            f"[bold]Evidence:[/bold] confirmed={len(result.confirmed)} "
            f"correlated={len(result.correlated)} "
            f"supporting={len(result.supporting)} unknown={len(result.unknown)}"
        )
        console.print(
            f"[bold]Ping:[/bold] "
            + (
                "NOT PROVIDED"
                if not result.ping.provided
                else f"events={len(result.ping.events)}"
            )
        )
        console.print()
        console.print(f"[dim]unified_report.md / dbcap_report.md -> {paths.get('unified_report_md')}[/dim]")
        console.print(f"[dim]unified_timeline.csv -> {paths.get('unified_timeline_csv')}[/dim]")
        return EXIT_OK
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        return EXIT_ERROR


def _top_help() -> str:
    return (
        "DBCAP commands:\n"
        "  dbcap doctor\n"
        "  dbcap case --jdbc-log ... --app-pcap ... --db-pcap ... --port ...\n"
        "  dbcap auto-case <case_dir> --port ... [--server-ip ...] [--dry-run]\n"
        "  dbcap batch <cases_root> --port ... [--server-ip ...]\n"
        "  dbcap -f <pcap> -p <port>\n"
    )


def _run_auto_case(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="dbcap auto-case", description="Discover a case folder and run dbcap case")
    p.add_argument("case_dir")
    p.add_argument("-p", "--port", type=int, default=None)
    p.add_argument("--server-ip", default=None)
    p.add_argument("-o", "--output", default=None)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--jdbc-log", default=None)
    p.add_argument("--app-pcap", default=None)
    p.add_argument("--db-pcap", default=None)
    p.add_argument("--ping-log", default=None)
    p.add_argument("--pcap-role", action="append", default=[], help="file=app or file=db")
    p.add_argument("--debug", action="store_true")
    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        return EXIT_OK if e.code in (0, None) else EXIT_ERROR

    roles = {}
    for item in args.pcap_role:
        name, sep, role = item.partition("=")
        if not sep:
            print("ERROR:\nInvalid --pcap-role (expected file=app or file=db)", file=sys.stderr)
            return EXIT_ERROR
        roles[name] = role

    from dbcap.autocase import run_auto_case

    try:
        rc, found, _result = run_auto_case(
            args.case_dir,
            server_ip=args.server_ip,
            server_port=args.port,
            output=args.output,
            dry_run=args.dry_run,
            role_overrides=roles,
            jdbc_log=args.jdbc_log,
            app_pcap=args.app_pcap,
            db_pcap=args.db_pcap,
            ping_log=args.ping_log,
        )
    except Exception as e:
        if args.debug:
            raise
        print(f"ERROR:\n{e}", file=sys.stderr)
        return EXIT_ERROR

    print(f"Status: {found.status}")
    print(found.message)
    if found.jdbc_log:
        print(f"JDBC: {found.jdbc_log}")
    if found.app_pcap:
        print(f"APP : {found.app_pcap}")
    if found.db_pcap:
        print(f"DB  : {found.db_pcap}")
    print(f"PING: {found.ping_log or 'NOT PROVIDED'}")
    if rc != 0:
        print("ERROR:", file=sys.stderr)
        print(found.message, file=sys.stderr)
    return rc


def _run_batch(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="dbcap batch", description="Analyze each immediate subdirectory as a case")
    p.add_argument("root")
    p.add_argument("-p", "--port", type=int, required=True)
    p.add_argument("--server-ip", default=None)
    p.add_argument("-o", "--output", default=None)
    p.add_argument("--debug", action="store_true")
    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        return EXIT_OK if e.code in (0, None) else EXIT_ERROR
    from dbcap.batch import run_batch

    try:
        rc, rows = run_batch(
            args.root,
            server_ip=args.server_ip,
            server_port=args.port,
            output=args.output,
        )
    except Exception as e:
        if args.debug:
            raise
        print(f"ERROR:\n{e}", file=sys.stderr)
        return 2
    ok = sum(1 for r in rows if r["status"] in {"SUCCESS", "SUCCESS_WITH_WARNINGS"})
    print(f"Cases: {len(rows)} success={ok} failed={len(rows) - ok}")
    return rc


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] == "doctor":
        out = "output"
        if "-o" in argv:
            idx = argv.index("-o")
            if idx + 1 < len(argv):
                out = argv[idx + 1]
        return run_doctor(out)

    if argv and argv[0] == "dual":
        return _run_dual(argv[1:])

    if argv and argv[0] == "jdbc":
        return _run_jdbc(argv[1:])

    if argv and argv[0] == "case":
        return _run_case(argv[1:])

    if argv and argv[0] in ("auto-case", "auto_case"):
        return _run_auto_case(argv[1:])

    if argv and argv[0] == "batch":
        return _run_batch(argv[1:])

    if argv and argv[0] in ("help", "--help", "-h"):
        print(_top_help())
        return EXIT_OK

    parser = build_argparser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        # argparse uses exit 2 for usage errors; map to EXIT_ERROR (1).
        if e.code in (0, None):
            return EXIT_OK
        return EXIT_ERROR

    if not args.file:
        print(
            "Error: -f/--file is required (or use: python -m dbcap doctor)",
            file=sys.stderr,
        )
        return EXIT_ERROR
    if args.port is None and args.db is None:
        print(
            "Error: -p/--port or -d/--db is required",
            file=sys.stderr,
        )
        return EXIT_ERROR

    try:
        port = resolve_port(args.db, args.port)
        validate_port(port)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_ERROR
    except AssertionError:
        print("Error: -p/--port or -d/--db is required", file=sys.stderr)
        return EXIT_ERROR

    db_type = args.db or str(port)
    display_filter = f"tcp.port == {port}"
    thresholds = load_thresholds(args)
    console = Console(color_system=None if args.no_color else "auto")

    try:
        console.print(f"[dim]Reading packets from {args.file}...[/dim]")
        loaded = load_pcap_file(
            args.file,
            display_filter=display_filter,
            max_packets=args.max_packets,
        )
        packets = loaded.packets
        console.print(f"[dim]Loaded {len(packets)} packet(s).[/dim]")
        if loaded.file_warning:
            console.print(f"[yellow]{loaded.file_warning}[/yellow]")

        sessions = group_into_sessions(packets, port)
        console.print(
            f"[dim]Grouped into {len(sessions)} TCP session(s) by tcp.stream.[/dim]"
        )

        if not sessions:
            console.print("[yellow]No matching TCP sessions found.[/yellow]")
            # Still evaluate capture quality on raw packets if any
            if packets:
                report = build_analysis_report(
                    {},
                    thresholds,
                    port,
                    args.file,
                    all_packets=packets,
                    file_cut_short=loaded.file_cut_short,
                    file_warning=loaded.file_warning,
                )
                render_terminal_report(report, console)
                export_all_reports(report, args.output)
                return _exit_for_report(report)
            return EXIT_OK

        console.print(f"[dim]Analyzing for {db_type} (port {port})...[/dim]")
        report = build_analysis_report(
            sessions,
            thresholds,
            port,
            args.file,
            all_packets=packets,
            file_cut_short=loaded.file_cut_short,
            file_warning=loaded.file_warning,
        )
        try:
            from dbcap.capture import find_tshark
            import subprocess

            tshark = find_tshark()
            report.metadata["tshark_path"] = tshark
            ver = subprocess.run(
                [tshark, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=0x08000000 if sys.platform == "win32" else 0,
            )
            report.metadata["tshark_version"] = (
                (ver.stdout or ver.stderr or "").splitlines()[0]
                if ver.returncode == 0
                else "unknown"
            )
        except Exception:
            report.metadata["tshark_path"] = None
            report.metadata["tshark_version"] = None

        for sid, session in sessions.items():
            retx = [r for r in report.persistent_retx if r.tcp_stream == sid]
            if retx:
                save_anomaly_payloads(session, retx, args.output)

        console.print()
        render_terminal_report(report, console)

        paths = export_all_reports(report, args.output)
        console.print(f"\n[dim]report.md     → {paths['report_md']}[/dim]")
        console.print(f"[dim]flows.csv     → {paths['flows_csv']}[/dim]")
        console.print(f"[dim]evidence.csv  → {paths['evidence_csv']}[/dim]")
        console.print(f"[dim]anomalies.json→ {args.output}/anomalies.json[/dim]")
        console.print(f"[dim]full JSON     → {paths['json']}[/dim]")

        rc = _exit_for_report(report)
        if rc == EXIT_QUALITY:
            console.print(
                "\n[yellow]Exit 2: analysis finished, but capture quality is degraded "
                "(e.g. PACKET_TRUNCATED).[/yellow]"
            )
        return rc

    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        return EXIT_ERROR
    except RuntimeError as e:
        console.print(f"[red]Error:[/red] {e}")
        return EXIT_ERROR
    except Exception as e:
        console.print(f"[red]Unexpected error:[/red] {e}")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
