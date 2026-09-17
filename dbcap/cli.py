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
  run.bat H:\\pcap\\case01.pcap 5236

退出码:
  0 = 分析完成，输入无阻断性质量问题
  1 = 程序执行失败
  2 = 分析完成，但 PCAP 存在影响完整性的质量问题（如 PACKET_TRUNCATED）
"""


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


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] == "doctor":
        out = "output"
        if "-o" in argv:
            idx = argv.index("-o")
            if idx + 1 < len(argv):
                out = argv[idx + 1]
        return run_doctor(out)

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
