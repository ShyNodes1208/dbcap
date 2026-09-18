"""Auto-case orchestration (V2.8). Calls existing case pipeline — no second analyzer."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from dbcap.autocase.discover import DiscoveryResult, discover_case, write_manifest


def run_auto_case(
    case_dir: str,
    *,
    server_ip: Optional[str] = None,
    server_port: Optional[int] = None,
    output: Optional[str] = None,
    dry_run: bool = False,
    role_overrides: Optional[dict[str, str]] = None,
    jdbc_log: Optional[str] = None,
    app_pcap: Optional[str] = None,
    db_pcap: Optional[str] = None,
    ping_log: Optional[str] = None,
    case_id: Optional[str] = None,
    jdbc_window_seconds: float = 10.0,
    lifetime_grace_seconds: float = 5.0,
    thresholds=None,
    max_packets: Optional[int] = None,
    probe=None,
) -> tuple[int, DiscoveryResult, Optional[object]]:
    """
    Return (exit_code, discovery, case_result_or_none).

    0 = analysis finished (or dry-run READY)
    1 = missing / ambiguous / analysis failure
    """
    kwargs = dict(
        server_ip=server_ip,
        server_port=server_port,
        role_overrides=role_overrides,
        jdbc_log=jdbc_log,
        app_pcap=app_pcap,
        db_pcap=db_pcap,
        ping_log=ping_log,
    )
    if probe is not None:
        kwargs["probe"] = probe
    found = discover_case(case_dir, **kwargs)

    out_dir = Path(output) if output else Path(case_dir) / "dbcap_output"
    out_dir.mkdir(parents=True, exist_ok=True)
    write_manifest(found, str(out_dir / "input_manifest.json"))

    if found.status != "READY":
        _write_error(out_dir, found.status, "discover", found.message)
        return 1, found, None

    if dry_run:
        return 0, found, None

    if not server_port:
        msg = "Database port is required to run analysis.\n\nAction:\nSpecify --port <db_port>"
        found.status = "MISSING_INPUT"
        found.message = msg
        write_manifest(found, str(out_dir / "input_manifest.json"))
        _write_error(out_dir, "MISSING_INPUT", "analyze", msg)
        return 1, found, None

    try:
        from dbcap.case import analyze_case, export_all_case

        result = analyze_case(
            found.jdbc_log,
            found.app_pcap,
            found.db_pcap,
            int(server_port),
            server_ip=server_ip,
            ping_log=found.ping_log,
            case_id=case_id or Path(case_dir).name,
            jdbc_window_seconds=jdbc_window_seconds,
            lifetime_grace_seconds=lifetime_grace_seconds,
            thresholds=thresholds,
            max_packets=max_packets,
        )
        export_all_case(result, str(out_dir))
        write_manifest(found, str(out_dir / "input_manifest.json"))
        return 0, found, result
    except Exception as e:
        _write_error(out_dir, "ANALYSIS_FAILED", "analyze", str(e))
        found.status = "ANALYSIS_FAILED"
        found.message = str(e)
        return 1, found, None


def _write_error(out_dir: Path, error_type: str, stage: str, message: str) -> None:
    import json

    payload = {
        "case": str(out_dir),
        "stage": stage,
        "error_type": error_type,
        "message": message,
    }
    (out_dir / "case_error.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
