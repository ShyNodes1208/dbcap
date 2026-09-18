"""Discover case-folder inputs (V2.8). Classification + role evidence only."""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from dbcap.jdbc.parser import parse_jdbc_log
from dbcap.ping.parser import parse_ping_log

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

TYPE_PCAP = "PCAP"
TYPE_JDBC = "JDBC"
TYPE_PING = "PING"
TYPE_UNKNOWN = "UNKNOWN"

ROLE_APP = "APP_SIDE"
ROLE_DB = "DB_SIDE"
ROLE_AMBIGUOUS = "AMBIGUOUS"
ROLE_NA = "N/A"


@dataclass
class FileRecord:
    path: str
    detected_type: str
    detected_role: str
    confidence: str
    reason: str
    selected: bool = False
    time_start: Optional[float] = None
    time_end: Optional[float] = None
    warnings: list[str] = field(default_factory=list)
    readable: bool = True
    packet_count: Optional[int] = None
    jdbc_events: int = 0
    ping_events: int = 0


@dataclass
class DiscoveryResult:
    case_dir: str
    files: list[FileRecord]
    status: str  # READY / INPUT_AMBIGUOUS / MISSING_INPUT
    message: str
    jdbc_log: Optional[str] = None
    app_pcap: Optional[str] = None
    db_pcap: Optional[str] = None
    ping_log: Optional[str] = None
    warnings: list[str] = field(default_factory=list)


def _read_head(path: Path, n: int = 8) -> bytes:
    try:
        with path.open("rb") as f:
            return f.read(n)
    except OSError:
        return b""


def looks_like_pcap(path: Path) -> bool:
    head = _read_head(path, 4)
    if head in PCAP_MAGIC or head == PCAPNG_MAGIC:
        return True
    return path.suffix.lower() in {".pcap", ".pcapng"} and head in PCAP_MAGIC | {PCAPNG_MAGIC}


def _text_sample(path: Path, limit: int = 200_000) -> str:
    try:
        data = path.read_bytes()[:limit]
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


def _jdbc_markers(text: str) -> bool:
    low = text.lower()
    keys = (
        "sqlexception",
        "socketexception",
        "connection reset",
        "read timed out",
        "broken pipe",
        "dmexception",
        "caused by:",
        "jdbc",
    )
    return any(k in low for k in keys)


def _ping_markers(text: str) -> bool:
    low = text.lower()
    keys = (
        "reply from",
        "request timed out",
        "destination host unreachable",
        "bytes from",
        "ttl=",
        "no answer yet",
        "ping monitor started",
    )
    return sum(1 for k in keys if k in low) >= 1


def probe_pcap(
    path: Path,
    *,
    server_ip: Optional[str],
    server_port: Optional[int],
    max_packets: int = 4000,
) -> dict:
    """Read endpoint direction evidence via tshark. No filename guessing."""
    from dbcap.capture import find_tshark

    if not looks_like_pcap(path):
        return {"readable": False, "error": "not a PCAP/PCAPNG", "to_server": 0, "from_server": 0}
    try:
        tshark = find_tshark()
    except Exception as e:
        return {"readable": False, "error": str(e), "to_server": 0, "from_server": 0}

    cmd = [tshark, "-r", str(path)]
    if server_port:
        cmd.extend(["-Y", f"tcp.port == {int(server_port)}"])
    cmd.extend(
        [
            "-c",
            str(max_packets),
            "-T",
            "fields",
            "-E",
            "separator=|",
            "-e",
            "ip.src",
            "-e",
            "tcp.srcport",
            "-e",
            "ip.dst",
            "-e",
            "tcp.dstport",
            "-e",
            "ip.ttl",
            "-e",
            "frame.time_epoch",
        ]
    )
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            creationflags=0x08000000 if sys.platform == "win32" else 0,
        )
    except Exception as e:
        return {"readable": False, "error": str(e), "to_server": 0, "from_server": 0}

    lines = [ln for ln in (proc.stdout or "").splitlines() if ln.strip()]
    if proc.returncode != 0 and not lines:
        err = (proc.stderr or "tshark failed").strip().splitlines()
        return {
            "readable": False,
            "error": err[-1] if err else "tshark failed",
            "to_server": 0,
            "from_server": 0,
        }

    to_server = 0
    from_server = 0
    times: list[float] = []
    ips: set[str] = set()
    server_ttls: dict[int, int] = {}
    client_ttls: dict[int, int] = {}
    for ln in lines:
        parts = ln.split("|")
        if len(parts) < 6:
            continue
        src, sport, dst, dport, ttl_s, ts = parts[:6]
        if src:
            ips.add(src)
        if dst:
            ips.add(dst)
        try:
            times.append(float(ts))
        except ValueError:
            pass
        ttl = None
        try:
            ttl = int(ttl_s) if ttl_s else None
        except ValueError:
            ttl = None
        if server_ip and server_port:
            if dst == server_ip and dport == str(int(server_port)):
                to_server += 1
            if src == server_ip and sport == str(int(server_port)):
                from_server += 1
            if ttl is not None:
                bucket = server_ttls if src == server_ip else client_ttls
                bucket[ttl] = bucket.get(ttl, 0) + 1

    def _mode(bucket: dict[int, int]):
        if not bucket:
            return None
        return max(bucket.items(), key=lambda kv: kv[1])[0]

    return {
        "readable": True,
        "error": None,
        "packet_count": len(lines),
        "to_server": to_server,
        "from_server": from_server,
        "time_start": min(times) if times else None,
        "time_end": max(times) if times else None,
        "ips": sorted(ips)[:12],
        "server_ttl_mode": _mode(server_ttls),
        "client_ttl_mode": _mode(client_ttls),
    }


def _role_from_probe(probe: dict, server_ip: Optional[str], server_port: Optional[int]) -> tuple[str, str, str]:
    if not server_ip or not server_port:
        return (
            ROLE_AMBIGUOUS,
            "LOW",
            "Server IP/port not provided; cannot infer APP vs DB from endpoints.",
        )
    # TTL: packets originated near the capture keep initial TTL (64/128/255).
    # This is packet evidence, not a filename hint and not a claimed NIC identity.
    s_ttl = probe.get("server_ttl_mode")
    c_ttl = probe.get("client_ttl_mode")
    initial = {32, 64, 128, 255}
    if isinstance(s_ttl, int) and isinstance(c_ttl, int) and s_ttl != c_ttl:
        if c_ttl in initial and c_ttl > s_ttl:
            return (
                ROLE_APP,
                "HIGH",
                f"Client-sourced packets keep initial TTL {c_ttl}; "
                f"server-sourced packets are TTL {s_ttl} "
                f"(capture is nearer the client than {server_ip}:{server_port}).",
            )
        if s_ttl in initial and s_ttl > c_ttl:
            return (
                ROLE_DB,
                "HIGH",
                f"Server-sourced packets keep initial TTL {s_ttl}; "
                f"client-sourced packets are TTL {c_ttl} "
                f"(capture is nearer {server_ip}:{server_port}).",
            )
    to_s = int(probe.get("to_server") or 0)
    from_s = int(probe.get("from_server") or 0)
    if to_s == 0 and from_s == 0:
        return (
            ROLE_AMBIGUOUS,
            "LOW",
            f"No TCP packets to/from {server_ip}:{server_port} in sample.",
        )
    if to_s >= 3 and to_s >= from_s * 2:
        return (
            ROLE_APP,
            "HIGH",
            f"server {server_ip}:{server_port} appears mainly as remote destination "
            f"(to_server={to_s}, from_server={from_s}).",
        )
    if from_s >= 3 and from_s >= to_s * 2:
        return (
            ROLE_DB,
            "HIGH",
            f"server {server_ip}:{server_port} appears mainly as local source "
            f"(from_server={from_s}, to_server={to_s}).",
        )
    return (
        ROLE_AMBIGUOUS,
        "LOW",
        f"Endpoint direction is mixed (to_server={to_s}, from_server={from_s}); "
        "cannot assign APP vs DB.",
    )


def classify_file(
    path: Path,
    *,
    server_ip: Optional[str] = None,
    server_port: Optional[int] = None,
    default_host: Optional[str] = None,
    default_port: Optional[int] = None,
    probe=probe_pcap,
) -> FileRecord:
    suffix = path.suffix.lower()
    if looks_like_pcap(path) or suffix in {".pcap", ".pcapng"}:
        if not looks_like_pcap(path):
            return FileRecord(
                path=str(path),
                detected_type=TYPE_PCAP,
                detected_role=ROLE_AMBIGUOUS,
                confidence="LOW",
                reason="Extension suggests PCAP but magic header is invalid.",
                readable=False,
                warnings=["corrupt or non-PCAP content"],
            )
        info = probe(path, server_ip=server_ip, server_port=server_port)
        if not info.get("readable"):
            return FileRecord(
                path=str(path),
                detected_type=TYPE_PCAP,
                detected_role=ROLE_AMBIGUOUS,
                confidence="LOW",
                reason=f"PCAP not readable: {info.get('error')}",
                readable=False,
                warnings=["unreadable PCAP"],
            )
        role, conf, why = _role_from_probe(info, server_ip, server_port)
        return FileRecord(
            path=str(path),
            detected_type=TYPE_PCAP,
            detected_role=role,
            confidence=conf,
            reason=why,
            readable=True,
            packet_count=info.get("packet_count"),
            time_start=info.get("time_start"),
            time_end=info.get("time_end"),
        )

    if suffix in {".exe", ".dll", ".zip", ".png", ".jpg", ".json", ".md", ".html"}:
        return FileRecord(
            path=str(path),
            detected_type=TYPE_UNKNOWN,
            detected_role=ROLE_NA,
            confidence="HIGH",
            reason="Non-text/non-capture file ignored.",
            readable=True,
        )

    text = _text_sample(path)
    jdbc_events = 0
    ping_events = 0
    if _jdbc_markers(text) or "exception" in text.lower():
        try:
            jdbc_events = len(
                parse_jdbc_log(str(path), default_host=default_host, default_port=default_port)
            )
        except Exception:
            jdbc_events = 0
    if _ping_markers(text):
        try:
            ping_events = len(parse_ping_log(str(path)))
        except Exception:
            ping_events = 0

    if jdbc_events > 0 and jdbc_events >= ping_events:
        return FileRecord(
            path=str(path),
            detected_type=TYPE_JDBC,
            detected_role=ROLE_NA,
            confidence="HIGH",
            reason=f"JDBC parser produced {jdbc_events} network fault event(s).",
            jdbc_events=jdbc_events,
        )
    if ping_events > 0 and ping_events > jdbc_events:
        return FileRecord(
            path=str(path),
            detected_type=TYPE_PING,
            detected_role=ROLE_NA,
            confidence="HIGH",
            reason=f"Ping parser produced {ping_events} event(s).",
            ping_events=ping_events,
        )
    if _jdbc_markers(text) and not _ping_markers(text):
        return FileRecord(
            path=str(path),
            detected_type=TYPE_JDBC,
            detected_role=ROLE_NA,
            confidence="LOW",
            reason="JDBC/stack markers present but no fault events parsed.",
            warnings=["jdbc markers without events"],
        )
    return FileRecord(
        path=str(path),
        detected_type=TYPE_UNKNOWN,
        detected_role=ROLE_NA,
        confidence="HIGH",
        reason="No JDBC/Ping/PCAP evidence; ignored.",
    )


def _match_override(path: Path, overrides: dict[str, str]) -> Optional[str]:
    name = path.name.lower()
    stem = path.stem.lower()
    full = str(path).lower()
    for key, role in overrides.items():
        k = key.lower()
        if k in {name, stem, full} or Path(key).name.lower() == name:
            r = role.lower()
            if r in {"app", "app_side"}:
                return ROLE_APP
            if r in {"db", "db_side"}:
                return ROLE_DB
    return None


def discover_case(
    case_dir: str,
    *,
    server_ip: Optional[str] = None,
    server_port: Optional[int] = None,
    role_overrides: Optional[dict[str, str]] = None,
    jdbc_log: Optional[str] = None,
    app_pcap: Optional[str] = None,
    db_pcap: Optional[str] = None,
    ping_log: Optional[str] = None,
    probe=probe_pcap,
) -> DiscoveryResult:
    root = Path(case_dir)
    if not root.is_dir():
        return DiscoveryResult(
            case_dir=str(root),
            files=[],
            status="MISSING_INPUT",
            message=f"Case directory does not exist: {root}",
        )

    records: list[FileRecord] = []
    for p in sorted(root.iterdir()):
        if not p.is_file():
            continue
        if p.name.lower() in {"input_manifest.json", "case_error.json"}:
            continue
        rec = classify_file(
            p,
            server_ip=server_ip,
            server_port=server_port,
            default_host=server_ip,
            default_port=server_port,
            probe=probe,
        )
        forced = _match_override(p, role_overrides or {})
        if forced and rec.detected_type == TYPE_PCAP and rec.readable:
            rec.detected_role = forced
            rec.confidence = "HIGH"
            rec.reason = f"Role set by --pcap-role ({forced}). " + rec.reason
        records.append(rec)

    warnings: list[str] = []

    # Explicit overrides win
    if jdbc_log:
        chosen_jdbc = str(Path(jdbc_log))
    else:
        jdbc_cands = [r for r in records if r.detected_type == TYPE_JDBC and r.jdbc_events > 0]
        if len(jdbc_cands) == 1:
            chosen_jdbc = jdbc_cands[0].path
        elif len(jdbc_cands) > 1:
            return _ambiguous(
                root, records, warnings,
                "Multiple JDBC logs parsed fault events. Specify --jdbc-log.",
            )
        else:
            return _missing(root, records, "No JDBC log was identified.", "Specify --jdbc-log <file>")

    if app_pcap and db_pcap:
        chosen_app, chosen_db = str(Path(app_pcap)), str(Path(db_pcap))
    else:
        pcaps = [r for r in records if r.detected_type == TYPE_PCAP]
        readable = [r for r in pcaps if r.readable]
        bad = [r for r in pcaps if not r.readable]
        if bad:
            warnings.append(f"{len(bad)} unreadable PCAP file(s) ignored.")
        if len(readable) == 0:
            return _missing(
                root, records,
                "Dual-PCAP case requires 2 captures. missing App-side / DB-side capture.",
                "Provide two readable PCAPs or --app-pcap and --db-pcap.",
            )
        if len(readable) == 1:
            return _missing(
                root, records,
                "Dual-PCAP case requires 2 captures. Only one readable PCAP was found.",
                "Add the missing App-side or DB-side capture.",
            )
        apps = [r for r in readable if r.detected_role == ROLE_APP]
        dbs = [r for r in readable if r.detected_role == ROLE_DB]
        if len(readable) > 2:
            # Prefer a unique APP+DB pair; otherwise ambiguous (no silent merge).
            if len(apps) == 1 and len(dbs) == 1:
                chosen_app, chosen_db = apps[0].path, dbs[0].path
                warnings.append(
                    f"{len(readable)} PCAPs found; selected the unique APP_SIDE/DB_SIDE pair."
                )
            else:
                return _ambiguous(
                    root, records, warnings,
                    "More than two PCAPs and roles are not unique. Specify --app-pcap and --db-pcap.",
                )
        else:
            if len(apps) == 1 and len(dbs) == 1:
                chosen_app, chosen_db = apps[0].path, dbs[0].path
            else:
                return _ambiguous(
                    root, records, warnings,
                    "PCAP roles are AMBIGUOUS. Specify --app-pcap/--db-pcap or --pcap-role.",
                )

    if ping_log:
        chosen_ping = str(Path(ping_log))
    else:
        pings = [r for r in records if r.detected_type == TYPE_PING and r.ping_events > 0]
        if len(pings) == 1:
            chosen_ping = pings[0].path
        elif len(pings) > 1:
            return _ambiguous(
                root, records, warnings,
                "Multiple Ping logs parsed events. Specify --ping-log.",
            )
        else:
            chosen_ping = None
            warnings.append("Ping log not identified. Ping Evidence = NOT PROVIDED.")

    selected = {chosen_jdbc, chosen_app, chosen_db}
    if chosen_ping:
        selected.add(chosen_ping)
    for r in records:
        r.selected = r.path in selected

    return DiscoveryResult(
        case_dir=str(root),
        files=records,
        status="READY",
        message="Inputs identified.",
        jdbc_log=chosen_jdbc,
        app_pcap=chosen_app,
        db_pcap=chosen_db,
        ping_log=chosen_ping,
        warnings=warnings,
    )


def _missing(root: Path, records: list[FileRecord], message: str, action: str) -> DiscoveryResult:
    return DiscoveryResult(
        case_dir=str(root),
        files=records,
        status="MISSING_INPUT",
        message=message + "\n\nAction:\n" + action,
    )


def _ambiguous(root: Path, records: list[FileRecord], warnings: list[str], message: str) -> DiscoveryResult:
    return DiscoveryResult(
        case_dir=str(root),
        files=records,
        status="INPUT_AMBIGUOUS",
        message=message + "\n\nAction:\nSpecify the missing role explicitly and rerun.",
        warnings=warnings,
    )


def write_manifest(result: DiscoveryResult, path: str) -> str:
    payload = {
        "case_directory": result.case_dir,
        "status": result.status,
        "message": result.message,
        "selected": {
            "jdbc_log": result.jdbc_log,
            "app_pcap": result.app_pcap,
            "db_pcap": result.db_pcap,
            "ping_log": result.ping_log,
        },
        "warnings": result.warnings,
        "files": [
            {
                "file": r.path,
                "detected_type": r.detected_type,
                "detected_role": r.detected_role,
                "confidence": r.confidence,
                "reason": r.reason,
                "selected": r.selected,
                "time_start": r.time_start,
                "time_end": r.time_end,
                "warnings": r.warnings,
                "readable": r.readable,
                "packet_count": r.packet_count,
            }
            for r in result.files
        ],
    }
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(out)
