"""TShark-based PCAP field extraction."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from dbcap.models import PacketSummary

TSHARK_NOT_FOUND_MSG = """
tshark not found.

Checked in order:
  1) <DBCAP_HOME>\\tools\\tshark\\tshark.exe  (release bundle)
  2) DBCAP_TSHARK environment variable
  3) PATH
  4) Common Wireshark install directories

Install Wireshark with the TShark component, or place tshark.exe under tools\\tshark\\
in the DBCAP release package. Then run doctor.bat.
"""

SEPARATOR = "|"


@dataclass
class PcapLoadResult:
    """Packets plus file-level quality signals from TShark."""

    packets: list[PacketSummary]
    tshark_exit_code: int = 0
    tshark_stderr: str = ""
    file_cut_short: bool = False
    file_warning: Optional[str] = None


FIELD_NAMES = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "tcp.flags",
    "tcp.seq",
    "tcp.ack",
    "tcp.window_size",
    "tcp.len",
    "tcp.payload",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission",
    "tcp.options.timestamp.tsval",
    "tcp.options.timestamp.tsecr",
]

_COMMON_TSHARK_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    r"D:\Wireshark\tshark.exe",
]


def _bundle_tshark_candidates() -> list[Path]:
    """Locate bundled tshark next to the release layout or DBCAP_HOME."""
    candidates: list[Path] = []
    env_home = os.environ.get("DBCAP_HOME")
    if env_home:
        candidates.append(Path(env_home) / "tools" / "tshark" / "tshark.exe")

    here = Path(__file__).resolve()
    for parent in list(here.parents)[:4]:
        candidates.append(parent / "tools" / "tshark" / "tshark.exe")
    return candidates


def find_tshark() -> str:
    """
    Locate tshark executable.

    Search order:
      1. Release bundle tools/tshark/tshark.exe (via DBCAP_HOME or package layout)
      2. DBCAP_TSHARK
      3. PATH
      4. Common Wireshark install directories
    """
    for path in _bundle_tshark_candidates():
        if path.is_file():
            return str(path)

    env = os.environ.get("DBCAP_TSHARK")
    if env and os.path.isfile(env):
        return env

    from shutil import which

    found = which("tshark")
    if found:
        return found

    for path in _COMMON_TSHARK_PATHS:
        if os.path.isfile(path):
            return path

    raise RuntimeError(TSHARK_NOT_FOUND_MSG)


def _creationflags() -> int:
    return 0x08000000 if sys.platform == "win32" else 0


def _parse_tcp_flags(flags_hex: str) -> int:
    return int(flags_hex, 16)


def _truthy(value: str) -> bool:
    return bool(value) and value not in ("0", "False", "false")


def _check_tshark(tshark: str) -> None:
    try:
        result = subprocess.run(
            [tshark, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=_creationflags(),
        )
        if result.returncode != 0:
            raise RuntimeError(TSHARK_NOT_FOUND_MSG)
    except FileNotFoundError as exc:
        raise RuntimeError(TSHARK_NOT_FOUND_MSG) from exc


def _parse_line(line: str) -> Optional[PacketSummary]:
    parts = line.split(SEPARATOR)
    while len(parts) < len(FIELD_NAMES):
        parts.append("")
    try:
        frame_number = int(parts[0]) if parts[0] else None
        ts = float(parts[1]) if parts[1] else None
        frame_len = int(parts[2]) if parts[2] else None
        cap_len = int(parts[3]) if parts[3] else None
        src_ip = parts[4]
        dst_ip = parts[5]
        src_port = int(parts[6]) if parts[6] else None
        dst_port = int(parts[7]) if parts[7] else None
        tcp_stream = int(parts[8]) if parts[8] != "" else None
        flags_str = parts[9]
        seq_str = parts[10]
        ack_str = parts[11]
        window_str = parts[12]
        len_str = parts[13]
        payload_hex = (parts[14] or "").replace(":", "")
        ws_retx = _truthy(parts[15])
        ws_fast = _truthy(parts[16])
        ws_spur = _truthy(parts[17])
        tsval_str = parts[18]
        tsecr_str = parts[19]

        if None in (ts, src_ip, dst_ip, src_port, dst_port, flags_str, seq_str):
            return None

        return PacketSummary(
            frame_number=frame_number,
            timestamp=ts,
            frame_len=frame_len,
            cap_len=cap_len,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            tcp_stream=tcp_stream,
            tcp_flags=_parse_tcp_flags(flags_str),
            tcp_seq=int(seq_str),
            tcp_ack=int(ack_str) if ack_str else 0,
            tcp_window=int(window_str) if window_str else 0,
            tcp_len=int(len_str) if len_str else 0,
            payload_hex=payload_hex,
            ws_retransmission=ws_retx,
            ws_fast_retransmission=ws_fast,
            ws_spurious_retransmission=ws_spur,
            tcp_options_tsval=int(tsval_str) if tsval_str else None,
            tcp_options_tsecr=int(tsecr_str) if tsecr_str else None,
        )
    except (ValueError, IndexError):
        return None


def load_pcap_file(
    filepath: str,
    display_filter: str = "",
    max_packets: Optional[int] = None,
    tshark_path: Optional[str] = None,
) -> PcapLoadResult:
    """
    Read a pcap/pcapng file via tshark.

    - TShark non-zero + zero packets → RuntimeError (CLI exit 1)
    - TShark non-zero + recovered packets (e.g. exit 14 cut-short) → packets
      returned with file_cut_short=True for quality exit 2
    - Intentional --max-packets stop is not treated as failure
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    tshark = tshark_path or find_tshark()
    _check_tshark(tshark)

    cmd = [
        tshark,
        "-r",
        filepath,
        "-T",
        "fields",
        "-E",
        f"separator={SEPARATOR}",
        "-E",
        "occurrence=f",
    ]
    if display_filter:
        cmd.extend(["-Y", display_filter])
    # Ask TShark to stop after N matching packets. Avoids reading the whole
    # file and prevents pipe deadlock when the Python side stops early.
    if max_packets is not None and max_packets > 0:
        cmd.extend(["-c", str(max_packets)])

    for name in FIELD_NAMES:
        cmd.extend(["-e", name])

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=_creationflags(),
    )

    packets: list[PacketSummary] = []
    stderr_chunks: list[str] = []
    assert proc.stdout is not None
    assert proc.stderr is not None

    def _drain_stderr() -> None:
        try:
            stderr_chunks.append(proc.stderr.read() or "")
        except Exception:
            stderr_chunks.append("")

    err_thread = threading.Thread(target=_drain_stderr, daemon=True)
    err_thread.start()

    intentional_stop = False
    try:
        for line in proc.stdout:
            if max_packets is not None and len(packets) >= max_packets:
                intentional_stop = True
                break
            line = line.strip()
            if not line:
                continue
            pkt = _parse_line(line)
            if pkt is not None:
                packets.append(pkt)
        if intentional_stop and proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
            raise RuntimeError("TShark timed out while reading PCAP.") from None
    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        err_thread.join(timeout=10)

    stderr_text = "".join(stderr_chunks)
    rc = proc.returncode if proc.returncode is not None else -1
    if max_packets is not None and len(packets) >= max_packets:
        intentional_stop = True

    stderr_l = stderr_text.lower()
    cut_short = (rc == 14) or ("cut short" in stderr_l) or ("truncated" in stderr_l and "packet" in stderr_l)

    if rc != 0 and not intentional_stop and not packets:
        detail = stderr_text.strip().splitlines()
        detail_msg = detail[-1] if detail else f"tshark exit code {rc}"
        raise RuntimeError(
            f"TShark failed to read PCAP (exit {rc}): {detail_msg}. "
            f"The capture may be corrupt, truncated, or unreadable. "
            f"Do not treat partial output as a complete analysis."
        )

    file_cut_short = bool(rc != 0 and not intentional_stop and packets and cut_short)
    file_warning = None
    if file_cut_short:
        detail = stderr_text.strip().splitlines()
        detail_msg = detail[-1] if detail else f"tshark exit code {rc}"
        file_warning = (
            f"TShark reported capture-file issue (exit {rc}): {detail_msg}. "
            f"Recovered {len(packets)} packet(s); analysis completeness may be affected."
        )
    elif rc != 0 and not intentional_stop and packets:
        # Unexpected non-zero with data: still analyze, but flag quality.
        file_cut_short = True
        detail = stderr_text.strip().splitlines()
        detail_msg = detail[-1] if detail else f"tshark exit code {rc}"
        file_warning = (
            f"TShark exited {rc} after recovering {len(packets)} packet(s): {detail_msg}."
        )

    return PcapLoadResult(
        packets=packets,
        tshark_exit_code=0 if intentional_stop else (rc or 0),
        tshark_stderr=stderr_text,
        file_cut_short=file_cut_short,
        file_warning=file_warning,
    )


def read_pcap_file(
    filepath: str,
    display_filter: str = "",
    max_packets: Optional[int] = None,
    tshark_path: Optional[str] = None,
) -> Iterator[PacketSummary]:
    """Iterator wrapper around load_pcap_file (compat)."""
    result = load_pcap_file(
        filepath,
        display_filter=display_filter,
        max_packets=max_packets,
        tshark_path=tshark_path,
    )
    yield from result.packets