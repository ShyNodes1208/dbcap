"""Offline environment doctor checks for DBCAP release and development."""

from __future__ import annotations

import os
import platform
import shutil
import site
import subprocess
import sys
from pathlib import Path


def _creationflags() -> int:
    return 0x08000000 if sys.platform == "win32" else 0


def _disk_free_gb(path: Path) -> float | None:
    try:
        usage = shutil.disk_usage(str(path))
        return round(usage.free / (1024**3), 2)
    except Exception:
        return None


def _resolve_home() -> Path:
    env = os.environ.get("DBCAP_HOME")
    if env:
        return Path(env).resolve()
    here = Path(__file__).resolve()
    for parent in list(here.parents)[:4]:
        if (parent / "VERSION").is_file() or (parent / "run.bat").is_file():
            return parent
    return here.parents[1]


def _path_is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def run_doctor(output_dir: str | None = None) -> int:
    """
    Check runtime health. No network checks (offline tool).

    Prints Overall: PASS or Overall: FAIL.
    Exit 0 on PASS, 1 on FAIL.
    """
    from rich.console import Console

    from dbcap import __version__

    console = Console()
    failures: list[str] = []
    home = _resolve_home()
    out_dir = Path(output_dir) if output_dir else (home / "output")
    input_dir = home / "input"
    config_file = home / "config" / "thresholds.json"

    console.print("[bold]dbcap doctor[/bold]")
    console.print(f"DBCAP Version: {__version__}")
    console.print(f"DBCAP_HOME: {home}")

    console.print(f"Windows: {platform.platform()}")
    console.print(f"Architecture: {platform.machine()}")

    console.print(f"Python: {sys.version.split()[0]}")
    console.print(f"Python executable: {sys.executable}")
    if not sys.executable or not Path(sys.executable).exists():
        failures.append("Python Runtime")
        console.print("[red]Python Runtime: FAIL[/red]")
    else:
        console.print("[green]Python Runtime: PASS[/green]")

    # Isolation checks (release runtime)
    user_site_enabled = bool(getattr(site, "ENABLE_USER_SITE", False))
    console.print(f"User site enabled: {user_site_enabled}")
    unexpected_paths: list[str] = []
    allowed_roots = [
        home,
        Path(sys.prefix),
        Path(sys.exec_prefix),
    ]
    # stdlib zip may appear as path ending with pythonXYZ.zip
    for entry in sys.path:
        if not entry:
            continue
        p = Path(entry)
        # Allow empty string / relative '.' resolved under prefix
        ok = False
        for root in allowed_roots:
            try:
                if p.exists() and _path_is_under(p, root):
                    ok = True
                    break
                if str(p).endswith(".zip") and _path_is_under(p.parent, root):
                    ok = True
                    break
            except Exception:
                continue
        # Also allow bare relative names from _pth that resolve under prefix
        if not ok and not p.is_absolute():
            ok = True
        if not ok:
            # Ignore Windows Store / known system stubs only if outside release — flag them
            low = str(p).lower()
            if "site-packages" in low and "appdata" in low:
                unexpected_paths.append(str(p))
            elif "users" in low and "site-packages" in low:
                unexpected_paths.append(str(p))
            elif user_site_enabled and "site-packages" in low:
                unexpected_paths.append(str(p))

    bundled = (home / "runtime" / "python").is_dir()
    if bundled:
        if user_site_enabled:
            failures.append("Python isolation")
            console.print("[red]Python isolated runtime: FAIL (user site enabled)[/red]")
        elif unexpected_paths:
            failures.append("Python isolation")
            console.print("[red]Python isolated runtime: FAIL (unexpected sys.path)[/red]")
            for up in unexpected_paths[:8]:
                console.print(f"  unexpected: {up}")
        else:
            console.print("[green]Python isolated runtime: PASS[/green]")
        console.print("sys.path (expected release-local entries):")
        for entry in sys.path:
            console.print(f"  {entry}")
    else:
        console.print(
            "[yellow]Python isolated runtime: SKIP (dev source layout, not release bundle)[/yellow]"
        )

    try:
        import dbcap  # noqa: F401

        console.print(f"[green]DBCAP Import: PASS[/green] (version {__version__})")
        console.print(f"DBCAP module file: {getattr(dbcap, '__file__', 'N/A')}")
    except Exception as e:
        failures.append("DBCAP Import")
        console.print(f"[red]DBCAP Import: FAIL — {e}[/red]")

    try:
        from dbcap.capture import find_tshark

        tshark = find_tshark()
        console.print(f"TShark Path: {tshark}")
        ver = subprocess.run(
            [tshark, "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=_creationflags(),
        )
        first = (
            (ver.stdout or ver.stderr or "").splitlines()[0]
            if ver.returncode == 0
            else "unknown"
        )
        console.print(f"TShark Version: {first}")
        if ver.returncode != 0:
            failures.append("TShark")
            console.print("[red]TShark: FAIL (non-zero exit)[/red]")
        else:
            bundled_ts = "tools" in Path(tshark).as_posix().lower()
            mode = "bundled" if bundled_ts else "system/PATH"
            console.print(f"TShark Mode: {mode}")
            console.print("[green]TShark: PASS[/green]")
    except Exception as e:
        failures.append("TShark")
        console.print(f"[red]TShark: FAIL — {e}[/red]")

    if config_file.is_file():
        console.print(f"[green]Config: PASS[/green] ({config_file})")
    else:
        if (home / "config").is_dir():
            failures.append("Config")
            console.print(f"[red]Config: FAIL — missing {config_file}[/red]")
        else:
            console.print(
                f"[yellow]Config: WARN — {config_file} not found; using built-in defaults[/yellow]"
            )

    try:
        input_dir.mkdir(parents=True, exist_ok=True)
        console.print(f"[green]input dir: PASS[/green] ({input_dir})")
    except Exception as e:
        failures.append("input dir")
        console.print(f"[red]input dir: FAIL — {e}[/red]")

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        probe = out_dir / ".dbcap_write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        console.print(f"[green]output dir writable: PASS[/green] ({out_dir.resolve()})")
    except Exception as e:
        failures.append("output writable")
        console.print(f"[red]output dir writable: FAIL — {e}[/red]")

    free = _disk_free_gb(out_dir if out_dir.exists() else home)
    if free is None:
        console.print("Disk free space: UNKNOWN")
    else:
        console.print(f"Disk free space: {free} GB")
        if free < 0.5:
            failures.append("disk space")
            console.print("[red]Disk free space: FAIL (< 0.5 GB)[/red]")
        else:
            console.print("[green]Disk free space: PASS[/green]")

    console.print("")
    if failures:
        console.print("[red]Failed items:[/red]")
        for item in failures:
            console.print(f"  - {item}")
        console.print("[bold red]Overall: FAIL[/bold red]")
        return 1

    console.print("[bold green]Overall: PASS[/bold green]")
    return 0
