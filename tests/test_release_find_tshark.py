"""Release-oriented tests (do not change TCP algorithm behavior)."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from dbcap import __version__
from dbcap.capture import find_tshark

_TEST_ROOT = Path(__file__).resolve().parents[1] / "output" / "_release_test_tmp"


def _fresh_dir(name: str) -> Path:
    path = _TEST_ROOT / name
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_version_is_v1():
    assert __version__ == "1.0.0"


def test_find_tshark_prefers_bundle(monkeypatch):
    root = _fresh_dir("bundle")
    exe = root / "tools" / "tshark" / "tshark.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"fake")
    monkeypatch.setenv("DBCAP_HOME", str(root))
    monkeypatch.delenv("DBCAP_TSHARK", raising=False)
    found = find_tshark()
    assert Path(found) == exe


def test_find_tshark_respects_explicit_env(monkeypatch):
    root = _fresh_dir("explicit")
    explicit = root / "custom" / "tshark.exe"
    explicit.parent.mkdir(parents=True)
    explicit.write_bytes(b"x")
    monkeypatch.delenv("DBCAP_HOME", raising=False)
    monkeypatch.setenv("DBCAP_TSHARK", str(explicit))
    found = find_tshark()
    assert Path(found) == explicit
