"""Dameng protocol decoder stub — not required for TCP evidence analysis."""

from __future__ import annotations

from typing import Any, Optional

from dbcap.protocols.base import ProtocolDecoder


class DamengDecoder(ProtocolDecoder):
    name = "dameng"

    def detect(self, payload: bytes) -> bool:
        # Intentionally minimal: first-phase priority is TCP evidence, not DM reverse.
        return False

    def decode(self, payload: bytes) -> Optional[dict[str, Any]]:
        return None
