"""Optional protocol decoder interface (DM/Oracle/MySQL stubs)."""

from __future__ import annotations

from typing import Any, Optional


class ProtocolDecoder:
    """Base interface — TCP analysis must work without any decoder."""

    name: str = "base"

    def detect(self, payload: bytes) -> bool:
        return False

    def decode(self, payload: bytes) -> Optional[dict[str, Any]]:
        return None
