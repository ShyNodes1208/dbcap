"""Basic sensitive-field redaction for JDBC logs/reports."""

from __future__ import annotations

import re

# password / pwd / token / secret / credential (word-boundary keys)
_SENSITIVE_KV = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|credential)\s*([=:])\s*([^\s,;}\"']+)"
)

# Underscored OAuth-style keys (access_token is NOT matched by \btoken\b)
_SENSITIVE_UNDERSCORE = re.compile(
    r"(?i)\b(access_token|refresh_token|id_token|client_secret)\s*([=:])\s*([^\s,;}\"']+)"
)

# Authorization: Bearer / Basic <secret>
_AUTHORIZATION = re.compile(
    r"(?i)\b(Authorization)\s*:\s*(Bearer|Basic)\s+([^\s,;}\"']+)"
)


def redact_secrets(text: str) -> str:
    if not text:
        return text
    out = _SENSITIVE_KV.sub(r"\1\2***", text)
    out = _SENSITIVE_UNDERSCORE.sub(r"\1\2***", out)
    out = _AUTHORIZATION.sub(r"\1: \2 ***", out)
    return out
