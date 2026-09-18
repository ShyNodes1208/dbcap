"""Classify JDBC/network exceptions into coarse event types (V2.6)."""

from __future__ import annotations

from typing import Optional

# Returned when the block is not a network/socket fault event.
NOT_NETWORK = "NOT_NETWORK"


def classify_exception(
    exception_class: Optional[str],
    message: Optional[str],
    caused_by_class: Optional[str] = None,
    caused_by_message: Optional[str] = None,
) -> str:
    """
    Return a JDBC network event type, or NOT_NETWORK if the exception is
    not a network/socket fault (caller should skip emitting a fault event).
    """
    blob = " ".join(
        x
        for x in (
            exception_class or "",
            message or "",
            caused_by_class or "",
            caused_by_message or "",
        )
        if x
    ).lower()

    leaf = f"{caused_by_class or ''} {caused_by_message or ''}".lower()
    primary = leaf if (caused_by_class or caused_by_message) else blob

    # --- precise leaf-first ---
    if "connection reset" in primary or "connection reset" in blob:
        return "CONNECTION_RESET"

    if any(
        k in primary or k in blob
        for k in (
            "connection refused",
            "connect refused",
            "actively refused",
            "connection reject",
        )
    ):
        return "CONNECTION_REFUSED"

    # Connect-phase timeout (must precede generic socket timeout)
    if (
        "connect timed out" in primary
        or "connect timed out" in blob
        or "connection timed out" in primary
        or (
            "connect" in primary
            and "timed out" in primary
            and "read" not in primary
        )
    ):
        return "CONNECT_TIMEOUT"

    if (
        "read timed out" in primary
        or "read timed out" in blob
        or "read timeout" in primary
        or "read timeout" in blob
    ):
        return "READ_TIMEOUT"

    if "broken pipe" in primary or "broken pipe" in blob:
        return "BROKEN_PIPE"

    # Socket timeout without connect/read specificity
    if "sockettimeoutexception" in primary.replace(".", "").replace(" ", "") or (
        "sockettimeoutexception" in blob.replace(".", "")
    ):
        # class name alone with generic "timed out"
        if "connect" not in primary and "read" not in primary:
            return "SOCKET_TIMEOUT"
    if "timed out" in primary and "socket" in primary and "connect" not in primary:
        if "read" in primary:
            return "READ_TIMEOUT"
        return "SOCKET_TIMEOUT"

    # Connection closed as fault (not successful pool close)
    closed_fault = any(
        k in primary or k in blob
        for k in (
            "connection is closed",
            "connection closed",
            "already closed",
            "closed by peer",
            "stream closed",
        )
    )
    if closed_fault:
        # Exclude benign wording when clearly "successfully closed" without error class
        if "successfully" in blob and "exception" not in blob:
            return NOT_NETWORK
        return "CONNECTION_CLOSED"

    # Network / socket / I/O communication context
    networkish = any(
        k in blob
        for k in (
            "network",
            "socket",
            "i/o",
            "ioexception",
            "通信",
            "eofexception",
            "connection reset",
            "broken pipe",
        )
    )
    if networkish:
        return "UNKNOWN_NETWORK_ERROR"

    # DMException / SQLException alone without network keywords → not a network fault
    cls = (exception_class or "").lower()
    if "sqlexception" in cls or "dmexception" in cls:
        if any(k in blob for k in ("network", "socket", "通信", "i/o", "io ")):
            return "UNKNOWN_NETWORK_ERROR"
        return NOT_NETWORK

    if "exception" in blob or "error" in blob:
        return NOT_NETWORK

    return NOT_NETWORK
