"""Group near-duplicate JDBC fault events (V2.6)."""

from __future__ import annotations

from dbcap.jdbc.models import JdbcEvent

DEFAULT_GROUP_WINDOW_SECONDS = 3.0


def _sig(e: JdbcEvent) -> tuple:
    return (
        e.event_type,
        e.thread_name or "",
        e.message or "",
        e.caused_by_message or "",
        e.connection_hint or "",
    )


def assign_event_groups(
    events: list[JdbcEvent],
    *,
    window_seconds: float = DEFAULT_GROUP_WINDOW_SECONDS,
) -> list[JdbcEvent]:
    """
    Assign group_id / occurrence_count without deleting events.

    Near-identical faults within ``window_seconds`` share a group.
    Far-apart identical messages remain separate groups.
    """
    if not events:
        return events

    # Preserve input order; group sequentially
    groups: dict[str, list[JdbcEvent]] = {}
    order: list[str] = []
    gid_n = 0

    for e in events:
        placed = False
        for gid in reversed(order):
            members = groups[gid]
            primary = members[0]
            if _sig(e) != _sig(primary):
                continue
            if e.timestamp is None or primary.timestamp is None:
                continue
            if abs(e.timestamp - primary.timestamp) <= window_seconds:
                # Also require last member proximity (chain within window of first)
                last = members[-1]
                if last.timestamp is not None and abs(e.timestamp - last.timestamp) <= window_seconds:
                    members.append(e)
                    e.group_id = gid
                    e.is_group_primary = False
                    placed = True
                    break
        if not placed:
            gid_n += 1
            gid = f"JG{gid_n:04d}"
            groups[gid] = [e]
            order.append(gid)
            e.group_id = gid
            e.is_group_primary = True

    for gid, members in groups.items():
        n = len(members)
        for m in members:
            m.occurrence_count = n
            m.group_id = gid

    return events
