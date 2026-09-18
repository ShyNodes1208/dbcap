"""Cross-PCAP TCP flow matching (never by tcp.stream id)."""

from __future__ import annotations

from dbcap.dual.models import (
    EV_CONFIRMED,
    EV_STRONG,
    EV_SUSPECTED,
    CorrelatedFlow,
    NormalizedFlowKey,
)
from dbcap.models import SessionSummary, TcpSession


def flow_key_from_session(session: TcpSession) -> NormalizedFlowKey:
    return NormalizedFlowKey(
        client_ip=session.key.client_ip,
        client_port=session.key.client_port,
        server_ip=session.key.server_ip,
        server_port=session.key.server_port,
    )


def flow_key_from_summary(s: SessionSummary) -> NormalizedFlowKey:
    return NormalizedFlowKey(
        client_ip=s.client_ip,
        client_port=s.client_port,
        server_ip=s.server_ip,
        server_port=s.server_port,
    )


def _overlap(a0: float | None, a1: float | None, b0: float | None, b1: float | None) -> float:
    if a0 is None or a1 is None or b0 is None or b1 is None:
        return 0.0
    lo = max(a0, b0)
    hi = min(a1, b1)
    return max(0.0, hi - lo)


def _relative_syn_seq(session: TcpSession) -> int | None:
    """
    Return TShark relative tcp.seq on client SYN if present.

    This is NOT a raw ISN. Ordinary SYNs are relative 0; equal zeros must never
    be treated as proof that two captures share the same initial sequence number.
    """
    for pkt in session.packets:
        if pkt.syn and not pkt.ack_flag:
            return int(pkt.tcp_seq)
    return None


def match_flows(
    app_sessions: dict[int, TcpSession],
    db_sessions: dict[int, TcpSession],
    *,
    clock_offset_hint: float | None = None,
) -> tuple[list[CorrelatedFlow], list[int], list[int]]:
    """
    Match APP and DB TcpSessions by normalized 4-tuple.

    Port reuse: when multiple sessions share a 4-tuple, prefer maximum
    time-overlap (db timestamps shifted by clock_offset_hint ≈ app - db).
    Never uses tcp.stream equality.
    Never boosts candidates using relative SYN tcp.seq (H-01).
    """
    app_by_key: dict[tuple, list[TcpSession]] = {}
    for s in app_sessions.values():
        app_by_key.setdefault(flow_key_from_session(s).as_tuple(), []).append(s)

    db_by_key: dict[tuple, list[TcpSession]] = {}
    for s in db_sessions.values():
        db_by_key.setdefault(flow_key_from_session(s).as_tuple(), []).append(s)

    correlated: list[CorrelatedFlow] = []
    used_app: set[int] = set()
    used_db: set[int] = set()
    corr_n = 0
    offset = clock_offset_hint or 0.0

    for key_t, app_list in sorted(app_by_key.items()):
        db_list = db_by_key.get(key_t, [])
        if not db_list:
            continue
        # Greedy best-overlap pairing (no relative-ISN boost)
        pairs: list[tuple[float, TcpSession, TcpSession, str]] = []
        for sa in app_list:
            for sb in db_list:
                b0 = (sb.start_time + offset) if sb.start_time is not None else None
                b1 = (sb.end_time + offset) if sb.end_time is not None else None
                ov = _overlap(sa.start_time, sa.end_time, b0, b1)
                syn_a, syn_b = _relative_syn_seq(sa), _relative_syn_seq(sb)

                # Relative SYN seq is non-discriminative when 0. Only reject when
                # both sides expose non-zero relative SYN seq and they differ
                # (synthetic / unusual captures); never boost on equality.
                if (
                    syn_a is not None
                    and syn_b is not None
                    and syn_a != 0
                    and syn_b != 0
                    and syn_a != syn_b
                ):
                    continue

                if ov > 0:
                    if len(app_list) > 1 or len(db_list) > 1:
                        conf = EV_STRONG
                        note = "4-tuple match with port-reuse disambiguation by time overlap"
                    else:
                        conf = EV_CONFIRMED
                        note = "Matched by normalized 4-tuple (tcp.stream ids ignored)"
                elif sa.start_time is not None and sb.start_time is not None:
                    gap = abs(sa.start_time - (sb.start_time + offset))
                    if gap > 600:
                        continue
                    conf = EV_SUSPECTED
                    note = f"4-tuple match; weak time proximity gap={gap:.3f}s"
                    ov = 1.0 / (1.0 + gap)
                else:
                    continue
                pairs.append((ov, sa, sb, conf + "|" + note))

        pairs.sort(key=lambda x: -x[0])
        local_used_a: set[int] = set()
        local_used_b: set[int] = set()
        for ov, sa, sb, conf_note in pairs:
            if sa.tcp_stream in local_used_a or sb.tcp_stream in local_used_b:
                continue
            if ov <= 0 and conf_note.startswith(EV_SUSPECTED):
                pass
            elif ov <= 0:
                continue
            conf, note = conf_note.split("|", 1)
            corr_n += 1
            cid = f"CF{corr_n:04d}"
            correlated.append(
                CorrelatedFlow(
                    correlation_id=cid,
                    flow_key=NormalizedFlowKey(*key_t[:4]),
                    app_stream=sa.tcp_stream,
                    db_stream=sb.tcp_stream,
                    app_start=sa.start_time,
                    app_end=sa.end_time,
                    db_start=sb.start_time,
                    db_end=sb.end_time,
                    confidence=conf,
                    note=note,
                )
            )
            local_used_a.add(sa.tcp_stream)
            local_used_b.add(sb.tcp_stream)
            used_app.add(sa.tcp_stream)
            used_db.add(sb.tcp_stream)

    unmatched_app = sorted(sid for sid in app_sessions if sid not in used_app)
    unmatched_db = sorted(sid for sid in db_sessions if sid not in used_db)
    return correlated, unmatched_app, unmatched_db
