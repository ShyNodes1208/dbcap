"""Cross-PCAP TCP segment matching via hash-indexed keys."""

from __future__ import annotations

from collections import defaultdict

from dbcap.dual.models import (
    DIR_APP_TO_DB,
    DIR_DB_TO_APP,
    EV_CONFIRMED,
    EV_STRONG,
    EV_SUSPECTED,
    EV_UNKNOWN,
    STATUS_AMBIGUOUS,
    STATUS_APP_ONLY,
    STATUS_BOTH,
    STATUS_DB_ONLY,
    STATUS_HASH_UNAVAIL,
    CorrelatedFlow,
    DualSegment,
)
from dbcap.models import TcpSession
from dbcap.retransmission import payload_sha256
from dbcap.seq_ack import expected_ack
from dbcap.session import packet_direction


def _role_direction(raw: str) -> str:
    if raw == "client_to_server":
        return DIR_APP_TO_DB
    if raw == "server_to_client":
        return DIR_DB_TO_APP
    return "UNKNOWN"


def _extract_side(
    session: TcpSession,
) -> dict[tuple, dict]:
    """
    Build index: (direction, seq, tcp_len, hash_or_None) -> aggregate.
    Uses first occurrence timestamp/frame; counts copies for retx hint.
    """
    buckets: dict[tuple, dict] = {}
    server_ip = session.key.server_ip
    server_port = session.key.server_port

    for pkt in session.packets:
        if pkt.tcp_len is None or pkt.tcp_len <= 0:
            continue
        direction = _role_direction(packet_direction(pkt, server_ip, server_port))
        truncated = bool(pkt.truncated)
        hash_ok = bool(pkt.payload_hex) and not truncated
        phash = payload_sha256(pkt.payload_hex) if hash_ok else None
        key = (direction, int(pkt.tcp_seq), int(pkt.tcp_len), phash)
        if key not in buckets:
            buckets[key] = {
                "direction": direction,
                "seq": int(pkt.tcp_seq),
                "tcp_len": int(pkt.tcp_len),
                "hash": phash,
                "truncated": truncated,
                "hash_available": hash_ok,
                "first_ts": pkt.timestamp,
                "frame": pkt.frame_number,
                "ack": pkt.tcp_ack,
                "count": 1,
                "expected_ack": expected_ack(int(pkt.tcp_seq), int(pkt.tcp_len)),
            }
        else:
            buckets[key]["count"] += 1
            buckets[key]["truncated"] = buckets[key]["truncated"] or truncated
    return buckets


def _lookup_seq_len(side: dict[tuple, dict], direction: str, seq: int, tcp_len: int) -> list[dict]:
    return [
        v
        for k, v in side.items()
        if k[0] == direction and k[1] == seq and k[2] == tcp_len
    ]


def match_segments_for_flow(
    flow: CorrelatedFlow,
    app_session: TcpSession,
    db_session: TcpSession,
) -> list[DualSegment]:
    """O(N) indexed segment correlation for one correlated flow."""
    app_map = _extract_side(app_session)
    db_map = _extract_side(db_session)

    results: list[DualSegment] = []
    used_app: set[tuple] = set()
    used_db: set[tuple] = set()

    # Exact key matches (including hash=None both sides)
    for key, sa in app_map.items():
        sb = db_map.get(key)
        if sb is None:
            continue
        used_app.add(key)
        used_db.add(key)
        phash = key[3]
        if phash is not None:
            status, evidence = STATUS_BOTH, EV_CONFIRMED
            note = (
                "Both capture points observed the same TCP payload segment. "
                "For this segment, it must not be described as fully lost between DB and APP."
                if key[0] == DIR_DB_TO_APP
                else "Both capture points observed the same TCP payload segment."
            )
            hash_match = True
        else:
            status, evidence = STATUS_HASH_UNAVAIL, EV_STRONG
            note = "Segment likely matched by Seq/Len; payload hash unavailable (truncation)."
            hash_match = None
        delta = None
        if sa["first_ts"] is not None and sb["first_ts"] is not None:
            delta = sa["first_ts"] - sb["first_ts"]
        results.append(
            DualSegment(
                correlation_id=flow.correlation_id,
                direction=key[0],
                seq=key[1],
                tcp_len=key[2],
                expected_ack=sa["expected_ack"],
                ack=sa.get("ack"),
                app_frame=sa["frame"],
                app_timestamp=sa["first_ts"],
                app_stream=flow.app_stream,
                db_frame=sb["frame"],
                db_timestamp=sb["first_ts"],
                db_stream=flow.db_stream,
                payload_hash_app=phash,
                payload_hash_db=phash,
                payload_hash_match=hash_match,
                observed_delta=delta,
                match_status=status,
                evidence_level=evidence,
                note=note,
                retransmission_count_app=sa["count"],
                retransmission_count_db=sb["count"],
            )
        )

    # Cross-match when one side has hash and the other lacks it.
    # H-02: if a hashless bucket faces multiple distinct hashed peers (same
    # direction/seq/len), remain AMBIGUOUS — do not force the first candidate.
    def _unused(side: dict[tuple, dict], used: set[tuple], direction: str, seq: int, tcp_len: int, *, want_hash: bool | None):
        out = []
        for k, v in side.items():
            if k in used:
                continue
            if k[0] != direction or k[1] != seq or k[2] != tcp_len:
                continue
            has_hash = k[3] is not None
            if want_hash is True and not has_hash:
                continue
            if want_hash is False and has_hash:
                continue
            out.append((k, v))
        return out

    def _ambiguous_multi(
        *,
        direction: str,
        seq: int,
        tcp_len: int,
        expected_ack: int | None,
        ack: int | None,
        app_frame: int | None,
        app_ts: float | None,
        db_frame: int | None,
        db_ts: float | None,
        payload_hash_app: str | None,
        payload_hash_db: str | None,
        note: str,
        retx_app: int = 0,
        retx_db: int = 0,
    ) -> DualSegment:
        return DualSegment(
            correlation_id=flow.correlation_id,
            direction=direction,
            seq=seq,
            tcp_len=tcp_len,
            expected_ack=expected_ack,
            ack=ack,
            app_frame=app_frame,
            app_timestamp=app_ts,
            app_stream=flow.app_stream,
            db_frame=db_frame,
            db_timestamp=db_ts,
            db_stream=flow.db_stream,
            payload_hash_app=payload_hash_app,
            payload_hash_db=payload_hash_db,
            payload_hash_match=None,
            observed_delta=None,
            match_status=STATUS_AMBIGUOUS,
            evidence_level=EV_SUSPECTED,
            note=note,
            retransmission_count_app=retx_app,
            retransmission_count_db=retx_db,
        )

    # Group keys still unused after exact matches by (direction, seq, len)
    groups: set[tuple[str, int, int]] = set()
    for k in list(app_map) + list(db_map):
        if k in used_app or k in used_db:
            # still collect groups from unused only below
            pass
        groups.add((k[0], k[1], k[2]))

    for direction, seq, tcp_len in sorted(groups):
        app_hashed = _unused(app_map, used_app, direction, seq, tcp_len, want_hash=True)
        app_hashless = _unused(app_map, used_app, direction, seq, tcp_len, want_hash=False)
        db_hashed = _unused(db_map, used_db, direction, seq, tcp_len, want_hash=True)
        db_hashless = _unused(db_map, used_db, direction, seq, tcp_len, want_hash=False)

        # App hashed ↔ DB hashless
        if app_hashed and db_hashless and not app_hashless:
            if len(app_hashed) > 1 or len(db_hashless) > 1:
                ka, sa = app_hashed[0]
                kb, sb = db_hashless[0]
                results.append(
                    _ambiguous_multi(
                        direction=direction,
                        seq=seq,
                        tcp_len=tcp_len,
                        expected_ack=sa["expected_ack"],
                        ack=sa.get("ack"),
                        app_frame=sa["frame"],
                        app_ts=sa["first_ts"],
                        db_frame=sb["frame"],
                        db_ts=sb["first_ts"],
                        payload_hash_app=ka[3],
                        payload_hash_db=None,
                        note=(
                            f"AMBIGUOUS: {len(app_hashed)} APP hashed and "
                            f"{len(db_hashless)} DB hashless Seq/Len candidates; not forced."
                        ),
                        retx_app=sa["count"],
                        retx_db=sb["count"],
                    )
                )
                for k, _ in app_hashed:
                    used_app.add(k)
                for k, _ in db_hashless:
                    used_db.add(k)
            else:
                ka, sa = app_hashed[0]
                kb, sb = db_hashless[0]
                used_app.add(ka)
                used_db.add(kb)
                results.append(
                    DualSegment(
                        correlation_id=flow.correlation_id,
                        direction=direction,
                        seq=seq,
                        tcp_len=tcp_len,
                        expected_ack=sa["expected_ack"],
                        ack=sa.get("ack"),
                        app_frame=sa["frame"],
                        app_timestamp=sa["first_ts"],
                        app_stream=flow.app_stream,
                        db_frame=sb["frame"],
                        db_timestamp=sb["first_ts"],
                        db_stream=flow.db_stream,
                        payload_hash_app=ka[3],
                        payload_hash_db=None,
                        payload_hash_match=None,
                        observed_delta=sa["first_ts"] - sb["first_ts"],
                        match_status=STATUS_HASH_UNAVAIL,
                        evidence_level=EV_STRONG,
                        note="Seq/Len match; one side payload hash unavailable.",
                        retransmission_count_app=sa["count"],
                        retransmission_count_db=sb["count"],
                    )
                )

        # DB hashed ↔ App hashless (Codex H-02 primary case)
        if db_hashed and app_hashless and not db_hashless:
            # Re-read unused in case prior branch consumed keys
            app_hashless = _unused(app_map, used_app, direction, seq, tcp_len, want_hash=False)
            db_hashed = _unused(db_map, used_db, direction, seq, tcp_len, want_hash=True)
            if not db_hashed or not app_hashless:
                continue
            if len(db_hashed) > 1 or len(app_hashless) > 1:
                ka, sa = app_hashless[0]
                kb, sb = db_hashed[0]
                cand_frames = sorted(
                    {v["frame"] for _, v in db_hashed if v.get("frame") is not None}
                    | {v["frame"] for _, v in app_hashless if v.get("frame") is not None}
                )
                results.append(
                    _ambiguous_multi(
                        direction=direction,
                        seq=seq,
                        tcp_len=tcp_len,
                        expected_ack=sb["expected_ack"],
                        ack=sb.get("ack"),
                        app_frame=sa["frame"],
                        app_ts=sa["first_ts"],
                        db_frame=sb["frame"],
                        db_ts=sb["first_ts"],
                        payload_hash_app=None,
                        payload_hash_db=kb[3],
                        note=(
                            f"AMBIGUOUS: hash unavailable cannot distinguish "
                            f"{len(db_hashed)} distinct DB hashed Seq/Len candidates "
                            f"(candidate_frames={cand_frames}); not forced."
                        ),
                        retx_app=sa["count"],
                        retx_db=sb["count"],
                    )
                )
                for k, _ in app_hashless:
                    used_app.add(k)
                for k, _ in db_hashed:
                    used_db.add(k)
            else:
                ka, sa = app_hashless[0]
                kb, sb = db_hashed[0]
                used_app.add(ka)
                used_db.add(kb)
                results.append(
                    DualSegment(
                        correlation_id=flow.correlation_id,
                        direction=direction,
                        seq=seq,
                        tcp_len=tcp_len,
                        expected_ack=sb["expected_ack"],
                        ack=sb.get("ack"),
                        app_frame=sa["frame"],
                        app_timestamp=sa["first_ts"],
                        app_stream=flow.app_stream,
                        db_frame=sb["frame"],
                        db_timestamp=sb["first_ts"],
                        db_stream=flow.db_stream,
                        payload_hash_app=None,
                        payload_hash_db=kb[3],
                        payload_hash_match=None,
                        observed_delta=sa["first_ts"] - sb["first_ts"],
                        match_status=STATUS_HASH_UNAVAIL,
                        evidence_level=EV_STRONG,
                        note="Seq/Len match; one side payload hash unavailable.",
                        retransmission_count_app=sa["count"],
                        retransmission_count_db=sb["count"],
                    )
                )

    # Same seq/len different hashes → not merged; remain side-only (implicit)
    # Remainders
    for key, sa in app_map.items():
        if key in used_app:
            continue
        # Check ambiguous different-hash peers
        peers = _lookup_seq_len(db_map, key[0], key[1], key[2])
        peer_unused = [p for p in peers if (p["direction"], p["seq"], p["tcp_len"], p["hash"]) not in used_db]
        if peer_unused and key[3] is not None and any(p["hash"] is not None and p["hash"] != key[3] for p in peer_unused):
            results.append(
                DualSegment(
                    correlation_id=flow.correlation_id,
                    direction=key[0],
                    seq=key[1],
                    tcp_len=key[2],
                    expected_ack=sa["expected_ack"],
                    ack=sa.get("ack"),
                    app_frame=sa["frame"],
                    app_timestamp=sa["first_ts"],
                    app_stream=flow.app_stream,
                    db_frame=peer_unused[0]["frame"],
                    db_timestamp=peer_unused[0]["first_ts"],
                    db_stream=flow.db_stream,
                    payload_hash_app=key[3],
                    payload_hash_db=peer_unused[0]["hash"],
                    payload_hash_match=False,
                    observed_delta=None,
                    match_status=STATUS_AMBIGUOUS,
                    evidence_level=EV_UNKNOWN,
                    note="Same Seq/Len but different payload hashes; not treated as same segment.",
                    retransmission_count_app=sa["count"],
                )
            )
            used_app.add(key)
            continue
        results.append(
            DualSegment(
                correlation_id=flow.correlation_id,
                direction=key[0],
                seq=key[1],
                tcp_len=key[2],
                expected_ack=sa["expected_ack"],
                ack=sa.get("ack"),
                app_frame=sa["frame"],
                app_timestamp=sa["first_ts"],
                app_stream=flow.app_stream,
                db_frame=None,
                db_timestamp=None,
                db_stream=flow.db_stream,
                payload_hash_app=key[3],
                payload_hash_db=None,
                payload_hash_match=None,
                observed_delta=None,
                match_status=STATUS_APP_ONLY,
                evidence_level=EV_STRONG if key[3] else EV_SUSPECTED,
                note=(
                    "Segment observed at APP capture point; not observed at DB capture point. "
                    "Does not by itself prove a specific network device drop "
                    "(check time coverage, snaplen, filters, clock)."
                ),
                retransmission_count_app=sa["count"],
            )
        )

    for key, sb in db_map.items():
        if key in used_db:
            continue
        results.append(
            DualSegment(
                correlation_id=flow.correlation_id,
                direction=key[0],
                seq=key[1],
                tcp_len=key[2],
                expected_ack=sb["expected_ack"],
                ack=sb.get("ack"),
                app_frame=None,
                app_timestamp=None,
                app_stream=flow.app_stream,
                db_frame=sb["frame"],
                db_timestamp=sb["first_ts"],
                db_stream=flow.db_stream,
                payload_hash_app=None,
                payload_hash_db=key[3],
                payload_hash_match=None,
                observed_delta=None,
                match_status=STATUS_DB_ONLY,
                evidence_level=EV_STRONG if key[3] else EV_SUSPECTED,
                note=(
                    "Segment observed at DB capture point; not observed at APP capture point. "
                    "Does not by itself prove a specific network device drop "
                    "(check time coverage, snaplen, filters, clock)."
                ),
                retransmission_count_db=sb["count"],
            )
        )

    results.sort(key=lambda r: (r.direction, r.seq, r.tcp_len, r.match_status))
    return results
