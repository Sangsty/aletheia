"""
Aletheia — Bulk Log Processor
Processes an entire raw Cowrie log file (potentially thousands of
events across hundreds of sessions) through classification,
enrichment, and storage in one pass — the batch alternative to
running run_full_pipeline.py once per session.

Performance note: this opens ONE database connection for the whole
run and reuses it for every session_exists()/save_record() call,
instead of opening and closing a fresh connection per session (which
was costing two full connect/auth round-trips per session on top of
the actual classify/enrich/insert work).

Usage:
    python bulk_process_log.py <path_to_raw_cowrie_log.json> --node-id node-A
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "models"))
sys.path.insert(0, str(Path(__file__).parent / "ingestion"))
sys.path.insert(0, str(Path(__file__).parent / "classifier"))
sys.path.insert(0, str(Path(__file__).parent / "enrichment"))
sys.path.insert(0, str(Path(__file__).parent / "storage"))

from session_reconstructor import reconstruct_session
from rule_classifier import classify_session
from enrichment import enrich_session
from session_record import EnrichedThreatRecord
from db import save_record, session_exists, get_connection


def load_raw_events(log_path: Path) -> list[dict]:
    events = []
    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def group_completed_sessions(events: list[dict]) -> dict[str, list[dict]]:
    sessions = defaultdict(list)
    for e in events:
        sid = e.get("session")
        if sid:
            sessions[sid].append(e)
    return {
        sid: evs for sid, evs in sessions.items()
        if any(e.get("eventid") == "cowrie.session.closed" for e in evs)
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("log_path", help="Path to raw Cowrie JSONL log")
    parser.add_argument("--node-id", required=True, help="Node identifier, e.g. node-A")
    args = parser.parse_args()

    events = load_raw_events(Path(args.log_path))
    sessions = group_completed_sessions(events)

    print(f"Found {len(sessions)} completed sessions in {args.log_path}")

    stats = defaultdict(int)
    severity_stats = defaultdict(int)
    skipped = 0
    processed = 0
    errors = 0

    # One connection for the entire bulk run, reused for every session's
    # existence check and insert, instead of reconnecting per session.
    conn = get_connection()
    try:
        for session_id, session_events in sessions.items():
            if session_exists(session_id, conn=conn):
                skipped += 1
                continue

            try:
                session = reconstruct_session(session_events, node_id=args.node_id)
                classification = classify_session(session)
                enrichment = enrich_session(session)
                record = EnrichedThreatRecord(
                    session=session, classification=classification, enrichment=enrichment
                )
                canonical_json = json.dumps(record.canonical_dict(), sort_keys=True)
                record_hash = hashlib.sha256(canonical_json.encode()).hexdigest()

                save_record(record, record_hash, conn=conn)

                stats[classification.attack_type.value] += 1
                severity_stats[classification.severity.value] += 1
                processed += 1
            except Exception as e:
                errors += 1
                print(f"  [ERROR] session {session_id}: {e}")
    finally:
        conn.close()

    print("\n" + "=" * 50)
    print("BULK PROCESSING SUMMARY")
    print("=" * 50)
    print(f"Total completed sessions found: {len(sessions)}")
    print(f"Newly processed:                {processed}")
    print(f"Already in DB (skipped):        {skipped}")
    print(f"Errors:                         {errors}")
    print("\nBy attack type:")
    for atype, count in sorted(stats.items(), key=lambda x: -x[1]):
        print(f"  {atype:30s} {count}")
    print("\nBy severity:")
    for sev, count in sorted(severity_stats.items(), key=lambda x: -x[1]):
        print(f"  {sev:30s} {count}")


if __name__ == "__main__":
    main()