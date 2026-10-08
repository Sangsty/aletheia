"""
Aletheia — Save Pipeline Output to Postgres
Runs one Cowrie log through the full pipeline (reconstruct -> classify
-> enrich -> hash) and writes the result directly into the Postgres
database via storage/db.py.

Usage:
    python save_to_db.py                                         # default sample
    python save_to_db.py ingestion\\sample_cowrie_session_2.json   # specific log
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "models"))
sys.path.insert(0, str(Path(__file__).parent / "ingestion"))
sys.path.insert(0, str(Path(__file__).parent / "classifier"))
sys.path.insert(0, str(Path(__file__).parent / "enrichment"))
sys.path.insert(0, str(Path(__file__).parent / "storage"))

from session_reconstructor import reconstruct_session, load_events
from rule_classifier import classify_session
from enrichment import enrich_session
from session_record import EnrichedThreatRecord
from db import save_record, session_exists


def main():
    if len(sys.argv) > 1:
        log_path = Path(sys.argv[1])
    else:
        log_path = Path(__file__).parent / "ingestion" / "sample_cowrie_session.json"

    print(f"Processing: {log_path.name}")

    events = load_events(log_path)
    session = reconstruct_session(events, node_id="node-blr-01")

    if session_exists(session.session_id):
        print(f"Session {session.session_id} is already in the database — skipping.")
        return

    classification = classify_session(session)
    enrichment = enrich_session(session)

    record = EnrichedThreatRecord(session=session, classification=classification, enrichment=enrichment)
    canonical_json = json.dumps(record.canonical_dict(), sort_keys=True)
    record_hash = hashlib.sha256(canonical_json.encode()).hexdigest()

    print(f"  Session ID:   {session.session_id}")
    print(f"  Source IP:    {session.src_ip}")
    print(f"  Attack type:  {classification.attack_type.value}")
    print(f"  Severity:     {classification.severity.value}")
    print(f"  Hash:         {record_hash}")

    session_uuid = save_record(record, record_hash=record_hash)
    print(f"\nSaved to Postgres. Session UUID: {session_uuid}")


if __name__ == "__main__":
    main()
