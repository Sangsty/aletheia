"""
Aletheia — Reclassify already-stored "unclassified" sessions
using the updated rule_classifier.py, without re-ingesting raw logs.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "classifier"))

from rule_classifier import classify_session
from db import fetch_all_records, get_connection


class _FakeSession:
    """Minimal stand-in for SessionRecord — only fields classify_session needs."""
    def __init__(self, command_sequence):
        self.command_sequence = command_sequence
        self.credential_attempts = []  # not exposed by the view; brute-force rule unaffected here
        self.file_artifacts = []       # not exposed by the view either


def main():
    records = fetch_all_records()
    unclassified = [r for r in records if r['attack_type'] == 'unclassified']
    print(f"Reclassifying {len(unclassified)} unclassified sessions...")

    updated = 0
    conn = get_connection()
    try:
        for r in unclassified:
            fake_session = _FakeSession(r['command_sequence'])
            result = classify_session(fake_session)
            if result.attack_type.value != "unclassified":
                conn.run(
                    """
                    UPDATE classifications
                    SET attack_type = :attack_type,
                        severity = :severity,
                        attck_technique_ids = :attck_ids,
                        matched_rules = :matched_rules
                    WHERE session_id = :session_uuid
                    """,
                    attack_type=result.attack_type.value,
                    severity=result.severity.value,
                    attck_ids=json.dumps(result.attck_technique_ids),
                    matched_rules=json.dumps(result.matched_rules),
                    session_uuid=r["session_uuid"],
                )
                updated += 1
                print(f"  {r['session_id']}: unclassified -> {result.attack_type.value}")
    finally:
        conn.close()

    print(f"\nDone. Reclassified {updated} of {len(unclassified)} previously-unclassified sessions.")


if __name__ == "__main__":
    main()