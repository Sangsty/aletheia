"""
Aletheia — PostgreSQL Storage Layer
Pipeline: Pillar 2/3 boundary (off-chain storage)

Writes a fully processed EnrichedThreatRecord into the real Postgres
database (schema.sql), across the sessions / credential_attempts /
file_artifacts / classifications / enrichments / chain_references
tables, inside a single transaction.

Uses pg8000 (a pure-Python PostgreSQL driver) instead of psycopg2,
since psycopg2 relies on a compiled C/DLL extension that can get
blocked by locked-down Windows Application Control policies on
managed/school machines. pg8000 has no compiled component, so it
avoids that problem entirely.

Connection config is read from environment variables (see .env at the
project root). To (re)create the local Docker container:
    docker run -d --name aletheia-postgres \\
        -e POSTGRES_PASSWORD=$env:ALETHEIA_DB_PASSWORD -e POSTGRES_DB=aletheia \\
        -p 5432:5432 postgres:16

Usage:
    from db import save_record, fetch_all_records
    save_record(record, record_hash)    # record: EnrichedThreatRecord
    rows = fetch_all_records()          # list of dicts, from the view
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
import pg8000.native

load_dotenv(Path(__file__).parent.parent.parent / ".env")

sys.path.insert(0, str(Path(__file__).parent.parent / "models"))
from session_record import EnrichedThreatRecord


DB_CONFIG = {
    "host": os.environ.get("ALETHEIA_DB_HOST", "localhost"),
    "port": int(os.environ.get("ALETHEIA_DB_PORT", "5432")),
    "database": os.environ.get("ALETHEIA_DB_NAME", "aletheia"),
    "user": os.environ.get("ALETHEIA_DB_USER", "postgres"),
    "password": os.environ.get("ALETHEIA_DB_PASSWORD"),
}

if DB_CONFIG["password"] is None:
    raise RuntimeError(
        "ALETHEIA_DB_PASSWORD is not set. Create a .env file at the project "
        "root with ALETHEIA_DB_PASSWORD=<your local Postgres password>."
    )


def get_connection() -> pg8000.native.Connection:
    """Opens a new connection using DB_CONFIG (env vars override defaults)."""
    return pg8000.native.Connection(**DB_CONFIG)


def save_record(record: EnrichedThreatRecord, record_hash: Optional[str] = None) -> str:
    """
    Inserts a fully processed EnrichedThreatRecord into Postgres,
    across all related tables, in a single transaction.

    If the session_id already exists, this raises (no ON CONFLICT) —
    a duplicate insert attempt usually means a bug upstream, and
    that should be visible rather than silently ignored.

    Returns the session's UUID (as text) on success.
    """
    session = record.session
    classification = record.classification
    enrichment = record.enrichment

    conn = get_connection()
    try:
        conn.run("BEGIN")

        result = conn.run(
            """
            INSERT INTO sessions
                (session_id, node_id, protocol, src_ip, src_port,
                 session_start, session_end, duration_seconds, command_sequence)
            VALUES (:session_id, :node_id, :protocol, :src_ip, :src_port,
                    :session_start, :session_end, :duration_seconds, :command_sequence)
            RETURNING id
            """,
            session_id=session.session_id,
            node_id=session.node_id,
            protocol=session.protocol.value,
            src_ip=str(session.src_ip),
            src_port=session.src_port,
            session_start=session.session_start,
            session_end=session.session_end,
            duration_seconds=session.duration_seconds,
            command_sequence=json.dumps(session.command_sequence),
        )
        session_uuid = result[0][0]

        for attempt in session.credential_attempts:
            conn.run(
                """
                INSERT INTO credential_attempts (session_id, username, password, success)
                VALUES (:session_id, :username, :password, :success)
                """,
                session_id=session_uuid, username=attempt.username,
                password=attempt.password, success=attempt.success,
            )

        for artifact in session.file_artifacts:
            conn.run(
                """
                INSERT INTO file_artifacts (session_id, url, sha256, file_size_bytes)
                VALUES (:session_id, :url, :sha256, :file_size_bytes)
                """,
                session_id=session_uuid, url=artifact.url,
                sha256=artifact.sha256, file_size_bytes=artifact.file_size_bytes,
            )

        conn.run(
            """
            INSERT INTO classifications
                (session_id, attack_type, severity, attck_technique_ids, matched_rules)
            VALUES (:session_id, :attack_type, :severity, :attck_ids, :matched_rules)
            """,
            session_id=session_uuid,
            attack_type=classification.attack_type.value,
            severity=classification.severity.value,
            attck_ids=json.dumps(classification.attck_technique_ids),
            matched_rules=json.dumps(classification.matched_rules),
        )

        abuse = enrichment.abuseipdb
        grey = enrichment.greynoise
        conn.run(
            """
            INSERT INTO enrichments
                (session_id, src_ip, abuseipdb_confidence_score, abuseipdb_categories,
                 abuseipdb_total_reports, abuseipdb_isp, abuseipdb_country_code,
                 greynoise_classification, greynoise_actor, greynoise_last_seen)
            VALUES (:session_id, :src_ip, :score, :categories,
                    :reports, :isp, :country,
                    :gn_class, :gn_actor, :gn_last_seen)
            """,
            session_id=session_uuid,
            src_ip=str(session.src_ip),
            score=abuse.confidence_score if abuse else None,
            categories=json.dumps(abuse.abuse_categories) if abuse else json.dumps([]),
            reports=abuse.total_reports if abuse else 0,
            isp=abuse.isp if abuse else None,
            country=abuse.country_code if abuse else None,
            gn_class=grey.classification.value if grey else "unknown",
            gn_actor=grey.actor if grey else None,
            gn_last_seen=grey.last_seen if grey else None,
        )

        if record_hash:
            conn.run(
                """
                INSERT INTO chain_references (session_id, record_hash, submitting_node)
                VALUES (:session_id, :record_hash, :submitting_node)
                """,
                session_id=session_uuid, record_hash=record_hash,
                submitting_node=session.node_id,
            )

        conn.run("COMMIT")
        return str(session_uuid)
    except Exception:
        conn.run("ROLLBACK")
        raise
    finally:
        conn.close()


def fetch_all_records() -> list[dict]:
    """Reads every record back via the enriched_threat_records view."""
    conn = get_connection()
    try:
        rows = conn.run("SELECT * FROM enriched_threat_records ORDER BY session_start DESC;")
        columns = [c["name"] for c in conn.columns]
        return [dict(zip(columns, row)) for row in rows]
    finally:
        conn.close()


def session_exists(session_id: str) -> bool:
    """Checks whether a session_id is already stored (useful before calling save_record)."""
    conn = get_connection()
    try:
        rows = conn.run("SELECT 1 FROM sessions WHERE session_id = :sid", sid=session_id)
        return len(rows) > 0
    finally:
        conn.close()


def get_session_by_hash(record_hash: str) -> Optional[dict]:
    """
    Resolves an on-chain record_hash back to its off-chain session
    details (src_ip, session_id, etc.) via the chain_references table.
    The blockchain never stores the IP directly (by design — only the
    hash + classification metadata go on-chain), so this join is how
    the automated-action watcher finds out *which* IP to act on.
    """
    conn = get_connection()
    try:
        rows = conn.run(
            """
            SELECT s.session_id, s.src_ip, s.node_id, c.attack_type, c.severity
            FROM chain_references cr
            JOIN sessions s ON s.id = cr.session_id
            JOIN classifications c ON c.session_id = s.id
            WHERE cr.record_hash = :record_hash
            """,
            record_hash=record_hash,
        )
        if not rows:
            return None
        columns = [c["name"] for c in conn.columns]
        return dict(zip(columns, rows[0]))
    finally:
        conn.close()


def is_already_actioned(record_hash: str) -> bool:
    """Checks whether an automated action has already fired for this record_hash."""
    conn = get_connection()
    try:
        rows = conn.run(
            "SELECT 1 FROM automated_actions WHERE record_hash = :record_hash",
            record_hash=record_hash,
        )
        return len(rows) > 0
    finally:
        conn.close()


def log_automated_action(
    record_hash: str,
    session_id: str,
    src_ip: str,
    attack_type: str,
    severity: str,
    corroboration_count: int,
    action_taken: str = "blocklist",
) -> None:
    """Records that an automated action fired for this record, so it never fires twice."""
    conn = get_connection()
    try:
        conn.run(
            """
            INSERT INTO automated_actions
                (record_hash, session_id, src_ip, attack_type, severity,
                 corroboration_count, action_taken)
            VALUES (:record_hash, :session_id, :src_ip, :attack_type, :severity,
                    :corroboration_count, :action_taken)
            """,
            record_hash=record_hash,
            session_id=session_id,
            src_ip=src_ip,
            attack_type=attack_type,
            severity=severity,
            corroboration_count=corroboration_count,
            action_taken=action_taken,
        )
    finally:
        conn.close()


def fetch_all_automated_actions() -> list[dict]:
    """Reads every automated action that has fired so far, newest first."""
    conn = get_connection()
    try:
        rows = conn.run("SELECT * FROM automated_actions ORDER BY triggered_at DESC;")
        columns = [c["name"] for c in conn.columns]
        return [dict(zip(columns, row)) for row in rows]
    finally:
        conn.close()


if __name__ == "__main__":
    try:
        conn = get_connection()
        conn.close()
        print(f"Connected to Postgres successfully ({DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']})")
    except Exception as e:
        print(f"Connection FAILED: {e}")
        sys.exit(1)

    print("\nCurrent records in database:")
    rows = fetch_all_records()
    if not rows:
        print("  (none yet)")
    else:
        for r in rows:
            print(f"  {r['session_id']}  |  {r['src_ip']}  |  {r['attack_type']}  |  {r['severity']}")