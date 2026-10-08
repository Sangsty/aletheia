"""
Aletheia — Session Reconstructor
Pipeline: Pillar 2 (The Brain), Stage 1 → Stage 2

Reads raw Cowrie JSON log lines (one event per line) and groups them
by session ID into a single reconstructed SessionRecord.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "models"))
from session_record import SessionRecord, CredentialAttempt, FileArtifact, Protocol


def reconstruct_session(events: list[dict], node_id: str) -> SessionRecord:
    if not events:
        raise ValueError("No events provided for session reconstruction")

    session_id = events[0]["session"]
    src_ip = events[0]["src_ip"]

    protocol = Protocol.ssh
    for e in events:
        if "protocol" in e:
            protocol = Protocol(e["protocol"])
            break

    connect_event = next((e for e in events if e["eventid"] == "cowrie.session.connect"), None)
    close_event = next((e for e in events if e["eventid"] == "cowrie.session.closed"), None)

    session_start = datetime.fromisoformat(connect_event["timestamp"].replace("Z", "+00:00")) \
        if connect_event else datetime.fromisoformat(events[0]["timestamp"].replace("Z", "+00:00"))
    session_end = datetime.fromisoformat(close_event["timestamp"].replace("Z", "+00:00")) \
        if close_event else None
    duration = close_event.get("duration") if close_event else None

    credential_attempts = []
    for e in events:
        if e["eventid"] in ("cowrie.login.failed", "cowrie.login.success") and "password" in e:
            credential_attempts.append(CredentialAttempt(
                username=e["username"],
                password=e["password"],
                success=(e["eventid"] == "cowrie.login.success"),
            ))

    command_sequence = [
        e["input"] for e in events if e["eventid"] == "cowrie.command.input"
    ]

    file_artifacts = []
    for e in events:
        if e["eventid"] == "cowrie.session.file_download":
            file_artifacts.append(FileArtifact(
                url=e.get("url"),
                sha256=e["shasum"],
            ))

    src_port = connect_event.get("src_port") if connect_event else None

    return SessionRecord(
        session_id=session_id,
        node_id=node_id,
        protocol=protocol,
        src_ip=src_ip,
        src_port=src_port,
        session_start=session_start,
        session_end=session_end,
        duration_seconds=duration,
        credential_attempts=credential_attempts,
        command_sequence=command_sequence,
        file_artifacts=file_artifacts,
    )


def load_events(path: Path) -> list[dict]:
    events = []
    with open(path) as f:
        for line in f:
            events.append(json.loads(line))
    return events


if __name__ == "__main__":
    sample_path = Path(__file__).parent / "sample_cowrie_session.json"
    events = load_events(sample_path)
    record = reconstruct_session(events, node_id="node-blr-01")
    print("Reconstructed SessionRecord:")
    print(record.model_dump_json(indent=2))
