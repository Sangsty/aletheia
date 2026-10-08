"""
Splits a raw Cowrie JSONL log into one JSONL file per completed session
(one JSON object per line), matching the format load_events() expects —
the same format used by sample_cowrie_session_*.json — so each can be run
through the existing pipeline unchanged.
"""

import json
import sys
import os
from collections import defaultdict


def split_cowrie_log(log_path: str, output_dir: str = "live_sessions") -> list:
    sessions = defaultdict(list)

    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            session_id = event.get("session")
            if session_id:
                sessions[session_id].append(event)

    os.makedirs(output_dir, exist_ok=True)
    output_files = []

    for session_id, events in sessions.items():
        has_close = any(e.get("eventid") == "cowrie.session.closed" for e in events)
        if not has_close:
            continue

        out_path = os.path.join(output_dir, f"live_{session_id}.json")
        with open(out_path, "w") as out_f:
            for event in events:
                out_f.write(json.dumps(event) + "\n")
        output_files.append(out_path)

    return output_files


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python live_log_processor.py <path_to_cowrie_log.json>")
        sys.exit(1)

    files = split_cowrie_log(sys.argv[1])

    print(f"Split into {len(files)} completed session(s):")
    for f in files:
        print(f"  {f}")