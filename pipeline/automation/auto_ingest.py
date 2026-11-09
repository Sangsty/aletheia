"""
Aletheia — Automated log ingestion.

Replaces the manual "pull the Cowrie log off the node, split it, run the
pipeline by hand" step with something that can run unattended on a
schedule (cron/systemd timer — see auto_ingest.sh / aletheia-ingest.*
in this directory).

What it does, each run:
  1. Opens this node's Cowrie JSON log and seeks to the byte offset it
     stopped at last time (state file — see below), so it never rescans
     the whole log from the start as it grows. This is the actual
     "automated" part: live_log_processor.py alone re-reads the entire
     log every time it's invoked, which gets slower forever as the log
     grows — fine for a one-off manual run, not for something meant to
     run every few minutes indefinitely.
  2. Parses any new lines into events, grouping them by session ID into
     an in-progress buffer that's ALSO kept in the state file — because
     a session's events arrive gradually; an attacker's session might
     still be open when this script runs, so its events-so-far have to
     be remembered until a cowrie.session.closed event shows up for it,
     possibly several runs later.
  3. For every session that reached cowrie.session.closed in this run
     (or a previous run, if it somehow never got flushed), writes its
     events to a per-session file and runs it through the real
     end-to-end pipeline (run_full_pipeline.py) for real: reconstruct
     -> classify -> enrich -> hash -> save to Postgres. (Blockchain
     submission is deliberately left out here — see --skip-chain below
     and the project's own phased rollout: automate ingestion first,
     wire up blockchain submission separately once that's ready.)
  4. Saves the updated byte offset + remaining in-progress session
     buffers back to the state file.

run_full_pipeline.py's own Stage 6 already checks session_exists()
before writing, so even if this script's state file were ever lost or
reset, re-processing an already-saved session is a safe no-op, not a
duplicate.

State file: one per node, defaults to .auto_ingest_state_<node_id>.json
next to this script. Safe to delete if you ever want to force a full
rescan from the start of the log (slow but harmless — same idempotency
guarantee).

Usage:
    python auto_ingest.py --log-path /path/to/cowrie.json --node-id node-blr-01
    python auto_ingest.py --log-path ... --node-id ... --contract 0x... --rpc-url ...
        (once blockchain wiring is ready — omit to stay DB-only, the
        default and the right choice until that phase)
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("auto_ingest")

AUTOMATION_DIR = Path(__file__).parent
PIPELINE_ROOT = AUTOMATION_DIR.parent
RUN_FULL_PIPELINE = PIPELINE_ROOT / "run_full_pipeline.py"


def default_state_path(node_id: str) -> Path:
    return AUTOMATION_DIR / f".auto_ingest_state_{node_id}.json"


def load_state(state_path: Path) -> dict:
    if state_path.exists():
        with open(state_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"byte_offset": 0, "pending_sessions": {}}


def save_state(state_path: Path, state: dict) -> None:
    tmp_path = state_path.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(state, f)
    tmp_path.replace(state_path)  # atomic on POSIX


def read_new_events(log_path: Path, byte_offset: int) -> tuple[list[dict], int]:
    """
    Reads whatever is new since byte_offset. Only COMPLETE lines are
    consumed — if the log's last line is still being written when we
    read it, we stop before it and leave the offset pointing at its
    start, so the next run picks it up whole instead of getting a
    truncated/invalid JSON line.
    """
    events = []
    with open(log_path, "rb") as f:
        f.seek(byte_offset)
        new_bytes = f.read()

    last_newline = new_bytes.rfind(b"\n")
    if last_newline == -1:
        # No complete line since the last run yet.
        return events, byte_offset

    complete_part = new_bytes[: last_newline + 1]
    new_offset = byte_offset + len(complete_part)

    for line in complete_part.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            logger.warning("Skipping unparseable log line: %r", line[:200])

    return events, new_offset


def flush_session(session_id: str, events: list[dict], node_id: str,
                   output_dir: Path, pipeline_args: list[str]) -> bool:
    """Writes one session's events to a file and runs it through the real pipeline."""
    output_dir.mkdir(parents=True, exist_ok=True)
    session_path = output_dir / f"live_{session_id}.json"
    with open(session_path, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    cmd = [sys.executable, str(RUN_FULL_PIPELINE), str(session_path), "--node-id", node_id, *pipeline_args]
    logger.info("Running pipeline on session %s (%d events): %s", session_id, len(events), " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        logger.error("Pipeline FAILED for session %s:\n%s", session_id, result.stderr[-2000:])
        return False

    logger.info("Pipeline OK for session %s", session_id)
    logger.debug(result.stdout)
    return True


def run_once(log_path: Path, node_id: str, state_path: Path,
              live_sessions_dir: Path, pipeline_args: list[str]) -> dict:
    state = load_state(state_path)
    byte_offset = state.get("byte_offset", 0)
    pending = {sid: evs for sid, evs in state.get("pending_sessions", {}).items()}

    new_events, new_offset = read_new_events(log_path, byte_offset)
    for event in new_events:
        session_id = event.get("session")
        if not session_id:
            continue
        pending.setdefault(session_id, []).append(event)

    closed_session_ids = [
        sid for sid, evs in pending.items()
        if any(e.get("eventid") == "cowrie.session.closed" for e in evs)
    ]

    flushed, failed = [], []
    for session_id in closed_session_ids:
        ok = flush_session(session_id, pending[session_id], node_id, live_sessions_dir, pipeline_args)
        if ok:
            flushed.append(session_id)
            del pending[session_id]
        else:
            failed.append(session_id)
            # Leave it in `pending` so the next run retries it instead of
            # silently dropping a session whose pipeline run failed.

    state["byte_offset"] = new_offset
    state["pending_sessions"] = pending
    save_state(state_path, state)

    summary = {
        "new_events": len(new_events),
        "sessions_flushed": flushed,
        "sessions_failed": failed,
        "sessions_still_open": list(pending.keys()),
        "byte_offset": new_offset,
    }
    logger.info("Run summary: %s", json.dumps(summary))
    return summary


def main():
    parser = argparse.ArgumentParser(description="Aletheia automated incremental log ingestion")
    parser.add_argument("--log-path", required=True, help="Path to this node's Cowrie JSON log")
    parser.add_argument("--node-id", required=True, help="This node's identity (e.g. node-blr-01)")
    parser.add_argument("--state-path", default=None, help="Override the state file path")
    parser.add_argument("--live-sessions-dir", default=None,
                         help="Where per-session files are written (default: automation/live_sessions/<node_id>)")
    parser.add_argument("--skip-chain", action="store_true", default=True,
                         help="Forwarded to run_full_pipeline.py (default: on — DB only, blockchain wired up separately)")
    parser.add_argument("--with-chain", dest="skip_chain", action="store_false",
                         help="Turn blockchain submission back on once that phase is ready")
    parser.add_argument("--contract", default=None, help="Forwarded to run_full_pipeline.py if --with-chain is set")
    parser.add_argument("--rpc-url", default=None, help="Forwarded to run_full_pipeline.py if --with-chain is set")
    args = parser.parse_args()

    log_path = Path(args.log_path)
    if not log_path.exists():
        logger.error("Log file not found: %s", log_path)
        sys.exit(1)

    state_path = Path(args.state_path) if args.state_path else default_state_path(args.node_id)
    live_sessions_dir = Path(args.live_sessions_dir) if args.live_sessions_dir \
        else AUTOMATION_DIR / "live_sessions" / args.node_id

    pipeline_args = []
    if args.skip_chain:
        pipeline_args.append("--skip-chain")
    else:
        if args.contract:
            pipeline_args += ["--contract", args.contract]
        if args.rpc_url:
            pipeline_args += ["--rpc-url", args.rpc_url]

    run_once(log_path, args.node_id, state_path, live_sessions_dir, pipeline_args)


if __name__ == "__main__":
    main()
