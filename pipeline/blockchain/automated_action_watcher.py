"""
Aletheia — Automated Action Watcher
Pillar 2/3 integration: closes the loop between "verified on-chain"
and "something actually happens."

Watches the AletheiaRegistry contract for corroboration events. When
a record crosses the trust threshold — severity is high/critical AND
at least 2 independent nodes have corroborated it — this fires an
automated action: the attacker IP is written to a local blocklist
file, and a clearly formatted alert is printed to the console.

This directly implements the "composability" justification from the
original architecture brief: smart contracts encode action thresholds,
and once an indicator reaches N corroborations from nodes with
reputation >= R, downstream systems respond automatically. The
contract itself never triggers anything (Solidity has no scheduler);
this watcher is the off-chain process that polls for that state and
reacts — the standard pattern for blockchain-triggered automation.

The IP being acted on is resolved from the off-chain Postgres
database (chain_references -> sessions), since the blockchain
itself never stores the IP directly — only the hash and
classification metadata do, by design.

Usage:
    python automated_action_watcher.py --contract 0x...
    python automated_action_watcher.py --contract 0x... --once   (single pass, no polling loop)
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "storage"))

from chain_bridge import ChainBridge
from db import get_session_by_hash, is_already_actioned, log_automated_action


# ─────────────────────────────────────────────────────────────
# Trigger rule
# ─────────────────────────────────────────────────────────────

ACTIONABLE_SEVERITIES = {"high", "critical"}
MIN_CORROBORATIONS = 2

BLOCKLIST_PATH = Path(__file__).parent / "blocklist.txt"


def crosses_threshold(severity: str, corroboration_count: int) -> bool:
    """
    The trigger rule: severity must be high/critical AND at least
    MIN_CORROBORATIONS independent nodes must have corroborated it.
    A single node's claim is never enough to trigger automated
    action — the whole point is that corroboration is what makes
    the signal trustworthy enough to act on without a human.
    """
    return severity in ACTIONABLE_SEVERITIES and corroboration_count >= MIN_CORROBORATIONS


def fire_action(record_hash: str, bridge: ChainBridge) -> bool:
    """
    Checks one record against the trigger rule, and if it crosses
    the threshold and hasn't already been actioned, fires the
    automated action (blocklist write + console alert + DB log).

    Returns True if an action was fired, False otherwise (already
    actioned, doesn't cross the threshold, or record not found).
    """
    # Normalize: the chain hands back hashes as "0x..." (web3's to_hex),
    # but the off-chain database stores the bare 64-char hex digest with
    # no prefix (see schema.sql's record_hash CHAR(64) column). All
    # database lookups below must use the unprefixed form to match;
    # bridge.verify() accepts either form internally, so it's unaffected.
    db_hash = record_hash[2:] if record_hash.startswith("0x") else record_hash

    if is_already_actioned(db_hash):
        return False

    chain_state = bridge.verify(record_hash)
    if not chain_state["exists"]:
        return False

    severity = chain_state["severity"]
    corroboration_count = chain_state["corroboration_count"]

    if not crosses_threshold(severity, corroboration_count):
        return False

    # Resolve the hash back to an actual IP via the off-chain database.
    session_info = get_session_by_hash(db_hash)
    if session_info is None:
        print(f"  [watcher] Record {record_hash[:16]}... crosses threshold on-chain, "
              f"but no matching off-chain session found (not saved to DB yet?). Skipping.")
        return False

    src_ip = session_info["src_ip"]
    session_id = session_info["session_id"]
    attack_type = session_info["attack_type"]

    # ── The actual automated action ─────────────────────────
    with open(BLOCKLIST_PATH, "a") as f:
        f.write(f"{src_ip}  # {attack_type}, {severity}, {corroboration_count} corroborations, "
                f"session {session_id}, hash {record_hash}\n")

    log_automated_action(
        record_hash=db_hash,
        session_id=session_id,
        src_ip=src_ip,
        attack_type=attack_type,
        severity=severity,
        corroboration_count=corroboration_count,
        action_taken="blocklist",
    )

    print("")
    print("=" * 64)
    print(f"  AUTOMATED ACTION TRIGGERED")
    print(f"  IP:             {src_ip}")
    print(f"  Attack type:    {attack_type}")
    print(f"  Severity:       {severity}")
    print(f"  Corroborations: {corroboration_count} independent nodes")
    print(f"  Session:        {session_id}")
    print(f"  Record hash:    {record_hash}")
    print(f"  Action taken:   Added to {BLOCKLIST_PATH.name}")
    print("=" * 64)
    print("")

    return True


# ─────────────────────────────────────────────────────────────
# Event scanning
# ─────────────────────────────────────────────────────────────

def scan_for_actionable_records(bridge: ChainBridge, from_block: int = 0) -> set[str]:
    """
    Scans RecordCorroborated events from from_block to 'latest' and
    returns the set of record hashes seen. A submission alone can
    never cross the threshold (corroboration_count starts at 0), so
    only corroboration events need to be watched for new candidates.
    """
    event_filter = bridge.contract.events.RecordCorroborated.create_filter(
        from_block=from_block, to_block="latest"
    )
    events = event_filter.get_all_entries()
    return {bridge.w3.to_hex(e["args"]["recordHash"]) for e in events}


def run_watch_loop(bridge: ChainBridge, poll_interval: int = 5, once: bool = False):
    print(f"Watching AletheiaRegistry at {bridge.contract.address}")
    print(f"Trigger rule: severity in {ACTIONABLE_SEVERITIES} AND corroborations >= {MIN_CORROBORATIONS}")
    print(f"Blocklist file: {BLOCKLIST_PATH}")
    print("")

    last_checked_block = 0

    while True:
        current_block = bridge.w3.eth.block_number
        candidate_hashes = scan_for_actionable_records(bridge, from_block=last_checked_block)

        for record_hash in candidate_hashes:
            fire_action(record_hash, bridge)

        last_checked_block = current_block + 1

        if once:
            break

        time.sleep(poll_interval)


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aletheia automated action watcher")
    parser.add_argument("--contract", required=True, help="Deployed AletheiaRegistry contract address")
    parser.add_argument("--rpc-url", default="http://127.0.0.1:8545", help="RPC endpoint")
    parser.add_argument("--once", action="store_true", help="Scan once and exit, instead of polling continuously")
    parser.add_argument("--poll-interval", type=int, default=5, help="Seconds between polls (default 5)")
    args = parser.parse_args()

    bridge = ChainBridge(rpc_url=args.rpc_url, contract_address=args.contract)

    try:
        run_watch_loop(bridge, poll_interval=args.poll_interval, once=args.once)
    except KeyboardInterrupt:
        print("\nWatcher stopped.")
