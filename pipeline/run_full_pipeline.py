"""
Aletheia — Unified Full Pipeline
Phase 4 integration: the single entry point that chains every stage
built so far into one command.

    raw Cowrie log
        -> reconstruct session
        -> classify (MITRE ATT&CK)
        -> enrich (AbuseIPDB / GreyNoise)
        -> compute SHA-256 hash
        -> save to PostgreSQL (off-chain full record)
        -> submit hash to the blockchain (on-chain verification)
        -> check the automated-action threshold for this record

Previously these were three separate manual steps (save_to_db.py,
test_chain_bridge.py, automated_action_watcher.py). This script does
all of them in one call, in the correct order, for one log file.

Each stage is idempotent — rerunning on the same log is safe and
will just report what's already done rather than erroring out.

Usage:
    python run_full_pipeline.py
    python run_full_pipeline.py ingestion\\sample_cowrie_session_2.json
    python run_full_pipeline.py --node-id node-blr-02 --contract 0x...
    python run_full_pipeline.py --skip-chain          (DB only, no blockchain needed)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "models"))
sys.path.insert(0, str(Path(__file__).parent / "ingestion"))
sys.path.insert(0, str(Path(__file__).parent / "classifier"))
sys.path.insert(0, str(Path(__file__).parent / "enrichment"))
sys.path.insert(0, str(Path(__file__).parent / "storage"))
sys.path.insert(0, str(Path(__file__).parent / "blockchain"))

from session_reconstructor import reconstruct_session, load_events
from rule_classifier import classify_session
from enrichment import enrich_session
from session_record import EnrichedThreatRecord
from db import save_record, session_exists, get_session_by_hash


def compute_record_hash(record: EnrichedThreatRecord) -> str:
    canonical_json = json.dumps(record.canonical_dict(), sort_keys=True)
    return hashlib.sha256(canonical_json.encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Aletheia — run the full pipeline on one log, end to end")
    parser.add_argument("log_path", nargs="?", default=None, help="Path to a Cowrie-format log (default: sample_cowrie_session.json)")
    parser.add_argument("--node-id", default="node-blr-01", help="This node's identity (default: node-blr-01)")
    parser.add_argument("--contract", default=None, help="Deployed AletheiaRegistry contract address")
    parser.add_argument("--private-key", default=None, help="Submitting node's private key (env ALETHEIA_PRIVATE_KEY also works)")
    parser.add_argument("--rpc-url", default="http://127.0.0.1:8545", help="RPC endpoint (default: local Hardhat node)")
    parser.add_argument("--artifact-path", default=None, help="Override path to the contract's ABI JSON (defaults to Hardhat's generated artifact)")
    parser.add_argument("--skip-chain", action="store_true", help="Skip blockchain submission — database only")
    args = parser.parse_args()

    log_path = Path(args.log_path) if args.log_path else Path(__file__).parent / "ingestion" / "sample_cowrie_session.json"

    print("=" * 64)
    print("ALETHEIA — FULL PIPELINE")
    print("=" * 64)

    # ── Stage 1: Ingest ──────────────────────────────────────
    events = load_events(log_path)
    print(f"\n[STAGE 1] Raw log ingested")
    print(f"  -> {len(events)} raw events loaded (source: {log_path.name})")

    # ── Stage 2: Reconstruct ─────────────────────────────────
    session = reconstruct_session(events, node_id=args.node_id)
    print(f"\n[STAGE 2] Session reconstructed")
    print(f"  -> Session ID: {session.session_id}")
    print(f"  -> Source IP: {session.src_ip}")
    print(f"  -> Node: {session.node_id}")

    # ── Stage 3: Classify ────────────────────────────────────
    classification = classify_session(session)
    print(f"\n[STAGE 3] Classification")
    print(f"  -> Attack type: {classification.attack_type.value}")
    print(f"  -> Severity: {classification.severity.value}")
    print(f"  -> ATT&CK: {', '.join(classification.attck_technique_ids)}")

    # ── Stage 4: Enrich ──────────────────────────────────────
    enrichment = enrich_session(session)
    print(f"\n[STAGE 4] Enrichment (mocked)")
    print(f"  -> AbuseIPDB confidence: {enrichment.abuseipdb.confidence_score}/100")
    print(f"  -> GreyNoise: {enrichment.greynoise.classification.value}")

    # ── Stage 5: Hash ────────────────────────────────────────
    record = EnrichedThreatRecord(session=session, classification=classification, enrichment=enrichment)
    record_hash = compute_record_hash(record)
    print(f"\n[STAGE 5] Canonical hash computed")
    print(f"  -> SHA-256: {record_hash}")

    # ── Stage 6: Save to Postgres ────────────────────────────
    print(f"\n[STAGE 6] Off-chain storage (PostgreSQL)")
    if session_exists(session.session_id):
        print(f"  -> Session {session.session_id} already in database — skipping save")
    else:
        session_uuid = save_record(record, record_hash=record_hash)
        print(f"  -> Saved. Session UUID: {session_uuid}")

    # ── Stage 7: Submit to blockchain ────────────────────────
    if args.skip_chain:
        print(f"\n[STAGE 7] Blockchain submission SKIPPED (--skip-chain)")
        print(f"\n{'=' * 64}")
        print("Pipeline complete (database only).")
        print("=" * 64)
        return

    if not args.contract:
        print(f"\n[STAGE 7] Blockchain submission SKIPPED (no --contract address given)")
        print(f"  -> Record is saved off-chain and hashed, ready to submit once you")
        print(f"     provide --contract <address> (and optionally --private-key).")
        print(f"\n{'=' * 64}")
        print("Pipeline complete (database only — blockchain step pending).")
        print("=" * 64)
        return

    from chain_bridge import ChainBridge

    print(f"\n[STAGE 7] Blockchain submission")
    bridge = ChainBridge(
        rpc_url=args.rpc_url,
        contract_address=args.contract,
        private_key=args.private_key,
        artifact_path=args.artifact_path,
    )
    print(f"  -> Submitting node address: {bridge.address}")

    existing = bridge.verify(record_hash)
    if existing["exists"]:
        print(f"  -> Already submitted on-chain by {existing['submitting_node']}")
        print(f"  -> Current corroboration count: {existing['corroboration_count']}")
    else:
        tx_hash = bridge.submit_record(
            record_hash=record_hash,
            attack_type=classification.attack_type.value,
            severity=classification.severity.value,
            attck_tags=classification.attck_technique_ids,
            enrichment_score=enrichment.abuseipdb.confidence_score,
        )
        print(f"  -> Submitted. Tx hash: {tx_hash}")

    # ── Stage 8: Automated action threshold check ────────────
    print(f"\n[STAGE 8] Automated action check")
    from automated_action_watcher import crosses_threshold, fire_action

    current_state = bridge.verify(record_hash)
    severity = current_state["severity"]
    corroboration_count = current_state["corroboration_count"]

    if crosses_threshold(severity, corroboration_count):
        fired = fire_action(record_hash, bridge)
        if fired:
            print(f"  -> Action fired (see above) — written to blocklist.txt")
        else:
            print(f"  -> Threshold crossed but already actioned previously")
    else:
        needed = 2 - corroboration_count
        print(f"  -> Not yet actionable: severity={severity}, corroborations={corroboration_count}")
        if severity not in ("high", "critical"):
            print(f"     (severity too low to ever trigger regardless of corroboration)")
        elif needed > 0:
            print(f"     (needs {needed} more independent corroboration(s) to cross the threshold)")

    print(f"\n{'=' * 64}")
    print("Pipeline complete.")
    print("=" * 64)


if __name__ == "__main__":
    main()
