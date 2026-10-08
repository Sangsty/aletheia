"""
Aletheia — chain_bridge.py local test
Runs a real session through the pipeline, then submits it on-chain to
your locally deployed AletheiaRegistry contract, corroborates it from
a second simulated node, and reads everything back.

Before running:
  1. `npx hardhat node` running in another terminal
  2. Contract deployed via `npx hardhat run scripts/deploy.js --network localhost`
  3. Set CONTRACT_ADDRESS below to the address that printed

Usage:
    python test_chain_bridge.py
"""

import sys
import hashlib
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "models"))
sys.path.insert(0, str(Path(__file__).parent.parent / "ingestion"))
sys.path.insert(0, str(Path(__file__).parent.parent / "classifier"))
sys.path.insert(0, str(Path(__file__).parent.parent / "enrichment"))
sys.path.insert(0, str(Path(__file__).parent))

from session_reconstructor import reconstruct_session, load_events
from rule_classifier import classify_session
from enrichment import enrich_session
from session_record import EnrichedThreatRecord
from chain_bridge import ChainBridge

# ─── EDIT THIS ───────────────────────────────────────────────
CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
# ─────────────────────────────────────────────────────────────

# Hardhat's standard local test accounts — well-known, public dev keys.
# NEVER use these on a real network; they're meant only for local testing.
NODE_A_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # Account #0
NODE_B_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"  # Account #1

ARTIFACT_PATH = (
    Path(__file__).parent.parent.parent / "blockchain" / "artifacts" / "contracts"
    / "AletheiaRegistry.sol" / "AletheiaRegistry.json"
)


def main():
    log_path = Path(__file__).parent.parent / "ingestion" / "sample_cowrie_session.json"
    events = load_events(log_path)
    session = reconstruct_session(events, node_id="node-blr-01")
    classification = classify_session(session)
    enrichment = enrich_session(session)
    record = EnrichedThreatRecord(session=session, classification=classification, enrichment=enrichment)

    canonical_json = json.dumps(record.canonical_dict(), sort_keys=True)
    record_hash = hashlib.sha256(canonical_json.encode()).hexdigest()
    print(f"Computed hash: {record_hash}\n")

    bridge_a = ChainBridge(
        rpc_url="http://127.0.0.1:8545",
        contract_address=CONTRACT_ADDRESS,
        private_key=NODE_A_KEY,
        artifact_path=ARTIFACT_PATH,
    )
    print(f"Node A address: {bridge_a.address}")

    print("\n=== submit_record() ===")
    existing = bridge_a.verify(record_hash)
    if existing["exists"]:
        print(f"This hash was already submitted in an earlier run (by {existing['submitting_node']}).")
        print("Skipping submission, proceeding straight to corroboration.")
    else:
        tx_hash = bridge_a.submit_record(
            record_hash=record_hash,
            attack_type=classification.attack_type.value,
            severity=classification.severity.value,
            attck_tags=classification.attck_technique_ids,
            enrichment_score=enrichment.abuseipdb.confidence_score,
        )
        print(f"Submitted. Tx hash: {tx_hash}")

    print("\n=== verify() ===")
    result = bridge_a.verify(record_hash)
    for k, v in result.items():
        print(f"  {k}: {v}")

    print("\n=== corroborate() from a second independent node ===")
    bridge_b = ChainBridge(
        rpc_url="http://127.0.0.1:8545",
        contract_address=CONTRACT_ADDRESS,
        private_key=NODE_B_KEY,
        artifact_path=ARTIFACT_PATH,
    )
    print(f"Node B address: {bridge_b.address}")
    if bridge_b.has_corroborated(record_hash):
        print("Node B already corroborated this record in an earlier run. Skipping.")
    else:
        tx_hash_corrob = bridge_b.corroborate(record_hash)
        print(f"Corroborated. Tx hash: {tx_hash_corrob}")

    print("\n=== verify() after corroboration ===")
    result2 = bridge_a.verify(record_hash)
    for k, v in result2.items():
        print(f"  {k}: {v}")

    print("\n=== get_reputation() for Node A (the submitter) ===")
    rep = bridge_a.get_reputation()
    for k, v in rep.items():
        print(f"  {k}: {v}")

    print("\n=== get_record_details() ===")
    details = bridge_a.get_record_details(record_hash)
    for k, v in details.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
