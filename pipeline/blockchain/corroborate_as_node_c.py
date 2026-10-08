"""
Quick one-off: corroborates the sample session's record hash as a
THIRD independent node (Hardhat's standard Account #2), so the
record crosses the 2-corroboration threshold and the automated
action watcher has something to actually fire on.
"""

import hashlib
import json
import sys
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

# ─── EDIT THIS to match your deployed contract ──────────────
CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
# ──────────────────────────────────────────────────────────

# Hardhat's standard Account #2 — well-known public dev key, local testing only.
NODE_C_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"

ARTIFACT_PATH = (
    Path(__file__).parent.parent.parent / "blockchain" / "artifacts" / "contracts"
    / "AletheiaRegistry.sol" / "AletheiaRegistry.json"
)

log_path = Path(__file__).parent.parent / "ingestion" / "sample_cowrie_session.json"
events = load_events(log_path)
session = reconstruct_session(events, node_id="node-blr-01")
classification = classify_session(session)
enrichment = enrich_session(session)
record = EnrichedThreatRecord(session=session, classification=classification, enrichment=enrichment)
canonical_json = json.dumps(record.canonical_dict(), sort_keys=True)
record_hash = hashlib.sha256(canonical_json.encode()).hexdigest()

print(f"Record hash: {record_hash}")

bridge_c = ChainBridge(
    rpc_url="http://127.0.0.1:8545",
    contract_address=CONTRACT_ADDRESS,
    private_key=NODE_C_KEY,
    artifact_path=ARTIFACT_PATH,
)
print(f"Node C address: {bridge_c.address}")

tx_hash = bridge_c.corroborate(record_hash)
print(f"Corroborated by Node C. Tx hash: {tx_hash}")

result = bridge_c.verify(record_hash)
print(f"\nNew corroboration_count: {result['corroboration_count']}")
