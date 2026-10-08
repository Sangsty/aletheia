"""
Aletheia — Unified Pipeline Runner
Pillar 2 (The Brain), full chain

Chains all four processing stages into one script:
  raw Cowrie log -> SessionRecord -> ClassificationResult
                  -> EnrichmentResult -> EnrichedThreatRecord (+ SHA-256 hash)

The final hash is what would be submitted to the blockchain in
Pillar 3 (submitRecord) — not yet implemented, but this is the
exact artifact that step consumes.

Usage:
    python run_pipeline.py                        # runs default sample
    python run_pipeline.py <path-to-log.json>      # runs a specific log
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

from session_record import EnrichedThreatRecord
from session_reconstructor import reconstruct_session, load_events
from rule_classifier import classify_session
from enrichment import enrich_session


def compute_record_hash(record: EnrichedThreatRecord) -> str:
    """
    SHA-256 of the canonical dict — deterministic, so the same
    record always produces the same hash. This is what would be
    submitted on-chain via submitRecord() in Pillar 3.
    """
    canonical_json = json.dumps(record.canonical_dict(), sort_keys=True)
    return hashlib.sha256(canonical_json.encode()).hexdigest()


def run_pipeline(log_path: Path, node_id: str = "node-blr-01") -> EnrichedThreatRecord:
    print("=" * 60)
    print("ALETHEIA — PIPELINE DEMONSTRATION")
    print("=" * 60)

    # Stage 1: ingest raw log
    events = load_events(log_path)
    print(f"\n[STAGE 1] Raw Cowrie log ingested")
    print(f"  -> {len(events)} raw events loaded (source: {log_path.name})")

    # Stage 2: reconstruct session
    session = reconstruct_session(events, node_id=node_id)
    print(f"\n[STAGE 2] Session reconstructed")
    print(f"  -> Session ID: {session.session_id}")
    print(f"  -> Source IP: {session.src_ip}")
    print(f"  -> Protocol: {session.protocol.value}")
    print(f"  -> Credential attempts: {len(session.credential_attempts)}"
          f" ({sum(1 for c in session.credential_attempts if c.success)} successful)")
    print(f"  -> Commands executed: {len(session.command_sequence)}")
    print(f"  -> Files downloaded: {len(session.file_artifacts)}")

    # Stage 3: classify
    classification = classify_session(session)
    print(f"\n[STAGE 3] Classification")
    print(f"  -> Attack type: {classification.attack_type.value}")
    print(f"  -> Severity: {classification.severity.value}")
    print(f"  -> MITRE ATT&CK: {', '.join(classification.attck_technique_ids)}")
    print(f"  -> Matched rules: {', '.join(classification.matched_rules)}")

    # Stage 4: enrich
    enrichment = enrich_session(session)
    print(f"\n[STAGE 4] Enrichment (MOCKED — no live API calls yet)")
    print(f"  -> AbuseIPDB confidence score: {enrichment.abuseipdb.confidence_score}/100")
    print(f"  -> Abuse categories: {', '.join(enrichment.abuseipdb.abuse_categories)}")
    print(f"  -> GreyNoise classification: {enrichment.greynoise.classification.value}")

    # Final: composite record + hash
    record = EnrichedThreatRecord(
        session=session,
        classification=classification,
        enrichment=enrichment,
    )
    record_hash = compute_record_hash(record)

    print(f"\n[FINAL] Enriched Threat Record ready for blockchain submission")
    print(f"  -> Canonical SHA-256 hash: {record_hash}")
    print(f"  -> (This hash is what Pillar 3's submitRecord() would receive)")
    print("=" * 60)

    return record, record_hash


if __name__ == "__main__":
    if len(sys.argv) > 1:
        log_path = Path(sys.argv[1])
    else:
        log_path = Path(__file__).parent / "ingestion" / "sample_cowrie_session.json"

    run_pipeline(log_path)
