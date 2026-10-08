"""
Aletheia — Corpus Builder
Runs the full pipeline (reconstruct -> classify -> enrich -> hash)
against every sample Cowrie log in pipeline/ingestion/, and saves
the results as one JSON corpus file. This corpus is what the
searchable "dictionary" demo (search_demo.html) queries against.

In the real system, this corpus is the enriched_threat_records view
in PostgreSQL — this script is a stand-in until that's live.

Usage:
    python build_corpus.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "models"))
sys.path.insert(0, str(Path(__file__).parent / "ingestion"))
sys.path.insert(0, str(Path(__file__).parent / "classifier"))
sys.path.insert(0, str(Path(__file__).parent / "enrichment"))

from session_reconstructor import reconstruct_session, load_events
from rule_classifier import classify_session
from enrichment import enrich_session
from run_pipeline import compute_record_hash
from session_record import EnrichedThreatRecord


def build_corpus() -> list[dict]:
    ingestion_dir = Path(__file__).parent / "ingestion"
    log_files = sorted(ingestion_dir.glob("sample_cowrie_session*.json"))

    corpus = []
    for log_path in log_files:
        # alternate node_id assignment based on filename, just for demo variety
        node_id = "node-blr-02" if "_4" in log_path.stem or "_5" in log_path.stem else "node-blr-01"

        events = load_events(log_path)
        session = reconstruct_session(events, node_id=node_id)
        classification = classify_session(session)
        enrichment = enrich_session(session)

        record = EnrichedThreatRecord(
            session=session,
            classification=classification,
            enrichment=enrichment,
        )
        record_hash = compute_record_hash(record)

        corpus.append({
            "session_id": session.session_id,
            "node_id": session.node_id,
            "protocol": session.protocol.value,
            "src_ip": str(session.src_ip),
            "duration_seconds": session.duration_seconds,
            "credential_attempts": len(session.credential_attempts),
            "commands": session.command_sequence,
            "files_downloaded": len(session.file_artifacts),
            "attack_type": classification.attack_type.value,
            "severity": classification.severity.value,
            "attck_technique_ids": classification.attck_technique_ids,
            "matched_rules": classification.matched_rules,
            "abuseipdb_confidence": enrichment.abuseipdb.confidence_score,
            "abuseipdb_categories": enrichment.abuseipdb.abuse_categories,
            "greynoise_classification": enrichment.greynoise.classification.value,
            "record_hash": record_hash,
            "source_log": log_path.name,
        })

    return corpus


if __name__ == "__main__":
    corpus = build_corpus()

    output_path = Path(__file__).parent / "corpus.json"
    output_path.write_text(json.dumps(corpus, indent=2), encoding="utf-8")

    print(f"Built corpus of {len(corpus)} records -> {output_path}")
    print()
    for r in corpus:
        print(f"  {r['session_id']}  |  {r['src_ip']:16s}  |  {r['attack_type']:26s}  |  {r['severity']:8s}  |  ATT&CK: {', '.join(r['attck_technique_ids'])}")
