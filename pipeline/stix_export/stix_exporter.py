"""
Aletheia — STIX 2.1 Export
Converts an EnrichedThreatRecord (or any record fetched from the
database / blockchain) into a STIX 2.1 Bundle, using the stix2
library (OASIS's reference implementation).

STIX (Structured Threat Information eXpression) is the industry
standard format for threat intelligence interchange — used by MISP,
OpenCTI, and most enterprise SIEM/SOAR platforms. Exporting records
in this format is what makes Aletheia's corpus usable by real-world
security tooling, not just its own dashboard.

Mapping from Aletheia's data model to STIX objects:
    SessionRecord.src_ip            -> Indicator (pattern matches the IP)
    ClassificationResult.attack_type -> Malware object
    ClassificationResult.attck_technique_ids -> Attack Pattern objects,
                                                 cross-referenced to MITRE ATT&CK
    ChainReference.record_hash      -> embedded as a custom property on the
                                        Indicator, for integrity verification
                                        (the whole point of Pillar 3)
    EnrichmentResult.abuseipdb/greynoise -> embedded as custom properties,
                                             since STIX has no first-class
                                             "reputation score" object type
    relationships                   -> Indicator "indicates" Malware,
                                        Malware "uses" each Attack Pattern

Usage:
    from stix_exporter import record_to_stix_bundle, db_row_to_stix_bundle

    bundle = record_to_stix_bundle(enriched_threat_record, record_hash)
    print(bundle.serialize(pretty=True))

    # Or straight from a database row (see pipeline/storage/db.py fetch_all_records()):
    bundle = db_row_to_stix_bundle(row)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from stix2 import (
    AttackPattern,
    Bundle,
    ExternalReference,
    Indicator,
    Malware,
    Relationship,
)

# ─────────────────────────────────────────────────────────────
# MITRE ATT&CK technique ID -> human-readable name
# (small local lookup, since full STIX ATT&CK bundles are huge;
#  this covers exactly the technique IDs Aletheia's classifier uses)
# ─────────────────────────────────────────────────────────────

ATTCK_TECHNIQUE_NAMES = {
    "T1110": "Brute Force",
    "T1082": "System Information Discovery",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1105": "Ingress Tool Transfer",
    "T1496": "Resource Hijacking",
    "T1071": "Application Layer Protocol",
    "T1584": "Compromise Infrastructure",
}

ATTACK_TYPE_LABELS = {
    "credential_brute_force": "Credential Brute Force",
    "reconnaissance": "Reconnaissance",
    "malware_deployment": "Malware Deployment",
    "cryptominer_installation": "Cryptominer Installation",
    "botnet_recruitment": "Botnet Recruitment",
    "unclassified": "Unclassified Activity",
}


def _attck_external_reference(technique_id: str) -> ExternalReference:
    """Builds the standard MITRE ATT&CK external reference for a technique ID."""
    base_id = technique_id.split(".")[0]  # T1059.004 -> T1059 for the URL
    return ExternalReference(
        source_name="mitre-attack",
        external_id=technique_id,
        url=f"https://attack.mitre.org/techniques/{base_id}/" + (
            technique_id.split(".")[1] + "/" if "." in technique_id else ""
        ),
    )


def _build_indicator(src_ip: str, record_hash: Optional[str], severity: str,
                      abuseipdb_score: Optional[int], greynoise_classification: Optional[str],
                      session_start: Optional[datetime] = None) -> Indicator:
    """
    The IP address, as a STIX Indicator with a proper pattern expression.
    Custom x_ fields carry Aletheia-specific data STIX has no native
    slot for (the verification hash, the enrichment scores).
    """
    valid_from = session_start or datetime.now(timezone.utc)

    custom_props = {}
    if record_hash:
        custom_props["x_aletheia_record_hash"] = record_hash
    if abuseipdb_score is not None:
        custom_props["x_aletheia_abuseipdb_score"] = abuseipdb_score
    if greynoise_classification:
        custom_props["x_aletheia_greynoise_classification"] = greynoise_classification

    return Indicator(
        name=f"Malicious activity from {src_ip}",
        description=f"Source IP observed by an Aletheia honeypot node, "
                     f"severity={severity}, cryptographically verified on-chain.",
        pattern=f"[ipv4-addr:value = '{src_ip}']",
        pattern_type="stix",
        valid_from=valid_from,
        indicator_types=["malicious-activity"],
        allow_custom=True,
        **custom_props,
    )


def _build_malware(attack_type: str) -> Malware:
    label = ATTACK_TYPE_LABELS.get(attack_type, attack_type)
    return Malware(
        name=label,
        description=f"Attack classified by Aletheia's rule-based engine as: {label}",
        is_family=False,
    )


def _build_attack_patterns(technique_ids: list[str]) -> list[AttackPattern]:
    patterns = []
    for tid in technique_ids:
        name = ATTCK_TECHNIQUE_NAMES.get(tid, tid)
        patterns.append(
            AttackPattern(
                name=name,
                external_references=[_attck_external_reference(tid)],
            )
        )
    return patterns


def build_stix_bundle(
    src_ip: str,
    attack_type: str,
    severity: str,
    attck_technique_ids: list[str],
    record_hash: Optional[str] = None,
    abuseipdb_score: Optional[int] = None,
    greynoise_classification: Optional[str] = None,
    session_start: Optional[datetime] = None,
) -> Bundle:
    """
    Core builder: takes plain values (not tied to any specific
    Aletheia internal type) and returns a complete STIX 2.1 Bundle —
    Indicator + Malware + Attack Patterns + the Relationships linking
    them, ready to serialize and hand to MISP/OpenCTI/any STIX
    consumer.
    """
    indicator = _build_indicator(
        src_ip=src_ip,
        record_hash=record_hash,
        severity=severity,
        abuseipdb_score=abuseipdb_score,
        greynoise_classification=greynoise_classification,
        session_start=session_start,
    )
    malware = _build_malware(attack_type)
    attack_patterns = _build_attack_patterns(attck_technique_ids)

    relationships = [
        Relationship(indicator, "indicates", malware),
    ]
    for pattern in attack_patterns:
        relationships.append(Relationship(malware, "uses", pattern))

    objects = [indicator, malware, *attack_patterns, *relationships]
    return Bundle(objects=objects, allow_custom=True)


# ─────────────────────────────────────────────────────────────
# Convenience wrappers for Aletheia's own data shapes
# ─────────────────────────────────────────────────────────────

def record_to_stix_bundle(record, record_hash: Optional[str] = None) -> Bundle:
    """
    Takes an EnrichedThreatRecord (pipeline/models/session_record.py)
    straight from the pipeline and converts it to a STIX bundle.
    """
    session = record.session
    classification = record.classification
    enrichment = record.enrichment

    return build_stix_bundle(
        src_ip=str(session.src_ip),
        attack_type=classification.attack_type.value,
        severity=classification.severity.value,
        attck_technique_ids=classification.attck_technique_ids,
        record_hash=record_hash,
        abuseipdb_score=enrichment.abuseipdb.confidence_score if enrichment.abuseipdb else None,
        greynoise_classification=enrichment.greynoise.classification.value if enrichment.greynoise else None,
        session_start=session.session_start,
    )


def db_row_to_stix_bundle(row: dict) -> Bundle:
    """
    Takes one row as returned by pipeline/storage/db.py's
    fetch_all_records() (which queries the enriched_threat_records
    view) and converts it to a STIX bundle. This is the path the
    dashboard's "export as STIX" button would actually use, since
    the dashboard reads from the database, not from in-memory
    pipeline objects.
    """
    attck_ids = row.get("attck_technique_ids") or []
    if isinstance(attck_ids, str):
        attck_ids = json.loads(attck_ids)

    return build_stix_bundle(
        src_ip=str(row["src_ip"]),
        attack_type=row["attack_type"],
        severity=row["severity"],
        attck_technique_ids=attck_ids,
        record_hash=row.get("record_hash"),
        abuseipdb_score=row.get("abuseipdb_confidence_score"),
        greynoise_classification=row.get("greynoise_classification"),
        session_start=row.get("session_start"),
    )


def bundle_to_json(bundle: Bundle, pretty: bool = True) -> str:
    return bundle.serialize(pretty=pretty)


if __name__ == "__main__":
    import argparse
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent / "storage"))

    parser = argparse.ArgumentParser(
        description="Export Aletheia threat records as a STIX 2.1 bundle"
    )
    parser.add_argument(
        "--session-id", default=None,
        help="Export only this session_id (default: export every record in the database)",
    )
    parser.add_argument(
        "--output", default=None,
        help="Write the bundle to this file instead of printing it",
    )
    args = parser.parse_args()

    from db import fetch_all_records

    rows = fetch_all_records()
    if args.session_id:
        rows = [r for r in rows if r["session_id"] == args.session_id]
        if not rows:
            print(f"No record found with session_id={args.session_id}")
            sys.exit(1)

    if not rows:
        print("No records in the database to export.")
        sys.exit(0)

    # One combined bundle covering every matched record, since a STIX
    # Bundle is just a container — this is the natural shape for
    # "export my whole corpus" or "export everything matching a filter."
    all_objects = []
    for row in rows:
        bundle = db_row_to_stix_bundle(row)
        all_objects.extend(bundle.objects)

    combined = Bundle(objects=all_objects, allow_custom=True)
    output = bundle_to_json(combined)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Exported {len(rows)} record(s) ({len(all_objects)} STIX objects) to {args.output}")
    else:
        print(output)
