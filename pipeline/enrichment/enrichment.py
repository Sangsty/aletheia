"""
Aletheia — Enrichment Module
Pipeline: Pillar 2 (The Brain), Stage 3 → Stage 4

Enriches a SessionRecord's source IP with external threat
intelligence context: AbuseIPDB (abuse confidence, report history)
and GreyNoise (mass-scanner noise vs targeted-actor classification).

IMPORTANT — current state: this module uses MOCKED/SIMULATED
responses, not live API calls. Real AbuseIPDB/GreyNoise integration
requires API keys and network access, which come later. The mock
layer is deliberately structured so swapping in real HTTP calls
later only touches the two `_fetch_*` functions below — nothing
else in the pipeline changes.

Caching design note: enrichment is looked up by src_ip and cached
(see schema.sql's enrichments table + idx_enrichments_src_ip) so
repeat sessions from the same attacker IP don't re-query external
APIs. This module includes a simple in-memory cache to demonstrate
that behavior even without a live DB.
"""

from __future__ import annotations

import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "models"))
from session_record import (
    SessionRecord,
    EnrichmentResult,
    AbuseIPDBResult,
    GreyNoiseResult,
    GreyNoiseClassification,
)

# Simple in-memory cache: src_ip -> EnrichmentResult
# Mirrors the DB-level caching described in schema.sql; swapping this
# for a real Postgres-backed cache later doesn't change the interface.
_ENRICHMENT_CACHE: dict[str, EnrichmentResult] = {}


def _deterministic_seed(ip: str) -> int:
    """
    Turns an IP into a stable integer seed so mock responses are
    consistent across runs for the same IP (not random each time),
    which makes the demo reproducible.
    """
    return int(hashlib.sha256(ip.encode()).hexdigest(), 16) % (10 ** 6)


def _fetch_abuseipdb_mock(src_ip: str) -> AbuseIPDBResult:
    """
    MOCK — simulates an AbuseIPDB lookup response.
    Replace with a real `requests.get("https://api.abuseipdb.com/...")`
    call once an API key is available; the return type stays identical.
    """
    seed = _deterministic_seed(src_ip)

    # Simulate "known bad" IPs scoring high, others scoring low —
    # deterministic per IP so results are stable across demo runs.
    confidence_score = 60 + (seed % 40)  # lands in 60-99 range for demo IPs

    return AbuseIPDBResult(
        confidence_score=confidence_score,
        abuse_categories=["SSH", "Brute-Force"] if confidence_score > 75 else ["Port Scan"],
        total_reports=seed % 200,
        isp="Simulated ISP / mock response — replace with live AbuseIPDB data",
        country_code="RU" if seed % 3 == 0 else ("CN" if seed % 3 == 1 else "NL"),
    )


def _fetch_greynoise_mock(src_ip: str) -> GreyNoiseResult:
    """
    MOCK — simulates a GreyNoise community API lookup.
    Replace with a real GreyNoise API call later; return type unchanged.
    """
    seed = _deterministic_seed(src_ip)

    if seed % 5 == 0:
        classification = GreyNoiseClassification.targeted
        actor = "unknown-targeted-actor"
    elif seed % 5 in (1, 2, 3):
        classification = GreyNoiseClassification.noise
        actor = None
    else:
        classification = GreyNoiseClassification.unknown
        actor = None

    return GreyNoiseResult(
        classification=classification,
        actor=actor,
        last_seen=datetime.now(timezone.utc),
    )


def enrich_session(session: SessionRecord) -> EnrichmentResult:
    """
    Enriches a session's source IP via (mocked) AbuseIPDB + GreyNoise.
    Checks the in-memory cache first — a real deployment would check
    the enrichments table (keyed on src_ip) before hitting external APIs.
    """
    src_ip = str(session.src_ip)

    if src_ip in _ENRICHMENT_CACHE:
        return _ENRICHMENT_CACHE[src_ip]

    result = EnrichmentResult(
        abuseipdb=_fetch_abuseipdb_mock(src_ip),
        greynoise=_fetch_greynoise_mock(src_ip),
    )

    _ENRICHMENT_CACHE[src_ip] = result
    return result


if __name__ == "__main__":
    import json

    sys.path.insert(0, str(Path(__file__).parent.parent / "ingestion"))
    from session_reconstructor import reconstruct_session

    sample_path = Path(__file__).parent.parent / "ingestion" / "sample_cowrie_session.json"

    events = []
    with open(sample_path) as f:
        for line in f:
            events.append(json.loads(line))

    session = reconstruct_session(events, node_id="node-blr-01")
    enrichment = enrich_session(session)

    print("SessionRecord → EnrichmentResult (MOCKED — no live API calls)")
    print("=" * 60)
    print(f"Source IP:               {session.src_ip}")
    print(f"AbuseIPDB confidence:    {enrichment.abuseipdb.confidence_score}/100")
    print(f"AbuseIPDB categories:    {enrichment.abuseipdb.abuse_categories}")
    print(f"AbuseIPDB total reports: {enrichment.abuseipdb.total_reports}")
    print(f"GreyNoise classification:{enrichment.greynoise.classification.value}")
