"""
Aletheia — Enrichment Module
Pipeline: Pillar 2 (The Brain), Stage 3 → Stage 4

Enriches a SessionRecord's source IP with external threat
intelligence context: AbuseIPDB (abuse confidence, report history)
and GreyNoise (mass-scanner noise vs targeted-actor classification).

Real vs mocked, decided independently per service, at call time:
  - If ABUSEIPDB_API_KEY is set (in .env at the repo root, same
    pattern as pipeline/storage/db.py's DB credentials), AbuseIPDB
    lookups are REAL live API calls.
  - If GREYNOISE_API_KEY is set, same for GreyNoise.
  - Whichever key is missing, that service silently stays on its
    mock — so this keeps working with zero config (demo/offline),
    and switches on piecemeal as keys become available, without
    code changes.

IMPORTANT, read before relying on this in the report: the real-API
code paths below were written from AbuseIPDB's v2 /check and
GreyNoise's v3 /community/<ip> documented response shapes, but could
NOT be exercised against the live APIs while writing this (no key
was available in that environment) — Ishika, the first time you run
this with real keys, actually look at a few real responses (print
them, or check pipeline/enrichment's __main__ output) before trusting
the numbers in anything you submit. The GreyNoise classification
mapping in particular is an interpretation, not a direct field
match — see the comment on _fetch_greynoise_real for why.

Caching design note: enrichment is looked up by src_ip and cached
(see schema.sql's enrichments table + idx_enrichments_src_ip) so
repeat sessions from the same attacker IP don't re-query external
APIs. This matters a lot for real API calls specifically: both
AbuseIPDB's and GreyNoise's free tiers have a daily request cap, and
re-processing the full historical corpus (many sessions can share
the same src_ip) would burn through that cap fast without caching.
This module's in-memory cache (process-lifetime only) demonstrates
the behavior; auto_ingest.py's per-run process means this cache
resets every run — the real long-term cache is the `enrichments`
table itself (schema.sql), which a later pass should check before
calling either `_fetch_*_real` function at all.
"""

from __future__ import annotations

import hashlib
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent.parent / ".env")

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
GREYNOISE_API_KEY = os.environ.get("GREYNOISE_API_KEY")

logger = logging.getLogger("aletheia.enrichment")

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

# AbuseIPDB's fixed category ID -> friendly label, for the IDs this
# project is likely to actually see from honeypot traffic (the full
# official list has ~23 categories; these are the common ones).
# Source: AbuseIPDB's published category list at the time this was
# written — if a report comes back with a category ID not in this
# dict, it's shown as "category-<id>" rather than silently dropped.
ABUSEIPDB_CATEGORY_LABELS = {
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


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


def _fetch_abuseipdb_real(src_ip: str) -> AbuseIPDBResult:
    """
    REAL AbuseIPDB v2 /check lookup. Falls back to the mock (with a
    logged warning) on any network error, non-200 response, or
    malformed payload, rather than crashing the whole pipeline run
    over one bad lookup — this matters because auto_ingest.py calls
    this once per session, unattended, on a schedule.
    """
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": src_ip, "maxAgeInDays": 90, "verbose": "true"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()["data"]

        categories = set()
        for report in data.get("reports", []):
            for cat_id in report.get("categories", []):
                categories.add(ABUSEIPDB_CATEGORY_LABELS.get(cat_id, f"category-{cat_id}"))

        return AbuseIPDBResult(
            confidence_score=data["abuseConfidenceScore"],
            abuse_categories=sorted(categories),
            total_reports=data.get("totalReports", 0),
            isp=data.get("isp"),
            country_code=data.get("countryCode"),
        )
    except Exception as exc:  # noqa: BLE001 — any failure here must not take down the pipeline
        logger.warning("AbuseIPDB lookup failed for %s (%s) — falling back to mock for this IP.", src_ip, exc)
        return _fetch_abuseipdb_mock(src_ip)


def _fetch_greynoise_real(src_ip: str) -> GreyNoiseResult:
    """
    REAL GreyNoise v3 /community/<ip> lookup.

    Mapping note: GreyNoise's Community API doesn't return a 3-way
    noise/targeted/unknown field matching our internal
    GreyNoiseClassification enum directly — it returns a boolean
    `noise` (seen doing broad/opportunistic internet-wide scanning)
    plus its own `classification` (benign/malicious/unknown, from
    GreyNoise's own risk judgment, not ours). This bridges the two:
        noise=true                        -> our "noise"
        noise=false, classification=malicious -> our "targeted"
            (not mass-scanner traffic, but still flagged malicious —
             treated as a more deliberate signal; this is this
             project's interpretation, not a GreyNoise-native field)
        everything else (incl. IP not in GreyNoise's dataset at all)
                                           -> our "unknown"
    Verify this mapping makes sense once you have real responses to
    look at — see the module docstring.
    """
    try:
        resp = requests.get(
            f"https://api.greynoise.io/v3/community/{src_ip}",
            headers={"key": GREYNOISE_API_KEY, "Accept": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        is_noise = bool(data.get("noise"))
        gn_classification = data.get("classification", "unknown")

        if is_noise:
            classification = GreyNoiseClassification.noise
        elif gn_classification == "malicious":
            classification = GreyNoiseClassification.targeted
        else:
            classification = GreyNoiseClassification.unknown

        last_seen_raw = data.get("last_seen")  # GreyNoise gives "YYYY-MM-DD" or None
        last_seen = None
        if last_seen_raw:
            try:
                last_seen = datetime.strptime(last_seen_raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                logger.warning("Unparseable GreyNoise last_seen %r for %s", last_seen_raw, src_ip)

        return GreyNoiseResult(
            classification=classification,
            actor=data.get("name"),  # best-effort; Community API rarely names an actor
            last_seen=last_seen,
        )
    except Exception as exc:  # noqa: BLE001 — same reasoning as the AbuseIPDB fallback above
        logger.warning("GreyNoise lookup failed for %s (%s) — falling back to mock for this IP.", src_ip, exc)
        return _fetch_greynoise_mock(src_ip)


def enrich_session(session: SessionRecord) -> EnrichmentResult:
    """
    Enriches a session's source IP via (mocked) AbuseIPDB + GreyNoise.
    Checks the in-memory cache first — a real deployment would check
    the enrichments table (keyed on src_ip) before hitting external APIs.
    """
    src_ip = str(session.src_ip)

    if src_ip in _ENRICHMENT_CACHE:
        return _ENRICHMENT_CACHE[src_ip]

    abuseipdb = _fetch_abuseipdb_real(src_ip) if ABUSEIPDB_API_KEY else _fetch_abuseipdb_mock(src_ip)
    greynoise = _fetch_greynoise_real(src_ip) if GREYNOISE_API_KEY else _fetch_greynoise_mock(src_ip)

    result = EnrichmentResult(
        abuseipdb=abuseipdb,
        greynoise=greynoise,
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

    abuseipdb_mode = "REAL" if ABUSEIPDB_API_KEY else "mocked (ABUSEIPDB_API_KEY not set)"
    greynoise_mode = "REAL" if GREYNOISE_API_KEY else "mocked (GREYNOISE_API_KEY not set)"
    print(f"SessionRecord → EnrichmentResult (AbuseIPDB: {abuseipdb_mode}, GreyNoise: {greynoise_mode})")
    print("=" * 60)
    print(f"Source IP:               {session.src_ip}")
    print(f"AbuseIPDB confidence:    {enrichment.abuseipdb.confidence_score}/100")
    print(f"AbuseIPDB categories:    {enrichment.abuseipdb.abuse_categories}")
    print(f"AbuseIPDB total reports: {enrichment.abuseipdb.total_reports}")
    print(f"GreyNoise classification:{enrichment.greynoise.classification.value}")