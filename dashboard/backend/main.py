"""
Aletheia dashboard — FastAPI backend.

Serves session/classification/enrichment/corroboration data to the React
frontend. Reads from the real Postgres DB when reachable (see
data_source.py), otherwise from the repo's sample corpus — either way,
every endpoint response says which source it came from, so the frontend
(and anyone reading a screenshot) can tell real data from the sample.

Run:
    uvicorn main:app --reload --port 8000
"""
from __future__ import annotations

import json
import logging
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from data_source import get_data_source

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aletheia.dashboard.main")

app = FastAPI(title="Aletheia Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # dev-only dashboard; tighten before any real deployment
    allow_methods=["*"],
    allow_headers=["*"],
)

# Friendly display names for known federation node IDs. Extend this with
# your real node IDs if they differ (e.g. the Oracle/Hyderabad, AWS/US
# East, GCP/Frankfurt nodes) — anything not listed here just falls back
# to showing the raw node_id, so nothing breaks if a node isn't mapped.
NODE_LABELS = {
    "node-blr-01": "Node A (sample)",
    "node-blr-02": "Node B (sample)",
    "node-blr-03": "Node C (sample)",
    "node-A": "Node A (Oracle / Hyderabad)",
    "node-B": "Node B (AWS / US East)",
    "node-C": "Node C (GCP / Frankfurt)",
}

# Geographic/provider metadata for the Nodes page and the About page's
# deployment cards.
#
# Keys are the real node_id values as stored in the sessions table —
# confirmed from the live dashboard to be "node-A"/"node-B"/"node-C",
# not the "oracle-hyderabad"/"aws-us-east"/"gcp-frankfurt" style names
# used in earlier project notes/commit messages.
NODE_METADATA = {
    "node-A": {
        "provider": "Oracle Cloud Infrastructure",
        "region": "Hyderabad, India",
        "lat": 17.385,
        "lon": 78.4867,
    },
    "node-B": {
        "provider": "Amazon Web Services",
        "region": "N. Virginia, US (us-east-1)",
        "lat": 39.0438,
        "lon": -77.4874,
    },
    "node-C": {
        "provider": "Google Cloud Platform",
        "region": "Frankfurt, Germany (europe-west3)",
        "lat": 50.1109,
        "lon": 8.6821,
    },
}


def friendly_node(node_id: Optional[str]) -> str:
    if not node_id:
        return "unknown"
    return NODE_LABELS.get(node_id, node_id)


@app.get("/api/health")
def health():
    ds = get_data_source()
    return {"status": "ok", "data_source": ds.source_name, "record_count": len(ds.records)}


@app.get("/api/sessions")
def list_sessions(
    node_id: Optional[str] = None,
    attack_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(default=200, le=2000),
):
    ds = get_data_source()
    rows = ds.records
    if node_id:
        rows = [r for r in rows if r["node_id"] == node_id]
    if attack_type:
        rows = [r for r in rows if r["attack_type"] == attack_type]
    if severity:
        rows = [r for r in rows if r["severity"] == severity]

    rows = rows[:limit]
    out = []
    for r in rows:
        out.append({**r, "node_label": friendly_node(r["node_id"])})

    return {"data_source": ds.source_name, "count": len(out), "sessions": out}


@app.get("/api/stats/summary")
def stats_summary():
    ds = get_data_source()
    rows = ds.records
    total = len(rows)
    unclassified = sum(1 for r in rows if (r["attack_type"] or "unclassified") == "unclassified")
    by_severity = Counter(r["severity"] or "unknown" for r in rows)
    by_node = Counter(friendly_node(r["node_id"]) for r in rows)

    return {
        "data_source": ds.source_name,
        "total_sessions": total,
        "unclassified_count": unclassified,
        "unclassified_pct": round((unclassified / total * 100), 2) if total else 0.0,
        "by_severity": dict(by_severity),
        "by_node": dict(by_node),
    }


@app.get("/api/stats/attack-types")
def stats_attack_types():
    """
    Attack-type counts, both overall and broken down per node (keyed by
    friendly node label, not the raw node_id, so the frontend's legend
    doesn't have to know about node-ID formatting).
    """
    ds = get_data_source()
    rows = ds.records

    overall = Counter(r["attack_type"] or "unclassified" for r in rows)
    by_node: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        label = friendly_node(r["node_id"])
        by_node[label][r["attack_type"] or "unclassified"] += 1

    return {
        "data_source": ds.source_name,
        "overall": dict(overall),
        "by_node": {node: dict(counts) for node, counts in by_node.items()},
    }


@app.get("/api/nodes")
def list_nodes():
    ds = get_data_source()
    rows = ds.records
    counts = Counter(r["node_id"] for r in rows)
    # Sorted by node_id so the Nodes/About pages always show A, B, C in
    # order — unsorted, this came out in whatever order each node_id
    # first appeared in the DB query (ORDER BY session_start DESC),
    # which is session-time order, not node order.
    return {
        "data_source": ds.source_name,
        "nodes": [
            {
                "node_id": node_id,
                "node_label": friendly_node(node_id),
                "session_count": counts[node_id],
                **NODE_METADATA.get(node_id, {}),
            }
            for node_id in sorted(counts.keys())
        ],
    }


# ─────────────────────────────────────────────────────────────
# STIX 2.1 export
# ─────────────────────────────────────────────────────────────

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "pipeline" / "stix_export"))
from stix_exporter import build_stix_bundle, bundle_to_json  # noqa: E402
from stix2 import Bundle  # noqa: E402


@app.get("/api/export/stix")
def export_stix(
    node_id: Optional[str] = None,
    attack_type: Optional[str] = None,
    severity: Optional[str] = None,
    session_id: Optional[str] = None,
    pretty: bool = False,
):
    """
    Exports the current (optionally filtered) set of records as one
    combined STIX 2.1 Bundle — the format MISP/OpenCTI/most SIEM and
    SOAR platforms ingest. Reuses pipeline/stix_export/stix_exporter.py's
    own build_stix_bundle()/bundle_to_json(), so this is exactly the
    same conversion logic already used (and documented) there — not a
    second, drifting implementation.

    pretty defaults to False on purpose: stix_exporter.py's own
    bundle_to_json() docstring measured pretty-printing as dramatically
    slower at real-corpus scale (see that file) — fine for a single
    session, bad for an "export everything" click.
    """
    ds = get_data_source()
    rows = ds.records
    if node_id:
        rows = [r for r in rows if r["node_id"] == node_id]
    if attack_type:
        rows = [r for r in rows if r["attack_type"] == attack_type]
    if severity:
        rows = [r for r in rows if r["severity"] == severity]
    if session_id:
        rows = [r for r in rows if r["session_id"] == session_id]

    if not rows:
        return Response(
            content=json.dumps({"error": "No records match these filters."}),
            media_type="application/json",
            status_code=404,
        )

    all_objects = []
    skipped = 0
    for row in rows:
        # One malformed row must not take down a 16,000-record export —
        # log it, skip it, keep going. Previously a single bad row threw
        # here and the whole request failed with nothing downloaded.
        try:
            bundle = build_stix_bundle(
                src_ip=row.get("src_ip") or "0.0.0.0",
                attack_type=row.get("attack_type") or "unclassified",
                severity=row.get("severity") or "unknown",
                attck_technique_ids=row.get("attck_technique_ids") or [],
                record_hash=row.get("record_hash"),
                abuseipdb_score=row.get("abuseipdb_confidence"),
                greynoise_classification=row.get("greynoise_classification"),
            )
            all_objects.extend(bundle.objects)
        except Exception as exc:  # noqa: BLE001 — isolate one bad row, not the whole export
            skipped += 1
            logger.warning(
                "Skipping session_id=%s in STIX export — build_stix_bundle failed: %s",
                row.get("session_id"), exc,
            )

    if not all_objects:
        return Response(
            content=json.dumps({"error": f"All {len(rows)} matched records failed to convert to STIX."}),
            media_type="application/json",
            status_code=500,
        )

    combined = Bundle(objects=all_objects, allow_custom=True)
    body = bundle_to_json(combined, pretty=pretty)

    if skipped:
        logger.warning("STIX export: %d/%d records skipped due to conversion errors.", skipped, len(rows))

    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="aletheia_stix_export_{len(rows) - skipped}records.json"'
            ),
            "X-Aletheia-Skipped-Records": str(skipped),
        },
    )


@app.get("/api/stats/corroboration")
def stats_corroboration():
    """
    Real on-chain corroboration status. Deliberately reports real zeros
    rather than fabricating activity when nothing has actually been
    submitted/corroborated on-chain yet (see blockchain_verification_checklist.md
    for the steps to make this non-zero for real).
    """
    ds = get_data_source()
    rows = ds.records
    with_tx = [r for r in rows if r.get("tx_hash")]
    total_corroborations = sum(r.get("corroboration_count") or 0 for r in rows)

    return {
        "data_source": ds.source_name,
        "records_submitted_onchain": len(with_tx),
        "total_corroborations": total_corroborations,
        "note": (
            "0 here means no real on-chain submission has happened yet from "
            "this data source — not a display bug. See "
            "blockchain_verification_checklist.md to make this real."
        ),
    }
