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

import logging
from collections import Counter, defaultdict
from typing import Optional

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

from data_source import get_data_source

logging.basicConfig(level=logging.INFO)

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
    "oracle-hyderabad": "Node A (Oracle / Hyderabad)",
    "aws-us-east": "Node B (AWS / US East)",
    "gcp-frankfurt": "Node C (GCP / Frankfurt)",
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
    return {
        "data_source": ds.source_name,
        "nodes": [
            {"node_id": node_id, "node_label": friendly_node(node_id), "session_count": count}
            for node_id, count in counts.items()
        ],
    }


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
