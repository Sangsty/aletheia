"""
Aletheia dashboard — data source layer.

Tries the REAL Postgres database first (same connection code/env vars as
pipeline/storage/db.py — ALETHEIA_DB_HOST/PORT/NAME/USER/PASSWORD). If that
fails (no DB reachable, no password set — the normal case when this runs
somewhere without a tunnel to the real DB), it falls back to the local
sample corpus shipped in the repo (pipeline/corpus.json), so the dashboard
is always runnable, and logs clearly which source is active.

This file does NOT fabricate data: the fallback corpus is the same
small, explicitly-labeled sample corpus already in the repo, and the API
layer marks every response with which source produced it.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger("aletheia.dashboard")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SAMPLE_CORPUS_PATH = REPO_ROOT / "pipeline" / "corpus.json"

sys.path.insert(0, str(REPO_ROOT / "pipeline" / "storage"))
sys.path.insert(0, str(REPO_ROOT / "pipeline" / "models"))


def _normalize_record(row: dict, source: str) -> dict:
    """
    Maps either a real Postgres `enriched_threat_records` view row, or a
    sample-corpus entry, onto one common shape the API/frontend use.
    """
    if source == "postgres":
        return {
            "session_id": row.get("session_id"),
            "node_id": row.get("node_id"),
            "protocol": row.get("protocol"),
            "src_ip": str(row.get("src_ip")) if row.get("src_ip") is not None else None,
            "duration_seconds": row.get("duration_seconds"),
            "attack_type": row.get("attack_type") or "unclassified",
            "severity": row.get("severity"),
            "attck_technique_ids": row.get("attck_technique_ids") or [],
            "abuseipdb_confidence": row.get("abuseipdb_confidence_score"),
            "greynoise_classification": row.get("greynoise_classification"),
            "record_hash": row.get("record_hash"),
            "tx_hash": row.get("tx_hash"),
            "block_number": row.get("block_number"),
            "corroboration_count": row.get("corroboration_count") or 0,
        }
    # sample corpus shape (pipeline/corpus.json)
    return {
        "session_id": row.get("session_id"),
        "node_id": row.get("node_id"),
        "protocol": row.get("protocol"),
        "src_ip": row.get("src_ip"),
        "duration_seconds": row.get("duration_seconds"),
        "attack_type": row.get("attack_type") or "unclassified",
        "severity": row.get("severity"),
        "attck_technique_ids": row.get("attck_technique_ids") or [],
        "abuseipdb_confidence": row.get("abuseipdb_confidence"),
        "greynoise_classification": row.get("greynoise_classification"),
        "record_hash": row.get("record_hash"),
        "tx_hash": None,
        "block_number": None,
        "corroboration_count": 0,
    }


class DataSource:
    """Loaded once at FastAPI startup; exposes .records and .source_name."""

    def __init__(self) -> None:
        self.records: list[dict] = []
        self.source_name: str = "unknown"
        self._load()

    def _load(self) -> None:
        pg_rows = self._try_postgres()
        if pg_rows is not None:
            self.records = [_normalize_record(r, "postgres") for r in pg_rows]
            self.source_name = "postgres (real data)"
            logger.info("Dashboard data source: REAL Postgres DB (%d records)", len(self.records))
            return

        self.records = self._load_sample_corpus()
        self.source_name = f"sample corpus ({SAMPLE_CORPUS_PATH.name})"
        logger.warning(
            "Dashboard data source: FALLBACK sample corpus (%d records) — "
            "set ALETHEIA_DB_HOST/PORT/NAME/USER/PASSWORD to use the real DB.",
            len(self.records),
        )

    @staticmethod
    def _try_postgres() -> Optional[list[dict]]:
        if not os.environ.get("ALETHEIA_DB_PASSWORD"):
            return None
        try:
            from db import fetch_all_records  # type: ignore
            return fetch_all_records()
        except Exception as exc:  # noqa: BLE001 - any DB/connection failure -> fallback
            logger.warning("Could not reach real Postgres DB (%s) — falling back to sample data.", exc)
            return None

    @staticmethod
    def _load_sample_corpus() -> list[dict]:
        if not SAMPLE_CORPUS_PATH.exists():
            return []
        with open(SAMPLE_CORPUS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [_normalize_record(r, "sample") for r in data]


_instance: Optional[DataSource] = None


def get_data_source() -> DataSource:
    global _instance
    if _instance is None:
        _instance = DataSource()
    return _instance
