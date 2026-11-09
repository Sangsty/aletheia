#!/usr/bin/env bash
# Wrapper for auto_ingest.py, meant to be run on a schedule (cron or a
# systemd timer — see aletheia-ingest.service / aletheia-ingest.timer
# in this directory) directly ON each of the 3 federation nodes.
#
# Deploy this + auto_ingest.py + the rest of pipeline/ to each node,
# then fill in the 3 variables below for that node, or override them
# via environment variables of the same name before calling this script
# (cron/systemd can set env vars per-unit without editing this file).
set -euo pipefail

# ---- Per-node config (edit these 3, or set as env vars) ----
NODE_ID="${NODE_ID:-node-blr-01}"
COWRIE_LOG_PATH="${COWRIE_LOG_PATH:-/home/cowrie/cowrie/var/log/cowrie/cowrie.json}"
ALETHEIA_REPO_ROOT="${ALETHEIA_REPO_ROOT:-/opt/aletheia}"

# ---- Fixed paths (shouldn't need editing) ----
PIPELINE_DIR="$ALETHEIA_REPO_ROOT/pipeline"
LOG_FILE="$ALETHEIA_REPO_ROOT/pipeline/automation/auto_ingest_cron.log"

cd "$PIPELINE_DIR"

# DB credentials come from .env at the repo root, loaded by db.py itself
# (python-dotenv) — nothing to source here.

{
  echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) — node=$NODE_ID ==="
  python3 automation/auto_ingest.py \
    --log-path "$COWRIE_LOG_PATH" \
    --node-id "$NODE_ID" \
    --skip-chain
} >> "$LOG_FILE" 2>&1
