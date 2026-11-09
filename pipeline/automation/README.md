# Automated log ingestion — deployment

Replaces the manual "copy the Cowrie log off the node, split it, run the
pipeline by hand" step with something that runs unattended, incrementally
(doesn't rescan the whole log every time), on each of the 3 federation
nodes.

**This has been tested for real** (not just written): against a real
local Postgres instance with the actual `pipeline/models/schema.sql`
applied, feeding a synthetic incrementally-growing log across multiple
runs — including a session deliberately left "open" (no closing event)
in one run that only got flushed into the DB once its closing event
showed up in a later run, with correct byte-offset tracking (no
re-scanning already-processed log lines) and a clean no-op on a repeat
run with nothing new. See the conversation this came from for the full
run output if you want to see it.

## What it does

`auto_ingest.py` is the real logic: incremental byte-offset tracking
into the Cowrie JSON log, buffering in-progress sessions across runs,
and — once a session's `cowrie.session.closed` event shows up — writing
that session to its own file and running it through the project's real
pipeline (`run_full_pipeline.py`): reconstruct → classify → enrich →
hash → save to Postgres. Blockchain submission is deliberately left
off for now (`--skip-chain`) — that gets wired up in its own phase,
once wallets/contract deployment are done.

## Deploying to each of your 3 nodes

1. Get the repo (or at least `pipeline/`) onto each node, e.g. at
   `/opt/aletheia`.
2. Make sure `.env` exists at the repo root on that node with the
   `ALETHEIA_DB_*` variables pointing at your (presumably central)
   Postgres instance — same as `pipeline/storage/db.py` already expects.
3. `pip install -r dashboard/backend/requirements.txt` (or just
   `pg8000 python-dotenv pydantic` — `auto_ingest.py` itself only needs
   the same deps `run_full_pipeline.py` already needs).
4. Pick cron or systemd:

   **Cron** (simpler):
   ```
   */5 * * * * NODE_ID=node-blr-01 COWRIE_LOG_PATH=/home/cowrie/cowrie/var/log/cowrie/cowrie.json ALETHEIA_REPO_ROOT=/opt/aletheia /bin/bash /opt/aletheia/pipeline/automation/run_auto_ingest.sh
   ```
   (edit `NODE_ID`/`COWRIE_LOG_PATH` per node — each of the 3 nodes
   needs its own distinct `NODE_ID`)

   **systemd timer** (better logs/status, auto-restarts on boot):
   ```bash
   sudo cp aletheia-ingest.service aletheia-ingest.timer /etc/systemd/system/
   sudo systemctl edit aletheia-ingest.service   # set NODE_ID/COWRIE_LOG_PATH/ALETHEIA_REPO_ROOT for THIS node
   sudo systemctl daemon-reload
   sudo systemctl enable --now aletheia-ingest.timer
   systemctl status aletheia-ingest.timer
   journalctl -u aletheia-ingest.service -f       # watch it run
   ```

5. Check it's working:
   ```
   tail -f pipeline/automation/auto_ingest_cron.log
   ```
   or query the DB directly:
   ```sql
   SELECT node_id, count(*) FROM sessions GROUP BY node_id;
   ```

## State files

`pipeline/automation/.auto_ingest_state_<node_id>.json` — one per node,
created automatically. Holds the byte offset into that node's Cowrie
log and any sessions still "open" (no closing event seen yet). Safe to
delete if you ever want to force a full rescan from the start of the
log — slower, but harmless, since `run_full_pipeline.py` already skips
sessions already saved to the DB.

## 5-minute interval

Chosen as a reasonable default (frequent enough that an attacker
session shows up in the dashboard within minutes, not hours; infrequent
enough not to hammer the DB with near-empty runs). Change
`OnUnitActiveSec=` in the timer, or the cron schedule, if you want
something different.
