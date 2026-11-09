# Aletheia Dashboard

A FastAPI backend + React (Vite, Recharts, react-router-dom) frontend for
the Aletheia honeypot threat-intel pipeline. Dark theme, 3 pages:
Overview (stat cards + charts), Sessions (filterable table), Nodes.

## How the data source works (important)

The backend (`dashboard/backend/data_source.py`) tries the **real**
Postgres database first, using the exact same env vars as
`pipeline/storage/db.py`:

```
ALETHEIA_DB_HOST
ALETHEIA_DB_PORT
ALETHEIA_DB_NAME
ALETHEIA_DB_USER
ALETHEIA_DB_PASSWORD
```

If those aren't set, or the DB isn't reachable, it falls back to the
small sample corpus already in the repo (`pipeline/corpus.json` — 5
sample sessions) so the dashboard still runs. **Every API response
includes `data_source`**, and the frontend shows a banner ("Live data"
in green vs "Sample data" in amber) so it's never ambiguous which one
you're looking at — this was built in this sandbox, which has no
tunnel to your real DB, so what you'll see here by default is the
sample-data banner. Point it at your real DB locally (set the env vars
above, e.g. in `.env` at the repo root like the pipeline scripts
already do) and it'll show the real 12,000+ session corpus with zero
code changes.

## Running it

Backend:
```bash
cd dashboard/backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Frontend:
```bash
cd dashboard/frontend
npm install
npm run dev
```
Then open the Vite dev server URL (usually http://localhost:5173).

If your backend isn't on `http://localhost:8000`, set `VITE_API_BASE`
(e.g. in `dashboard/frontend/.env`: `VITE_API_BASE=http://localhost:8000`).

## Endpoints

- `GET /api/health` — data source + record count
- `GET /api/sessions?node_id=&attack_type=&severity=&limit=` — session list
- `GET /api/stats/summary` — totals, unclassified %, by severity, by node
- `GET /api/stats/attack-types` — overall + per-node attack-type counts
- `GET /api/nodes` — node list with friendly labels + session counts
- `GET /api/stats/corroboration` — on-chain submission/corroboration
  counts (reports real zeros — not a bug — until you actually run the
  blockchain submission steps in `blockchain_verification_checklist.md`)

## Node labels

`dashboard/backend/main.py` has a `NODE_LABELS` dict mapping raw
`node_id` values to friendly display names. It currently covers the
sample corpus's IDs (`node-blr-01`/`02`) and a guess at your real 3
node IDs (`oracle-hyderabad`, `aws-us-east`, `gcp-frankfurt`) — edit
that dict to match whatever `node_id` values your real sessions table
actually uses; anything not listed just falls back to showing the raw
ID, so nothing breaks either way.

## Verified working

Both built and run for real in the sandbox that produced this: backend
exercised against all 6 endpoints via curl, frontend built with `vite
build` (no errors) and screenshotted via headless Chromium against the
live backend — Overview, Sessions and Nodes all render correctly with
no console errors.
