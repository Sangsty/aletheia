
**Key design point:** only the SHA-256 hash of a classified record goes on-chain — never raw attacker IPs or other personal data. The blockchain proves a record existed and wasn't altered; the full enriched data stays in each node's own off-chain Postgres store.

## Components

| Pillar | What it does |
|---|---|
| **Pillar 1 — The Senses** | Cowrie honeypots on three independent clouds, de-fingerprinted from stock defaults (custom SSH banner + hostname) to reduce early attacker disengagement |
| **Pillar 2 — The Brain** | `pipeline/` — reconstructs sessions from raw Cowrie JSON logs, classifies them with a rule-based engine (`pipeline/classifier/rule_classifier.py`) against MITRE ATT&CK techniques, enriches with AbuseIPDB/GreyNoise-style threat context, and stores the result in PostgreSQL |
| **Pillar 3 — The Ledger** | `blockchain/` — Solidity smart contracts deployed to the Polygon Amoy public testnet; nodes submit record hashes and corroborate records independently discovered by other nodes |

## Tech stack

- **Honeypot:** [Cowrie](https://github.com/cowrie/cowrie) (SSH/Telnet emulation), Docker
- **Pipeline:** Python, [pydantic](https://docs.pydantic.dev/) data models, [pg8000](https://github.com/tlocke/pg8000) (pure-Python Postgres driver — avoids compiled-dependency issues on locked-down Windows dev machines)
- **Storage:** PostgreSQL
- **Blockchain:** Solidity, Polygon Amoy testnet (PoA)
- **Infrastructure:** Oracle Cloud (Node A, India), AWS free tier (Node B, US East), Google Cloud Platform (Node C, Frankfurt)

## Classification

The rule-based classifier maps session behavior to MITRE ATT&CK techniques across 14 categories, including reconnaissance, credential brute force, malware deployment, cryptominer installation, botnet recruitment, reverse shell, and privilege escalation, plus four low-signal/edge categories added specifically to close taxonomy gaps found during testing:

- `banner_grab` — connect, no auth attempt, disconnect (mass scanner fingerprinting)
- `single_credential_probe` — one opportunistic login try, no shell activity
- `shell_verification_probe` — a single bare `echo <token>` command and nothing else: the classic shell-liveness check IoT-botnet loaders run to confirm they got a real, responsive shell before committing to a payload
- `defense_evasion` (extended) — now also catches the `chattr -i` / `lockr` "device lockdown" pattern, where a bot locks the `.ssh` directory's immutable attribute to exclude rival bots or the admin after claiming a host (MITRE T1222)

Together these mean low-interaction scanner and botnet traffic is captured meaningfully rather than falling into a generic "unclassified" bucket.

## Current status

As of the latest full reclassification pass across all three nodes (Oct 2026):

- **14,538** real captured sessions processed across Node A/B/C, **99.993% classified** (1 session left genuinely unclassified — an architecture-fingerprinting + disk-space probe, documented rather than forced into a rule built off a single sample)
- Per-node breakdown:

  | Attack Type | Node A | Node B | Node C |
  |---|---|---|---|
  | reconnaissance | 4,253 | 5,625 | 1,932 |
  | single_credential_probe | 633 | 80 | 275 |
  | banner_grab | 435 | 127 | 334 |
  | shell_verification_probe | 742 | — | 1 |
  | persistence_mechanism | 72 | — | 4 |
  | malware_deployment | 8 | — | 15 |
  | defense_evasion | 1 | — | — |
  | unclassified | — | — | 1 |
  | **Total** | **6,144** | **5,832** | **2,562** |

- A pre-existing data-integrity bug was found and corrected during this pass: several hundred sessions with a real recorded login attempt had been stored as `banner_grab` (which requires zero credential attempts) rather than `single_credential_probe` — likely a historical ingestion-time mismatch. All affected records were corrected via a dry-run-then-apply reclassification script, wrapped in a single transaction for safety.
- Clear IoT-botnet signal in the dataset: `shell_verification_probe` (bare `echo` liveness checks) and the `lockr`/`chattr -i` device-lockdown pattern are both textbook Mirai-family behaviors; default-credential pairs observed (e.g. `root`/`xiaomao`, `admin`/`888888`) match known IoT scanner dictionaries.
- All three nodes de-fingerprinted from Cowrie's stock defaults (default hostname `svr04`, default SSH banner falsely claiming Debian on an Ubuntu host) to a non-default, internally-consistent configuration — intended to reduce attackers disengaging immediately after detecting a honeypot signature

### Known limitations (honest, not yet addressed)

- **Threat-intel enrichment (AbuseIPDB/GreyNoise) is currently mocked** — deterministic hash-seeded fake scores, not live API calls. Real API key integration is a planned next step.
- **Log collection is manual**, pulled per-node via SSH/`docker cp` rather than an automated, scheduled pipeline.
- **No egress firewall / outbound rate-limiting** on the honeypot containers, and containers are not confirmed to run as non-root — identified as a gap, not yet implemented, for this academic-scope deployment.
- **Frontend/dashboard** is deferred until shortly before presentation; data is currently inspected via direct SQL queries and exported CSV snapshots.

## Setup

1. Each honeypot node runs Cowrie in Docker with a custom `cowrie.cfg` (see `pipeline/` for the override, not the stock `cowrie.cfg.dist`).
2. Create a `.env` at the project root (see `.env.example`) with your local PostgreSQL connection details.
3. Apply `pipeline/models/schema.sql` to initialize the database.
4. Pull a node's log file and process it:
   ```bash
   python pipeline/bulk_process_log.py --node-id node-A path/to/cowrie_log.json
   ```
5. Check current totals:
   ```bash
   python pipeline/storage/check_totals.py
   ```
