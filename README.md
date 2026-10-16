# Aletheia

**A federated, blockchain-anchored honeypot threat intelligence framework.**

Aletheia deploys independently-operated SSH/Telnet honeypots across multiple cloud providers and continents, classifies the attack sessions they capture using a rule-based engine mapped to MITRE ATT&CK, enriches them with threat-intel context, and anchors a tamper-evident hash of each classified record on a public blockchain — so that threat intelligence from one node can be independently corroborated by others without trusting a single central authority.

---

## Why federated + blockchain?

A single honeypot only sees what hits it. A centralized threat-intel platform requires trusting whoever operates it. Aletheia's design goal is to let multiple independently-operated honeypot nodes contribute threat records to a shared, append-only, corroborable ledger — so that an attacker IP flagged by one node can be cross-verified against sightings from others, and the resulting record can't be quietly altered after the fact.

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Node A      │     │   Node B      │     │   Node C      │
│ Oracle Cloud  │     │  AWS (US)     │     │  GCP (EU)     │
│  (India)      │     │               │     │ Frankfurt     │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │ Cowrie honeypot (SSH/Telnet, de-fingerprinted)
       ▼                     ▼                     ▼
              Raw session logs (cowrie.json)
                       │
                       ▼
         ┌─────────────────────────────┐
         │   Pillar 2 — The Brain        │
         │  Session reconstruction       │
         │  Rule-based classifier        │
         │  (MITRE ATT&CK mapped)        │
         │  Threat-intel enrichment      │
         └──────────────┬────────────────┘
                         ▼
         ┌─────────────────────────────┐
         │  PostgreSQL (off-chain store) │
         │  Full enriched records        │
         └──────────────┬────────────────┘
                         ▼
         ┌─────────────────────────────┐
         │   Pillar 3 — The Ledger       │
         │  SHA-256 record hash          │
         │  Polygon Amoy testnet (PoA)   │
         │  Cross-node corroboration     │
         └─────────────────────────────┘
```

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

The rule-based classifier maps session behavior to MITRE ATT&CK techniques across 13 categories, including reconnaissance, credential brute force, malware deployment, cryptominer installation, botnet recruitment, reverse shell, privilege escalation, and two low-signal categories added specifically to close a taxonomy gap found during testing — `banner_grab` (connect, no auth attempt, disconnect) and `single_credential_probe` (one opportunistic login try, no shell activity) — so that low-interaction scanner traffic is captured meaningfully rather than falling into a generic "unclassified" bucket.

## Current status

As of the latest full data pull across all three nodes:

- **12,216** real captured sessions processed, **0% unclassified** — full classifier coverage
- **90%** of captured sessions classified as `reconnaissance` (genuine command execution inside the emulated shell), consistent across all three nodes
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

