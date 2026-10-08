-- ═══════════════════════════════════════════════════════════════
-- Aletheia — Migration: automated_actions table
-- Additive only — safe to run against an existing database that
-- already has the schema.sql tables. Does not touch any existing
-- table or data.
--
-- Supports the automated-action watcher (Pillar 2/3 integration):
-- tracks which records have already triggered an automated response,
-- so the same record never fires twice.
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS automated_actions (
    id                   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    record_hash          CHAR(64) NOT NULL UNIQUE,
    session_id           TEXT NOT NULL,
    src_ip               INET NOT NULL,
    attack_type          TEXT NOT NULL,
    severity             TEXT NOT NULL,
    corroboration_count  INTEGER NOT NULL,
    action_taken         TEXT NOT NULL,       -- e.g. 'blocklist'
    triggered_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_automated_actions_src_ip ON automated_actions (src_ip);
CREATE INDEX IF NOT EXISTS idx_automated_actions_triggered_at ON automated_actions (triggered_at);
