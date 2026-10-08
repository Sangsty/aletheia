-- ═══════════════════════════════════════════════════════════════
-- Aletheia — PostgreSQL Schema
-- Off-chain storage (Pillar 2/3 boundary)
--
-- Mirrors pipeline/models/session_record.py 1:1 so the pydantic
-- models and the DB schema never drift apart. Full enriched
-- records live here; only hashes + metadata go on-chain.
-- ═══════════════════════════════════════════════════════════════

-- Enable UUID generation (used for internal row IDs)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ───────────────────────────────────────────────────────────────
-- Enum types — mirror the Python Enums exactly
-- ───────────────────────────────────────────────────────────────

CREATE TYPE protocol_enum AS ENUM ('ssh', 'telnet');

CREATE TYPE attack_type_enum AS ENUM (
    'credential_brute_force',
    'reconnaissance',
    'malware_deployment',
    'cryptominer_installation',
    'botnet_recruitment',
    'reverse_shell',
    'data_exfiltration',
    'privilege_escalation',
    'persistence_mechanism',
    'defense_evasion',
    'unclassified'
);

CREATE TYPE severity_enum AS ENUM ('low', 'medium', 'high', 'critical');

CREATE TYPE greynoise_classification_enum AS ENUM ('noise', 'targeted', 'unknown');


-- ───────────────────────────────────────────────────────────────
-- Core table: sessions
-- Mirrors SessionRecord
-- ───────────────────────────────────────────────────────────────

CREATE TABLE sessions (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id              TEXT NOT NULL UNIQUE,       -- Cowrie's own session ID
    node_id                 TEXT NOT NULL,              -- which honeypot node captured this
    protocol                protocol_enum NOT NULL,

    src_ip                  INET NOT NULL,
    src_port                INTEGER,

    session_start           TIMESTAMPTZ NOT NULL,
    session_end             TIMESTAMPTZ,
    duration_seconds        DOUBLE PRECISION,

    command_sequence        JSONB NOT NULL DEFAULT '[]',   -- ordered list of commands
    behavioral_fingerprint  TEXT,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sessions_src_ip ON sessions (src_ip);
CREATE INDEX idx_sessions_node_id ON sessions (node_id);
CREATE INDEX idx_sessions_session_start ON sessions (session_start);


-- ───────────────────────────────────────────────────────────────
-- credential_attempts
-- Mirrors CredentialAttempt (one-to-many with sessions)
-- ───────────────────────────────────────────────────────────────

CREATE TABLE credential_attempts (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id      UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    username        TEXT NOT NULL,
    password        TEXT NOT NULL,
    success         BOOLEAN NOT NULL,
    attempted_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_credential_attempts_session_id ON credential_attempts (session_id);


-- ───────────────────────────────────────────────────────────────
-- file_artifacts
-- Mirrors FileArtifact (one-to-many with sessions)
-- ───────────────────────────────────────────────────────────────

CREATE TABLE file_artifacts (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id      UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    url             TEXT,
    sha256          TEXT NOT NULL,
    file_size_bytes BIGINT
);

CREATE INDEX idx_file_artifacts_session_id ON file_artifacts (session_id);
CREATE INDEX idx_file_artifacts_sha256 ON file_artifacts (sha256);


-- ───────────────────────────────────────────────────────────────
-- classifications
-- Mirrors ClassificationResult (one-to-one with sessions)
-- ───────────────────────────────────────────────────────────────

CREATE TABLE classifications (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id              UUID NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,
    attack_type             attack_type_enum NOT NULL,
    severity                severity_enum NOT NULL,
    attck_technique_ids     JSONB NOT NULL DEFAULT '[]',   -- e.g. ["T1110", "T1082"]
    matched_rules           JSONB NOT NULL DEFAULT '[]',   -- rule names, for auditability
    classified_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_classifications_attack_type ON classifications (attack_type);
CREATE INDEX idx_classifications_severity ON classifications (severity);


-- ───────────────────────────────────────────────────────────────
-- enrichments
-- Mirrors EnrichmentResult (one-to-one with sessions)
-- Cache-friendly: enrichment is looked up by src_ip, so a second
-- session from the same IP can reuse a recent enrichment row
-- instead of re-querying AbuseIPDB/GreyNoise.
-- ───────────────────────────────────────────────────────────────

CREATE TABLE enrichments (
    id                          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id                  UUID NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,
    src_ip                      INET NOT NULL,

    -- AbuseIPDB fields
    abuseipdb_confidence_score  SMALLINT CHECK (abuseipdb_confidence_score BETWEEN 0 AND 100),
    abuseipdb_categories        JSONB DEFAULT '[]',
    abuseipdb_total_reports     INTEGER DEFAULT 0,
    abuseipdb_isp               TEXT,
    abuseipdb_country_code      TEXT,

    -- GreyNoise fields
    greynoise_classification    greynoise_classification_enum DEFAULT 'unknown',
    greynoise_actor              TEXT,
    greynoise_last_seen          TIMESTAMPTZ,

    enriched_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_enrichments_src_ip ON enrichments (src_ip);
CREATE INDEX idx_enrichments_enriched_at ON enrichments (enriched_at);


-- ───────────────────────────────────────────────────────────────
-- chain_references
-- Mirrors ChainReference (one-to-one with sessions)
-- Populated only after successful on-chain submission — nullable
-- relationship is intentional, since a record can exist off-chain
-- before/without being submitted (e.g. during local testing).
-- ───────────────────────────────────────────────────────────────

CREATE TABLE chain_references (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id              UUID NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,

    record_hash             CHAR(64) NOT NULL,          -- SHA-256 hex digest
    tx_hash                 TEXT,
    block_number            BIGINT,
    submitted_at             TIMESTAMPTZ,
    submitting_node         TEXT NOT NULL,
    corroboration_count     INTEGER NOT NULL DEFAULT 0,

    UNIQUE (record_hash)
);

CREATE INDEX idx_chain_references_record_hash ON chain_references (record_hash);
CREATE INDEX idx_chain_references_submitting_node ON chain_references (submitting_node);


-- ───────────────────────────────────────────────────────────────
-- corroborations
-- Tracks which nodes independently corroborated a given record.
-- Supports the smart contract's corroborate() method and the
-- on-chain reputation logic (Pillar 3).
-- ───────────────────────────────────────────────────────────────

CREATE TABLE corroborations (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    chain_reference_id  UUID NOT NULL REFERENCES chain_references(id) ON DELETE CASCADE,
    corroborating_node  TEXT NOT NULL,
    corroborated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (chain_reference_id, corroborating_node)   -- a node can't corroborate the same record twice
);

CREATE INDEX idx_corroborations_chain_reference_id ON corroborations (chain_reference_id);


-- ───────────────────────────────────────────────────────────────
-- node_reputation
-- Tracks per-node reputation over time (mirrors on-chain state,
-- kept off-chain too for fast dashboard queries).
-- ───────────────────────────────────────────────────────────────

CREATE TABLE node_reputation (
    node_id             TEXT PRIMARY KEY,
    reputation_score    DOUBLE PRECISION NOT NULL DEFAULT 0,
    total_submissions   INTEGER NOT NULL DEFAULT 0,
    total_corroborated  INTEGER NOT NULL DEFAULT 0,
    last_updated        TIMESTAMPTZ NOT NULL DEFAULT now()
);


-- ───────────────────────────────────────────────────────────────
-- Convenience view: full enriched record in one query
-- Mirrors EnrichedThreatRecord (the composite pydantic model)
-- Useful for the dashboard backend and STIX export.
-- ───────────────────────────────────────────────────────────────

CREATE VIEW enriched_threat_records AS
SELECT
    s.id                            AS session_uuid,
    s.session_id,
    s.node_id,
    s.protocol,
    s.src_ip,
    s.src_port,
    s.session_start,
    s.session_end,
    s.duration_seconds,
    s.command_sequence,
    s.behavioral_fingerprint,

    c.attack_type,
    c.severity,
    c.attck_technique_ids,

    e.abuseipdb_confidence_score,
    e.abuseipdb_categories,
    e.greynoise_classification,

    cr.record_hash,
    cr.tx_hash,
    cr.block_number,
    cr.submitting_node,
    cr.corroboration_count

FROM sessions s
LEFT JOIN classifications c    ON c.session_id = s.id
LEFT JOIN enrichments e        ON e.session_id = s.id
LEFT JOIN chain_references cr  ON cr.session_id = s.id;
