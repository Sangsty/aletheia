-- Adds two new attack_type_enum values for low-signal, pre-auth sessions
-- that were previously falling into "unclassified" even though they're
-- a distinct, nameable behavior (no commands run, little/no credential activity).
ALTER TYPE attack_type_enum ADD VALUE IF NOT EXISTS 'banner_grab';
ALTER TYPE attack_type_enum ADD VALUE IF NOT EXISTS 'single_credential_probe';