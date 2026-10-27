-- Adds one new attack_type_enum value for a narrow, nameable low-signal
-- pattern that was previously folding into "reconnaissance" or
-- "unclassified": a single plain `echo <token>` command with nothing
-- else in the session — the classic shell-liveness check bots run to
-- confirm they got a real, responsive shell before committing to a
-- payload, distinct from genuine recon commands (whoami/uname/etc.)
-- and from the hex-encoded shell_fingerprint_probe pattern.
ALTER TYPE attack_type_enum ADD VALUE IF NOT EXISTS 'shell_verification_probe';