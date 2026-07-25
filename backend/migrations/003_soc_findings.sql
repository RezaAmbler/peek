-- Migration 003: SOC-grade finding trustworthiness (foundation)
-- Date: 2026-07-25
-- Description:
--   Adds a stable finding fingerprint to vulnerabilities so run-to-run scan
--   comparison can de-noise scan non-determinism (ephemeral/RPC ports, volatile
--   crawl URLs). The fingerprint is computed at ingest from
--     normalized_host | (cve or template_id) | normalized_port | normalized_path
--   See backend/app/services/fingerprint.py.
--
-- Idempotency: the Python runner (apply_migrations.py) guards each ADD COLUMN and
-- skips columns that already exist, mirroring migrations 001/002. This SQL is kept
-- as documentation of intent. Later SOC agents will APPEND columns/tables here
-- (enrichment, finding state/triage) — keep additions grouped and commented.

-- vulnerabilities.fingerprint: stable sha256 hex (nullable; backfilled lazily and
-- computed for all new rows at ingest). Indexed for fingerprint-keyed comparison.
ALTER TABLE vulnerabilities ADD COLUMN fingerprint VARCHAR(64);
CREATE INDEX IF NOT EXISTS ix_vulnerabilities_fingerprint ON vulnerabilities (fingerprint);
