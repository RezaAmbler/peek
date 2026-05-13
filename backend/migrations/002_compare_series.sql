-- Migration 002: per-config series via config snapshot + hash
-- Date: 2026-05-13
-- Description:
--   - Adds config_snapshot (JSON-as-text) and config_hash (TEXT) to scans.
--   - Wipes existing scan-side rows. Existing scans pre-date the new model
--     and have no captured snapshot, so they would never be comparable
--     under the new rule anyway.
--
-- The Python runner (apply_migrations.py) is the source of truth — it gates
-- the data wipe on a sentinel file so it only runs once. This SQL is kept
-- as documentation of intent.

ALTER TABLE scans ADD COLUMN config_snapshot TEXT;
ALTER TABLE scans ADD COLUMN config_hash TEXT;

-- The wipe (in FK-safe order) is handled by apply_migrations.py.
