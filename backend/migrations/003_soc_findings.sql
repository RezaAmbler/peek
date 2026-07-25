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

-- === Risk enrichment (SOC hardening) ========================================
-- Structured CVE identity + threat-intel context + a computed prioritization
-- score, resolved after a scan completes from external feeds (NVD/CVSS,
-- FIRST/EPSS, CISA KEV). All nullable/best-effort so enrichment never blocks a
-- scan and degrades gracefully offline. See services/enrichment_service.py.
-- Idempotency: apply_migrations.apply_003 guards each ADD COLUMN and skips
-- columns that already exist (mirrors the fingerprint column above).
ALTER TABLE vulnerabilities ADD COLUMN cve_id VARCHAR;          -- canonical CVE-YYYY-NNNN
ALTER TABLE vulnerabilities ADD COLUMN cvss_score FLOAT;        -- CVSS base score 0.0-10.0
ALTER TABLE vulnerabilities ADD COLUMN cvss_vector VARCHAR;     -- CVSS vector string
ALTER TABLE vulnerabilities ADD COLUMN epss_score FLOAT;        -- EPSS probability 0.0-1.0
ALTER TABLE vulnerabilities ADD COLUMN kev_flag BOOLEAN DEFAULT 0;        -- in CISA KEV catalog
ALTER TABLE vulnerabilities ADD COLUMN exploit_known BOOLEAN DEFAULT 0;   -- public exploit known
ALTER TABLE vulnerabilities ADD COLUMN risk_score FLOAT;        -- computed 0..100 prioritization
CREATE INDEX IF NOT EXISTS ix_vulnerabilities_cve_id ON vulnerabilities (cve_id);
CREATE INDEX IF NOT EXISTS ix_vulnerabilities_risk_score ON vulnerabilities (risk_score);
