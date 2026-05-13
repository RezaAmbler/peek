-- Migration: Add httpx screenshot and vhost discovery support
-- Date: 2024-12-30
-- Description: Adds columns for screenshot capture and virtual host discovery

-- Add new columns to scan_configs table
ALTER TABLE scan_configs ADD COLUMN httpx_screenshots BOOLEAN DEFAULT FALSE NOT NULL;
ALTER TABLE scan_configs ADD COLUMN httpx_screenshot_timeout INTEGER DEFAULT 10 NOT NULL;
ALTER TABLE scan_configs ADD COLUMN httpx_vhost_discovery BOOLEAN DEFAULT TRUE NOT NULL;

-- Add screenshot_path column to httpx_results table
ALTER TABLE httpx_results ADD COLUMN screenshot_path VARCHAR;

-- Note: The virtual_hosts column already exists in httpx_results
-- If it doesn't exist in your database, uncomment the following:
-- ALTER TABLE httpx_results ADD COLUMN virtual_hosts JSON;
