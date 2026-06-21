-- =============================================================================
-- 006_settings.sql — instance-wide key/value settings
--
-- Small table for master-configurable instance settings (first use: audit-log
-- retention). Values are TEXT; callers parse as needed.
-- =============================================================================

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
