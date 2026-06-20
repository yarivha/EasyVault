-- =============================================================================
-- 005_secret_max_reads.sql — single-use / N-use secrets (burn after read)
--
-- A secret version may cap how many times it can be read over the token API.
-- `max_reads` NULL = unlimited; once `read_count` reaches it the version is
-- destroyed and its ciphertext wiped.
-- =============================================================================

ALTER TABLE secrets ADD COLUMN max_reads  INTEGER;                       -- NULL = unlimited
ALTER TABLE secrets ADD COLUMN read_count INTEGER NOT NULL DEFAULT 0;
