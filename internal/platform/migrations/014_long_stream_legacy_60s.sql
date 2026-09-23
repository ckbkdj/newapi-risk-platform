-- Routes created before/after the v22 migration may still carry historical
-- short values. In particular 60000 ms was previously left untouched and
-- causes healthy SSE streams with >60s gaps to be canceled.
--
-- Migrate only known legacy/default values. Preserve deliberate operator
-- overrides outside this set.
UPDATE routes
SET request_timeout_ms = 2700000,
    updated_at = now()
WHERE deleted_at IS NULL
  AND enabled = TRUE
  AND request_timeout_ms IN (10000, 60000, 120000, 300000);
