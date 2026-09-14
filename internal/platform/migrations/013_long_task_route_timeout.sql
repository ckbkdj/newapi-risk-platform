-- Long-running coding/agent/model requests can legitimately take 5-30 minutes.
-- Historical defaults (10s/120s) and the temporary 5-minute workaround are too
-- short and cause healthy upstream work to be canceled. Migrate only these
-- known legacy values; preserve every other explicit operator override.
UPDATE routes
SET request_timeout_ms = 2700000,
    updated_at = now()
WHERE deleted_at IS NULL
  AND enabled = TRUE
  AND request_timeout_ms IN (10000, 120000, 300000);
