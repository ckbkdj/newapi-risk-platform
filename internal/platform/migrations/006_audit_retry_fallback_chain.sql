ALTER TABLE audit_profiles
ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 2
CHECK (retry_count BETWEEN 0 AND 5);
-- statement-breakpoint
ALTER TABLE audit_profiles
ADD COLUMN IF NOT EXISTS fallback_profile_ids BIGINT[] NOT NULL DEFAULT '{}'::BIGINT[];
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS audit_profiles_enabled_id_idx
ON audit_profiles (id) WHERE enabled = TRUE;
