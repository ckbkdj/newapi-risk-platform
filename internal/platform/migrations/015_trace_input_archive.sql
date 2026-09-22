-- Full request bodies are stored separately from trace summaries and event buses.
-- Ciphertext is lossless gzip + AES-256-GCM, bound to request identity with AAD.
CREATE TABLE IF NOT EXISTS trace_input_archives (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    route_slug TEXT NOT NULL,
    started_at_text TEXT NOT NULL,
    expires_unix BIGINT NOT NULL,
    body_bytes BIGINT NOT NULL CHECK (body_bytes >= 0 AND body_bytes <= 268435456),
    body_ciphertext BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS trace_input_archives_request ON trace_input_archives(request_id, created_at DESC, id);
CREATE INDEX IF NOT EXISTS trace_input_archives_expiry ON trace_input_archives(expires_unix);
-- statement-breakpoint
CREATE TABLE IF NOT EXISTS trace_input_accesses (
    id BIGSERIAL PRIMARY KEY,
    input_id TEXT NOT NULL,
    admin_user_id BIGINT NOT NULL,
    action TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS trace_input_accesses_created ON trace_input_accesses(created_at);
