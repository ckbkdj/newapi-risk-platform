ALTER TABLE request_traces ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;
ALTER TABLE request_traces ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;
ALTER TABLE request_traces ADD COLUMN IF NOT EXISTS ingested_at TIMESTAMPTZ;
-- statement-breakpoint
UPDATE request_traces
SET started_at = COALESCE(started_at, created_at),
    completed_at = COALESCE(completed_at, created_at + latency_ms * interval '1 millisecond'),
    ingested_at = COALESCE(ingested_at, created_at);
-- statement-breakpoint
ALTER TABLE request_traces ALTER COLUMN started_at SET DEFAULT now();
ALTER TABLE request_traces ALTER COLUMN completed_at SET DEFAULT now();
ALTER TABLE request_traces ALTER COLUMN ingested_at SET DEFAULT now();
ALTER TABLE request_traces ALTER COLUMN started_at SET NOT NULL;
ALTER TABLE request_traces ALTER COLUMN completed_at SET NOT NULL;
ALTER TABLE request_traces ALTER COLUMN ingested_at SET NOT NULL;
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS request_traces_started_at_idx ON request_traces (started_at DESC);
CREATE INDEX IF NOT EXISTS request_traces_completed_at_idx ON request_traces (completed_at DESC);
CREATE INDEX IF NOT EXISTS request_traces_ingested_at_idx ON request_traces (ingested_at DESC);
