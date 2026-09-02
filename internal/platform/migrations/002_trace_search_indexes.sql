CREATE INDEX IF NOT EXISTS request_traces_newapi_request_created_idx
ON request_traces (newapi_request_id, created_at DESC)
WHERE newapi_request_id <> '';
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS request_traces_external_event_created_idx
ON request_traces (external_event_id, created_at DESC)
WHERE external_event_id <> '';
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS request_traces_source_created_idx
ON request_traces (source, created_at DESC);
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS request_traces_model_created_idx
ON request_traces (model, created_at DESC)
WHERE model <> '';
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS request_traces_http_status_created_idx
ON request_traces (http_status, created_at DESC);
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS request_traces_upstream_status_created_idx
ON request_traces (upstream_status, created_at DESC);
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS request_traces_user_lower_prefix_idx
ON request_traces (lower(external_user_id) text_pattern_ops, created_at DESC)
WHERE external_user_id <> '';
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS request_traces_model_lower_prefix_idx
ON request_traces (lower(model) text_pattern_ops, created_at DESC)
WHERE model <> '';
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS request_traces_endpoint_lower_prefix_idx
ON request_traces (lower(endpoint) text_pattern_ops, created_at DESC)
WHERE endpoint <> '';
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS request_traces_tenant_created_idx
ON request_traces ((metadata ->> 'tenant_id'), created_at DESC)
WHERE metadata ? 'tenant_id';
