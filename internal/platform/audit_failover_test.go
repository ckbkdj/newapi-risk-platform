package platform

import "testing"

func TestAuditErrorRetryableOnSameProfile(t *testing.T) {
	for _, class := range []string{
		"connection",
		"timeout",
		"rate_limited",
		"audit_server_error",
		"response_read",
		"response_format",
		"empty_response",
		"invalid_json",
		"invalid_decision",
	} {
		if !auditErrorRetryableOnSameProfile(newAuditModelCallError(class, 0, class, nil)) {
			t.Fatalf("class %q should be retryable", class)
		}
	}
	for _, class := range []string{
		"authentication",
		"endpoint_or_model_not_found",
		"context_length",
		"input_too_large",
		"credential_decrypt",
		"request_build",
		"request_encode",
		"http_status",
	} {
		if auditErrorRetryableOnSameProfile(newAuditModelCallError(class, 0, class, nil)) {
			t.Fatalf("class %q should not retry the same profile", class)
		}
	}
}

func TestMergeAuditCallMetadataPreservesLargestTokenObservation(t *testing.T) {
	primary := auditCallMetadata{
		Mode:                "chunked_after_context_limit",
		ChunkCount:          3,
		ChunkBytes:          200000,
		RequestedTokens:     281432,
		ContextWindowTokens: 260000,
		RetryCount:          1,
	}
	fallback := auditCallMetadata{
		Mode:       "single",
		ChunkCount: 1,
		ChunkBytes: 1000,
	}
	got := mergeAuditCallMetadata(primary, fallback)
	if got.RequestedTokens != 281432 || got.ContextWindowTokens != 260000 {
		t.Fatalf("token diagnostics lost: %+v", got)
	}
	if got.RetryCount != 1 {
		t.Fatalf("chunk retry count lost: %+v", got)
	}
}
