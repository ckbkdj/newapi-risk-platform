package platform

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResolveAuditTextMaxBytesAutomatic(t *testing.T) {
	resolved, mode := resolveAuditTextMaxBytes(0, 64*1024*1024)
	if mode != "automatic_request_hard_ceiling" {
		t.Fatalf("mode=%q", mode)
	}
	if int64(resolved) < 64*1024*1024 {
		t.Fatalf("resolved=%d is below accepted request hard ceiling", resolved)
	}
}

func TestAutomaticAuditTextKeepsTailOfAcceptedLargeUserIntent(t *testing.T) {
	const hardLimit = int64(1024 * 1024)
	resolved, _ := resolveAuditTextMaxBytes(0, hardLimit)
	content := strings.Repeat("normal-project-content-", 35000) + "TAIL_AUDIT_MARKER"
	body, err := json.Marshal(map[string]any{
		"messages": []map[string]any{{"role": "user", "content": content}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(body)) > hardLimit {
		t.Fatalf("test body unexpectedly exceeds hard limit: %d", len(body))
	}
	extraction := ExtractAuditTextDetails(body, resolved)
	if !strings.Contains(extraction.Text, "TAIL_AUDIT_MARKER") {
		t.Fatalf("accepted request tail was silently omitted; extracted=%d body=%d limit=%d", len(extraction.Text), len(body), resolved)
	}
}

func TestConfiguredAuditTextLimitIsPreserved(t *testing.T) {
	resolved, mode := resolveAuditTextMaxBytes(512*1024, 64*1024*1024)
	if mode != "configured" || resolved != 512*1024 {
		t.Fatalf("resolved=%d mode=%q", resolved, mode)
	}
}
