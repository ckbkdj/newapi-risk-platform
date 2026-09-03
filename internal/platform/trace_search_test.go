package platform

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParseTraceSearchFilter(t *testing.T) {
	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	values := url.Values{
		"q":                 {"newapi-request"},
		"request_id":        {"req-123"},
		"newapi_request_id": {"newapi-123"},
		"user_id":           {"tenant-user-42"},
		"user_match":        {"prefix"},
		"tenant_id":         {"tenant-a"},
		"model":             {"gpt-5"},
		"decision":          {"allow"},
		"http_status":       {"200"},
		"from":              {"2026-09-01T12:00:00Z"},
		"to":                {"2026-09-02T12:00:00Z"},
		"limit":             {"100"},
		"offset":            {"200"},
		"time_basis":        {"completed"},
	}
	filter, err := parseTraceSearchFilter(values, now)
	if err != nil {
		t.Fatal(err)
	}
	if filter.Query != "newapi-request" || filter.RequestID != "req-123" || filter.NewAPIRequestID != "newapi-123" {
		t.Fatalf("unexpected identifiers: %#v", filter)
	}
	if filter.UserID != "tenant-user-42" || filter.UserMatch != "prefix" || filter.TenantID != "tenant-a" {
		t.Fatalf("unexpected user filters: %#v", filter)
	}
	if filter.HTTPStatus == nil || *filter.HTTPStatus != 200 || filter.Limit != 100 || filter.Offset != 200 || filter.TimeBasis != TraceTimeBasisCompleted {
		t.Fatalf("unexpected pagination or status: %#v", filter)
	}
	if !filter.From.Equal(time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)) || !filter.To.Equal(now) {
		t.Fatalf("unexpected time range: %s - %s", filter.From, filter.To)
	}
}

func TestParseTraceSearchFilterDefaultsAndValidation(t *testing.T) {
	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	filter, err := parseTraceSearchFilter(url.Values{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if filter.Limit != defaultTraceSearchLimit || filter.Offset != 0 || filter.UserMatch != "exact" || filter.TimeBasis != TraceTimeBasisCompleted {
		t.Fatalf("unexpected defaults: %#v", filter)
	}
	if !filter.From.Equal(now.Add(-24*time.Hour)) || !filter.To.Equal(now) {
		t.Fatalf("unexpected default range: %s - %s", filter.From, filter.To)
	}
	if _, err := parseTraceSearchFilter(url.Values{"q": {"ab"}}, now); err == nil {
		t.Fatal("expected a too-short global query to be rejected")
	}
	if _, err := parseTraceSearchFilter(url.Values{
		"from": {"2026-09-02T12:00:00Z"},
		"to":   {"2026-09-01T12:00:00Z"},
	}, now); err == nil {
		t.Fatal("expected a reversed time range to be rejected")
	}
	if _, err := parseTraceSearchFilter(url.Values{
		"user_id":    {"a"},
		"user_match": {"contains"},
	}, now); err == nil {
		t.Fatal("expected a broad one-character user search to be rejected")
	}
}

func TestBuildTraceSearchWhereEscapesPatterns(t *testing.T) {
	filter := TraceSearchFilter{
		From:      time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC),
		To:        time.Date(2026, time.September, 2, 0, 0, 0, 0, time.UTC),
		UserID:    `user%_id\segment`,
		UserMatch: "contains",
		TenantID:  "tenant-a",
		Model:     "gpt_5%",
	}
	whereSQL, arguments := buildTraceSearchWhere(filter)
	if !strings.Contains(whereSQL, "COALESCE(completed_at, created_at)") || !strings.Contains(whereSQL, "lower(external_user_id)") || !strings.Contains(whereSQL, "metadata ->> 'tenant_id'") {
		t.Fatalf("missing expected search clauses: %s", whereSQL)
	}
	if got, ok := arguments[3].(string); !ok || got != `%user\%\_id\\segment%` {
		t.Fatalf("unexpected escaped user pattern %#v", arguments[3])
	}
	if got, ok := arguments[4].(string); !ok || got != `%gpt\_5\%%` {
		t.Fatalf("unexpected escaped model pattern %#v", arguments[4])
	}
}

func TestAdminUIContainsTraceSearchControls(t *testing.T) {
	page, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	for _, marker := range []string{
		`id="trace-from"`,
		`id="trace-to"`,
		`id="trace-time-basis"`,
		`id="trace-request-id"`,
		`id="trace-user-match"`,
		`id="trace-summary"`,
		`id="trace-detail"`,
		`data-trace-hours="168"`,
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("admin UI is missing trace search marker %s", marker)
		}
	}
}
