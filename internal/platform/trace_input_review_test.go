package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Run against a disposable PostgreSQL database, never production.
func TestTraceInputPostgresPermissionsAndRetention(t *testing.T) {
	dsn := os.Getenv("TRACE_INPUT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TRACE_INPUT_TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := &Store{pool: pool, log: logger}
	if err := store.Migrate(ctx); err != nil {
		pool.Close()
		cancel()
		t.Fatal(err)
	}
	cfg := Config{MasterKey: bytes.Repeat([]byte{9}, 32), JWTSecret: bytes.Repeat([]byte{8}, 32), JWTIssuer: "input-review-test", JWTTTL: time.Hour, RetentionDays: 7, RequestHardMaxBytes: 1024 * 1024}
	security := NewSecurity(cfg)
	service := &HTTPService{cfg: cfg, store: store, security: security, log: logger}
	handler, wait, err := service.HandlerWithInputReview(ctx)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer func() { server.Close(); cancel(); wait(); pool.Close() }()
	tokens := map[string]string{}
	ids := map[string]int64{}
	for _, role := range []string{"admin", "operator", "viewer"} {
		username := "input-test-" + role
		_, err := pool.Exec(ctx, `INSERT INTO admin_users(username,password_hash,role,enabled) VALUES($1,'unused',$2,true) ON CONFLICT(username) DO UPDATE SET role=EXCLUDED.role,enabled=true`, username, role)
		if err != nil {
			t.Fatal(err)
		}
		user, err := store.GetAdminUser(ctx, username)
		if err != nil {
			t.Fatal(err)
		}
		tokens[role], err = security.IssueAdminToken(user)
		if err != nil {
			t.Fatal(err)
		}
		ids[role] = user.ID
	}
	body := []byte(`{"input":[{"role":"user","content":"` + strings.Repeat("完整输入\\n", 20000) + `END_SENTINEL"}],"metadata":{"preserved":true}}`)
	id, _ := newTraceInputID()
	record := traceInputRecord{ID: id, RequestID: "input-review-integration", RouteSlug: "test-route", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), ExpiresUnix: time.Now().Add(7 * 24 * time.Hour).Unix(), BodyBytes: int64(len(body))}
	sealed, err := sealTraceInput(cfg.MasterKey, record, [][]byte{body})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveInput(ctx, record, sealed); err != nil {
		t.Fatal(err)
	}
	fetch := func(path, token string) (int, http.Header, []byte) {
		t.Helper()
		request, err := http.NewRequest("GET", server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, response.Header, data
	}
	path := "/api/admin/v1/trace-inputs/" + id + "/body"
	for _, role := range []string{"", "operator", "viewer"} {
		code, _, data := fetch(path, tokens[role])
		expected := 403
		if role == "" {
			expected = 401
		}
		if code != expected || bytes.Contains(data, []byte("END_SENTINEL")) {
			t.Fatalf("unauthorized %s received data: %d", role, code)
		}
	}
	for _, suffix := range []string{"", "?download=1"} {
		code, headers, data := fetch(path+suffix, tokens["admin"])
		if code != 200 || !bytes.Equal(body, data) || headers.Get("X-Trace-Input-Complete") != "true" {
			t.Fatalf("full body mismatch: %d %d/%d", code, len(data), len(body))
		}
		if !strings.Contains(headers.Get("Cache-Control"), "no-store") {
			t.Fatal("sensitive response is cacheable")
		}
	}
	code, _, data := fetch("/api/admin/v1/trace-inputs?request_id="+record.RequestID, tokens["admin"])
	var list struct {
		Items []traceInputRecord `json:"items"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatal(err)
	}
	if code != 200 || len(list.Items) == 0 || bytes.Contains(data, []byte("END_SENTINEL")) {
		t.Fatal("summary endpoint contains body or misses stored item")
	}
	var accessCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM trace_input_accesses WHERE input_id=$1`, id).Scan(&accessCount); err != nil || accessCount != 2 {
		t.Fatal("read/download access log missing", err, accessCount)
	}
	// Revocation is checked in the database, not only in a still-valid JWT.
	if _, err := pool.Exec(ctx, `UPDATE admin_users SET enabled=false WHERE id=$1`, ids["admin"]); err != nil {
		t.Fatal(err)
	}
	code, _, _ = fetch(path, tokens["admin"])
	if code != 403 {
		t.Fatal("disabled admin retained raw-body access")
	}
	if _, err := pool.Exec(ctx, `UPDATE admin_users SET enabled=true WHERE id=$1`, ids["admin"]); err != nil {
		t.Fatal(err)
	}
	// Expiry denies access before maintenance, and maintenance deletes the blob.
	if _, err := pool.Exec(ctx, `UPDATE trace_input_archives SET expires_unix=$2 WHERE id=$1`, id, time.Now().Unix()-1); err != nil {
		t.Fatal(err)
	}
	code, _, _ = fetch(path, tokens["admin"])
	if code != 410 {
		t.Fatal("expired input still readable")
	}
	if err := store.PurgeInputs(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.FindInput(ctx, id); err != ErrNotFound {
		t.Fatal("expired input not physically removed", err)
	}
	code, _, _ = fetch(path, tokens["admin"])
	if code != 404 {
		t.Fatal("missing record not explained")
	}
	code, _, data = fetch("/admin", "")
	if code != 200 || !bytes.Contains(data, []byte("/admin/input-review.js")) {
		t.Fatal("input review UI not integrated")
	}
}
