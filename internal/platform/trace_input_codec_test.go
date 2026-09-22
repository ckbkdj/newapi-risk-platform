package platform

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func inputTestRecord(size int) traceInputRecord {
	return traceInputRecord{ID: strings.Repeat("a", 32), RequestID: "request-test", RouteSlug: "main", StartedAt: "2026-09-22T02:45:46.751251897Z", ExpiresUnix: 1790659200, BodyBytes: int64(size)}
}
func TestTraceInputCodecFullRoundTrip(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"` + strings.Repeat("完整原文—not a summary\\n", 12000) + `token=original-sentinel"}],"input":{"unknown":"kept"}}`)
	key := bytes.Repeat([]byte{7}, 32)
	record := inputTestRecord(len(body))
	sealed, err := sealTraceInput(key, record, [][]byte{body[:112889], body[112889:]})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("original-sentinel")) {
		t.Fatal("plaintext in ciphertext")
	}
	decoded, err := openTraceInput(key, record, sealed)
	if err != nil || !bytes.Equal(body, decoded) {
		t.Fatalf("full roundtrip failed: %v bytes=%d/%d", err, len(decoded), len(body))
	}
	second, err := sealTraceInput(key, record, [][]byte{body})
	if err != nil || bytes.Equal(sealed, second) {
		t.Fatal("nonce reused")
	}
	record.RequestID = "other-request"
	if _, err = openTraceInput(key, record, sealed); err == nil {
		t.Fatal("cross-request ciphertext accepted")
	}
}
func TestTraceInputCodecRejectsCorruptionAndBounds(t *testing.T) {
	key := bytes.Repeat([]byte{8}, 32)
	record := inputTestRecord(4)
	sealed, err := sealTraceInput(key, record, [][]byte{[]byte{0, 1, 2, 255}})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := openTraceInput(key, record, sealed)
	if err != nil || !bytes.Equal(decoded, []byte{0, 1, 2, 255}) {
		t.Fatal("binary roundtrip lost bytes")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := openTraceInput(key, record, sealed); err == nil {
		t.Fatal("tampered archive accepted")
	}
	if _, err := openTraceInput([]byte("wrong-key"), record, sealed); err == nil {
		t.Fatal("invalid key accepted")
	}
	record.BodyBytes = inputCaptureMaximumBytes + 1
	if _, err := openTraceInput(key, record, sealed); err == nil {
		t.Fatal("oversized archive accepted")
	}
	record.BodyBytes = 4
	if _, err := sealTraceInput(key, record, [][]byte{[]byte("shorter-or-longer")}); err == nil {
		t.Fatal("size mismatch accepted")
	}
}

type inputTestRepository struct {
	mu      sync.Mutex
	records []traceInputRecord
	bodies  [][]byte
	saved   chan struct{}
	fail    bool
}

func (s *inputTestRepository) SaveInput(_ context.Context, r traceInputRecord, b []byte) error {
	if s.fail {
		return errors.New("database unavailable")
	}
	s.mu.Lock()
	s.records = append(s.records, r)
	s.bodies = append(s.bodies, append([]byte(nil), b...))
	s.mu.Unlock()
	select {
	case s.saved <- struct{}{}:
	default:
	}
	return nil
}
func (s *inputTestRepository) FindInput(context.Context, string) (traceInputRecord, []byte, error) {
	return traceInputRecord{}, nil, errors.New("not found")
}
func (s *inputTestRepository) ListInputs(context.Context, string, int, int) ([]traceInputRecord, error) {
	return nil, nil
}
func (s *inputTestRepository) PurgeInputs(context.Context, int) error { return nil }

func TestTraceInputCapturePreservesBodyAndExcludesHeaders(t *testing.T) {
	repo := &inputTestRepository{saved: make(chan struct{}, 2)}
	ctx, cancel := context.WithCancel(context.Background())
	key := bytes.Repeat([]byte{3}, 32)
	r := newTraceInputRecorder(ctx, repo, key, true, 1024*1024, 16*1024*1024, 8, 7, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer func() { cancel(); r.Wait() }()
	body := strings.Repeat("原文 without truncation ", 8000) + "LAST-BYTE-MARKER"
	base := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("X-Risk-Request-ID", "same-retry-id")
		w.Header().Set("X-Risk-Started-At", time.Now().UTC().Format(time.RFC3339Nano))
		read, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		if string(read) != body {
			t.Error("capture changed gateway request")
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("upstream ok"))
	})
	for i := 0; i < 2; i++ {
		request := httptest.NewRequest("POST", "/gateway/main/v1/responses", strings.NewReader(body))
		request.Header.Set("Authorization", "HEADER_SECRET_MUST_NOT_BE_STORED")
		out := httptest.NewRecorder()
		r.Wrap(base).ServeHTTP(out, request)
		if out.Code != 200 || out.Body.String() != "upstream ok" {
			t.Fatal("capture changed response")
		}
	}
	for i := 0; i < 2; i++ {
		select {
		case <-repo.saved:
		case <-time.After(3 * time.Second):
			t.Fatal("input persistence did not complete")
		}
	}
	cancel()
	r.Wait()
	if len(repo.records) != 2 || repo.records[0].ID == repo.records[1].ID {
		t.Fatal("retries overwritten")
	}
	for i, record := range repo.records {
		plain, err := openTraceInput(key, record, repo.bodies[i])
		if err != nil || string(plain) != body {
			t.Fatal("stored original is incomplete", err)
		}
		if bytes.Contains(plain, []byte("HEADER_SECRET_MUST_NOT_BE_STORED")) {
			t.Fatal("authorization header stored")
		}
	}
	if r.budget.used.Load() != 0 {
		t.Fatal("capture memory reservation leaked")
	}
}
func TestTraceInputCaptureOverLimitDoesNotBlockOrStorePrefix(t *testing.T) {
	repo := &inputTestRepository{saved: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	r := newTraceInputRecorder(ctx, repo, bytes.Repeat([]byte{3}, 32), true, 4, 1024*1024, 8, 7, slog.New(slog.NewTextHandler(io.Discard, nil)))
	request := httptest.NewRequest("POST", "/gateway/main/v1/responses", strings.NewReader("too long"))
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(w, r.Body) })
	out := httptest.NewRecorder()
	r.Wrap(next).ServeHTTP(out, request)
	cancel()
	r.Wait()
	if out.Body.String() != "too long" || r.stored.Load() != 0 || r.dropped.Load() != 1 || r.budget.used.Load() != 0 {
		t.Fatal("overflow altered response or stored incomplete input")
	}
}
func TestTraceInputNoReadNoCapture(t *testing.T) {
	repo := &inputTestRepository{saved: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	r := newTraceInputRecorder(ctx, repo, bytes.Repeat([]byte{3}, 32), true, 4096, 1024*1024, 8, 7, slog.New(slog.NewTextHandler(io.Discard, nil)))
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	r.Wrap(next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/gateway/main", strings.NewReader("unauthenticated request")))
	cancel()
	r.Wait()
	if r.queued.Load() != 0 || r.budget.used.Load() != 0 {
		t.Fatal("unauthenticated body was read or retained")
	}
}
func TestTraceInputExpiryAndConfig(t *testing.T) {
	now := time.Date(2026, 9, 22, 3, 0, 0, 0, time.UTC)
	record := inputTestRecord(4)
	record.ExpiresUnix = now.Add(7 * 24 * time.Hour).Unix()
	if traceInputExpired(record, now, 7) {
		t.Fatal("live record expired")
	}
	if !traceInputExpired(record, now.Add(25*time.Hour), 1) {
		t.Fatal("shortened retention ignored")
	}
	record.ExpiresUnix = now.Unix()
	if !traceInputExpired(record, now, 7) {
		t.Fatal("expired record readable")
	}
	if validateTraceInputOptions(1024, 1024*1024, 4, 7) != nil {
		t.Fatal("valid options rejected")
	}
	if validateTraceInputOptions(inputCaptureMaximumBytes+1, 1, 0, 0) == nil {
		t.Fatal("invalid options accepted")
	}
}
