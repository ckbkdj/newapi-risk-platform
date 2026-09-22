package platform

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type traceInputRepository interface {
	SaveInput(context.Context, traceInputRecord, []byte) error
	FindInput(context.Context, string) (traceInputRecord, []byte, error)
	ListInputs(context.Context, string, int, int) ([]traceInputRecord, error)
	PurgeInputs(context.Context, int) error
}
type traceInputJob struct {
	record  traceInputRecord
	parts   [][]byte
	charged int64
}
type traceInputRecorder struct {
	backend       traceInputRepository
	key           []byte
	budget        traceInputByteBudget
	maxBytes      int64
	retentionDays int
	enabled       bool
	queue         chan traceInputJob
	mu            sync.Mutex
	closed        bool
	writeContext  context.Context
	stopWrites    context.CancelFunc
	stopTimer     *time.Timer
	wg            sync.WaitGroup
	log           *slog.Logger
	queued        atomic.Int64
	stored        atomic.Int64
	dropped       atomic.Int64
	failed        atomic.Int64
}

func newTraceInputRecorder(ctx context.Context, backend traceInputRepository, key []byte, enabled bool, maxBytes, memoryBytes int64, queueSize, days int, log *slog.Logger) *traceInputRecorder {
	recorder := &traceInputRecorder{backend: backend, key: append([]byte(nil), key...), enabled: enabled, maxBytes: maxBytes, retentionDays: days, queue: make(chan traceInputJob, queueSize), log: log}
	recorder.budget.limit = memoryBytes
	recorder.writeContext, recorder.stopWrites = context.WithCancel(context.Background())
	for i := 0; i < 2; i++ {
		recorder.wg.Add(1)
		go recorder.worker()
	}
	recorder.wg.Add(1)
	go func() {
		defer recorder.wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		purge := func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := backend.PurgeInputs(cleanup, days); err != nil {
				log.Warn("input archive cleanup failed")
			}
		}
		purge()
		for {
			select {
			case <-ctx.Done():
				recorder.close()
				return
			case <-ticker.C:
				purge()
			}
		}
	}()
	return recorder
}
func (r *traceInputRecorder) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		// Bound shutdown drain time even while PostgreSQL is unavailable.
		r.stopTimer = time.AfterFunc(10*time.Second, r.stopWrites)
		close(r.queue)
	}
}
func (r *traceInputRecorder) Wait() {
	r.wg.Wait()
	r.stopWrites()
	r.mu.Lock()
	if r.stopTimer != nil {
		r.stopTimer.Stop()
	}
	r.mu.Unlock()
}
func (r *traceInputRecorder) enqueue(job traceInputJob) {
	r.mu.Lock()
	accepted := false
	if !r.closed {
		select {
		case r.queue <- job:
			accepted = true
		default:
		}
	}
	r.mu.Unlock()
	if accepted {
		r.queued.Add(1)
		return
	}
	r.budget.used.Add(-job.charged)
	r.dropped.Add(1)
	r.log.Warn("input archive queue full or stopped", "request_id", job.record.RequestID)
}
func (r *traceInputRecorder) worker() {
	defer r.wg.Done()
	for job := range r.queue {
		func() {
			defer r.budget.used.Add(-job.charged)
			if r.writeContext.Err() != nil {
				r.dropped.Add(1)
				return
			}
			sealed, err := sealTraceInput(r.key, job.record, job.parts)
			job.parts = nil
			if err != nil {
				r.failed.Add(1)
				r.log.Error("input archive encryption failed", "request_id", job.record.RequestID)
				return
			}
			// Independent from caller cancellation, but retries and DB time are bounded.
			for attempt := 0; attempt < 2; attempt++ {
				ctx, cancel := context.WithTimeout(r.writeContext, 5*time.Second)
				err = r.backend.SaveInput(ctx, job.record, sealed)
				cancel()
				if err == nil {
					r.stored.Add(1)
					return
				}
			}
			r.failed.Add(1)
			// Never put body/ciphertext into standard traces, Redis DLQ or Kafka.
			r.log.Error("input archive persistence failed", "request_id", job.record.RequestID)
		}()
	}
}

func (r *traceInputRecorder) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !r.enabled || !strings.HasPrefix(request.URL.Path, "/gateway/") || request.Body == nil {
			next.ServeHTTP(w, request)
			return
		}
		route := strings.SplitN(strings.TrimPrefix(request.URL.Path, "/gateway/"), "/", 2)[0]
		capture := &traceInputBody{ReadCloser: request.Body, budget: &r.budget, limit: r.maxBytes}
		capture.onFailure = func(code string) {
			r.dropped.Add(1)
			// Codes are platform-owned and contain no submitted content.
			r.log.Warn("input archive not captured", "reason", code, "request_id", w.Header().Get("X-Risk-Request-ID"))
		}
		capture.onComplete = func(parts [][]byte, size, charged int64) {
			requestID := w.Header().Get("X-Risk-Request-ID")
			started := w.Header().Get("X-Risk-Started-At")
			id, err := newTraceInputID()
			start, parseErr := time.Parse(time.RFC3339Nano, started)
			if err != nil || parseErr != nil || requestID == "" || len(requestID) > 128 || len(route) > 100 {
				r.budget.used.Add(-charged)
				r.dropped.Add(1)
				return
			}
			// Gateway emits the correlation headers and reads the body only AFTER its
			// route authentication. Do not pre-read, re-run audit, change or replay data.
			record := traceInputRecord{ID: id, RequestID: requestID, RouteSlug: route, StartedAt: started, ExpiresUnix: start.Add(time.Duration(r.retentionDays) * 24 * time.Hour).Unix(), BodyBytes: size}
			r.enqueue(traceInputJob{record: record, parts: parts, charged: charged})
		}
		request.Body = capture
		defer capture.Close()
		next.ServeHTTP(w, request)
	})
}

func validateTraceInputOptions(maxBytes, memoryBytes int64, queueSize, days int) error {
	if maxBytes < 1 || maxBytes > inputCaptureMaximumBytes || memoryBytes < 4*inputCaptureBlockBytes || memoryBytes > 8*1024*1024*1024 || queueSize < 1 || queueSize > 4096 || days < 1 || days > 365 {
		return errors.New("invalid input archive limits")
	}
	return nil
}

// Used by tests and diagnostics to inspect bounded capture without exposing text.
var _ io.ReadCloser = (*traceInputBody)(nil)
