package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestV14FullAcceptedTextBeyondLegacyCaps(t *testing.T) {
	const tail = "COMPLETE_V14_TAIL"
	var calls, tails atomic.Int32
	e, p := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
		text, _, err := incidentPayload(r)
		if err != nil {
			return nil, err
		}
		if len(text) > cyberDenyChunkBytes {
			return nil, fmt.Errorf("unchunked input: %d", len(text))
		}
		if strings.Contains(text, tail) {
			tails.Add(1)
		}
		calls.Add(1)
		return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
	})
	e.maxAuditChunks = 0
	e.longContextTimeout = 30 * time.Second
	input := strings.Repeat("ordinary component text\n", 200000) + tail
	body, _ := json.Marshal(map[string]string{"input": input})
	got := e.Audit(context.Background(), Route{AuditProfileID: &p.ID}, body)
	if got.Decision != DecisionAllow || got.ErrorClass != "" || got.AuditChunkCount <= 256 || got.AuditChunksCompleted != got.AuditChunkCount || int(calls.Load()) != 2*got.AuditChunkCount || tails.Load() != 2 {
		t.Fatalf("not a complete two-pass result: decision=%s error=%s chunks=%d/%d calls=%d tail=%d", got.Decision, got.ErrorClass, got.AuditChunksCompleted, got.AuditChunkCount, calls.Load(), tails.Load())
	}
	if got.AuditInputPartial || got.AuditCoverageStatus != "complete" || got.AuditCapacityTextLimit != 0 || got.TextBytes < len(input) {
		t.Fatal("input was clipped or capacity-limited")
	}
}

func TestV14ContextRecoveryReplansWithoutDroppingTail(t *testing.T) {
	for _, ending := range []string{"normal tail", "synthetic prohibited operation", "invalid tail"} {
		t.Run(ending, func(t *testing.T) {
			var calls, tails atomic.Int32
			e, p := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
				text, _, err := incidentPayload(r)
				if err != nil {
					return nil, err
				}
				calls.Add(1)
				if len(text) > 2200 {
					return incidentHTTP(400, `{"error":{"message":"maximum context length is 4096 tokens; requested 16000 input tokens"}}`), nil
				}
				if strings.Contains(text, ending) {
					tails.Add(1)
					if ending == "invalid tail" {
						return incidentHTTP(200, "not-json"), nil
					}
					if ending == "synthetic prohibited operation" {
						return incidentHTTP(200, incidentDecision(DecisionBlock, ending)), nil
					}
				}
				return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
			})
			e.maxAuditChunks = 0
			e.longContextTimeout = 30 * time.Second
			ctx := context.WithValue(context.Background(), cyberDenyContextKey{}, true)
			d, _, m, err := e.callModelWithFailover(ctx, p, strings.Repeat("x", 620000)+ending)
			if m.CallMetadata.ChunkCount <= 256 || tails.Load() == 0 {
				t.Fatalf("tail/large plan not reached: chunks=%d tails=%d err=%v", m.CallMetadata.ChunkCount, tails.Load(), err)
			}
			if ending == "normal tail" {
				if err != nil || d.Decision != DecisionAllow || m.CallMetadata.ChunksCompleted != m.CallMetadata.ChunkCount || calls.Load() <= 512 || tails.Load() != 2 {
					t.Fatalf("incomplete plan: d=%s err=%v calls=%d tails=%d", d.Decision, err, calls.Load(), tails.Load())
				}
			} else if ending == "invalid tail" {
				if err == nil || d.Decision == DecisionAllow {
					t.Fatal("invalid tail became allow")
				}
			} else if err != nil || d.Decision != DecisionBlock {
				t.Fatalf("valid late veto lost: %s %v", d.Decision, err)
			}
		})
	}
}

func TestV14ContextsPreserveCallerOwnership(t *testing.T) {
	e := &AuditEngine{}
	ctx, cancel := e.fullAuditContext(context.Background())
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("default has a hidden cumulative deadline")
	}
	parent, stop := context.WithTimeout(context.Background(), time.Hour)
	defer stop()
	child, done := e.fullAuditContext(parent)
	defer done()
	a, _ := parent.Deadline()
	b, _ := child.Deadline()
	if a != b {
		t.Fatal("caller deadline changed")
	}
	stop()
	if !errors.Is(child.Err(), context.Canceled) {
		t.Fatal("caller cancellation detached")
	}
	e.requestTimeout = time.Millisecond
	limited, finish := e.fullAuditContext(context.Background())
	defer finish()
	select {
	case <-limited.Done():
	case <-time.After(time.Second):
		t.Fatal("configured total timeout ignored")
	}
	if !errors.Is(limited.Err(), context.DeadlineExceeded) {
		t.Fatal(limited.Err())
	}
}

func TestV14ModelSlotCancellationAndSingleSlotVerification(t *testing.T) {
	e := &AuditEngine{modelSlots: make(chan struct{}, 1)}
	release, err := e.acquireAuditModelSlot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() {
		r, e := e.acquireAuditModelSlot(ctx)
		if r != nil {
			r()
		}
		finished <- e
	}()
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("slot wait ignored cancellation")
	}
	release()
	if len(e.modelSlots) != 0 {
		t.Fatal("slot leaked")
	}
	var calls atomic.Int32
	engine, p := incidentEngine(t, func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
	})
	engine.modelSlots = make(chan struct{}, 1)
	contextWithDeadline, end := context.WithTimeout(context.Background(), time.Second)
	defer end()
	got := engine.Audit(contextWithDeadline, Route{AuditProfileID: &p.ID}, []byte(`{"input":"Explain a layout component"}`))
	if got.Decision != DecisionAllow || calls.Load() != 2 || len(engine.modelSlots) != 0 {
		t.Fatalf("nested review retained slot: %s %s calls=%d", got.Decision, got.ErrorClass, calls.Load())
	}
}

func TestV14GlobalModelSlotsAreBounded(t *testing.T) {
	e := &AuditEngine{modelSlots: make(chan struct{}, 3)}
	var active, peak atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := e.acquireAuditModelSlot(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			defer release()
			n := active.Add(1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			active.Add(-1)
		}()
	}
	wg.Wait()
	if peak.Load() > 3 || peak.Load() == 0 || len(e.modelSlots) != 0 {
		t.Fatalf("slot accounting: peak=%d", peak.Load())
	}
}

func TestV14CancelledPartialAuditIsNeverAllow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	e, p := incidentEngine(t, func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 6 {
			cancel()
		}
		if r.Context().Err() != nil {
			return nil, r.Context().Err()
		}
		return incidentHTTP(200, incidentDecision(DecisionAllow, "")), nil
	})
	e.maxAuditChunks = 0
	body, _ := json.Marshal(map[string]string{"input": strings.Repeat("normal line\n", 10000)})
	got := e.Audit(ctx, Route{AuditProfileID: &p.ID}, body)
	if got.Decision != DecisionBlock || got.ErrorClass != "audit_cancelled" || got.AuditChunksCompleted >= got.AuditChunkCount {
		t.Fatalf("partial cancellation approved: %s %s", got.Decision, got.ErrorClass)
	}
}

func TestV14PlanGuardsAndMonotonicAccounting(t *testing.T) {
	s := &auditSemanticState{httpCalls: 60, reviewCalls: 30}
	if err := s.configureChunkBudget(600); err != nil {
		t.Fatal(err)
	}
	h, r := s.httpBudget, s.reviewBudget
	if h < 1200 || r < 600 || s.httpCalls != 60 || s.reviewCalls != 30 {
		t.Fatal("plan resets or clips work")
	}
	if err := s.configureChunkBudget(10); err != nil || s.httpBudget <= h || s.reviewBudget <= r {
		t.Fatal("replan lost budget")
	}
	for _, bad := range []int{-1, 0, int(^uint(0) >> 1)} {
		h, r = s.httpBudget, s.reviewBudget
		if s.configureChunkBudget(bad) == nil || h != s.httpBudget || r != s.reviewBudget {
			t.Fatal("invalid/overflow plan altered state")
		}
	}
	s.budgetPlans = maxAuditChunkPlans
	if s.configureChunkBudget(1) == nil {
		t.Fatal("unbounded retry plans")
	}
	s.reviewCalls = s.reviewBudget
	if s.reserveReview() {
		t.Fatal("per-plan guard removed")
	}
}

func FuzzV14PlanAccounting(f *testing.F) {
	f.Add(300, 3)
	f.Add(0, 1)
	f.Add(-1, 4)
	f.Fuzz(func(t *testing.T, chunks, reviewers int) {
		s := &auditSemanticState{httpCalls: 7, reviewCalls: 3}
		err := s.configureChunkBudget(chunks, reviewers)
		if s.httpCalls != 7 || s.reviewCalls != 3 {
			t.Fatal("spent counters modified")
		}
		if err == nil && (s.httpBudget < cyberDenyHTTPBudget || s.reviewBudget < maxAuditSemanticCalls || s.budgetPlans != 1) {
			t.Fatal("overflow or incomplete reservation")
		}
	})
}
