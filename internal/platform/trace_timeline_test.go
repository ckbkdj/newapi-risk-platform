package platform

import (
	"testing"
	"time"
)

func TestNormalizeTraceTimelineUsesStartAndLatency(t *testing.T) {
	start := time.Date(2026, time.September, 3, 1, 2, 3, 0, time.UTC)
	event := TraceEvent{CreatedAt: start, LatencyMS: 1250}
	normalizeTraceTimeline(&event, start.Add(2*time.Second))
	if !event.StartedAt.Equal(start) || !event.CompletedAt.Equal(start.Add(1250*time.Millisecond)) {
		t.Fatalf("unexpected timeline: %+v", event)
	}
	if event.IngestedAt.IsZero() {
		t.Fatal("ingested time was not set")
	}
}

func TestDeriveTrackingTimelineAlignsCompletionWithOccurredAt(t *testing.T) {
	received := time.Date(2026, time.September, 3, 2, 0, 5, 0, time.UTC)
	occurred := received.Add(-5 * time.Second)
	timeline := deriveTrackingTimeline(TrackingEvent{OccurredAt: occurred, LatencyMS: 1500}, received)
	if !timeline.CompletedAt.Equal(occurred) || !timeline.StartedAt.Equal(occurred.Add(-1500*time.Millisecond)) {
		t.Fatalf("unexpected tracking timeline: %+v", timeline)
	}
	if timeline.ClockOffset != 5*time.Second {
		t.Fatalf("clock offset=%s", timeline.ClockOffset)
	}
}

func TestTraceTimeExpression(t *testing.T) {
	if got := traceTimeExpression(TraceTimeBasisCompleted); got != "COALESCE(completed_at, created_at)" {
		t.Fatalf("completed expression=%q", got)
	}
	if got := traceTimeExpression(TraceTimeBasisStarted); got != "COALESCE(started_at, created_at)" {
		t.Fatalf("started expression=%q", got)
	}
}
