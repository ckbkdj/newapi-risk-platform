package platform

import "time"

const (
	TraceTimeBasisCompleted = "completed"
	TraceTimeBasisStarted   = "started"
	TraceTimeBasisIngested  = "ingested"
)

func normalizeTraceTimeline(event *TraceEvent, now time.Time) {
	if event == nil {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if event.StartedAt.IsZero() {
		switch {
		case !event.CreatedAt.IsZero():
			event.StartedAt = event.CreatedAt.UTC()
		case !event.CompletedAt.IsZero() && event.LatencyMS > 0:
			event.StartedAt = event.CompletedAt.UTC().Add(-time.Duration(event.LatencyMS) * time.Millisecond)
		default:
			event.StartedAt = now
		}
	} else {
		event.StartedAt = event.StartedAt.UTC()
	}
	if event.CompletedAt.IsZero() {
		event.CompletedAt = event.StartedAt.Add(time.Duration(maxInt64Value(event.LatencyMS, 0)) * time.Millisecond)
	} else {
		event.CompletedAt = event.CompletedAt.UTC()
	}
	if event.CompletedAt.Before(event.StartedAt) {
		event.CompletedAt = event.StartedAt
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = event.StartedAt
	} else {
		event.CreatedAt = event.CreatedAt.UTC()
	}
	if event.IngestedAt.IsZero() {
		event.IngestedAt = now
	} else {
		event.IngestedAt = event.IngestedAt.UTC()
	}
}

func maxInt64Value(value int64, minimum int64) int64 {
	if value < minimum {
		return minimum
	}
	return value
}

type trackingTimeline struct {
	StartedAt   time.Time
	CompletedAt time.Time
	IngestedAt  time.Time
	Source      string
	ClockOffset time.Duration
}

func deriveTrackingTimeline(event TrackingEvent, receivedAt time.Time) trackingTimeline {
	if receivedAt.IsZero() {
		receivedAt = time.Now().UTC()
	} else {
		receivedAt = receivedAt.UTC()
	}
	completedAt := event.CompletedAt
	source := "received_at"
	if completedAt.IsZero() {
		completedAt = event.OccurredAt
		if !completedAt.IsZero() {
			source = "occurred_at"
		}
	} else {
		source = "completed_at"
	}
	if completedAt.IsZero() {
		completedAt = receivedAt
	} else {
		completedAt = completedAt.UTC()
	}
	// Do not allow an untrusted tracking payload to move the visible event time
	// outside the searchable retention window or far into the future.
	if completedAt.After(receivedAt.Add(5*time.Minute)) || completedAt.Before(receivedAt.Add(-366*24*time.Hour)) {
		completedAt = receivedAt
		source += "_clamped"
	}
	startedAt := event.StartedAt
	if startedAt.IsZero() {
		startedAt = completedAt.Add(-time.Duration(maxInt64Value(event.LatencyMS, 0)) * time.Millisecond)
		source += "+latency"
	} else {
		startedAt = startedAt.UTC()
		source += "+started_at"
	}
	if startedAt.After(completedAt) {
		startedAt = completedAt
		source += "_normalized"
	}
	return trackingTimeline{
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		IngestedAt:  receivedAt,
		Source:      source,
		ClockOffset: receivedAt.Sub(completedAt),
	}
}

func traceTimeExpression(basis string) string {
	switch basis {
	case TraceTimeBasisStarted:
		return "COALESCE(started_at, created_at)"
	case TraceTimeBasisIngested:
		return "COALESCE(ingested_at, created_at)"
	default:
		return "COALESCE(completed_at, created_at)"
	}
}
