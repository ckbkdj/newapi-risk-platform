package platform

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestInitialAuditChunkBytesUsesContextRatio(t *testing.T) {
	engine := &AuditEngine{
		outputMaxTokens:   128,
		contextTargetTokens: 260000,
		fallbackChunkBytes: 192 * 1024,
	}
	got := engine.initialAuditChunkBytes(1_000_000, 400_000, 262_144)
	if got < 550_000 || got > 620_000 {
		t.Fatalf("chunk bytes = %d, want ratio-sized chunk around 585000", got)
	}
}

func TestInitialAuditChunkBytesFallsBackWithoutTokenCounts(t *testing.T) {
	engine := &AuditEngine{
		outputMaxTokens:     128,
		contextTargetTokens: 260000,
		fallbackChunkBytes:  192 * 1024,
	}
	if got := engine.initialAuditChunkBytes(800_000, 0, 0); got != 192*1024 {
		t.Fatalf("fallback chunk bytes = %d, want %d", got, 192*1024)
	}
}

func TestSplitAuditTextByBytesKeepsAllBoundariesAndUTF8(t *testing.T) {
	text := "BEGIN\n" + strings.Repeat("甲乙丙丁安全文本\n", 200) + "END"
	chunks := splitAuditTextByBytes(text, 240, 32)
	if len(chunks) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(chunks))
	}
	if !strings.HasPrefix(chunks[0], "BEGIN") {
		t.Fatalf("first chunk lost beginning: %q", chunks[0])
	}
	if !strings.HasSuffix(chunks[len(chunks)-1], "END") {
		t.Fatalf("last chunk lost ending: %q", chunks[len(chunks)-1])
	}
	for index, chunk := range chunks {
		if !utf8.ValidString(chunk) {
			t.Fatalf("chunk %d is not valid UTF-8", index)
		}
		if chunk == "" {
			t.Fatalf("chunk %d is empty", index)
		}
	}
	for index := 1; index < len(chunks); index++ {
		previous := chunks[index-1]
		current := chunks[index]
		matched := false
		limit := 32
		if len(previous) < limit {
			limit = len(previous)
		}
		for size := limit; size > 0; size-- {
			if strings.HasPrefix(current, previous[len(previous)-size:]) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("chunks %d and %d have no overlap", index-1, index)
		}
	}
}

func TestDecorateAuditChunkAndDecision(t *testing.T) {
	content := decorateAuditChunk("payload", 1, 3)
	if !strings.Contains(content, "2/3") || !strings.Contains(content, "payload") {
		t.Fatalf("unexpected decorated chunk: %q", content)
	}
	decision := decorateChunkDecision(AuditDecision{
		Decision: DecisionBlock,
		Reason:   "detected",
		Source:   "model",
	}, 1, 3)
	if decision.Source != "model_chunked" || !strings.Contains(decision.Reason, "2/3") {
		t.Fatalf("unexpected decorated decision: %#v", decision)
	}
}
