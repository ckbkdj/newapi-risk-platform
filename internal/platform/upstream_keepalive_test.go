package platform

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProxySSEHeartbeatKeepsSilentGenerationAlive(t *testing.T) {
	reader, writer := io.Pipe()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://upstream.invalid/v1/chat/completions", nil)
	if err != nil {
		t.Fatal(err)
	}
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": {"text/event-stream"},
		},
		Body:    reader,
		Request: request,
	}
	gateway := &Gateway{cfg: Config{
		SSELineMaxBytes:      1024 * 1024,
		SSEHeartbeatInterval: 10 * time.Millisecond,
	}}
	recorder := httptest.NewRecorder()

	done := make(chan struct{})
	var bytesWritten int64
	var riskCode string
	var status int
	go func() {
		bytesWritten, riskCode, status, _, _ = gateway.proxySSE(recorder, response, "long-sse-test", nil, nil)
		close(done)
	}()

	// Simulate a model that has returned SSE headers but spends a long time in
	// prefill/reasoning before producing the first actual event.
	time.Sleep(35 * time.Millisecond)
	_, _ = io.WriteString(writer, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n")
	_, _ = io.WriteString(writer, "data: [DONE]\n\n")
	_ = writer.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxySSE did not finish")
	}
	if riskCode != "" || status != http.StatusOK {
		t.Fatalf("unexpected SSE result: risk=%q status=%d", riskCode, status)
	}
	body := recorder.Body.String()
	if strings.Count(body, ": risk-gateway-keepalive\n\n") < 2 {
		t.Fatalf("silent generation did not receive periodic keepalives: %q", body)
	}
	if !strings.Contains(body, "\"content\":\"ok\"") || !strings.Contains(body, "data: [DONE]") {
		t.Fatalf("upstream SSE events were not preserved: %q", body)
	}
	if recorder.Header().Get("X-Accel-Buffering") != "no" {
		t.Fatalf("X-Accel-Buffering=%q", recorder.Header().Get("X-Accel-Buffering"))
	}
	if bytesWritten != int64(len(body)) {
		t.Fatalf("bytesWritten=%d body=%d", bytesWritten, len(body))
	}
}

func TestProxySSEPromptErrorPreservesHTTP555(t *testing.T) {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://upstream.invalid/v1/chat/completions", nil)
	if err != nil {
		t.Fatal(err)
	}
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{"Content-Type": {"text/event-stream"}},
		Body: io.NopCloser(strings.NewReader("event: error\ndata: {\"error\":{\"message\":\"synthetic\"}}\n\n")),
		Request: request,
	}
	gateway := &Gateway{cfg: Config{
		ErrorHTTPStatus:       555,
		SSELineMaxBytes:      1024 * 1024,
		SSEHeartbeatInterval: 15 * time.Second,
	}}
	recorder := httptest.NewRecorder()
	_, riskCode, status, _, committed := gateway.proxySSE(recorder, response, "early-error-test", nil, nil)
	if riskCode != "UPSTREAM_STREAM_ERROR" || status != 555 || committed {
		t.Fatalf("pre-stream error contract changed: risk=%q status=%d committed=%v", riskCode, status, committed)
	}
	if recorder.Code != 555 {
		t.Fatalf("HTTP status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "risk-gateway-keepalive") {
		t.Fatalf("heartbeat committed before prompt upstream error: %q", recorder.Body.String())
	}
}
