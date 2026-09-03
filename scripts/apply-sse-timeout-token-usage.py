from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


# ---------------------------------------------------------------------------
# Gateway: route timeout is total for buffered responses, but an idle timeout
# for SSE streams. Capture exact upstream usage while proxying.
# ---------------------------------------------------------------------------
gateway = ROOT / "internal/platform/gateway.go"
replace_once(
    gateway,
    '''\trequestContext, cancel := context.WithTimeout(r.Context(), timeout)
\tdefer cancel()
\tupstreamRequest = upstreamRequest.WithContext(requestContext)
\tresponse, err := g.client.Do(upstreamRequest)
\tif err != nil {
\t\triskCode := "UPSTREAM_CONNECTION_ERROR"
\t\tif errors.Is(err, context.DeadlineExceeded) || errors.Is(requestContext.Err(), context.DeadlineExceeded) {
\t\t\triskCode = "UPSTREAM_TIMEOUT"
\t\t}
\t\ttrace.Metadata["failure_stage"] = "upstream_connect"
\t\ttrace.Metadata["error_class"] = riskCode
\t\tfinish("error", riskCode, g.cfg.ErrorHTTPStatus, 0, 0)
\t\twriteRiskError(w, g.cfg.ErrorHTTPStatus, requestID, riskCode, "upstream model request failed")
\t\treturn
\t}
\tdefer response.Body.Close()
\tif response.StatusCode < 200 || response.StatusCode >= 300 {
\t\tfailureBody, _ := io.ReadAll(io.LimitReader(response.Body, adaptiveProviderErrorLimit))
\t\t_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
\t\tg.audit.ObserveUpstreamFailure(
\t\t\troute,
\t\t\trequestID,
\t\t\tclientIdentity,
\t\t\tbody,
\t\t\tresponse.StatusCode,
\t\t\t"UPSTREAM_MODEL_ERROR",
\t\t\tfailureBody,
\t\t)
\t\ttrace.Metadata["error_class"] = "upstream_http_error"
\t\trecordUpstreamFailureMetadata(&trace, "UPSTREAM_MODEL_ERROR", response.StatusCode, failureBody, "upstream_http")
\t\tfinish("error", "UPSTREAM_MODEL_ERROR", g.cfg.ErrorHTTPStatus, response.StatusCode, 0)
\t\twriteRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "UPSTREAM_MODEL_ERROR", "upstream model returned an error")
\t\treturn
\t}

\tif strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
\t\tbytesWritten, riskCode, status, failureEvidence, streamCommitted := g.proxySSE(w, response, requestID)
\t\tif riskCode != "" {
\t\t\tif riskCode == "UPSTREAM_STREAM_ERROR" {
\t\t\t\tg.audit.ObserveUpstreamFailure(route, requestID, clientIdentity, body, response.StatusCode, riskCode, failureEvidence)
\t\t\t}
\t\t\tstage := "upstream_stream"
\t\t\tif riskCode == "CLIENT_DISCONNECT" {
\t\t\t\tstage = "client_disconnect"
\t\t\t}
\t\t\trecordUpstreamFailureMetadata(&trace, riskCode, response.StatusCode, failureEvidence, stage)
\t\t\tif streamCommitted && (riskCode == "UPSTREAM_STREAM_ERROR" || riskCode == "UPSTREAM_STREAM_INTERRUPTED") {
\t\t\t\ttrace.Metadata["stream_error_semantics"] = "logical_555_after_headers"
\t\t\t}
\t\t\tfinish("error", riskCode, status, response.StatusCode, bytesWritten)
\t\t\treturn
\t\t}
\t\tfinish(DecisionAllow, "", status, response.StatusCode, bytesWritten)
\t\treturn
\t}

\tbytesWritten, riskCode, status, failureEvidence := g.proxyBuffered(w, response, requestID)
\tif riskCode != "" {
\t\tif riskCode == "UPSTREAM_MODEL_ERROR" {
\t\t\tg.audit.ObserveUpstreamFailure(route, requestID, clientIdentity, body, response.StatusCode, riskCode, failureEvidence)
\t\t}
\t\tstage := "upstream_response"
\t\tif riskCode == "CLIENT_DISCONNECT" {
\t\t\tstage = "client_disconnect"
\t\t}
\t\trecordUpstreamFailureMetadata(&trace, riskCode, response.StatusCode, failureEvidence, stage)
\t\tfinish("error", riskCode, status, response.StatusCode, bytesWritten)
\t\treturn
\t}
\tfinish(DecisionAllow, "", status, response.StatusCode, bytesWritten)
''',
    '''\trequestContext, cancelRequest := context.WithCancelCause(r.Context())
\trequestTimer := time.AfterFunc(timeout, func() {
\t\tcancelRequest(errUpstreamRequestTimeout)
\t})
\tdefer func() {
\t\trequestTimer.Stop()
\t\tcancelRequest(context.Canceled)
\t}()
\tupstreamRequest = upstreamRequest.WithContext(requestContext)
\tupstreamStarted := time.Now()
\tresponse, err := g.client.Do(upstreamRequest)
\ttrace.Metadata["upstream_header_latency_ms"] = time.Since(upstreamStarted).Milliseconds()
\tif err != nil {
\t\triskCode := "UPSTREAM_CONNECTION_ERROR"
\t\tif errors.Is(context.Cause(requestContext), errUpstreamRequestTimeout) ||
\t\t\terrors.Is(err, context.DeadlineExceeded) || errors.Is(context.Cause(requestContext), context.DeadlineExceeded) {
\t\t\triskCode = "UPSTREAM_TIMEOUT"
\t\t}
\t\ttrace.Metadata["failure_stage"] = "upstream_connect"
\t\ttrace.Metadata["error_class"] = riskCode
\t\tfinish("error", riskCode, g.cfg.ErrorHTTPStatus, 0, 0)
\t\twriteRiskError(w, g.cfg.ErrorHTTPStatus, requestID, riskCode, "upstream model request failed")
\t\treturn
\t}
\tdefer response.Body.Close()
\tif response.StatusCode < 200 || response.StatusCode >= 300 {
\t\tfailureBody, _ := io.ReadAll(io.LimitReader(response.Body, adaptiveProviderErrorLimit))
\t\t_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
\t\tg.audit.ObserveUpstreamFailure(
\t\t\troute,
\t\t\trequestID,
\t\t\tclientIdentity,
\t\t\tbody,
\t\t\tresponse.StatusCode,
\t\t\t"UPSTREAM_MODEL_ERROR",
\t\t\tfailureBody,
\t\t)
\t\ttrace.Metadata["error_class"] = "upstream_http_error"
\t\trecordUpstreamFailureMetadata(&trace, "UPSTREAM_MODEL_ERROR", response.StatusCode, failureBody, "upstream_http")
\t\tfinish("error", "UPSTREAM_MODEL_ERROR", g.cfg.ErrorHTTPStatus, response.StatusCode, 0)
\t\twriteRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "UPSTREAM_MODEL_ERROR", "upstream model returned an error")
\t\treturn
\t}

\tisEventStream := strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream")
\tif isEventStream {
\t\t// request_timeout_ms used to be a hard wall-clock deadline for the full
\t\t// generation. A 4,970-token response at 41 t/s already takes more than
\t\t// 120 seconds, so healthy streams were canceled and mislabeled as
\t\t// UPSTREAM_STREAM_INTERRUPTED. Once SSE headers arrive, use the route
\t\t// timeout as an inactivity deadline that is reset by every SSE event.
\t\trequestTimer.Stop()
\t\ttrace.Metadata["upstream_timeout_scope"] = "response_headers_then_stream_idle"
\t\ttrace.Metadata["upstream_stream_idle_timeout_ms"] = timeout.Milliseconds()
\t\tstreamIdleTimer := time.AfterFunc(timeout, func() {
\t\t\tcancelRequest(errUpstreamStreamIdleTimeout)
\t\t})
\t\tresetStreamIdleTimer := func() {
\t\t\tstreamIdleTimer.Reset(timeout)
\t\t}
\t\tvar observation upstreamResponseObservation
\t\tbytesWritten, riskCode, status, failureEvidence, streamCommitted := g.proxySSE(
\t\t\tw, response, requestID, &observation, resetStreamIdleTimer,
\t\t)
\t\tstreamIdleTimer.Stop()
\t\trecordUpstreamObservationMetadata(&trace, observation)
\t\tif riskCode != "" {
\t\t\tif riskCode == "UPSTREAM_STREAM_ERROR" {
\t\t\t\tg.audit.ObserveUpstreamFailure(route, requestID, clientIdentity, body, response.StatusCode, riskCode, failureEvidence)
\t\t\t}
\t\t\tstage := "upstream_stream"
\t\t\tif riskCode == "CLIENT_DISCONNECT" {
\t\t\t\tstage = "client_disconnect"
\t\t\t}
\t\t\trecordUpstreamFailureMetadata(&trace, riskCode, response.StatusCode, failureEvidence, stage)
\t\t\tif streamCommitted && (riskCode == "UPSTREAM_STREAM_ERROR" || riskCode == "UPSTREAM_STREAM_INTERRUPTED" || riskCode == "UPSTREAM_STREAM_TIMEOUT") {
\t\t\t\ttrace.Metadata["stream_error_semantics"] = "logical_555_after_headers"
\t\t\t}
\t\t\tfinish("error", riskCode, status, response.StatusCode, bytesWritten)
\t\t\treturn
\t\t}
\t\tfinish(DecisionAllow, "", status, response.StatusCode, bytesWritten)
\t\treturn
\t}

\ttrace.Metadata["upstream_timeout_scope"] = "full_response"
\tvar observation upstreamResponseObservation
\tbytesWritten, riskCode, status, failureEvidence := g.proxyBuffered(w, response, requestID, &observation)
\trecordUpstreamObservationMetadata(&trace, observation)
\tif riskCode != "" {
\t\tif riskCode == "UPSTREAM_MODEL_ERROR" {
\t\t\tg.audit.ObserveUpstreamFailure(route, requestID, clientIdentity, body, response.StatusCode, riskCode, failureEvidence)
\t\t}
\t\tstage := "upstream_response"
\t\tif riskCode == "CLIENT_DISCONNECT" {
\t\t\tstage = "client_disconnect"
\t\t}
\t\trecordUpstreamFailureMetadata(&trace, riskCode, response.StatusCode, failureEvidence, stage)
\t\tfinish("error", riskCode, status, response.StatusCode, bytesWritten)
\t\treturn
\t}
\tfinish(DecisionAllow, "", status, response.StatusCode, bytesWritten)
''',
    "gateway upstream timeout and usage flow",
)

replace_once(
    gateway,
    '''func (g *Gateway) proxyBuffered(
\tw http.ResponseWriter,
\tresponse *http.Response,
\trequestID string,
) (int64, string, int, []byte) {
\tprefix, err := io.ReadAll(io.LimitReader(response.Body, g.cfg.ResponseInspectMaxBytes+1))
\tif err != nil {
\t\twriteRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "UPSTREAM_READ_ERROR", "upstream model response failed")
\t\treturn 0, "UPSTREAM_READ_ERROR", g.cfg.ErrorHTTPStatus, nil
\t}
\tif int64(len(prefix)) <= g.cfg.ResponseInspectMaxBytes && responseContainsErrorEnvelope(prefix) {
\t\twriteRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "UPSTREAM_MODEL_ERROR", "upstream model returned an error")
\t\treturn 0, "UPSTREAM_MODEL_ERROR", g.cfg.ErrorHTTPStatus, append([]byte(nil), prefix...)
\t}
\tcopyResponseHeaders(w.Header(), response.Header)
\tw.Header().Set("X-Risk-Request-ID", requestID)
\tw.WriteHeader(response.StatusCode)
\twritten, writeError := w.Write(prefix)
\ttotal := int64(written)
\tif writeError == nil && int64(len(prefix)) > g.cfg.ResponseInspectMaxBytes {
\t\tcopied, copyError := io.Copy(w, response.Body)
\t\ttotal += copied
\t\twriteError = copyError
\t}
\tif writeError != nil {
\t\treturn total, "CLIENT_DISCONNECT", response.StatusCode, nil
\t}
\treturn total, "", response.StatusCode, nil
}
''',
    '''func (g *Gateway) proxyBuffered(
\tw http.ResponseWriter,
\tresponse *http.Response,
\trequestID string,
\tobservation *upstreamResponseObservation,
) (int64, string, int, []byte) {
\tstarted := time.Now()
\tdefer func() {
\t\tif observation != nil {
\t\t\tobservation.Duration = time.Since(started)
\t\t}
\t}()
\tprefix, err := io.ReadAll(io.LimitReader(response.Body, g.cfg.ResponseInspectMaxBytes+1))
\tif err != nil {
\t\tif observation != nil {
\t\t\tobservation.ReadError = err.Error()
\t\t}
\t\twriteRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "UPSTREAM_READ_ERROR", "upstream model response failed")
\t\treturn 0, "UPSTREAM_READ_ERROR", g.cfg.ErrorHTTPStatus, []byte("upstream buffered response read failed: " + err.Error())
\t}
\tcompleteBody := int64(len(prefix)) <= g.cfg.ResponseInspectMaxBytes
\tif observation != nil {
\t\tobservation.ObserveBufferedBody(prefix, completeBody)
\t}
\tif completeBody && responseContainsErrorEnvelope(prefix) {
\t\twriteRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "UPSTREAM_MODEL_ERROR", "upstream model returned an error")
\t\treturn 0, "UPSTREAM_MODEL_ERROR", g.cfg.ErrorHTTPStatus, append([]byte(nil), prefix...)
\t}
\tcopyResponseHeaders(w.Header(), response.Header)
\tw.Header().Set("X-Risk-Request-ID", requestID)
\tw.WriteHeader(response.StatusCode)
\twritten, writeError := w.Write(prefix)
\ttotal := int64(written)
\tif writeError == nil && !completeBody {
\t\tcopied, copyError := io.Copy(w, response.Body)
\t\ttotal += copied
\t\twriteError = copyError
\t\tif writeError == nil && observation != nil {
\t\t\tobservation.CompletionObserved = true
\t\t\tobservation.CompletionSemantics = "buffered_response_streamed"
\t\t}
\t}
\tif writeError != nil {
\t\treturn total, "CLIENT_DISCONNECT", response.StatusCode, nil
\t}
\treturn total, "", response.StatusCode, nil
}
''',
    "buffered upstream usage",
)

start = gateway.read_text(encoding="utf-8").index("func (g *Gateway) proxySSE(")
end = gateway.read_text(encoding="utf-8").index("func nextSSEEvent(", start)
text = gateway.read_text(encoding="utf-8")
new_proxy_sse = '''func (g *Gateway) proxySSE(
\tw http.ResponseWriter,
\tresponse *http.Response,
\trequestID string,
\tobservation *upstreamResponseObservation,
\tonProgress func(),
) (int64, string, int, []byte, bool) {
\tstarted := time.Now()
\tdefer func() {
\t\tif observation != nil {
\t\t\tobservation.Duration = time.Since(started)
\t\t}
\t}()
\tobserveEvent := func(event []string) {
\t\tif onProgress != nil {
\t\t\tonProgress()
\t\t}
\t\tif observation != nil {
\t\t\tobservation.ObserveSSEEvent(event)
\t\t}
\t}
\treadFailure := func(readError error) (string, []byte) {
\t\tif observation != nil {
\t\t\tobservation.ReadError = readError.Error()
\t\t}
\t\treturn classifyUpstreamStreamReadError(response, readError)
\t}

\tscanner := bufio.NewScanner(response.Body)
\tscanner.Buffer(make([]byte, 64*1024), g.cfg.SSELineMaxBytes)
\tbuffered := make([][]string, 0, 4)
\tbufferedBytes := 0
\tfor len(buffered) < 16 && bufferedBytes < 64*1024 {
\t\tevent, ok, err := nextSSEEvent(scanner)
\t\tif err != nil {
\t\t\triskCode, evidence := readFailure(err)
\t\t\tif riskCode != "CLIENT_DISCONNECT" {
\t\t\t\twriteRiskError(w, g.cfg.ErrorHTTPStatus, requestID, riskCode, "upstream stream failed before starting")
\t\t\t}
\t\t\treturn 0, riskCode, g.cfg.ErrorHTTPStatus, evidence, false
\t\t}
\t\tif !ok {
\t\t\tbreak
\t\t}
\t\tobserveEvent(event)
\t\tif isSSEErrorEvent(event) {
\t\t\twriteRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "UPSTREAM_STREAM_ERROR", "upstream model returned a stream error")
\t\t\treturn 0, "UPSTREAM_STREAM_ERROR", g.cfg.ErrorHTTPStatus, sseEventEvidence(event), false
\t\t}
\t\tbuffered = append(buffered, event)
\t\tbufferedBytes += sseEventSize(event)
\t\tif isMeaningfulSSEEvent(event) {
\t\t\tbreak
\t\t}
\t}

\tcopyResponseHeaders(w.Header(), response.Header)
\tw.Header().Set("X-Risk-Request-ID", requestID)
\tw.WriteHeader(response.StatusCode)
\tflusher, canFlush := w.(http.Flusher)
\tvar total int64
\twriteEvent := func(lines []string) error {
\t\tfor _, line := range lines {
\t\t\tcount, err := io.WriteString(w, line+"\\n")
\t\t\ttotal += int64(count)
\t\t\tif err != nil {
\t\t\t\treturn err
\t\t\t}
\t\t}
\t\tif canFlush {
\t\t\tflusher.Flush()
\t\t}
\t\treturn nil
\t}
\tfor _, event := range buffered {
\t\tif err := writeEvent(event); err != nil {
\t\t\treturn total, "CLIENT_DISCONNECT", response.StatusCode, nil, true
\t\t}
\t}
\tfor {
\t\tevent, hasEvent, readError := nextSSEEvent(scanner)
\t\tif readError != nil {
\t\t\tif observation != nil {
\t\t\t\tobservation.ReadError = readError.Error()
\t\t\t\tif observation.CompletionObserved {
\t\t\t\t\tobservation.TransportClosedAfterTerminal = true
\t\t\t\t\tif observation.CompletionSemantics != "" {
\t\t\t\t\t\tobservation.CompletionSemantics += "_then_transport_close"
\t\t\t\t\t}
\t\t\t\t\t// A provider may close with a TCP reset immediately after a
\t\t\t\t\t// valid finish_reason/[DONE]/response.completed event. The
\t\t\t\t\t// generation is already complete and must not become a false 555.
\t\t\t\t\treturn total, "", response.StatusCode, nil, true
\t\t\t\t}
\t\t\t}
\t\t\triskCode, evidence := readFailure(readError)
\t\t\tif riskCode == "CLIENT_DISCONNECT" {
\t\t\t\treturn total, riskCode, response.StatusCode, nil, true
\t\t\t}
\t\twritten, _ := writeSSELogicalError(w, requestID, riskCode)
\t\ttotal += written
\t\tif canFlush {
\t\t\tflusher.Flush()
\t\t}
\t\treturn total, riskCode, response.StatusCode, evidence, true
\t\t}
\t\tif !hasEvent {
\t\t\tif observation != nil && observation.CompletionSemantics == "" {
\t\t\t\tobservation.CompletionSemantics = "clean_eof"
\t\t\t}
\t\t\tbreak
\t\t}
\t\tobserveEvent(event)
\t\tif isSSEErrorEvent(event) {
\t\t\twritten, _ := writeSSELogicalError(w, requestID, "UPSTREAM_STREAM_ERROR")
\t\t\ttotal += written
\t\t\tif canFlush {
\t\t\t\tflusher.Flush()
\t\t\t}
\t\t\treturn total, "UPSTREAM_STREAM_ERROR", response.StatusCode, sseEventEvidence(event), true
\t\t}
\t\tif err := writeEvent(event); err != nil {
\t\t\treturn total, "CLIENT_DISCONNECT", response.StatusCode, nil, true
\t\t}
\t}
\treturn total, "", response.StatusCode, nil, true
}

'''
gateway.write_text(text[:start] + new_proxy_sse + text[end:], encoding="utf-8")

replace_once(
    gateway,
    "\t\tResponseHeaderTimeout: 120 * time.Second,\n",
    "\t\t// Route request_timeout_ms controls response-header timeouts. Keeping\n"
    "\t\t// another fixed 120-second transport deadline would silently override\n"
    "\t\t// routes configured with a larger value.\n"
    "\t\tResponseHeaderTimeout: 0,\n",
    "remove hidden transport header timeout",
)

# ---------------------------------------------------------------------------
# Human-readable timeout diagnosis.
# ---------------------------------------------------------------------------
diagnostics = ROOT / "internal/platform/audit_diagnostics.go"
replace_once(
    diagnostics,
    '''\tcase "UPSTREAM_STREAM_INTERRUPTED":
\t\treturn "真实上游流式连接在完成前中断"
\tcase "UPSTREAM_READ_ERROR":
''',
    '''\tcase "UPSTREAM_STREAM_INTERRUPTED":
\t\treturn "真实上游流式连接在完成前中断；查看流读取诊断和完成标记"
\tcase "UPSTREAM_STREAM_TIMEOUT":
\t\treturn "真实上游流式响应超过配置的空闲超时；只有连续无事件才会触发，不再限制总生成时长"
\tcase "UPSTREAM_READ_ERROR":
''',
    "stream timeout diagnostic",
)

# ---------------------------------------------------------------------------
# Web: show upstream input/output/cache tokens in the same compact form as
# NewAPI, plus exact stream completion and timeout diagnostics.
# ---------------------------------------------------------------------------
web = ROOT / "internal/platform/web/index.html"
replace_once(
    web,
    '''      function renderTraceTable(items) {
''',
    '''      function traceUpstreamUsage(item) {
        const metadata=item.metadata||{};
        const input=Number(metadata.upstream_input_tokens??metadata.input_tokens??metadata.prompt_tokens??0);
        const output=Number(metadata.upstream_output_tokens??metadata.output_tokens??metadata.completion_tokens??0);
        const total=Number(metadata.upstream_total_tokens??metadata.total_tokens??0);
        const cached=Number(metadata.upstream_cached_tokens??metadata.cached_tokens??0);
        const reasoning=Number(metadata.upstream_reasoning_tokens??metadata.reasoning_tokens??0);
        const rate=Number(metadata.upstream_output_tokens_per_second||0);
        return {input,output,total,cached,reasoning,rate};
      }
      function renderTraceTable(items) {
''',
    "web upstream usage helper",
)
replace_once(
    web,
    '''          const inputTokens=Number(item.metadata?.audit_input_tokens||item.metadata?.audit_requested_tokens||0);const contextTokens=Number(item.metadata?.audit_context_window_tokens||0);const overTokens=Number(item.metadata?.audit_tokens_over_limit||0);const tokenLine=inputTokens?`<span class="trace-subline mono">Tokens ${number(inputTokens)}${contextTokens?` / ${number(contextTokens)}`:''}${overTokens?` · 超 ${number(overTokens)}`:''}</span>`:'';
''',
    '''          const inputTokens=Number(item.metadata?.audit_input_tokens||item.metadata?.audit_requested_tokens||0);const contextTokens=Number(item.metadata?.audit_context_window_tokens||0);const overTokens=Number(item.metadata?.audit_tokens_over_limit||0);const tokenLine=inputTokens?`<span class="trace-subline mono">审计 Tokens ${number(inputTokens)}${contextTokens?` / ${number(contextTokens)}`:''}${overTokens?` · 超 ${number(overTokens)}`:''}</span>`:'';
          const upstreamUsage=traceUpstreamUsage(item);const upstreamUsageLine=(upstreamUsage.input||upstreamUsage.output)?`<span class="trace-subline mono">输入 / 输出 ${number(upstreamUsage.input)} / ${number(upstreamUsage.output)}</span>${upstreamUsage.cached?`<span class="trace-subline mono">缓存：${number(upstreamUsage.cached)}</span>`:''}${upstreamUsage.rate?`<span class="trace-subline mono">${upstreamUsage.rate.toFixed(1)} t/s</span>`:''}`:'';
''',
    "web table upstream usage values",
)
replace_once(
    web,
    '''<td>${escapeHTML(item.model||'-')}<span class="trace-subline mono">${escapeHTML(item.endpoint||'-')}</span></td><td>${badge(item.decision||'unknown')}''',
    '''<td>${escapeHTML(item.model||'-')}<span class="trace-subline mono">${escapeHTML(item.endpoint||'-')}</span>${upstreamUsageLine}</td><td>${badge(item.decision||'unknown')}''',
    "web table model usage placement",
)
replace_once(
    web,
    '''        if (!item) return;
        const fields = [
''',
    '''        if (!item) return;
        const upstreamUsage=traceUpstreamUsage(item);
        const fields = [
''',
    "web detail usage variable",
)
replace_once(
    web,
    '''          ['HTTP 状态',item.http_status||'-'], ['上游状态',item.upstream_status||'-'], ['总延迟',`${number(item.latency_ms)} ms`],
''',
    '''          ['HTTP 状态',item.http_status||'-'], ['上游状态',item.upstream_status||'-'], ['总延迟',`${number(item.latency_ms)} ms`],
          ['上游输入 Tokens',upstreamUsage.input||'-'], ['上游输出 Tokens',upstreamUsage.output||'-'], ['上游总 Tokens',upstreamUsage.total||'-'],
          ['上游缓存 Tokens',upstreamUsage.cached||'-'], ['上游推理 Tokens',upstreamUsage.reasoning||'-'], ['上游输出速度',upstreamUsage.rate?`${upstreamUsage.rate.toFixed(2)} t/s`:'-'],
          ['Token 用量来源',item.metadata?.upstream_usage_source||'-'], ['Token 是否精确',item.metadata?.upstream_usage_exact===true?'是（上游 usage）':(item.metadata?.upstream_usage_exact===false?'否':'-')],
          ['上游响应头耗时',item.metadata?.upstream_header_latency_ms!=null?`${number(item.metadata.upstream_header_latency_ms)} ms`:'-'], ['上游响应持续时间',item.metadata?.upstream_response_duration_ms!=null?`${number(item.metadata.upstream_response_duration_ms)} ms`:'-'],
          ['上游超时语义',item.metadata?.upstream_timeout_scope||'-'], ['流完成标记',item.metadata?.upstream_completion_semantics||'-'], ['流读取诊断',item.metadata?.upstream_stream_read_error||'-'],
''',
    "web detail upstream usage fields",
)
replace_once(
    web,
    '''const header = ['created_at','request_id','newapi_request_id','external_event_id','external_user_id','tenant_id','source','route_slug','model','endpoint','decision','risk_code','reason','audit_model_decision','audit_model_confidence','audit_model_evidence','audit_model_evidence_context','audit_model_evidence_verified','audit_model_evidence_chunk_index','audit_model_evidence_chunk_count','audit_error_class','audit_http_status','http_status','upstream_status','latency_ms','audit_latency_ms','request_bytes','request_body_limit_bytes','request_body_over_limit_bytes','request_body_size_exact','response_bytes','prompt_hmac','metadata'];
''',
    '''const header = ['created_at','request_id','newapi_request_id','external_event_id','external_user_id','tenant_id','source','route_slug','model','endpoint','decision','risk_code','reason','audit_model_decision','audit_model_confidence','audit_model_evidence','audit_model_evidence_context','audit_model_evidence_verified','audit_model_evidence_chunk_index','audit_model_evidence_chunk_count','audit_error_class','audit_http_status','http_status','upstream_status','upstream_input_tokens','upstream_output_tokens','upstream_total_tokens','upstream_cached_tokens','upstream_reasoning_tokens','upstream_output_tokens_per_second','upstream_usage_source','upstream_completion_semantics','upstream_timeout_scope','upstream_stream_read_error','latency_ms','audit_latency_ms','request_bytes','request_body_limit_bytes','request_body_over_limit_bytes','request_body_size_exact','response_bytes','prompt_hmac','metadata'];
''',
    "CSV token headers",
)
replace_once(
    web,
    '''item.metadata?.audit_error_class,item.metadata?.audit_http_status,item.http_status,item.upstream_status,item.latency_ms,item.audit_latency_ms''',
    '''item.metadata?.audit_error_class,item.metadata?.audit_http_status,item.http_status,item.upstream_status,item.metadata?.upstream_input_tokens,item.metadata?.upstream_output_tokens,item.metadata?.upstream_total_tokens,item.metadata?.upstream_cached_tokens,item.metadata?.upstream_reasoning_tokens,item.metadata?.upstream_output_tokens_per_second,item.metadata?.upstream_usage_source,item.metadata?.upstream_completion_semantics,item.metadata?.upstream_timeout_scope,item.metadata?.upstream_stream_read_error,item.latency_ms,item.audit_latency_ms''',
    "CSV token rows",
)

# ---------------------------------------------------------------------------
# Mock provider and E2E: prove a stream can run longer than route timeout as
# long as it keeps producing events, and prove usage is persisted.
# ---------------------------------------------------------------------------
mock = ROOT / "cmd/mockprovider/main.go"
replace_once(
    mock,
    '''\tcase "stream-normal":
\t\tstreamNormal(w)
\t\treturn
\t}
''',
    '''\tcase "stream-normal":
\t\tstreamNormal(w)
\t\treturn
\tcase "stream-slow-usage":
\t\tstreamSlowUsage(w)
\t\treturn
\tcase "buffered-usage":
\t\tbufferedUsage(w)
\t\treturn
\t}
''',
    "mock usage routes",
)
replace_once(
    mock,
    '''func flush(w http.ResponseWriter) {
''',
    '''func streamSlowUsage(w http.ResponseWriter) {
\tw.Header().Set("Content-Type", "text/event-stream")
\tw.WriteHeader(http.StatusOK)
\tfor index := 0; index < 8; index++ {
\t\t_, _ = fmt.Fprintf(w, "data: {\\\"choices\\\":[{\\\"delta\\\":{\\\"content\\\":\\\"part-%d \\\"}}]}\\n\\n", index)
\t\tflush(w)
\t\ttime.Sleep(75 * time.Millisecond)
\t}
\t_, _ = fmt.Fprint(w, "data: {\\\"choices\\\":[{\\\"delta\\\":{},\\\"finish_reason\\\":\\\"stop\\\"}],\\\"usage\\\":{\\\"prompt_tokens\\\":17969,\\\"completion_tokens\\\":4970,\\\"total_tokens\\\":22939,\\\"prompt_tokens_details\\\":{\\\"cached_tokens\\\":9984},\\\"completion_tokens_details\\\":{\\\"reasoning_tokens\\\":321}}}\\n\\n")
\tflush(w)
\ttime.Sleep(25 * time.Millisecond)
\t_, _ = fmt.Fprint(w, "data: [DONE]\\n\\n")
\tflush(w)
}

func bufferedUsage(w http.ResponseWriter) {
\twriteJSON(w, http.StatusOK, map[string]any{
\t\t"id": "buffered-usage",
\t\t"choices": []any{map[string]any{
\t\t\t"message":       map[string]any{"role": "assistant", "content": "usage response"},
\t\t\t"finish_reason": "stop",
\t\t}},
\t\t"usage": map[string]any{
\t\t\t"prompt_tokens":     321,
\t\t\t"completion_tokens": 45,
\t\t\t"total_tokens":      366,
\t\t},
\t})
}

func flush(w http.ResponseWriter) {
''',
    "mock slow usage stream",
)

# Fix the intentionally staged unit test import before validation.
usage_test = ROOT / "internal/platform/upstream_usage_test.go"
replace_once(
    usage_test,
    '''import (
\t"errors"
''',
    '''import (
\t"context"
\t"errors"
''',
    "usage test context import",
)

e2e = ROOT / "scripts/e2e.sh"
replace_once(
    e2e,
    '''contains "${WORKDIR}/route.json" '\"slug\":\"mock-main\"'


curl --fail''',
    '''contains "${WORKDIR}/route.json" '\"slug\":\"mock-main\"'

stream_route_payload="$(python3 - <<PY
import json
print(json.dumps({
  "id": 0,
  "slug": "mock-stream",
  "name": "E2E streaming idle-timeout route",
  "base_url": "http://mock-provider:18081",
  "provider": "generic",
  "auth_mode": "none",
  "secret_header": "",
  "upstream_secret": "",
  "inbound_key": "${ROUTE_KEY}",
  "audit_profile_id": None,
  "enabled": True,
  "fail_closed": True,
  "request_timeout_ms": 200,
  "max_concurrency": 10,
  "rate_limit_rps": 1000,
  "rate_limit_burst": 1000
}, separators=(",", ":")))
PY
)"
curl --fail --silent --show-error \\
  "${BASE_URL}/api/admin/v1/routes" \\
  "${auth[@]}" \\
  -H 'Content-Type: application/json' \\
  --data-binary "${stream_route_payload}" >"${WORKDIR}/stream-route.json"
contains "${WORKDIR}/stream-route.json" '\"slug\":\"mock-stream\"'


curl --fail''',
    "E2E streaming route",
)
replace_once(
    e2e,
    '''gateway="${BASE_URL}/gateway/mock-main/v1/chat/completions"
gateway_auth=''',
    '''gateway="${BASE_URL}/gateway/mock-main/v1/chat/completions"
stream_gateway="${BASE_URL}/gateway/mock-stream/v1/chat/completions"
gateway_auth=''',
    "E2E stream gateway URL",
)
replace_once(
    e2e,
    '''contains "${WORKDIR}/stream-normal.txt" '[DONE]'

BASE_URL=''',
    '''contains "${WORKDIR}/stream-normal.txt" '[DONE]'

# This stream runs for roughly 625 ms while its route timeout is only 200 ms.
# It must succeed because events arrive every 75 ms: request_timeout_ms is an
# SSE idle timeout, not a hard cap on total generation time.
status="$(curl --silent --show-error --no-buffer -o "${WORKDIR}/stream-slow-usage.txt" -w '%{http_code}' \\
  "${stream_gateway}" "${gateway_auth[@]}" \\
  -H 'X-Request-ID: e2e-stream-slow-usage' \\
  --data-binary '{"model":"stream-slow-usage","stream":true,"messages":[{"role":"user","content":"safe long stream with usage"}]}')"
assert_status 200 "${status}" "${WORKDIR}/stream-slow-usage.txt"
contains "${WORKDIR}/stream-slow-usage.txt" 'finish_reason'
contains "${WORKDIR}/stream-slow-usage.txt" 'prompt_tokens'
contains "${WORKDIR}/stream-slow-usage.txt" '[DONE]'

status="$(curl --silent --show-error -o "${WORKDIR}/buffered-usage.json" -w '%{http_code}' \\
  "${gateway}" "${gateway_auth[@]}" \\
  -H 'X-Request-ID: e2e-buffered-usage' \\
  --data-binary '{"model":"buffered-usage","messages":[{"role":"user","content":"safe buffered usage"}]}')"
assert_status 200 "${status}" "${WORKDIR}/buffered-usage.json"
contains "${WORKDIR}/buffered-usage.json" 'usage response'

BASE_URL=''',
    "E2E slow stream usage request",
)
replace_once(
    e2e,
    '''     grep -Fq 'e2e-stream-normal' "${WORKDIR}/traces.json" && \\
     grep -Fq 'e2e-model-block-evidence' ''',
    '''     grep -Fq 'e2e-stream-normal' "${WORKDIR}/traces.json" && \\
     grep -Fq 'e2e-stream-slow-usage' "${WORKDIR}/traces.json" && \\
     grep -Fq 'e2e-buffered-usage' "${WORKDIR}/traces.json" && \\
     grep -Fq 'e2e-model-block-evidence' ''',
    "E2E trace polling usage IDs",
)
replace_once(
    e2e,
    '''for key in ("error_reason", "failure_stage", "stream_error_semantics", "upstream_error_reason"):
    if normal_meta.get(key):
        raise RuntimeError(f"normal stream was polluted with {key}: {normal_meta}")
PY
''',
    '''for key in ("error_reason", "failure_stage", "stream_error_semantics", "upstream_error_reason"):
    if normal_meta.get(key):
        raise RuntimeError(f"normal stream was polluted with {key}: {normal_meta}")

slow_usage = next((item for item in items if item.get("request_id") == "e2e-stream-slow-usage"), None)
if not slow_usage:
    raise RuntimeError("slow usage stream trace missing")
slow_meta = slow_usage.get("metadata", {})
if slow_usage.get("decision") != "allow" or int(slow_usage.get("http_status", 0)) != 200:
    raise RuntimeError(f"healthy long SSE stream was falsely interrupted: {slow_usage}")
if int(slow_usage.get("latency_ms", 0)) <= 200:
    raise RuntimeError(f"slow stream did not exceed route timeout as intended: {slow_usage}")
for key in ("error_reason", "failure_stage", "stream_error_semantics", "upstream_error_reason"):
    if slow_meta.get(key):
        raise RuntimeError(f"healthy slow stream was polluted with {key}: {slow_meta}")
expected_usage = {
    "upstream_input_tokens": 17969,
    "upstream_output_tokens": 4970,
    "upstream_total_tokens": 22939,
    "upstream_cached_tokens": 9984,
    "upstream_reasoning_tokens": 321,
}
for key, expected in expected_usage.items():
    if int(slow_meta.get(key, 0)) != expected:
        raise RuntimeError(f"{key}={slow_meta.get(key)!r}, expected {expected}: {slow_meta}")
if slow_meta.get("upstream_usage_exact") is not True:
    raise RuntimeError(f"upstream usage was not marked exact: {slow_meta}")
if slow_meta.get("upstream_timeout_scope") != "response_headers_then_stream_idle":
    raise RuntimeError(f"SSE timeout semantics missing: {slow_meta}")
if slow_meta.get("upstream_completion_semantics") != "data_done":
    raise RuntimeError(f"SSE completion marker missing: {slow_meta}")
if float(slow_meta.get("upstream_output_tokens_per_second", 0)) <= 0:
    raise RuntimeError(f"output token rate missing: {slow_meta}")

buffered_usage = next((item for item in items if item.get("request_id") == "e2e-buffered-usage"), None)
if not buffered_usage:
    raise RuntimeError("buffered usage trace missing")
buffered_meta = buffered_usage.get("metadata", {})
if int(buffered_meta.get("upstream_input_tokens", 0)) != 321 or int(buffered_meta.get("upstream_output_tokens", 0)) != 45:
    raise RuntimeError(f"buffered token usage missing: {buffered_meta}")
PY
''',
    "E2E usage trace assertions",
)

# ---------------------------------------------------------------------------
# Operations guide.
# ---------------------------------------------------------------------------
(ROOT / "docs/upstream-stream-and-token-usage.md").write_text(
    '''# 上游流式超时与 Token 用量\n\n## 误报原因\n\n旧版把渠道路由的 `request_timeout_ms` 应用于整个 SSE 生命周期。以\n`4,970` 输出 Tokens、`41 t/s` 为例，仅解码就需要约 `121.2s`；再加上\n`17,969` 输入 Tokens 的 prefill 和网络时间，会超过常见的 `120000ms`。\n网关因此主动取消一个仍持续输出的健康流，并记录\n`UPSTREAM_STREAM_INTERRUPTED`。\n\n新版语义：\n\n- 普通非流式响应：`request_timeout_ms` 仍是完整响应超时；\n- SSE 流：收到响应头之前是建立响应超时；收到响应头之后变成**流空闲超时**；\n- 每收到一个 SSE event 都会重置空闲计时器；\n- 只要上游持续输出，总生成时间可以超过 `request_timeout_ms`；\n- 已看到 `[DONE]`、`finish_reason`、`response.completed` 或 `message_stop` 后，\n  即使服务端随后用 TCP reset 关闭连接，也按已完成处理，不再伪造逻辑 555。\n\nTrace 会记录：\n\n```text\nupstream_timeout_scope\nupstream_stream_idle_timeout_ms\nupstream_header_latency_ms\nupstream_response_duration_ms\nupstream_completion_semantics\nupstream_stream_read_error\n```\n\n## Token 用量\n\n网关会解析 OpenAI Chat Completions、Responses API、Anthropic 和 Gemini\n兼容返回中的 usage 字段，并写入：\n\n```text\nupstream_input_tokens\nupstream_output_tokens\nupstream_total_tokens\nupstream_cached_tokens\nupstream_cache_creation_tokens\nupstream_reasoning_tokens\nupstream_output_tokens_per_second\nupstream_usage_source\nupstream_usage_exact\n```\n\nWeb 请求列表以 `输入 / 输出` 的形式展示，例如：\n\n```text\n17,969 / 4,970\n缓存：9,984\n41.0 t/s\n```\n\n这些值来自上游返回的 usage，因此是精确值。若渠道没有在流中返回 usage，\n平台不会伪造精确数字；字段保持为空。对于 OpenAI 兼容流，NewAPI/调用方应\n保留 `stream_options.include_usage=true`，Responses API 通常会在\n`response.completed` 事件中携带 usage。\n''',
    encoding="utf-8",
)

print("SSE timeout and upstream token usage patch applied")
