from pathlib import Path

path = Path(__file__).with_name("apply-auto-body-timeline-role-audit.py")
source = path.read_text(encoding="utf-8")
source = source.replace('    """ALTER TABLE request_traces ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;\\n"', '    "ALTER TABLE request_traces ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;\\n"', 1)
source = source.replace('    """# 自动请求体、时间线与角色感知审计\\n\\n"', '    "# 自动请求体、时间线与角色感知审计\\n\\n"', 1)


def remove_labeled_call(program: str, label: str, call_prefix: str) -> str:
    label_pos = program.index(f'"{label}"')
    block_start = program.rfind(call_prefix, 0, label_pos)
    if block_start < 0:
        raise SystemExit(f"{label}: call start not found")
    block_end = program.index("\n)\n", label_pos) + len("\n)\n")
    return program[:block_start] + program[block_end:]


# PR #13 inserted request-limit diagnostics into the detail field sequence, so
# apply that small Web addition after the main script against the current tree.
source = remove_labeled_call(
    source,
    "web trace detail correlation fields",
    "web = replace_once(",
)

# The original staged replacement used a repeated `trace.RequestBytes` line as
# its end marker. Patch this block after the main script using the stable
# boundary immediately before `trace.Model = ExtractRequestedModel(body)`.
source = remove_labeled_call(
    source,
    "gateway automatic body admission block",
    "gateway = replace_range(",
)

code = compile(source, str(path), "exec")
exec(code, {"__name__": "__main__", "__file__": str(path)})

root = path.parents[1]
gateway_path = root / "internal/platform/gateway.go"
gateway = gateway_path.read_text(encoding="utf-8")
start_marker = "\t// If Content-Length is present we know the exact size before reading."
end_marker = "\ttrace.Model = ExtractRequestedModel(body)"
start = gateway.find(start_marker)
end = gateway.find(end_marker, start)
if start < 0 or end < 0:
    raise SystemExit("stable gateway body-admission boundaries were not found")

body_block = r'''	bodyPolicy := resolveRequestBodyLimit(g.cfg.RequestMaxBytes, g.cfg.RequestHardMaxBytes, r.ContentLength)
	trace.Metadata["request_body_limit_mode"] = bodyPolicy.Mode
	trace.Metadata["request_body_effective_limit_bytes"] = bodyPolicy.EffectiveLimitBytes
	trace.Metadata["request_body_hard_limit_bytes"] = bodyPolicy.HardLimitBytes
	if bodyPolicy.ConfiguredLimitBytes > 0 {
		trace.Metadata["request_body_configured_limit_bytes"] = bodyPolicy.ConfiguredLimitBytes
	}

	// In automatic mode a known Content-Length is admitted at its actual size
	// up to the hard ceiling. This lets large but valid NewAPI payloads pass
	// without an operator manually chasing each observed body size.
	if bodyPolicy.ExceedsKnownLength(r.ContentLength) {
		reason := markRequestTooLarge(&trace, r.ContentLength, bodyPolicy, true)
		w.Header().Set("X-Risk-Request-Bytes", fmt.Sprintf("%d", trace.RequestBytes))
		w.Header().Set("X-Risk-Request-Limit-Bytes", fmt.Sprintf("%d", bodyPolicy.EffectiveLimitBytes))
		w.Header().Set("X-Risk-Request-Hard-Limit-Bytes", fmt.Sprintf("%d", bodyPolicy.HardLimitBytes))
		w.Header().Set("X-Risk-Request-Limit-Mode", bodyPolicy.Mode)
		w.Header().Set("X-Risk-Request-Size-Exact", "true")
		finish("error", "REQUEST_TOO_LARGE", g.cfg.ErrorHTTPStatus, 0, 0)
		writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "REQUEST_TOO_LARGE", reason)
		return
	}

	if requestBodyNeedsLargeSlot(r.ContentLength, g.cfg.LargeRequestThresholdBytes) {
		select {
		case g.largeBodies <- struct{}{}:
			defer func() { <-g.largeBodies }()
			trace.Metadata["large_request_slot"] = true
			trace.Metadata["large_request_max_concurrency"] = g.cfg.LargeRequestMaxConcurrency
		default:
			trace.Metadata["error_origin"] = "risk_gateway"
			trace.Metadata["failure_stage"] = "gateway_ingress"
			trace.Metadata["failure_component"] = "large_request_memory_guard"
			trace.Metadata["error_reason"] = "large request concurrency limit reached; retry when another large request finishes"
			finish("error", "LARGE_REQUEST_CONCURRENCY_LIMITED", http.StatusServiceUnavailable, 0, 0)
			w.Header().Set("Retry-After", "1")
			writeGatewayError(w, http.StatusServiceUnavailable, requestID, "LARGE_REQUEST_CONCURRENCY_LIMITED", "large request concurrency limit reached")
			return
		}
	}

	bodyReader := http.MaxBytesReader(w, r.Body, bodyPolicy.EffectiveLimitBytes)
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			// Unknown-length requests are read only to the effective safety
			// boundary. Record a lower bound rather than claiming an exact size.
			observed := bodyPolicy.EffectiveLimitBytes + 1
			if int64(len(body)) > observed {
				observed = int64(len(body))
			}
			reason := markRequestTooLarge(&trace, observed, bodyPolicy, false)
			w.Header().Set("X-Risk-Request-Bytes", fmt.Sprintf("%d", trace.RequestBytes))
			w.Header().Set("X-Risk-Request-Limit-Bytes", fmt.Sprintf("%d", bodyPolicy.EffectiveLimitBytes))
			w.Header().Set("X-Risk-Request-Hard-Limit-Bytes", fmt.Sprintf("%d", bodyPolicy.HardLimitBytes))
			w.Header().Set("X-Risk-Request-Limit-Mode", bodyPolicy.Mode)
			w.Header().Set("X-Risk-Request-Size-Exact", "false")
			finish("error", "REQUEST_TOO_LARGE", g.cfg.ErrorHTTPStatus, 0, 0)
			writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "REQUEST_TOO_LARGE", reason)
			return
		}
		trace.RequestBytes = int64(len(body))
		trace.Metadata["error_class"] = "request_body_read"
		trace.Metadata["error_reason"] = truncateString("failed to read request body: "+err.Error(), auditDiagnosticTextLimit)
		finish("error", "REQUEST_READ_ERROR", g.cfg.ErrorHTTPStatus, 0, 0)
		writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "REQUEST_READ_ERROR", "gateway could not read the request body")
		return
	}
	trace.RequestBytes = int64(len(body))
'''
gateway = gateway[:start] + body_block + gateway[end:]
gateway_path.write_text(gateway, encoding="utf-8")

web_path = root / "internal/platform/web/index.html"
web = web_path.read_text(encoding="utf-8")
anchor = "          ['建议请求体上限',item.metadata?.request_body_recommended_limit_bytes?byteText(item.metadata.request_body_recommended_limit_bytes):'-'], ['解决建议',item.metadata?.request_body_remediation||'-'], ['上游错误原因',item.metadata?.upstream_error_reason||'-'],\n"
addition = anchor + "          ['请求 ID 来源',item.metadata?.request_id_source||'-'], ['时间持续',item.metadata?.timeline_duration_ms!=null?`${number(item.metadata.timeline_duration_ms)} ms`:'-'], ['跟踪时间来源',item.metadata?.tracking_time_source||'gateway'], ['NewAPI→入库偏差',item.metadata?.tracking_clock_offset_ms!=null?`${number(item.metadata.tracking_clock_offset_ms)} ms`:'-'],\n"
if web.count(anchor) != 1:
    raise SystemExit(f"current Web correlation anchor count={web.count(anchor)}")
web_path.write_text(web.replace(anchor, addition, 1), encoding="utf-8")
