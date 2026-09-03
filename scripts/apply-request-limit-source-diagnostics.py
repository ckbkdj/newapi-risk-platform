from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


# ---------------------------------------------------------------------------
# Gateway attribution: REQUEST_TOO_LARGE is an ingress guard, not audit/upstream.
# ---------------------------------------------------------------------------
gateway_path = ROOT / "internal/platform/gateway.go"
gateway = gateway_path.read_text(encoding="utf-8")
old_gateway = '''func markRequestTooLarge(trace *TraceEvent, requestBytes int64, limitBytes int64, exact bool) string {
	if limitBytes < 1 {
		limitBytes = 1
	}
	if requestBytes <= limitBytes {
		requestBytes = limitBytes + 1
	}
	overBytes := requestBytes - limitBytes
	trace.RequestBytes = requestBytes
	trace.Metadata["error_class"] = "request_body_too_large"
	trace.Metadata["request_body_bytes"] = requestBytes
	trace.Metadata["request_body_limit_bytes"] = limitBytes
	trace.Metadata["request_body_over_limit_bytes"] = overBytes
	trace.Metadata["request_body_size_exact"] = exact

	qualifier := ""
	if !exact {
		qualifier = "at least "
	}
	reason := fmt.Sprintf(
		"request body is %s%d bytes; gateway limit is %d bytes; over limit by %s%d bytes",
		qualifier, requestBytes, limitBytes, qualifier, overBytes,
	)
	trace.Metadata["error_reason"] = reason
	return reason
}
'''
new_gateway = '''func markRequestTooLarge(trace *TraceEvent, requestBytes int64, limitBytes int64, exact bool) string {
	if limitBytes < 1 {
		limitBytes = 1
	}
	if requestBytes <= limitBytes {
		requestBytes = limitBytes + 1
	}
	overBytes := requestBytes - limitBytes
	trace.RequestBytes = requestBytes
	trace.Metadata["error_class"] = "request_body_too_large"
	trace.Metadata["error_origin"] = "risk_gateway"
	trace.Metadata["failure_stage"] = "gateway_ingress"
	trace.Metadata["failure_component"] = "request_body_guard"
	trace.Metadata["limit_owner"] = "risk_gateway"
	trace.Metadata["limit_config"] = "REQUEST_MAX_BYTES"
	trace.Metadata["limit_scope"] = "inbound_http_request_body"
	trace.Metadata["limit_unit"] = "bytes"
	trace.Metadata["audit_started"] = false
	trace.Metadata["upstream_started"] = false
	trace.Metadata["request_body_bytes"] = requestBytes
	trace.Metadata["request_body_limit_bytes"] = limitBytes
	trace.Metadata["request_body_over_limit_bytes"] = overBytes
	trace.Metadata["request_body_size_exact"] = exact

	recommended := recommendedRequestMaxBytes(requestBytes)
	var remediation string
	if recommended > 0 {
		trace.Metadata["request_body_recommended_limit_bytes"] = recommended
		remediation = fmt.Sprintf(
			"This is a Risk Gateway ingress byte limit, not an audit-model or upstream-model limit. " +
				"For an expected trusted request, set REQUEST_MAX_BYTES=%d and restart the gateway; otherwise reduce conversation history or replace inline base64 files/images with URLs. Audit and upstream were not called.",
			recommended,
		)
	} else {
		remediation = "This is a Risk Gateway ingress byte limit, not an audit-model or upstream-model limit. " +
			"The request exceeds the supported 64 MiB body ceiling; reduce or split the payload, or replace inline base64 files/images with URLs. Audit and upstream were not called."
	}
	trace.Metadata["request_body_remediation"] = remediation

	qualifier := ""
	if !exact {
		qualifier = "at least "
	}
	reason := fmt.Sprintf(
		"Risk Gateway ingress rejected the request before audit and upstream: request body is %s%d bytes; REQUEST_MAX_BYTES is %d bytes; over limit by %s%d bytes",
		qualifier, requestBytes, limitBytes, qualifier, overBytes,
	)
	trace.Metadata["error_reason"] = reason
	return reason
}
'''
gateway = replace_once(gateway, old_gateway, new_gateway, "gateway request-size attribution")
gateway_path.write_text(gateway, encoding="utf-8")

helper_path = ROOT / "internal/platform/request_limit_source.go"
helper_path.write_text('''package platform

const (
	minimumRecommendedRequestMaxBytes int64 = 8 * 1024 * 1024
	maximumSupportedRequestMaxBytes   int64 = 64 * 1024 * 1024
)

// recommendedRequestMaxBytes returns a power-of-two limit that can contain the
// observed request without silently exceeding the platform's supported 64 MiB
// ceiling. A zero result means the caller must reduce or externalize payloads.
func recommendedRequestMaxBytes(requestBytes int64) int64 {
	if requestBytes <= 0 || requestBytes > maximumSupportedRequestMaxBytes {
		return 0
	}
	limit := minimumRecommendedRequestMaxBytes
	for limit < requestBytes && limit < maximumSupportedRequestMaxBytes {
		limit *= 2
	}
	if limit > maximumSupportedRequestMaxBytes {
		return 0
	}
	return limit
}
''', encoding="utf-8")

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
test_path = ROOT / "internal/platform/request_size_diagnostics_test.go"
test = test_path.read_text(encoding="utf-8")
test = replace_once(
    test,
    '''	if !strings.Contains(reason, "10485760") || !strings.Contains(reason, "8388608") {
		t.Fatalf("reason lacks sizes: %q", reason)
	}
}
''',
    '''	if !strings.Contains(reason, "10485760") || !strings.Contains(reason, "8388608") {
		t.Fatalf("reason lacks sizes: %q", reason)
	}
	if !strings.Contains(reason, "Risk Gateway ingress") || !strings.Contains(reason, "before audit and upstream") {
		t.Fatalf("reason does not identify the owning stage: %q", reason)
	}
	for key, expected := range map[string]any{
		"error_origin":      "risk_gateway",
		"failure_stage":     "gateway_ingress",
		"failure_component": "request_body_guard",
		"limit_config":      "REQUEST_MAX_BYTES",
		"audit_started":     false,
		"upstream_started":  false,
	} {
		if got := trace.Metadata[key]; got != expected {
			t.Fatalf("%s = %#v, want %#v; metadata=%#v", key, got, expected, trace.Metadata)
		}
	}
	if trace.Metadata["request_body_recommended_limit_bytes"] != int64(16*1024*1024) {
		t.Fatalf("unexpected recommended limit: %#v", trace.Metadata)
	}
	if guidance, _ := trace.Metadata["request_body_remediation"].(string); !strings.Contains(guidance, "not an audit-model or upstream-model limit") {
		t.Fatalf("remediation lacks source distinction: %#v", trace.Metadata)
	}
}
''',
    "exact-size diagnostic test",
)
test += '''
func TestRecommendedRequestMaxBytesForObservedProductionSize(t *testing.T) {
	const observed = int64(60853983)
	if got := recommendedRequestMaxBytes(observed); got != 64*1024*1024 {
		t.Fatalf("recommended limit = %d, want %d", got, int64(64*1024*1024))
	}
}

func TestMarkRequestTooLargeAboveSupportedCeiling(t *testing.T) {
	trace := TraceEvent{Metadata: map[string]any{}}
	_ = markRequestTooLarge(&trace, 80*1024*1024, 8*1024*1024, true)
	if _, exists := trace.Metadata["request_body_recommended_limit_bytes"]; exists {
		t.Fatalf("unsupported request must not receive an unsafe recommendation: %#v", trace.Metadata)
	}
	guidance, _ := trace.Metadata["request_body_remediation"].(string)
	if !strings.Contains(guidance, "supported 64 MiB body ceiling") {
		t.Fatalf("hard-ceiling guidance missing: %#v", trace.Metadata)
	}
}
'''
test_path.write_text(test, encoding="utf-8")

# ---------------------------------------------------------------------------
# Admin Web: show source/stage and remediation without reading raw metadata.
# ---------------------------------------------------------------------------
web_path = ROOT / "internal/platform/web/index.html"
web = web_path.read_text(encoding="utf-8")
web = replace_once(
    web,
    '''          const requestSize=requestBodyDiagnostic(item);
          const ruleIndicators=(item.metadata?.audit_rule_indicators||[]).join(' + ');
''',
    '''          const requestSize=requestBodyDiagnostic(item);
          const requestLimitSource=item.metadata?.limit_config==='REQUEST_MAX_BYTES'?`<span class="trace-error-class">超限来源：Risk Gateway 入口 REQUEST_MAX_BYTES · 审计模型未调用 · 真实上游未调用</span>`:'';
          const ruleIndicators=(item.metadata?.audit_rule_indicators||[]).join(' + ');
''',
    "web request limit source line",
)
web = replace_once(
    web,
    '''${requestSize?`<span class="trace-error-class">请求体：${escapeHTML(requestSize)}</span>`:''}${modelEvidenceLine}''',
    '''${requestSize?`<span class="trace-error-class">请求体：${escapeHTML(requestSize)}</span>`:''}${requestLimitSource}${modelEvidenceLine}''',
    "web request source rendering",
)
web = replace_once(
    web,
    '''          ['问题原因',traceReason(item)], ['最终失败阶段',item.metadata?.failure_stage||'-'], ['上游错误原因',item.metadata?.upstream_error_reason||'-'],
''',
    '''          ['问题原因',traceReason(item)], ['错误来源',item.metadata?.error_origin||'-'], ['最终失败阶段',item.metadata?.failure_stage||'-'], ['失败组件',item.metadata?.failure_component||'-'],
          ['限制归属',item.metadata?.limit_owner||'-'], ['限制配置',item.metadata?.limit_config||'-'], ['限制范围',item.metadata?.limit_scope||'-'],
          ['审计模型是否启动',item.metadata?.audit_started===false?'否':(item.metadata?.audit_started===true?'是':'-')], ['真实上游是否启动',item.metadata?.upstream_started===false?'否':(item.metadata?.upstream_started===true?'是':'-')],
          ['建议请求体上限',item.metadata?.request_body_recommended_limit_bytes?byteText(item.metadata.request_body_recommended_limit_bytes):'-'], ['解决建议',item.metadata?.request_body_remediation||'-'], ['上游错误原因',item.metadata?.upstream_error_reason||'-'],
''',
    "web request source detail fields",
)
web = replace_once(
    web,
    "'request_bytes','request_body_limit_bytes','request_body_over_limit_bytes','request_body_size_exact','response_bytes'",
    "'request_bytes','request_body_limit_bytes','request_body_over_limit_bytes','request_body_size_exact','error_origin','failure_stage','failure_component','limit_owner','limit_config','limit_scope','audit_started','upstream_started','request_body_recommended_limit_bytes','request_body_remediation','response_bytes'",
    "web CSV request-source headers",
)
web = replace_once(
    web,
    "item.request_bytes,item.metadata?.request_body_limit_bytes,item.metadata?.request_body_over_limit_bytes,item.metadata?.request_body_size_exact,item.response_bytes",
    "item.request_bytes,item.metadata?.request_body_limit_bytes,item.metadata?.request_body_over_limit_bytes,item.metadata?.request_body_size_exact,item.metadata?.error_origin,item.metadata?.failure_stage,item.metadata?.failure_component,item.metadata?.limit_owner,item.metadata?.limit_config,item.metadata?.limit_scope,item.metadata?.audit_started,item.metadata?.upstream_started,item.metadata?.request_body_recommended_limit_bytes,item.metadata?.request_body_remediation,item.response_bytes",
    "web CSV request-source rows",
)
web_path.write_text(web, encoding="utf-8")

# ---------------------------------------------------------------------------
# E2E trace assertions
# ---------------------------------------------------------------------------
e2e_path = ROOT / "scripts/e2e.sh"
e2e = e2e_path.read_text(encoding="utf-8")
e2e = replace_once(
    e2e,
    '''if metadata.get("request_body_size_exact") is not True:
    raise RuntimeError(f"Content-Length request should have exact size: {metadata}")

rule_item = next''',
    '''if metadata.get("request_body_size_exact") is not True:
    raise RuntimeError(f"Content-Length request should have exact size: {metadata}")
if metadata.get("error_origin") != "risk_gateway" or metadata.get("failure_stage") != "gateway_ingress":
    raise RuntimeError(f"REQUEST_TOO_LARGE source/stage is ambiguous: {metadata}")
if metadata.get("limit_config") != "REQUEST_MAX_BYTES" or metadata.get("failure_component") != "request_body_guard":
    raise RuntimeError(f"REQUEST_TOO_LARGE owning guard is missing: {metadata}")
if metadata.get("audit_started") is not False or metadata.get("upstream_started") is not False:
    raise RuntimeError(f"REQUEST_TOO_LARGE must state that audit/upstream were not called: {metadata}")
if not metadata.get("request_body_remediation"):
    raise RuntimeError(f"REQUEST_TOO_LARGE remediation is missing: {metadata}")

rule_item = next''',
    "E2E request-source diagnostics",
)
e2e_path.write_text(e2e, encoding="utf-8")

# ---------------------------------------------------------------------------
# Operator documentation
# ---------------------------------------------------------------------------
doc_path = ROOT / "docs/request-size-and-context-limits.md"
doc_path.write_text('''# 请求体大小与模型上下文限制

平台区分三个阶段，不能把它们混为同一种“超限”：

1. `REQUEST_TOO_LARGE`：**Risk Gateway 入口 HTTP 请求体字节限制**。由 `REQUEST_MAX_BYTES` 触发，审计模型和真实上游都还没有被调用。
2. `AUDIT_CONTEXT_TOO_LARGE`：审计模型自己报告 prompt/input tokens 超过审计模型上下文。
3. 上游模型上下文错误：真实上游返回 HTTP/流式错误，Trace 的 `failure_stage` 为 `upstream_http`、`upstream_response` 或 `upstream_stream`，并保存上游错误原因。

## REQUEST_TOO_LARGE：来源是 Risk Gateway

新版 Trace 会明确包含：

```json
{
  "error_class": "request_body_too_large",
  "error_origin": "risk_gateway",
  "failure_stage": "gateway_ingress",
  "failure_component": "request_body_guard",
  "limit_owner": "risk_gateway",
  "limit_config": "REQUEST_MAX_BYTES",
  "limit_scope": "inbound_http_request_body",
  "limit_unit": "bytes",
  "audit_started": false,
  "upstream_started": false
}
```

这表示请求在进入风控平台时就因 HTTP body 太大被拒绝，既不是审计模型超限，也不是上游模型超限。

如果客户端携带可靠 `Content-Length`，Trace 会记录精确：

```text
request_body_bytes
request_body_limit_bytes
request_body_over_limit_bytes
request_body_size_exact=true
```

对于 HTTP chunked 或没有 Content-Length 的请求，为避免通过“读完整个超大请求”绕过防 DoS 上限，平台只读取到安全边界并记录：

```text
request_body_size_exact=false
request_body_bytes=至少 REQUEST_MAX_BYTES+1
```

Web 会明确显示“至少”，不会把下界伪装成精确大小。

### 60,853,983 bytes 的请求

该大小约为 58.04 MiB，低于平台支持的 64 MiB 配置上限。要允许该请求，服务器 `.env` 可设置：

```env
REQUEST_MAX_BYTES=67108864
```

然后重新部署 Risk Gateway。不要把 `AUDIT_TEXT_MAX_BYTES` 当成同一个参数：它限制从 JSON 中抽取给审计模型的文本，内联图片/文件的 base64 应由抽取器跳过。如果实际文本本身也非常大，应拆分会话或请求，而不是无限提高内存上限。

对于高并发商业部署，不建议全局长期放开大 body 后仍保持很高并发。优先使用对象存储 URL 代替内联 base64，并对大请求路由降低 `max_concurrency`。

## 审计模型 Token 上下文

`AUDIT_CONTEXT_TARGET_TOKENS=0` 为默认值，表示平台不设置固定 token 天花板。平台先发送完整审计请求；只有审计模型明确返回 context-length 错误后，才使用模型报告的最大上下文和实际 input tokens 动态计算重叠分段。

例如 Qwen vLLM 使用：

```text
--max-model-len 260000
```

则 260,000 是这个 Qwen 实例的模型上下文上限，不是风控平台硬编码的限制。

## 判断来源

```text
REQUEST_TOO_LARGE
+ error_origin=risk_gateway
+ failure_stage=gateway_ingress
+ audit_started=false
+ upstream_started=false
    => Risk Gateway 请求体字节限制

AUDIT_CONTEXT_TOO_LARGE
+ audit_input_tokens / audit_context_window_tokens
    => 审计模型上下文限制

UPSTREAM_*
+ failure_stage=upstream_*
+ upstream_error_reason
    => 真实上游或上游链路错误
```
''', encoding="utf-8")

print("request-limit source diagnostics applied")
