from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def replace_once(path: str, old: str, new: str, label: str) -> None:
    p = ROOT / path
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match in {path}, found {count}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")

replace_once(
    "docker-compose.yml",
    'AUDIT_CONTEXT_TARGET_TOKENS: ${AUDIT_CONTEXT_TARGET_TOKENS:-260000}',
    'AUDIT_CONTEXT_TARGET_TOKENS: ${AUDIT_CONTEXT_TARGET_TOKENS:-0}',
    "compose automatic context target",
)

ci = ROOT / ".github/workflows/ci.yml"
text = ci.read_text(encoding="utf-8")
if text.count("assert values['AUDIT_CONTEXT_TARGET_TOKENS'] == '260000'") != 2:
    raise SystemExit("expected two CI assertions for historical 260000 target")
text = text.replace("assert values['AUDIT_CONTEXT_TARGET_TOKENS'] == '260000'", "assert values['AUDIT_CONTEXT_TARGET_TOKENS'] == '0'")
ci.write_text(text, encoding="utf-8")

replace_once(
    "docs/qwen38-fast-audit.md",
    "Qwen3.8 的 262,144 tokens 是系统提示词、用户内容、聊天模板和模型输出的总窗口，不是 262,144 个纯输入 token。平台把目标 prompt 容量设为 260,000 tokens，并把输出压到 128 tokens。",
    "Qwen3.8/vLLM 的上下文上限由模型服务自己的 `--max-model-len` 决定。平台默认 `AUDIT_CONTEXT_TARGET_TOKENS=0`，不再固定卡 260K；只有模型真实返回 context-length 错误后，平台才读取模型报告的 maximum/requested tokens 并动态分段。审计输出仍压到 128 tokens。",
    "qwen doc no fixed target",
)
replace_once(
    "docs/qwen38-fast-audit.md",
    "AUDIT_CONTEXT_TARGET_TOKENS=260000",
    "AUDIT_CONTEXT_TARGET_TOKENS=0  # 自动，以模型真实上下文错误为准",
    "qwen doc context env",
)

# Keep test bodies small while exercising the exact Content-Length diagnostics.
replace_once(
    "docker-compose.test.yml",
    'AUDIT_MAX_CHUNKS: "32"',
    'AUDIT_MAX_CHUNKS: "32"\n      REQUEST_MAX_BYTES: "65536"',
    "test request max bytes",
)

replace_once(
    "scripts/e2e.sh",
    '''gateway="${BASE_URL}/gateway/mock-main/v1/chat/completions"\ngateway_auth=(-H "Authorization: Bearer ${ROUTE_KEY}" -H 'Content-Type: application/json')\n\nstatus="$(curl --silent --show-error -o "${WORKDIR}/allow.json" -w '%{http_code}' \\\n''',
    '''gateway="${BASE_URL}/gateway/mock-main/v1/chat/completions"\ngateway_auth=(-H "Authorization: Bearer ${ROUTE_KEY}" -H 'Content-Type: application/json')\n\npython3 - "${WORKDIR}/too-large.json" <<'PY'\nimport json\nimport sys\nwith open(sys.argv[1], "w", encoding="utf-8") as handle:\n    json.dump({"model":"normal","messages":[{"role":"user","content":"x" * 70000}]}, handle)\nPY\nstatus="$(curl --silent --show-error -D "${WORKDIR}/too-large.headers" -o "${WORKDIR}/too-large-response.json" -w '%{http_code}' \\\n  "${gateway}" "${gateway_auth[@]}" \\\n  -H 'X-Request-ID: e2e-request-too-large' \\\n  --data-binary @"${WORKDIR}/too-large.json")"\nassert_status 555 "${status}" "${WORKDIR}/too-large-response.json"\ncontains "${WORKDIR}/too-large-response.json" 'REQUEST_TOO_LARGE'\ncontains "${WORKDIR}/too-large.headers" 'X-Risk-Request-Limit-Bytes: 65536'\ncontains "${WORKDIR}/too-large.headers" 'X-Risk-Request-Size-Exact: true'\n\nstatus="$(curl --silent --show-error -o "${WORKDIR}/allow.json" -w '%{http_code}' \\\n''',
    "e2e oversized request",
)

replace_once(
    "scripts/e2e.sh",
    '''long_items = {item.get("request_id"): item for item in items if item.get("request_id") in {"e2e-long-safe", "e2e-long-block"}}\n''',
    '''too_large = next((item for item in items if item.get("request_id") == "e2e-request-too-large"), None)\nif not too_large:\n    raise RuntimeError("REQUEST_TOO_LARGE trace is missing")\nmetadata = too_large.get("metadata", {})\nif int(too_large.get("request_bytes", 0)) <= 65536:\n    raise RuntimeError(f"oversized request bytes were not persisted: {too_large}")\nif int(metadata.get("request_body_limit_bytes", 0)) != 65536:\n    raise RuntimeError(f"oversized request limit missing: {metadata}")\nif int(metadata.get("request_body_over_limit_bytes", 0)) <= 0:\n    raise RuntimeError(f"oversized request overage missing: {metadata}")\nif metadata.get("request_body_size_exact") is not True:\n    raise RuntimeError(f"Content-Length request should have exact size: {metadata}")\n\nlong_items = {item.get("request_id"): item for item in items if item.get("request_id") in {"e2e-long-safe", "e2e-long-block"}}\n''',
    "e2e trace oversized metadata",
)

# Small unit tests for exact/lower-bound metadata semantics.
test_path = ROOT / "internal/platform/request_size_diagnostics_test.go"
test_path.write_text(r'''package platform

import (
    "strings"
    "testing"
)

func TestMarkRequestTooLargeExact(t *testing.T) {
    trace := TraceEvent{Metadata: map[string]any{}}
    reason := markRequestTooLarge(&trace, 10*1024*1024, 8*1024*1024, true)
    if trace.RequestBytes != 10*1024*1024 {
        t.Fatalf("request bytes = %d", trace.RequestBytes)
    }
    if trace.Metadata["request_body_size_exact"] != true {
        t.Fatalf("expected exact size metadata: %#v", trace.Metadata)
    }
    if trace.Metadata["request_body_over_limit_bytes"] != int64(2*1024*1024) {
        t.Fatalf("unexpected over-limit bytes: %#v", trace.Metadata)
    }
    if !strings.Contains(reason, "10485760") || !strings.Contains(reason, "8388608") {
        t.Fatalf("reason lacks sizes: %q", reason)
    }
}

func TestMarkRequestTooLargeLowerBound(t *testing.T) {
    trace := TraceEvent{Metadata: map[string]any{}}
    reason := markRequestTooLarge(&trace, 65537, 65536, false)
    if trace.Metadata["request_body_size_exact"] != false {
        t.Fatalf("expected lower-bound metadata: %#v", trace.Metadata)
    }
    if !strings.Contains(reason, "at least") {
        t.Fatalf("lower-bound reason is not explicit: %q", reason)
    }
}
''', encoding="utf-8")

print("request-size follow-up patch applied")
