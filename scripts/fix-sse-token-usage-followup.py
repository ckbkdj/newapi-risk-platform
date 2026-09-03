from pathlib import Path

root = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


usage = root / "internal/platform/upstream_usage.go"
replace_once(
    usage,
    '''\tu.TotalTokens = maxInt64(u.TotalTokens, other.TotalTokens)
\tu.CachedTokens = maxInt64(u.CachedTokens, other.CachedTokens)
''',
    '''\tu.TotalTokens = maxInt64(u.TotalTokens, other.TotalTokens)
\tu.CachedTokens = maxInt64(u.CachedTokens, other.CachedTokens)
''',
    "usage merge anchor",
)
replace_once(
    usage,
    '''\tif u.TotalTokens == 0 && (u.InputTokens > 0 || u.OutputTokens > 0) {
\t\tu.TotalTokens = u.InputTokens + u.OutputTokens
\t}
''',
    '''\t// Some streaming APIs report input usage in an early event and output
\t// usage in a later event. Preserve an explicitly reported total, but once
\t// both sides are known never leave total_tokens equal to only one side.
\tif computed := u.InputTokens + u.OutputTokens; computed > u.TotalTokens {
\t\tu.TotalTokens = computed
\t}
''',
    "usage total across streaming events",
)

usage_test = root / "internal/platform/upstream_usage_test.go"
replace_once(
    usage_test,
    '''func TestParseResponsesCompletedUsage(t *testing.T) {
''',
    '''func TestMergeSeparateStreamingUsageEvents(t *testing.T) {
\tvar usage upstreamTokenUsage
\tusage.Merge(upstreamTokenUsage{InputTokens: 100, TotalTokens: 100, Source: "anthropic_usage", Exact: true})
\tusage.Merge(upstreamTokenUsage{OutputTokens: 25, TotalTokens: 25, Source: "anthropic_usage", Exact: true})
\tif usage.InputTokens != 100 || usage.OutputTokens != 25 || usage.TotalTokens != 125 {
\t\tt.Fatalf("separate streaming usage was not merged: %+v", usage)
\t}
}

func TestParseResponsesCompletedUsage(t *testing.T) {
''',
    "separate usage event test",
)

web = root / "internal/platform/web/index.html"
replace_once(
    web,
    '''<div class="field"><label for="route-timeout">超时（毫秒）</label><input id="route-timeout" type="number" min="1000" value="120000"></div>''',
    '''<div class="field"><label for="route-timeout">非流式总超时 / SSE 空闲超时（毫秒）</label><input id="route-timeout" type="number" min="1000" value="120000"><small>非流式限制完整响应时长；流式仅在连续无任何 SSE 事件达到该时长时超时，持续输出不会被总时长截断。</small></div>''',
    "route timeout UI semantics",
)

mock = root / "cmd/mockprovider/main.go"
replace_once(
    mock,
    '''\t\ttime.Sleep(75 * time.Millisecond)
''',
    '''\t\ttime.Sleep(200 * time.Millisecond)
''',
    "mock slow stream interval",
)

e2e = root / "scripts/e2e.sh"
replace_once(
    e2e,
    '''  "request_timeout_ms": 200,
''',
    '''  "request_timeout_ms": 1000,
''',
    "valid E2E route timeout",
)
replace_once(
    e2e,
    '''# This stream runs for roughly 625 ms while its route timeout is only 200 ms.
# It must succeed because events arrive every 75 ms: request_timeout_ms is an
''',
    '''# This stream runs for roughly 1.6 seconds while its route timeout is only
# 1 second. It must succeed because events arrive every 200 ms: request_timeout_ms is an
''',
    "E2E slow stream comment",
)
replace_once(
    e2e,
    '''if int(slow_usage.get("latency_ms", 0)) <= 200:
''',
    '''if int(slow_usage.get("latency_ms", 0)) <= 1000:
''',
    "E2E slow stream duration assertion",
)

print("SSE usage follow-up fixes applied")
