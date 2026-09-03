from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


# ---------------------------------------------------------------------------
# Resolve audit extraction capacity from the same hard ceiling that admitted
# the request body. This prevents automatic 64 MiB body admission from silently
# auditing only the first historical 8 MiB of user text.
# ---------------------------------------------------------------------------
limit_path = ROOT / "internal/platform/audit_text_limit.go"
limit_path.write_text(
    r'''package platform

const automaticAuditTextOverheadBytes int64 = 64 * 1024

// resolveAuditTextMaxBytes returns the maximum role-aware text buffer used by
// the rule/model audit layer. A zero configured value follows the accepted
// request hard ceiling and includes small headroom for ROLE=USER separators.
func resolveAuditTextMaxBytes(configured int, requestHardMaxBytes int64) (int, string) {
	if configured > 0 {
		return configured, "configured"
	}
	if requestHardMaxBytes <= 0 {
		requestHardMaxBytes = defaultRequestHardMaxBytes
	}
	resolved := requestHardMaxBytes + automaticAuditTextOverheadBytes
	maximumInt := int64(^uint(0) >> 1)
	if resolved > maximumInt {
		resolved = maximumInt
	}
	return int(resolved), "automatic_request_hard_ceiling"
}
''',
    encoding="utf-8",
)

config_path = ROOT / "internal/platform/config.go"
config = config_path.read_text(encoding="utf-8")
config = replace_once(
    config,
    '\t\tAuditTextMaxBytes:              envInt("AUDIT_TEXT_MAX_BYTES", 8*1024*1024),\n',
    '\t\tAuditTextMaxBytes:              envInt("AUDIT_TEXT_MAX_BYTES", 0),\n',
    "config audit text automatic default",
)
config = replace_once(
    config,
    '\tif c.AuditTextMaxBytes < 4096 || c.AuditTextMaxBytes > 16*1024*1024 {\n'
    '\t\tproblems = append(problems, "AUDIT_TEXT_MAX_BYTES must be between 4 KiB and 16 MiB")\n'
    '\t}\n',
    '\tmaximumConfiguredAuditTextBytes := c.RequestHardMaxBytes + automaticAuditTextOverheadBytes\n'
    '\tif c.AuditTextMaxBytes != 0 && (c.AuditTextMaxBytes < 4096 || int64(c.AuditTextMaxBytes) > maximumConfiguredAuditTextBytes) {\n'
    '\t\tproblems = append(problems, "AUDIT_TEXT_MAX_BYTES must be 0 to follow REQUEST_HARD_MAX_BYTES or between 4 KiB and REQUEST_HARD_MAX_BYTES plus separator headroom")\n'
    '\t}\n'
    '\teffectiveAuditTextMaxBytes, _ := resolveAuditTextMaxBytes(c.AuditTextMaxBytes, c.RequestHardMaxBytes)\n',
    "config audit text validation",
)
config = replace_once(
    config,
    '\tif c.AuditLongContextThresholdBytes < 256 || c.AuditLongContextThresholdBytes > c.AuditTextMaxBytes {\n'
    '\t\tproblems = append(problems, "AUDIT_LONG_CONTEXT_THRESHOLD_BYTES must be between 256 bytes and AUDIT_TEXT_MAX_BYTES")\n'
    '\t}\n',
    '\tif c.AuditLongContextThresholdBytes < 256 || c.AuditLongContextThresholdBytes > effectiveAuditTextMaxBytes {\n'
    '\t\tproblems = append(problems, "AUDIT_LONG_CONTEXT_THRESHOLD_BYTES must be between 256 bytes and the effective audit text limit")\n'
    '\t}\n',
    "config long context effective text limit",
)
config = replace_once(
    config,
    '\tif c.AuditFallbackChunkBytes < 1024 || c.AuditFallbackChunkBytes > c.AuditTextMaxBytes {\n'
    '\t\tproblems = append(problems, "AUDIT_FALLBACK_CHUNK_BYTES must be between 1024 and AUDIT_TEXT_MAX_BYTES")\n'
    '\t}\n',
    '\tif c.AuditFallbackChunkBytes < 1024 || c.AuditFallbackChunkBytes > effectiveAuditTextMaxBytes {\n'
    '\t\tproblems = append(problems, "AUDIT_FALLBACK_CHUNK_BYTES must be between 1024 and the effective audit text limit")\n'
    '\t}\n',
    "config fallback chunk effective text limit",
)
config_path.write_text(config, encoding="utf-8")

# ---------------------------------------------------------------------------
# Audit engine and trace diagnostics
# ---------------------------------------------------------------------------
audit_path = ROOT / "internal/platform/audit.go"
audit = audit_path.read_text(encoding="utf-8")
audit = replace_once(
    audit,
    "\tmaxTextBytes              int\n\toutputMaxTokens           int\n",
    "\tmaxTextBytes              int\n"
    "\ttextLimitMode             string\n"
    "\toutputMaxTokens           int\n",
    "audit engine text limit mode field",
)
audit = replace_once(
    audit,
    "func NewAuditEngine(\n"
    "\tcfg Config,\n"
    "\tstore *Store,\n"
    "\tsecurity *Security,\n"
    "\tlog *slog.Logger,\n"
    ") *AuditEngine {\n"
    "\tengine := &AuditEngine{\n",
    "func NewAuditEngine(\n"
    "\tcfg Config,\n"
    "\tstore *Store,\n"
    "\tsecurity *Security,\n"
    "\tlog *slog.Logger,\n"
    ") *AuditEngine {\n"
    "\tresolvedTextMaxBytes, textLimitMode := resolveAuditTextMaxBytes(cfg.AuditTextMaxBytes, cfg.RequestHardMaxBytes)\n"
    "\tengine := &AuditEngine{\n",
    "audit engine resolve text limit",
)
audit = replace_once(
    audit,
    "\t\tmaxTextBytes:              cfg.AuditTextMaxBytes,\n"
    "\t\toutputMaxTokens:           cfg.AuditOutputMaxTokens,\n",
    "\t\tmaxTextBytes:              resolvedTextMaxBytes,\n"
    "\t\ttextLimitMode:             textLimitMode,\n"
    "\t\toutputMaxTokens:           cfg.AuditOutputMaxTokens,\n",
    "audit engine resolved text limit initialization",
)
audit = replace_once(
    audit,
    "\t\tAuditIgnoredRoles:        append([]string(nil), extraction.IgnoredRoles...),\n"
    "\t}\n",
    "\t\tAuditIgnoredRoles:        append([]string(nil), extraction.IgnoredRoles...),\n"
    "\t\tAuditTextLimitMode:       e.textLimitMode,\n"
    "\t\tAuditTextLimitBytes:      e.maxTextBytes,\n"
    "\t}\n",
    "audit result text limit diagnostics",
)
audit_path.write_text(audit, encoding="utf-8")

types_path = ROOT / "internal/platform/types.go"
types = types_path.read_text(encoding="utf-8")
types = replace_once(
    types,
    "\tAuditIgnoredRoles        []string              `json:\"audit_ignored_roles,omitempty\"`\n",
    "\tAuditIgnoredRoles        []string              `json:\"audit_ignored_roles,omitempty\"`\n"
    "\tAuditTextLimitMode       string                `json:\"audit_text_limit_mode,omitempty\"`\n"
    "\tAuditTextLimitBytes      int                   `json:\"audit_text_limit_bytes,omitempty\"`\n",
    "audit result text limit fields",
)
types_path.write_text(types, encoding="utf-8")

gateway_path = ROOT / "internal/platform/gateway.go"
gateway = gateway_path.read_text(encoding="utf-8")
gateway = replace_once(
    gateway,
    "\ttrace.Metadata[\"audit_ignored_context_bytes\"] = auditResult.AuditIgnoredContextBytes\n"
    "\tif len(auditResult.AuditIgnoredRoles) > 0 {\n",
    "\ttrace.Metadata[\"audit_ignored_context_bytes\"] = auditResult.AuditIgnoredContextBytes\n"
    "\ttrace.Metadata[\"audit_text_limit_mode\"] = auditResult.AuditTextLimitMode\n"
    "\ttrace.Metadata[\"audit_text_limit_bytes\"] = auditResult.AuditTextLimitBytes\n"
    "\tif len(auditResult.AuditIgnoredRoles) > 0 {\n",
    "gateway audit text limit metadata",
)
gateway_path.write_text(gateway, encoding="utf-8")

# ---------------------------------------------------------------------------
# Environment/deployment defaults and migration
# ---------------------------------------------------------------------------
env_path = ROOT / ".env.example"
env = env_path.read_text(encoding="utf-8")
env = replace_once(
    env,
    "AUDIT_TEXT_MAX_BYTES=8388608\n",
    "# 0 = extract every eligible end-user text byte from an accepted request,\n"
    "# following REQUEST_HARD_MAX_BYTES with small separator headroom.\n"
    "AUDIT_TEXT_MAX_BYTES=0\n",
    "environment automatic audit text limit",
)
env = replace_once(env, "AUDIT_MAX_CHUNKS=64\n", "AUDIT_MAX_CHUNKS=256\n", "environment chunk maximum")
env_path.write_text(env, encoding="utf-8")

compose_path = ROOT / "docker-compose.yml"
compose = compose_path.read_text(encoding="utf-8")
compose = replace_once(
    compose,
    "      AUDIT_TEXT_MAX_BYTES: ${AUDIT_TEXT_MAX_BYTES:-8388608}\n",
    "      AUDIT_TEXT_MAX_BYTES: ${AUDIT_TEXT_MAX_BYTES:-0}\n",
    "compose automatic audit text limit",
)
compose = replace_once(
    compose,
    "      AUDIT_MAX_CHUNKS: ${AUDIT_MAX_CHUNKS:-64}\n",
    "      AUDIT_MAX_CHUNKS: ${AUDIT_MAX_CHUNKS:-256}\n",
    "compose chunk maximum",
)
compose_path.write_text(compose, encoding="utf-8")

k8s_path = ROOT / "deploy/kubernetes.yaml"
k8s = k8s_path.read_text(encoding="utf-8")
k8s = replace_once(k8s, '  AUDIT_TEXT_MAX_BYTES: "8388608"\n', '  AUDIT_TEXT_MAX_BYTES: "0"\n', "Kubernetes automatic audit text limit")
k8s = replace_once(k8s, '  AUDIT_MAX_CHUNKS: "64"\n', '  AUDIT_MAX_CHUNKS: "256"\n', "Kubernetes chunk maximum")
k8s_path.write_text(k8s, encoding="utf-8")

init_path = ROOT / "scripts/init-env.sh"
init_text = init_path.read_text(encoding="utf-8")
init_text = replace_once(
    init_text,
    '    "AUDIT_TEXT_MAX_BYTES": "8388608",\n',
    '    "AUDIT_TEXT_MAX_BYTES": "0",\n',
    "init-env automatic audit text default",
)
init_text = replace_once(
    init_text,
    '    "AUDIT_MAX_CHUNKS": "64",\n',
    '    "AUDIT_MAX_CHUNKS": "256",\n',
    "init-env chunk maximum default",
)
init_text = replace_once(
    init_text,
    '    if key == "AUDIT_TEXT_MAX_BYTES" and current in {"262144", "2097152"}:\n'
    '        should_set = True\n'
    '        warnings.append(\n'
    '            "AUDIT_TEXT_MAX_BYTES was upgraded to 8 MiB so the request layer can segment and audit the complete prompt."\n'
    '        )\n',
    '    if key == "AUDIT_TEXT_MAX_BYTES" and current in {"262144", "2097152", "8388608", "67108864"}:\n'
    '        should_set = True\n'
    '        warnings.append(\n'
    '            "AUDIT_TEXT_MAX_BYTES was changed to 0 so every accepted end-user text byte is eligible for complete chunked audit."\n'
    '        )\n'
    '    if key == "AUDIT_MAX_CHUNKS" and current == "64":\n'
    '        should_set = True\n'
    '        warnings.append(\n'
    '            "AUDIT_MAX_CHUNKS was increased from 64 to 256 for complete large-text request auditing."\n'
    '        )\n',
    "init-env audit text and chunk migration",
)
init_path.write_text(init_text, encoding="utf-8")

# ---------------------------------------------------------------------------
# Web, runtime and docs
# ---------------------------------------------------------------------------
admin_path = ROOT / "internal/platform/admin.go"
admin = admin_path.read_text(encoding="utf-8")
admin = replace_once(
    admin,
    "\t\t\"request_large_body_max_concurrency\": s.cfg.LargeRequestMaxConcurrency,\n"
    "\t\t\"allow_private_upstreams\":            s.cfg.AllowPrivateUpstreams,\n",
    "\t\t\"request_large_body_max_concurrency\": s.cfg.LargeRequestMaxConcurrency,\n"
    "\t\t\"audit_text_max_bytes\":               s.cfg.AuditTextMaxBytes,\n"
    "\t\t\"audit_text_limit_mode\":              map[bool]string{true: \"automatic_request_hard_ceiling\", false: \"configured\"}[s.cfg.AuditTextMaxBytes == 0],\n"
    "\t\t\"audit_text_effective_limit_bytes\":   func() int { value, _ := resolveAuditTextMaxBytes(s.cfg.AuditTextMaxBytes, s.cfg.RequestHardMaxBytes); return value }(),\n"
    "\t\t\"allow_private_upstreams\":            s.cfg.AllowPrivateUpstreams,\n",
    "runtime audit text diagnostics",
)
admin_path.write_text(admin, encoding="utf-8")

web_path = ROOT / "internal/platform/web/index.html"
web = web_path.read_text(encoding="utf-8")
web = replace_once(
    web,
    "          ['审计延迟',`${number(item.audit_latency_ms)} ms`], ['审计输入范围',item.metadata?.audit_input_scope||'-'], ['审计用户意图字节',item.metadata?.audit_intent_bytes??'-'], ['忽略的系统/工具上下文字节',item.metadata?.audit_ignored_context_bytes??0], ['忽略的上下文角色',(item.metadata?.audit_ignored_roles||[]).join(', ')||'-'],\n",
    "          ['审计延迟',`${number(item.audit_latency_ms)} ms`], ['审计输入范围',item.metadata?.audit_input_scope||'-'], ['审计用户意图字节',item.metadata?.audit_intent_bytes??'-'], ['审计文本上限模式',item.metadata?.audit_text_limit_mode||'-'], ['本次审计文本容量',byteText(item.metadata?.audit_text_limit_bytes)], ['忽略的系统/工具上下文字节',item.metadata?.audit_ignored_context_bytes??0], ['忽略的上下文角色',(item.metadata?.audit_ignored_roles||[]).join(', ')||'-'],\n",
    "Web audit text capacity fields",
)
web_path.write_text(web, encoding="utf-8")

doc_path = ROOT / "docs/automatic-body-timeline-and-role-aware-audit.md"
doc = doc_path.read_text(encoding="utf-8")
doc += "\n## 完整大文本审计\n\n`AUDIT_TEXT_MAX_BYTES=0` 表示审计文本容量自动跟随 `REQUEST_HARD_MAX_BYTES`，并为角色标签保留少量空间。合法大请求不会再出现“Gateway 已放行 58 MiB，但只审计前 8 MiB 文本”的隐藏截断。超过审计模型上下文后仍使用重叠分段，默认最多 256 段；无法完成所有分段时保持 fail-closed，不会放行未审计尾部。\n"
doc_path.write_text(doc, encoding="utf-8")

# ---------------------------------------------------------------------------
# Tests and CI migration assertions
# ---------------------------------------------------------------------------
test_path = ROOT / "internal/platform/audit_text_limit_test.go"
test_path.write_text(
    r'''package platform

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResolveAuditTextMaxBytesAutomatic(t *testing.T) {
	resolved, mode := resolveAuditTextMaxBytes(0, 64*1024*1024)
	if mode != "automatic_request_hard_ceiling" {
		t.Fatalf("mode=%q", mode)
	}
	if int64(resolved) < 64*1024*1024 {
		t.Fatalf("resolved=%d is below accepted request hard ceiling", resolved)
	}
}

func TestAutomaticAuditTextKeepsTailOfAcceptedLargeUserIntent(t *testing.T) {
	const hardLimit = int64(1024 * 1024)
	resolved, _ := resolveAuditTextMaxBytes(0, hardLimit)
	content := strings.Repeat("normal-project-content-", 35000) + "TAIL_AUDIT_MARKER"
	body, err := json.Marshal(map[string]any{
		"messages": []map[string]any{{"role": "user", "content": content}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(body)) > hardLimit {
		t.Fatalf("test body unexpectedly exceeds hard limit: %d", len(body))
	}
	extraction := ExtractAuditTextDetails(body, resolved)
	if !strings.Contains(extraction.Text, "TAIL_AUDIT_MARKER") {
		t.Fatalf("accepted request tail was silently omitted; extracted=%d body=%d limit=%d", len(extraction.Text), len(body), resolved)
	}
}

func TestConfiguredAuditTextLimitIsPreserved(t *testing.T) {
	resolved, mode := resolveAuditTextMaxBytes(512*1024, 64*1024*1024)
	if mode != "configured" || resolved != 512*1024 {
		t.Fatalf("resolved=%d mode=%q", resolved, mode)
	}
}
''',
    encoding="utf-8",
)

ci_path = ROOT / ".github/workflows/ci.yml"
ci = ci_path.read_text(encoding="utf-8")
ci = ci.replace("assert values['AUDIT_TEXT_MAX_BYTES'] == '8388608'", "assert values['AUDIT_TEXT_MAX_BYTES'] == '0'")
ci = ci.replace("assert values['AUDIT_MAX_CHUNKS'] == '64'", "assert values['AUDIT_MAX_CHUNKS'] == '256'")
ci_path.write_text(ci, encoding="utf-8")

print("complete audit text extraction patch applied")
