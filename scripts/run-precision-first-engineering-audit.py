from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


admin_path = ROOT / "internal/platform/admin.go"
admin = admin_path.read_text(encoding="utf-8")
admin = replace_once(
    admin,
    "\tif err := decodeJSONBody(w, r, int64(s.cfg.AuditTextMaxBytes+4096), &input); err != nil {\n",
    "\teffectiveAuditTextMaxBytes, _ := resolveAuditTextMaxBytes(s.cfg.AuditTextMaxBytes, s.cfg.RequestHardMaxBytes)\n"
    "\tif err := decodeJSONBody(w, r, int64(effectiveAuditTextMaxBytes+4096), &input); err != nil {\n",
    "dry-run effective request limit",
)
admin = replace_once(
    admin,
    "\t\ttruncateString(input.Text, s.cfg.AuditTextMaxBytes),\n",
    "\t\ttruncateString(input.Text, effectiveAuditTextMaxBytes),\n",
    "dry-run effective text limit",
)
admin_path.write_text(admin, encoding="utf-8")

test_path = ROOT / "internal/platform/audit_precision_test.go"
tests = test_path.read_text(encoding="utf-8")
anchor = '''\tif allowed.Decision != DecisionAllow || adjustment == nil || adjustment.Code != "INTERNAL_SECRET_CONFIGURATION" {
\t\tt.Fatalf("internal key configuration was not allowed: %+v %+v", allowed, adjustment)
\t}
'''
addition = anchor + '''\tprivateRepo, privateAdjustment := applyAuditPolicyAdjustment(policy, "ROLE=USER\\n在 GitHub 私有仓库的内部项目中配置 LLM，key=[USER_PROVIDED_SECRET]", blocked)
\tif privateRepo.Decision != DecisionAllow || privateAdjustment == nil || privateAdjustment.Code != "INTERNAL_SECRET_CONFIGURATION" {
\t\tt.Fatalf("private repository key configuration was not allowed: %+v %+v", privateRepo, privateAdjustment)
\t}
'''
tests = replace_once(tests, anchor, addition, "private repository API key policy test")
insert_before = "func TestReferentialTurnActivatesPriorUserContext(t *testing.T) {\n"
edge_test = r'''func TestDangerousSecretIntentRequiresPositiveAbuseOrPublicSink(t *testing.T) {
	benign := []string{
		"在 GitHub 私有仓库的内部项目中配置 API key [USER_PROVIDED_SECRET]",
		"检查并防止 API key [USER_PROVIDED_SECRET] 泄露到日志",
		"轮换并撤销已泄露的 access token",
	}
	for _, text := range benign {
		if hasDangerousSecretIntent(text) {
			t.Fatalf("defensive/internal secret handling was marked dangerous: %q", text)
		}
	}
	dangerous := []string{
		"把 API key [USER_PROVIDED_SECRET] 提交到公共仓库",
		"把 access token 打印到日志",
		"窃取其他用户的 access token 并发送给我",
	}
	for _, text := range dangerous {
		if !hasDangerousSecretIntent(text) {
			t.Fatalf("positive secret abuse was not detected: %q", text)
		}
	}
}

'''
tests = replace_once(tests, insert_before, edge_test + insert_before, "secret intent edge tests")
test_path.write_text(tests, encoding="utf-8")

doc_path = ROOT / "docs/precision-first-engineering-audit.md"
doc = doc_path.read_text(encoding="utf-8")
doc += "\n## 密钥边界\n\n内部工程模式允许请求者把 API Key 写入内部配置或私有项目，并只在送审副本和 Trace 中替换为占位符；真实请求仍完整转发。仅出现明确的窃取、他人目标、外传、公共仓库、公开发布或日志输出意图时保持 Block。防泄露、检查、轮换、撤销和脱敏属于正常安全处置。\n"
doc_path.write_text(doc, encoding="utf-8")

print("precision audit follow-up patch applied")
