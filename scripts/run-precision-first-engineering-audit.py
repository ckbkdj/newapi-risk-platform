from pathlib import Path

path = Path(__file__).with_name("apply-precision-first-engineering-audit.py")
source = path.read_text(encoding="utf-8")
source = source.replace('    """# 精度优先的内部工程审计\\n\\n"', '    "# 精度优先的内部工程审计\\n\\n"', 1)

unsupported = r'(?=\.[a-z0-9]{1,8}\b)'
replacement = r'(\.[a-z0-9]{1,8}\b)'
if unsupported not in source:
    raise SystemExit("unsupported UUID lookahead fragment was not found")
source = source.replace(unsupported, replacement, 1)
source = source.replace('replacement = "${1}[ARTIFACT_ID]"', 'replacement = "${1}[ARTIFACT_ID]${2}"', 1)
source = source.replace(
    'func isUserProvidedSecretConfiguration(text string) bool {\n\treturn secretTermPattern.MatchString(text) && secretConfigurationPattern.MatchString(text)\n}',
    'func isUserProvidedSecretConfiguration(text string) bool {\n\treturn strings.Contains(text, "[USER_PROVIDED_SECRET]") && secretConfigurationPattern.MatchString(text)\n}',
    1,
)

source = source.replace(
    'func (e *AuditEngine) matchRules(text string, policy AuditPolicy) (*AuditDecision, *RuleMatchDiagnostics, []RuleSuppressionDiagnostic) {',
    'func (e *AuditEngine) matchRules(text string) (*AuditDecision, *RuleMatchDiagnostics) {\n'
    '\tdecision, diagnostics, _ := e.matchRulesWithPolicy(text, strictAuditPolicy())\n'
    '\treturn decision, diagnostics\n'
    '}\n\n'
    'func (e *AuditEngine) matchRulesWithPolicy(text string, policy AuditPolicy) (*AuditDecision, *RuleMatchDiagnostics, []RuleSuppressionDiagnostic) {',
    1,
)
source = source.replace('e.matchRules(text, policy)', 'e.matchRulesWithPolicy(text, policy)')
source = source.replace('engine.matchRules("ROLE=USER\\n"+text, policy)', 'engine.matchRulesWithPolicy("ROLE=USER\\n"+text, policy)')
exec(compile(source, str(path), "exec"), {"__name__": "__main__", "__file__": str(path)})
