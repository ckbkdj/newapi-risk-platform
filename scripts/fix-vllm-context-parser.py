from pathlib import Path

path = Path(__file__).resolve().parents[1] / "internal/platform/audit_diagnostics.go"
text = path.read_text(encoding="utf-8")
old = '''var auditRequestedTokenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:you requested|your request has|request has|sequence length(?: is|:|=)?|input length(?: is|:|=)?)[^0-9]{0,40}([0-9][0-9,]*)`),
	regexp.MustCompile(`(?i)([0-9][0-9,]*)\\s+input tokens`),
}
'''
new = '''var auditRequestedTokenPatterns = []*regexp.Regexp{
	// vLLM reports output tokens before input tokens. Match the explicit input
	// count first so a message such as "you requested 128 output tokens and your
	// prompt contains 270000 input tokens" never treats 128 as prompt length.
	regexp.MustCompile(`(?i)(?:your\\s+)?prompt(?:\\s+contains|\\s+has|\\s+length(?:\\s+is|:|=)?)[^0-9]{0,40}(?:at\\s+least\\s+)?([0-9][0-9,]*)\\s+input\\s+tokens`),
	regexp.MustCompile(`(?i)([0-9][0-9,]*)\\s+input\\s+tokens`),
	regexp.MustCompile(`(?i)(?:your request has|request has|sequence length(?: is|:|=)?|input length(?: is|:|=)?)[^0-9]{0,40}([0-9][0-9,]*)`),
	regexp.MustCompile(`(?i)for a total of[^0-9]{0,20}([0-9][0-9,]*)\\s+tokens`),
}
'''
if text.count(old) != 1:
    raise SystemExit(f"requested token pattern anchor count={text.count(old)}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
print("vLLM context-token parser corrected")
