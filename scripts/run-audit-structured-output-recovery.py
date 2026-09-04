from pathlib import Path

script_path = Path(__file__).with_name("apply-audit-structured-output-recovery.py")
source = script_path.read_text(encoding="utf-8")
source = source.replace('finishReason = stringValue(choice["finish_reason"])', 'finishReason = auditStringValue(choice["finish_reason"])')
source = source.replace('func stringValue(value any) string {', 'func auditStringValue(value any) string {')
exec(compile(source, str(script_path), "exec"), {"__name__": "__main__", "__file__": str(script_path)})
