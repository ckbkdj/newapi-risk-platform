from pathlib import Path

path = Path(__file__).resolve().parents[1] / "scripts/e2e.sh"
text = path.read_text(encoding="utf-8")

old_comment = '''# A defensive/self-service credential request may match the broad credential
# rule but must be downgraded to Review rather than hard-blocked. The mock audit
# model allows it, so the gateway should continue to the real upstream.
'''
new_comment = '''# Ambiguous credential access is a native Review rule. The mock audit model
# recognizes this as the requester's own secret-rotation workflow, so the
# gateway should continue to the real upstream without a hard-block downgrade.
'''
if new_comment not in text:
    if old_comment not in text:
        raise SystemExit("own-secret request comment anchor not found")
    text = text.replace(old_comment, new_comment, 1)

old_assertion = '''self_service = next((item for item in items if item.get("request_id") == "e2e-own-secret-self-service"), None)
if not self_service:
    raise RuntimeError("own-secret self-service trace is missing")
sm = self_service.get("metadata", {})
if sm.get("audit_rule_code") != "CYBER_CREDENTIAL_THEFT":
    raise RuntimeError(f"own-secret request did not match credential rule first: {sm}")
if sm.get("audit_rule_downgraded_to_review") is not True:
    raise RuntimeError(f"own-secret request was not downgraded to semantic review: {sm}")
if not sm.get("audit_rule_downgrade_reason") or not sm.get("audit_user_guidance"):
    raise RuntimeError(f"own-secret remediation diagnostics missing: {sm}")
if self_service.get("decision") != "allow" or int(self_service.get("http_status", 0)) != 200:
    raise RuntimeError(f"own-secret request should be allowed after model review: {self_service}")
'''
new_assertion = '''self_service = next((item for item in items if item.get("request_id") == "e2e-own-secret-self-service"), None)
if not self_service:
    raise RuntimeError("own-secret self-service trace is missing")
sm = self_service.get("metadata", {})
if sm.get("audit_rule_code") != "CYBER_CREDENTIAL_ACCESS_REVIEW":
    raise RuntimeError(f"own-secret request did not match the native credential-review rule: {sm}")
if sm.get("audit_rule_action") != "review":
    raise RuntimeError(f"own-secret request was not sent to semantic review: {sm}")
if sm.get("audit_rule_downgraded_to_review") is True:
    raise RuntimeError(f"native credential Review was incorrectly recorded as a downgraded Block: {sm}")
for key in ("audit_rule_context", "audit_trigger_input", "audit_user_guidance"):
    if not sm.get(key):
        raise RuntimeError(f"own-secret review diagnostic {key} missing: {sm}")
if self_service.get("decision") != "allow" or int(self_service.get("http_status", 0)) != 200:
    raise RuntimeError(f"own-secret request should be allowed after model review: {self_service}")
'''
if new_assertion not in text:
    if old_assertion not in text:
        raise SystemExit("own-secret trace assertion anchor not found")
    text = text.replace(old_assertion, new_assertion, 1)

path.write_text(text, encoding="utf-8")
print("native credential Review E2E assertions applied")
