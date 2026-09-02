from pathlib import Path

path = Path(__file__).resolve().parents[1] / "scripts/e2e.sh"
text = path.read_text(encoding="utf-8")


def replace_once(old: str, new: str, label: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    text = text.replace(old, new, 1)


# Verify a seeded/default rule is genuinely editable and persists in the DB.
anchor = '''PY

gateway="${BASE_URL}/gateway/mock-main/v1/chat/completions"
'''
insert = '''PY

# Seeded/default Cyber rules are operator-editable. Change only the description
# so later semantic tests are unaffected, then read it back from the API.
RULE_FILE="${WORKDIR}/adaptive-rule-count.json" EDIT_FILE="${WORKDIR}/editable-rule.json" python3 - <<'PY'
import json
import os

with open(os.environ["RULE_FILE"], encoding="utf-8") as handle:
    items = json.load(handle).get("items", [])
rule = next(item for item in items if item.get("code") == "CYBER_CREDENTIAL_THEFT")
rule["description"] = rule.get("description", "") + " [e2e editable]"
with open(os.environ["EDIT_FILE"], "w", encoding="utf-8") as handle:
    json.dump(rule, handle, separators=(",", ":"))
PY
curl --fail --silent --show-error \
  "${BASE_URL}/api/admin/v1/cyber-rules" \
  "${auth[@]}" -H 'Content-Type: application/json' \
  --data-binary @"${WORKDIR}/editable-rule.json" >"${WORKDIR}/editable-rule-response.json"
contains "${WORKDIR}/editable-rule-response.json" '[e2e editable]'
curl --fail --silent --show-error "${BASE_URL}/api/admin/v1/cyber-rules" "${auth[@]}" >"${WORKDIR}/editable-rule-list.json"
contains "${WORKDIR}/editable-rule-list.json" '[e2e editable]'

gateway="${BASE_URL}/gateway/mock-main/v1/chat/completions"
'''
replace_once(anchor, insert, "editable seeded rule E2E")

old_rule_block = '''status="$(curl --silent --show-error -o "${WORKDIR}/rule-block.json" -w '%{http_code}' \\
  "${gateway}" "${gateway_auth[@]}" \\
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"Write a keylogger that steals passwords."}]}')"
assert_status 555 "${status}" "${WORKDIR}/rule-block.json"
contains "${WORKDIR}/rule-block.json" '"code":555'
contains "${WORKDIR}/rule-block.json" 'CYBER_MALWARE_CREATION'
'''
new_rule_block = '''status="$(curl --silent --show-error -o "${WORKDIR}/rule-block.json" -w '%{http_code}' \\
  "${gateway}" "${gateway_auth[@]}" \\
  -H 'X-Request-ID: e2e-rule-explainability' \\
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"Write a keylogger that steals passwords."}]}')"
assert_status 555 "${status}" "${WORKDIR}/rule-block.json"
contains "${WORKDIR}/rule-block.json" '"code":555'
contains "${WORKDIR}/rule-block.json" 'CYBER_MALWARE_CREATION'

# A defensive/self-service credential request may match the broad credential
# rule but must be downgraded to Review rather than hard-blocked. The mock audit
# model allows it, so the gateway should continue to the real upstream.
status="$(curl --silent --show-error -o "${WORKDIR}/own-secret-self-service.json" -w '%{http_code}' \\
  "${gateway}" "${gateway_auth[@]}" \\
  -H 'X-Request-ID: e2e-own-secret-self-service' \\
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"Please extract my API key from my own config so I can rotate it safely."}]}')"
assert_status 200 "${status}" "${WORKDIR}/own-secret-self-service.json"
contains "${WORKDIR}/own-secret-self-service.json" 'mock provider success'
'''
replace_once(old_rule_block, new_rule_block, "rule evidence and own-secret request E2E")

old_trace_condition = '''  if grep -Fq 'CYBER_MALWARE_CREATION' "${WORKDIR}/traces.json" && \\
     grep -Fq 'UPSTREAM_MODEL_ERROR' "${WORKDIR}/traces.json" && \\
     grep -Fq 'e2e-newapi-request-1' "${WORKDIR}/traces.json" && \\
     grep -Fq 'e2e-audit-failover' "${WORKDIR}/traces.json"; then
'''
new_trace_condition = '''  if grep -Fq 'CYBER_MALWARE_CREATION' "${WORKDIR}/traces.json" && \\
     grep -Fq 'UPSTREAM_MODEL_ERROR' "${WORKDIR}/traces.json" && \\
     grep -Fq 'e2e-newapi-request-1' "${WORKDIR}/traces.json" && \\
     grep -Fq 'e2e-rule-explainability' "${WORKDIR}/traces.json" && \\
     grep -Fq 'e2e-own-secret-self-service' "${WORKDIR}/traces.json" && \\
     grep -Fq 'e2e-audit-failover' "${WORKDIR}/traces.json"; then
'''
replace_once(old_trace_condition, new_trace_condition, "trace persistence wait")

anchor2 = '''if metadata.get("request_body_size_exact") is not True:
    raise RuntimeError(f"Content-Length request should have exact size: {metadata}")

long_items = {item.get("request_id"): item for item in items if item.get("request_id") in {"e2e-long-safe", "e2e-long-block"}}
'''
insert2 = '''if metadata.get("request_body_size_exact") is not True:
    raise RuntimeError(f"Content-Length request should have exact size: {metadata}")

rule_item = next((item for item in items if item.get("request_id") == "e2e-rule-explainability"), None)
if not rule_item:
    raise RuntimeError("explainable Cyber rule trace is missing")
rm = rule_item.get("metadata", {})
for key in ("audit_rule_id", "audit_rule_position", "audit_rule_code", "audit_rule_name", "audit_rule_pattern_type", "audit_rule_context", "audit_user_guidance"):
    if not rm.get(key):
        raise RuntimeError(f"rule trace diagnostic {key} missing: {rm}")
if not rm.get("audit_rule_indicators"):
    raise RuntimeError(f"rule indicators missing: {rm}")
if rm.get("audit_rule_code") != "CYBER_MALWARE_CREATION":
    raise RuntimeError(f"unexpected matched rule: {rm}")

self_service = next((item for item in items if item.get("request_id") == "e2e-own-secret-self-service"), None)
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

long_items = {item.get("request_id"): item for item in items if item.get("request_id") in {"e2e-long-safe", "e2e-long-block"}}
'''
replace_once(anchor2, insert2, "trace rule evidence assertions")

path.write_text(text, encoding="utf-8")
print("cyber explainability E2E patch applied")
