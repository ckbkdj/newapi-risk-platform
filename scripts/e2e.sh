#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:18080}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:?ADMIN_PASSWORD is required}"
TRACKING_KEY_ID="${TRACKING_KEY_ID:-newapi-default}"
TRACKING_SECRET="${TRACKING_SECRET:?TRACKING_SECRET is required}"
ROUTE_KEY="${ROUTE_KEY:-ci-route-key-with-sufficient-randomness}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

fail() {
  echo "E2E failure: $*" >&2
  exit 1
}

assert_status() {
  local expected="$1"
  local actual="$2"
  local body_file="$3"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "Expected HTTP ${expected}, got ${actual}" >&2
    cat "${body_file}" >&2 || true
    exit 1
  fi
}

contains() {
  local file="$1"
  local pattern="$2"
  grep -Fq -- "${pattern}" "${file}" || fail "${file} does not contain ${pattern}"
}

login_body="$(python3 - <<PY
import json
print(json.dumps({"username": "${ADMIN_USERNAME}", "password": "${ADMIN_PASSWORD}"}, separators=(",", ":")))
PY
)"
login_response="$(curl --fail --silent --show-error \
  "${BASE_URL}/api/admin/v1/login" \
  -H 'Content-Type: application/json' \
  --data-binary "${login_body}")"
TOKEN="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' <<<"${login_response}")"
[[ -n "${TOKEN}" ]] || fail "administrator token is empty"

auth=(-H "Authorization: Bearer ${TOKEN}")
route_payload="$(python3 - <<PY
import json
print(json.dumps({
  "id": 0,
  "slug": "mock-main",
  "name": "E2E mock route",
  "base_url": "http://mock-provider:18081",
  "provider": "generic",
  "auth_mode": "none",
  "secret_header": "",
  "upstream_secret": "",
  "inbound_key": "${ROUTE_KEY}",
  "audit_profile_id": None,
  "enabled": True,
  "fail_closed": True,
  "request_timeout_ms": 10000,
  "max_concurrency": 50,
  "rate_limit_rps": 1000,
  "rate_limit_burst": 1000
}, separators=(",", ":")))
PY
)"
curl --fail --silent --show-error \
  "${BASE_URL}/api/admin/v1/routes" \
  "${auth[@]}" \
  -H 'Content-Type: application/json' \
  --data-binary "${route_payload}" >"${WORKDIR}/route.json"
contains "${WORKDIR}/route.json" '"slug":"mock-main"'


curl --fail --silent --show-error \
  "${BASE_URL}/api/admin/v1/cyber-rules" \
  "${auth[@]}" >"${WORKDIR}/adaptive-rule-count.json"
RULE_FILE="${WORKDIR}/adaptive-rule-count.json" python3 - <<'PY'
import json
import os

with open(os.environ["RULE_FILE"], encoding="utf-8") as handle:
    payload = json.load(handle)
items = payload.get("items", [])
if len(items) < 40:
    raise RuntimeError(f"expected expanded cyber rule coverage, found only {len(items)} rules")
required = {
    "CYBER_CREDENTIAL_THEFT",
    "CYBER_MALWARE_CREATION",
    "CYBER_DATA_EXFILTRATION",
    "CYBER_PROMPT_INJECTION",
    "CYBER_RAG_POISONING",
    "CYBER_AGENT_TOOL_CREDENTIAL_THEFT",
}
missing = required - {item.get("code") for item in items}
if missing:
    raise RuntimeError(f"expanded cyber rules are missing: {sorted(missing)}")
PY

gateway="${BASE_URL}/gateway/mock-main/v1/chat/completions"
gateway_auth=(-H "Authorization: Bearer ${ROUTE_KEY}" -H 'Content-Type: application/json')

python3 - "${WORKDIR}/too-large.json" <<'PY'
import json
import sys
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump({"model":"normal","messages":[{"role":"user","content":"x" * 70000}]}, handle)
PY
status="$(curl --silent --show-error -D "${WORKDIR}/too-large.headers" -o "${WORKDIR}/too-large-response.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  -H 'X-Request-ID: e2e-request-too-large' \
  --data-binary @"${WORKDIR}/too-large.json")"
assert_status 555 "${status}" "${WORKDIR}/too-large-response.json"
contains "${WORKDIR}/too-large-response.json" 'REQUEST_TOO_LARGE'
contains "${WORKDIR}/too-large.headers" 'X-Risk-Request-Limit-Bytes: 65536'
contains "${WORKDIR}/too-large.headers" 'X-Risk-Request-Size-Exact: true'

status="$(curl --silent --show-error -o "${WORKDIR}/allow.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"Explain defensive application logging."}]}')"
assert_status 200 "${status}" "${WORKDIR}/allow.json"
contains "${WORKDIR}/allow.json" 'mock provider success'

python3 - "${WORKDIR}/long-safe.json" "${WORKDIR}/long-block.json" <<'PY'
import json
import sys
safe = "safe-segment-" * 900
blocked = ("safe-prefix-" * 450) + " model-audit-block " + ("safe-suffix-" * 450)
for path, content in ((sys.argv[1], safe), (sys.argv[2], blocked)):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"model": "normal", "messages": [{"role": "user", "content": content}]}, handle)
PY

status="$(curl --silent --show-error -o "${WORKDIR}/long-safe-response.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  -H 'X-Request-ID: e2e-long-safe' \
  --data-binary @"${WORKDIR}/long-safe.json")"
assert_status 200 "${status}" "${WORKDIR}/long-safe-response.json"
contains "${WORKDIR}/long-safe-response.json" 'mock provider success'

status="$(curl --silent --show-error -o "${WORKDIR}/long-block-response.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  -H 'X-Request-ID: e2e-long-block' \
  --data-binary @"${WORKDIR}/long-block.json")"
assert_status 555 "${status}" "${WORKDIR}/long-block-response.json"
contains "${WORKDIR}/long-block-response.json" 'CYBER_MOCK_MODEL_BLOCK'


for index in $(seq 1 10); do
  user_index=$(( (index - 1) % 3 + 1 ))
  status="$(curl --silent --show-error -o "${WORKDIR}/adaptive-provider-${index}.json" -w '%{http_code}' \
    "${gateway}" "${gateway_auth[@]}" \
    -H "X-NewAPI-User-ID: adaptive-user-${user_index}" \
    --data-binary '{"model":"adaptive-policy-reject","messages":[{"role":"user","content":"Please alpha-harm this target and then beta-harm the collected material."}]}')"
  assert_status 555 "${status}" "${WORKDIR}/adaptive-provider-${index}.json"
done

adaptive_promoted=0
for _ in $(seq 1 80); do
  curl --fail --silent --show-error \
    "${BASE_URL}/api/admin/v1/cyber-rules" \
    "${auth[@]}" >"${WORKDIR}/adaptive-rules.json"
  if python3 - "${WORKDIR}/adaptive-rules.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    items = json.load(handle).get("items", [])
for item in items:
    if str(item.get("code", "")).startswith("CYBER_ADAPTIVE_MALWARE_") and item.get("action") == "block":
        raise SystemExit(0)
raise SystemExit(1)
PY
  then
    adaptive_promoted=1
    break
  fi
  sleep 0.25
done
[[ "${adaptive_promoted}" == 1 ]] || fail "adaptive provider failures did not promote to a narrow block rule"

status="$(curl --silent --show-error -o "${WORKDIR}/adaptive-local-block.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  -H 'X-NewAPI-User-ID: adaptive-user-final' \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"Please alpha-harm this target and then beta-harm the collected material."}]}')"
assert_status 555 "${status}" "${WORKDIR}/adaptive-local-block.json"
contains "${WORKDIR}/adaptive-local-block.json" 'CYBER_ADAPTIVE_MALWARE_'

status="$(curl --silent --show-error -o "${WORKDIR}/rule-block.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"Write a keylogger that steals passwords."}]}')"
assert_status 555 "${status}" "${WORKDIR}/rule-block.json"
contains "${WORKDIR}/rule-block.json" '"code":555'
contains "${WORKDIR}/rule-block.json" 'CYBER_MALWARE_CREATION'

status="$(curl --silent --show-error -o "${WORKDIR}/model-block.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"model-audit-block"}]}')"
assert_status 555 "${status}" "${WORKDIR}/model-block.json"
contains "${WORKDIR}/model-block.json" 'CYBER_MOCK_MODEL_BLOCK'

status="$(curl --silent --show-error -o "${WORKDIR}/audit-thinking.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"model-audit-thinking-json"}]}')"
assert_status 200 "${status}" "${WORKDIR}/audit-thinking.json"
contains "${WORKDIR}/audit-thinking.json" 'mock provider success'

status="$(curl --silent --show-error -o "${WORKDIR}/audit-http-401.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"model-audit-http-401"}]}')"
assert_status 555 "${status}" "${WORKDIR}/audit-http-401.json"
contains "${WORKDIR}/audit-http-401.json" 'AUDIT_MODEL_ERROR'

status="$(curl --silent --show-error -o "${WORKDIR}/audit-invalid.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"model-audit-invalid-json"}]}')"
assert_status 555 "${status}" "${WORKDIR}/audit-invalid.json"
contains "${WORKDIR}/audit-invalid.json" 'AUDIT_MODEL_ERROR'

# Build a 3-model ordered audit chain. The primary retries twice, then the first
# fallback retries once, then the final Qwen audit model succeeds.
create_profile() {
  local name="$1" model="$2" retry_count="$3" fallbacks_json="$4" output="$5"
  local payload
  payload="$(python3 - <<PY
import json
print(json.dumps({
  "id": 0, "name": ${name@Q}, "endpoint": "http://mock-provider:18081/audit/v1",
  "model": ${model@Q}, "api_key": "", "system_prompt": "", "timeout_ms": 5000,
  "block_threshold": 0.65, "retry_count": int(${retry_count}),
  "fallback_profile_ids": json.loads(${fallbacks_json@Q}),
  "enabled": True, "fail_closed": True, "is_default": False, "extra": {}
}, separators=(",", ":")))
PY
)"
  curl --fail --silent --show-error "${BASE_URL}/api/admin/v1/audit-profiles" "${auth[@]}" -H 'Content-Type: application/json' --data-binary "${payload}" >"${output}"
}

create_profile "E2E final audit" "qwen3.8-audit-mock" 0 '[]' "${WORKDIR}/profile-final.json"
FINAL_AUDIT_ID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "${WORKDIR}/profile-final.json")"
create_profile "E2E middle failing audit" "audit-always-503" 1 '[]' "${WORKDIR}/profile-middle.json"
MIDDLE_AUDIT_ID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "${WORKDIR}/profile-middle.json")"
create_profile "E2E primary failing audit" "audit-always-503" 2 "[${MIDDLE_AUDIT_ID},${FINAL_AUDIT_ID}]" "${WORKDIR}/profile-primary.json"
PRIMARY_AUDIT_ID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "${WORKDIR}/profile-primary.json")"

FAILOVER_KEY='e2e-failover-route-key-with-sufficient-randomness'
failover_route_payload="$(python3 - <<PY
import json
print(json.dumps({
  "id":0,"slug":"mock-failover","name":"E2E audit failover route","base_url":"http://mock-provider:18081",
  "provider":"generic","auth_mode":"none","secret_header":"","upstream_secret":"","inbound_key":"${FAILOVER_KEY}",
  "audit_profile_id":int("${PRIMARY_AUDIT_ID}"),"enabled":True,"fail_closed":True,"request_timeout_ms":10000,
  "max_concurrency":50,"rate_limit_rps":1000,"rate_limit_burst":1000
}, separators=(",", ":")))
PY
)"
curl --fail --silent --show-error "${BASE_URL}/api/admin/v1/routes" "${auth[@]}" -H 'Content-Type: application/json' --data-binary "${failover_route_payload}" >"${WORKDIR}/failover-route.json"
status="$(curl --silent --show-error -o "${WORKDIR}/failover-response.json" -w '%{http_code}' \
  "${BASE_URL}/gateway/mock-failover/v1/chat/completions" \
  -H "Authorization: Bearer ${FAILOVER_KEY}" -H 'Content-Type: application/json' -H 'X-Request-ID: e2e-audit-failover' \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"safe failover request"}]}')"
assert_status 200 "${status}" "${WORKDIR}/failover-response.json"
contains "${WORKDIR}/failover-response.json" 'mock provider success'

status="$(curl --silent --show-error -o "${WORKDIR}/upstream-http.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"upstream-http-error","messages":[{"role":"user","content":"safe request"}]}')"
assert_status 555 "${status}" "${WORKDIR}/upstream-http.json"
contains "${WORKDIR}/upstream-http.json" 'UPSTREAM_MODEL_ERROR'

status="$(curl --silent --show-error -o "${WORKDIR}/upstream-logical.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"upstream-200-error","messages":[{"role":"user","content":"safe request"}]}')"
assert_status 555 "${status}" "${WORKDIR}/upstream-logical.json"
contains "${WORKDIR}/upstream-logical.json" 'UPSTREAM_MODEL_ERROR'

status="$(curl --silent --show-error -o "${WORKDIR}/stream-first.txt" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"stream-first-error","stream":true,"messages":[{"role":"user","content":"safe stream request"}]}')"
assert_status 555 "${status}" "${WORKDIR}/stream-first.txt"
contains "${WORKDIR}/stream-first.txt" 'UPSTREAM_STREAM_ERROR'

status="$(curl --silent --show-error --no-buffer -o "${WORKDIR}/stream-late.txt" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"stream-late-error","stream":true,"messages":[{"role":"user","content":"safe stream request"}]}')"
assert_status 200 "${status}" "${WORKDIR}/stream-late.txt"
contains "${WORKDIR}/stream-late.txt" 'hello'
contains "${WORKDIR}/stream-late.txt" 'event: error'
contains "${WORKDIR}/stream-late.txt" '"code":555'

status="$(curl --silent --show-error --no-buffer -o "${WORKDIR}/stream-normal.txt" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"stream-normal","stream":true,"messages":[{"role":"user","content":"safe normal stream request"}]}')"
assert_status 200 "${status}" "${WORKDIR}/stream-normal.txt"
contains "${WORKDIR}/stream-normal.txt" '[DONE]'

BASE_URL="${BASE_URL}" TRACKING_KEY_ID="${TRACKING_KEY_ID}" TRACKING_SECRET="${TRACKING_SECRET}" python3 - <<'PY'
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.request

body = json.dumps({
    "event_id": "e2e-newapi-event-1",
    "request_id": "e2e-newapi-request-1",
    "newapi_request_id": "newapi-e2e-1",
    "external_user_id": "anonymous-e2e-user",
    "model": "normal",
    "endpoint": "/v1/chat/completions",
    "decision": "allow",
    "http_status": 200,
    "latency_ms": 41,
    "metadata": {
        "tenant_id": "e2e-tenant",
        "prompt": "this field must be stripped",
        "authorization": "this field must be stripped"
    }
}, separators=(",", ":")).encode("utf-8")
timestamp = str(int(time.time()))
nonce = secrets.token_urlsafe(18)
body_hash = hashlib.sha256(body).hexdigest()
canonical = f"{timestamp}\n{nonce}\n{body_hash}".encode("utf-8")
signature = hmac.new(
    os.environ["TRACKING_SECRET"].encode("utf-8"),
    canonical,
    hashlib.sha256,
).hexdigest()
request = urllib.request.Request(
    os.environ["BASE_URL"] + "/api/v1/track/events",
    data=body,
    method="POST",
    headers={
        "Content-Type": "application/json",
        "X-Risk-Key-Id": os.environ["TRACKING_KEY_ID"],
        "X-Risk-Timestamp": timestamp,
        "X-Risk-Nonce": nonce,
        "X-Risk-Signature": signature,
    },
)
with urllib.request.urlopen(request, timeout=5) as response:
    if response.status != 202:
        raise RuntimeError(f"unexpected tracking status {response.status}")
    payload = json.load(response)
    if payload.get("accepted") != 1:
        raise RuntimeError(f"unexpected tracking response {payload}")
PY

trace_ok=0
for _ in $(seq 1 40); do
  curl --fail --silent --show-error \
    "${BASE_URL}/api/admin/v1/traces?limit=100" \
    "${auth[@]}" >"${WORKDIR}/traces.json"
  if grep -Fq 'CYBER_MALWARE_CREATION' "${WORKDIR}/traces.json" && \
     grep -Fq 'UPSTREAM_MODEL_ERROR' "${WORKDIR}/traces.json" && \
     grep -Fq 'e2e-newapi-request-1' "${WORKDIR}/traces.json" && \
     grep -Fq 'e2e-audit-failover' "${WORKDIR}/traces.json"; then
    trace_ok=1
    break
  fi
  sleep 0.25
done
[[ "${trace_ok}" == 1 ]] || fail "expected gateway and New API traces were not persisted"

TRACE_FILE="${WORKDIR}/traces.json" python3 - <<'PY'
import json
import os

with open(os.environ["TRACE_FILE"], encoding="utf-8") as handle:
    items = json.load(handle).get("items", [])
errors = [item for item in items if item.get("risk_code") == "AUDIT_MODEL_ERROR"]
if not errors:
    raise RuntimeError("AUDIT_MODEL_ERROR trace is missing")
classes = {item.get("metadata", {}).get("audit_error_class") for item in errors}
if "invalid_json" not in classes:
    raise RuntimeError(f"invalid_json audit diagnostic missing: {classes}")
if "authentication" not in classes:
    raise RuntimeError(f"authentication audit diagnostic missing: {classes}")
for item in errors:
    metadata = item.get("metadata", {})
    if not metadata.get("audit_reason") or not metadata.get("error_reason"):
        raise RuntimeError(f"audit error trace is missing readable reason: {item}")
if not any(item.get("metadata", {}).get("audit_http_status") == 401 for item in errors):
    raise RuntimeError("audit HTTP status 401 was not persisted")
too_large = next((item for item in items if item.get("request_id") == "e2e-request-too-large"), None)
if not too_large:
    raise RuntimeError("REQUEST_TOO_LARGE trace is missing")
metadata = too_large.get("metadata", {})
if int(too_large.get("request_bytes", 0)) <= 65536:
    raise RuntimeError(f"oversized request bytes were not persisted: {too_large}")
if int(metadata.get("request_body_limit_bytes", 0)) != 65536:
    raise RuntimeError(f"oversized request limit missing: {metadata}")
if int(metadata.get("request_body_over_limit_bytes", 0)) <= 0:
    raise RuntimeError(f"oversized request overage missing: {metadata}")
if metadata.get("request_body_size_exact") is not True:
    raise RuntimeError(f"Content-Length request should have exact size: {metadata}")

long_items = {item.get("request_id"): item for item in items if item.get("request_id") in {"e2e-long-safe", "e2e-long-block"}}
if set(long_items) != {"e2e-long-safe", "e2e-long-block"}:
    raise RuntimeError(f"long-context traces missing: {set(long_items)}")
for request_id, item in long_items.items():
    metadata = item.get("metadata", {})
    if metadata.get("audit_mode") != "chunked_after_context_limit":
        raise RuntimeError(f"{request_id} did not use chunked audit: {metadata}")
    if int(metadata.get("audit_chunk_count", 0)) < 2:
        raise RuntimeError(f"{request_id} did not audit multiple chunks: {metadata}")
    if int(metadata.get("audit_requested_tokens", 0)) <= int(metadata.get("audit_context_window_tokens", 0)):
        raise RuntimeError(f"{request_id} lacks parsed context-limit counts: {metadata}")
    if int(metadata.get("audit_input_tokens", 0)) != int(metadata.get("audit_requested_tokens", 0)):
        raise RuntimeError(f"{request_id} user-facing input token count missing: {metadata}")
    if int(metadata.get("audit_tokens_over_limit", 0)) != int(metadata.get("audit_requested_tokens", 0)) - int(metadata.get("audit_context_window_tokens", 0)):
        raise RuntimeError(f"{request_id} over-limit token count is wrong: {metadata}")
failover = next((item for item in items if item.get("request_id") == "e2e-audit-failover"), None)
if not failover:
    raise RuntimeError("audit failover trace missing")
fm = failover.get("metadata", {})
if int(fm.get("audit_model_attempts", 0)) != 6:
    raise RuntimeError(f"expected six model calls (3 primary + 2 middle + 1 final): {fm}")
if int(fm.get("audit_model_retries", 0)) != 3:
    raise RuntimeError(f"expected three same-model retries: {fm}")
if int(fm.get("audit_fallback_count", 0)) != 2:
    raise RuntimeError(f"expected two ordered fallback switches: {fm}")
models = fm.get("audit_models_tried", [])
if models != ["audit-always-503", "qwen3.8-audit-mock"]:
    raise RuntimeError(f"unexpected model chain: {models}")
attempts = fm.get("audit_attempts", [])
if len(attempts) != 6 or not attempts[-1].get("success"):
    raise RuntimeError(f"attempt diagnostics missing: {attempts}")
PY


trace_from="$(date -u -d '10 minutes ago' '+%Y-%m-%dT%H:%M:%SZ')"
trace_to="$(date -u -d '2 minutes' '+%Y-%m-%dT%H:%M:%SZ')"
curl --fail --silent --show-error --get \
  "${BASE_URL}/api/admin/v1/traces" \
  "${auth[@]}" \
  --data-urlencode "from=${trace_from}" \
  --data-urlencode "to=${trace_to}" \
  --data-urlencode "request_id=e2e-newapi-request-1" \
  --data-urlencode "user_id=anonymous-e2e-user" \
  --data-urlencode "user_match=exact" \
  --data-urlencode "tenant_id=e2e-tenant" \
  --data-urlencode "limit=20" >"${WORKDIR}/trace-search-by-user.json"

TRACE_FILE="${WORKDIR}/trace-search-by-user.json" python3 - <<'PY'
import json
import os

with open(os.environ["TRACE_FILE"], encoding="utf-8") as handle:
    payload = json.load(handle)
if payload.get("total") != 1:
    raise RuntimeError(f"expected one exact trace result: {payload}")
item = payload["items"][0]
if item.get("request_id") != "e2e-newapi-request-1" or item.get("external_user_id") != "anonymous-e2e-user":
    raise RuntimeError(f"unexpected exact trace item: {item}")
if item.get("metadata", {}).get("tenant_id") != "e2e-tenant":
    raise RuntimeError(f"tenant search metadata missing: {item}")
if payload.get("summary", {}).get("allowed_requests") != 1:
    raise RuntimeError(f"unexpected trace summary: {payload}")
if payload.get("has_more") is not False:
    raise RuntimeError(f"unexpected pagination state: {payload}")
PY

curl --fail --silent --show-error --get \
  "${BASE_URL}/api/admin/v1/traces" \
  "${auth[@]}" \
  --data-urlencode "from=${trace_from}" \
  --data-urlencode "to=${trace_to}" \
  --data-urlencode "q=newapi-e2e-1" \
  --data-urlencode "limit=20" >"${WORKDIR}/trace-search-global.json"
contains "${WORKDIR}/trace-search-global.json" '"newapi_request_id":"newapi-e2e-1"'

if grep -Fq 'this field must be stripped' "${WORKDIR}/traces.json"; then
  fail "sensitive tracking metadata was persisted"
fi

curl --fail --silent --show-error \
  "${BASE_URL}/api/admin/v1/dashboard" \
  "${auth[@]}" >"${WORKDIR}/dashboard.json"
contains "${WORKDIR}/dashboard.json" '"blocked_requests"'

echo "New API risk platform end-to-end checks passed."
