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

status="$(curl --silent --show-error -o "${WORKDIR}/allow.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"Explain defensive application logging."}]}')"
assert_status 200 "${status}" "${WORKDIR}/allow.json"
contains "${WORKDIR}/allow.json" 'mock provider success'


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

status="$(curl --silent --show-error -o "${WORKDIR}/audit-invalid.json" -w '%{http_code}' \
  "${gateway}" "${gateway_auth[@]}" \
  --data-binary '{"model":"normal","messages":[{"role":"user","content":"model-audit-invalid-json"}]}')"
assert_status 555 "${status}" "${WORKDIR}/audit-invalid.json"
contains "${WORKDIR}/audit-invalid.json" 'AUDIT_MODEL_ERROR'

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
     grep -Fq 'e2e-newapi-request-1' "${WORKDIR}/traces.json"; then
    trace_ok=1
    break
  fi
  sleep 0.25
done
[[ "${trace_ok}" == 1 ]] || fail "expected gateway and New API traces were not persisted"


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
